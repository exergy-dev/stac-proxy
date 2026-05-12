// Package federation provides the origin client for upstream STAC servers.
package federation

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/yourorg/stac-proxy/internal/middleware"
	"github.com/yourorg/stac-proxy/internal/stac"
)

// OriginClient handles communication with a single downstream STAC server.
type OriginClient struct {
	origin       *Origin
	httpClient   *http.Client
	authProvider AuthProvider
	baseURL      *url.URL

	// Cached collection info
	collections     map[string]*stac.Collection
	collectionsLock sync.RWMutex
	lastDiscovery   time.Time
}

// NewOriginClient creates a new client for an origin.
func NewOriginClient(origin *Origin) (*OriginClient, error) {
	baseURL, err := url.Parse(origin.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}

	// Build HTTP client
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}

	// TODO: Add mTLS support if ClientCert is configured

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   origin.Timeout,
	}

	// Build auth provider
	authProvider, err := BuildAuthProvider(origin.Auth)
	if err != nil {
		return nil, fmt.Errorf("auth provider error: %w", err)
	}

	client := &OriginClient{
		origin:       origin,
		httpClient:   httpClient,
		authProvider: authProvider,
		baseURL:      baseURL,
		collections:  make(map[string]*stac.Collection),
	}

	// Initial collection discovery if enabled
	if origin.AutoDiscover {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := client.DiscoverCollections(ctx); err != nil {
				// Log warning but don't fail
				fmt.Printf("initial collection discovery failed for %s: %v\n", origin.ID, err)
			}
		}()
	}

	return client, nil
}

// DoRequest executes an HTTP request to the origin with authentication.
func (c *OriginClient) DoRequest(ctx context.Context, method, path string,
	body io.Reader) (*http.Response, error) {

	reqURL := c.baseURL.ResolveReference(&url.URL{Path: path})

	req, err := http.NewRequestWithContext(ctx, method, reqURL.String(), body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/geo+json, application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	// Forward the inbound request ID so per-origin logs correlate
	// with the proxy's request log.
	if rid, ok := ctx.Value(middleware.RequestIDKey).(string); ok && rid != "" {
		req.Header.Set("X-Request-ID", rid)
	}

	// Apply origin-specific authentication
	if c.authProvider != nil {
		if err := c.authProvider.ApplyAuth(ctx, req); err != nil {
			return nil, fmt.Errorf("auth failed for origin %s: %w", c.origin.ID, err)
		}
	}

	// Execute with retry if configured
	if c.origin.Retry != nil && c.origin.Retry.MaxRetries > 0 {
		return c.doWithRetry(ctx, req)
	}

	return c.httpClient.Do(req)
}

// doWithRetry executes the request with retry logic.
func (c *OriginClient) doWithRetry(ctx context.Context, req *http.Request) (*http.Response, error) {
	policy := c.origin.Retry
	var lastErr error
	backoff := policy.InitialBackoff

	for attempt := 0; attempt <= policy.MaxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
				backoff = minDuration(backoff*2, policy.MaxBackoff)
			}
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		if !c.shouldRetry(resp.StatusCode) {
			return resp, nil
		}

		resp.Body.Close()
		lastErr = fmt.Errorf("received status %d", resp.StatusCode)
	}

	return nil, fmt.Errorf("max retries exceeded: %w", lastErr)
}

// shouldRetry checks if the status code should trigger a retry.
func (c *OriginClient) shouldRetry(statusCode int) bool {
	policy := c.origin.Retry
	if policy == nil || len(policy.RetryOn) == 0 {
		return statusCode >= 500
	}
	for _, code := range policy.RetryOn {
		if statusCode == code {
			return true
		}
	}
	return false
}

// Search executes a search request against this origin.
func (c *OriginClient) Search(ctx context.Context, req *stac.SearchRequest) (*stac.FeatureCollection, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal search request: %w", err)
	}

	resp, err := c.DoRequest(ctx, "POST", "/search", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("search failed with status %d: %s", resp.StatusCode, string(body))
	}

	var fc stac.FeatureCollection
	if err := json.NewDecoder(resp.Body).Decode(&fc); err != nil {
		return nil, fmt.Errorf("failed to parse search response: %w", err)
	}

	return &fc, nil
}

// GetCollections fetches all collections from this origin.
func (c *OriginClient) GetCollections(ctx context.Context) ([]stac.Collection, error) {
	resp, err := c.DoRequest(ctx, "GET", "/collections", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("get collections failed with status %d: %s", resp.StatusCode, string(body))
	}

	var result stac.CollectionsResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to parse collections response: %w", err)
	}

	return result.Collections, nil
}

// GetCollection fetches a single collection by ID.
func (c *OriginClient) GetCollection(ctx context.Context, collectionID string) (*stac.Collection, error) {
	path := fmt.Sprintf("/collections/%s", collectionID)
	resp, err := c.DoRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("get collection failed with status %d: %s", resp.StatusCode, string(body))
	}

	var collection stac.Collection
	if err := json.NewDecoder(resp.Body).Decode(&collection); err != nil {
		return nil, fmt.Errorf("failed to parse collection response: %w", err)
	}

	return &collection, nil
}

// GetItem fetches a single item by collection and item ID.
func (c *OriginClient) GetItem(ctx context.Context, collectionID, itemID string) (*stac.Item, error) {
	path := fmt.Sprintf("/collections/%s/items/%s", collectionID, itemID)
	resp, err := c.DoRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("get item failed with status %d: %s", resp.StatusCode, string(body))
	}

	var item stac.Item
	if err := json.NewDecoder(resp.Body).Decode(&item); err != nil {
		return nil, fmt.Errorf("failed to parse item response: %w", err)
	}

	return &item, nil
}

// DiscoverCollections fetches and caches collections from this origin.
func (c *OriginClient) DiscoverCollections(ctx context.Context) error {
	collections, err := c.GetCollections(ctx)
	if err != nil {
		return err
	}

	c.collectionsLock.Lock()
	defer c.collectionsLock.Unlock()

	c.collections = make(map[string]*stac.Collection)
	for i := range collections {
		c.collections[collections[i].ID] = &collections[i]
	}
	c.lastDiscovery = time.Now()

	return nil
}

// CachedCollections returns the cached collection IDs.
func (c *OriginClient) CachedCollections() []string {
	c.collectionsLock.RLock()
	defer c.collectionsLock.RUnlock()

	ids := make([]string, 0, len(c.collections))
	for id := range c.collections {
		ids = append(ids, id)
	}
	return ids
}

// HasCollection checks if this origin serves a collection (based on cache or config).
func (c *OriginClient) HasCollection(collectionID string) bool {
	// Check explicit configuration first
	if len(c.origin.Collections) > 0 {
		for _, id := range c.origin.Collections {
			if id == collectionID {
				return true
			}
		}
		return false
	}

	// Check exclusions
	for _, id := range c.origin.ExcludeCollections {
		if id == collectionID {
			return false
		}
	}

	// Check cache
	c.collectionsLock.RLock()
	defer c.collectionsLock.RUnlock()
	_, ok := c.collections[collectionID]
	return ok
}

// Origin returns the origin configuration.
func (c *OriginClient) Origin() *Origin {
	return c.origin
}

// BaseURL returns the origin's base URL.
func (c *OriginClient) BaseURL() string {
	return c.baseURL.String()
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
