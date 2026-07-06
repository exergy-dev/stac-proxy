// Package federation provides the origin client for upstream STAC servers.
package federation

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/yourorg/stac-proxy/internal/httpx"
	"github.com/yourorg/stac-proxy/internal/middleware"
	"github.com/yourorg/stac-proxy/internal/stac"
)

// defaultMaxResponseBytes is the per-call upstream response body cap
// used when Origin.MaxResponseBytes is unset (zero or negative).
const defaultMaxResponseBytes int64 = 32 << 20 // 32 MiB

// OriginClient handles communication with a single downstream STAC server.
type OriginClient struct {
	origin           *Origin
	httpClient       *http.Client
	transport        http.RoundTripper
	authProvider     AuthProvider
	baseURL          *url.URL
	maxResponseBytes int64

	// Cached collection info
	collections     map[string]*stac.Collection
	collectionsLock sync.RWMutex
	lastDiscovery   time.Time
}

// NewOriginClient creates a new client for an origin using a detached
// background context for auto-discovery. Prefer NewOriginClientWithContext
// for new call sites — it ties background discovery to the proxy's
// lifetime so shutdown aborts in-flight upstream calls.
func NewOriginClient(origin *Origin) (*OriginClient, error) {
	return NewOriginClientWithContext(context.Background(), slog.Default(), origin)
}

// NewOriginClientWithContext creates a new client for an origin and
// binds the background discovery goroutine to parentCtx. Retry and
// auth are layered into the transport so that ReverseProxy, raw
// DoRequest calls, and Search/GetCollection/GetItem helpers all share
// the same per-origin behavior automatically.
func NewOriginClientWithContext(parentCtx context.Context, logger *slog.Logger, origin *Origin) (*OriginClient, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if parentCtx == nil {
		parentCtx = context.Background()
	}
	baseURL, err := url.Parse(origin.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}

	maxIdle := origin.MaxIdleConnsPerHost
	if maxIdle <= 0 {
		maxIdle = 100
	}

	base := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: maxIdle,
		IdleConnTimeout:     90 * time.Second,
	}

	// Wire retry transport using locked httpx contract. When Retry is
	// nil we still wrap with a zero-MaxRetries config — httpx treats
	// that as a single-attempt passthrough.
	var retryCfg httpx.RetryConfig
	if origin.Retry != nil {
		retryCfg = httpx.RetryConfig{
			MaxRetries:     origin.Retry.MaxRetries,
			InitialBackoff: origin.Retry.InitialBackoff,
			MaxBackoff:     origin.Retry.MaxBackoff,
			RetryOn:        origin.Retry.RetryOn,
		}
	}
	retry := httpx.NewRetryTransport(base, retryCfg)

	// Build auth provider.
	authProvider, err := BuildAuthProvider(origin.Auth)
	if err != nil {
		return nil, fmt.Errorf("auth provider error: %w", err)
	}

	var rt http.RoundTripper = retry
	if authProvider != nil {
		if _, isNoop := authProvider.(*NoOpAuthProvider); !isNoop {
			rt = &authRoundTripper{auth: authProvider, next: retry}
		}
	}

	httpClient := &http.Client{
		Transport: rt,
		Timeout:   origin.Timeout,
	}

	maxResp := origin.MaxResponseBytes
	if maxResp <= 0 {
		maxResp = defaultMaxResponseBytes
	}

	client := &OriginClient{
		origin:           origin,
		httpClient:       httpClient,
		transport:        rt,
		authProvider:     authProvider,
		baseURL:          baseURL,
		maxResponseBytes: maxResp,
		collections:      make(map[string]*stac.Collection),
	}

	// Initial collection discovery if enabled. Bound to parentCtx so
	// a shutdown signal aborts any in-flight discovery rather than
	// letting it run to its 30s cap.
	if origin.AutoDiscover {
		go func() {
			ctx, cancel := context.WithTimeout(parentCtx, 30*time.Second)
			defer cancel()
			if err := client.DiscoverCollections(ctx); err != nil {
				logger.Warn("initial collection discovery failed",
					"origin", origin.ID,
					"error", err,
				)
			}
		}()
	}

	return client, nil
}

// DoRequest executes an HTTP request to the origin. Authentication and
// retry are applied transparently by the client's RoundTripper chain
// — see NewOriginClient.
//
// The supplied path is treated as a suffix to be appended to the
// origin's BaseURL path: BaseURL=https://example.com/v1 + path=/search
// yields https://example.com/v1/search. (url.ResolveReference would
// instead REPLACE the base path with an absolute path reference, per
// RFC 3986, which is the wrong operation for STAC endpoints — every
// public STAC API in the wild hosts its endpoints under a version
// prefix like /v1 or /api/stac/v1, and ResolveReference would strip
// that prefix.)
func (c *OriginClient) DoRequest(ctx context.Context, method, path string,
	body io.Reader) (*http.Response, error) {

	reqURL := *c.baseURL
	basePath := strings.TrimSuffix(c.baseURL.Path, "/")
	reqURL.Path = basePath + "/" + strings.TrimPrefix(path, "/")

	req, err := http.NewRequestWithContext(ctx, method, reqURL.String(), body)
	if err != nil {
		return nil, err
	}

	// Buffer + GetBody for retry replay safety on bodied requests.
	if body != nil {
		if err := httpx.BufferAndSetGetBody(req); err != nil {
			return nil, fmt.Errorf("buffer request body: %w", err)
		}
	}

	req.Header.Set("Accept", "application/geo+json, application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	middleware.ForwardRequestID(ctx, req)

	return c.httpClient.Do(req)
}

// countingReader wraps an io.Reader and tracks the cumulative number
// of bytes read so callers can enforce a maximum after a streaming
// decode.
type countingReader struct {
	r io.Reader
	n int64
}

func (cr *countingReader) Read(p []byte) (int, error) {
	n, err := cr.r.Read(p)
	cr.n += int64(n)
	return n, err
}

// limitedBody wraps the upstream resp.Body with an io.LimitReader at
// (maxResponseBytes + 1) bytes and a counter so that, after JSON
// decoding, we can detect whether the response exceeded the cap.
// Returns the counting reader (use cr.n to check the bytes read).
func (c *OriginClient) limitedBody(body io.Reader) *countingReader {
	return &countingReader{r: io.LimitReader(body, c.maxResponseBytes+1)}
}

// Search executes a search request against this origin. When the
// request carries an OverrideURL (set by the federation layer's
// pagination adapter), the URL is fetched verbatim via GET instead of
// POSTing the standard /search endpoint — this lets the proxy follow
// upstream-issued next-page links regardless of their query-parameter
// convention. The OverrideURL is allowlist-checked against this
// origin's BaseURL.
//
// Returns the parsed FeatureCollection and the upstream response
// headers. Headers are needed by the link_header pagination adapter,
// which parses RFC 5988 next-page links from the `Link:` header.
func (c *OriginClient) Search(ctx context.Context, req *stac.SearchRequest) (*stac.FeatureCollection, http.Header, error) {
	if req != nil && req.OverrideURL != "" {
		if len(req.OverrideBody) > 0 {
			return c.searchByPOST(ctx, req.OverrideURL, req.OverrideBody)
		}
		return c.searchByURL(ctx, req.OverrideURL)
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal search request: %w", err)
	}

	resp, err := c.DoRequest(ctx, "POST", "/search", bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, c.maxResponseBytes+1))
		return nil, nil, fmt.Errorf("search failed with status %d: %s", resp.StatusCode, string(body))
	}

	fc, err := c.decodeFC(resp.Body)
	if err != nil {
		return nil, nil, err
	}
	return fc, resp.Header, nil
}

// searchByURL fetches a verbatim upstream URL with GET, allowlist-
// checked against this client's BaseURL. The URL is expected to be
// the value an upstream emitted in a `rel: next` link or `Link:`
// header — the SSRF defense layer is `SameOrigin` on the way in.
func (c *OriginClient) searchByURL(ctx context.Context, fullURL string) (*stac.FeatureCollection, http.Header, error) {
	if !urlRootedAtBase(fullURL, c.baseURL) {
		return nil, nil, fmt.Errorf("search override URL %q not rooted at origin base %q", fullURL, c.BaseURL())
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Accept", "application/geo+json, application/json")
	middleware.ForwardRequestID(ctx, req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, c.maxResponseBytes+1))
		return nil, nil, fmt.Errorf("search-by-url failed with status %d: %s", resp.StatusCode, string(body))
	}

	fc, err := c.decodeFC(resp.Body)
	if err != nil {
		return nil, nil, err
	}
	return fc, resp.Header, nil
}

// searchByPOST issues POST fullURL with body verbatim, allowlist-
// checked against this client's BaseURL. The (fullURL, body) pair is
// the (href, body) from an upstream's POST-style rel=next link, as
// captured by the post_body pagination adapter. The body carries the
// original search parameters plus the upstream's cursor field, so
// the proxy doesn't need to rebuild anything — it just replays.
func (c *OriginClient) searchByPOST(ctx context.Context, fullURL string, body []byte) (*stac.FeatureCollection, http.Header, error) {
	if !urlRootedAtBase(fullURL, c.baseURL) {
		return nil, nil, fmt.Errorf("search override URL %q not rooted at origin base %q", fullURL, c.BaseURL())
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fullURL, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Accept", "application/geo+json, application/json")
	req.Header.Set("Content-Type", "application/json")
	middleware.ForwardRequestID(ctx, req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, c.maxResponseBytes+1))
		return nil, nil, fmt.Errorf("search-by-post failed with status %d: %s", resp.StatusCode, string(errBody))
	}

	fc, err := c.decodeFC(resp.Body)
	if err != nil {
		return nil, nil, err
	}
	return fc, resp.Header, nil
}

// decodeFC parses a FeatureCollection from a bounded response body,
// erroring when the body exceeds maxResponseBytes. Extracted because
// both Search and searchByURL share the parse-with-cap pattern.
func (c *OriginClient) decodeFC(body io.Reader) (*stac.FeatureCollection, error) {
	cr := c.limitedBody(body)
	var fc stac.FeatureCollection
	if err := json.NewDecoder(cr).Decode(&fc); err != nil {
		if cr.n > c.maxResponseBytes {
			return nil, fmt.Errorf("upstream search response exceeded max %d bytes", c.maxResponseBytes)
		}
		return nil, fmt.Errorf("failed to parse search response: %w", err)
	}
	if cr.n > c.maxResponseBytes {
		return nil, fmt.Errorf("upstream search response exceeded max %d bytes", c.maxResponseBytes)
	}
	return &fc, nil
}

// urlRootedAtBase returns true when fullURL has the same scheme + host
// as base and its path starts with base's path. Defends against SSRF
// via tampered upstream responses (an upstream that returns a `rel:
// next` href pointing to a different host or tenant path).
func urlRootedAtBase(fullURL string, base *url.URL) bool {
	if fullURL == "" || base == nil {
		return false
	}
	u, err := url.Parse(fullURL)
	if err != nil || !u.IsAbs() {
		return false
	}
	if !strings.EqualFold(u.Scheme, base.Scheme) {
		return false
	}
	if !strings.EqualFold(u.Host, base.Host) {
		return false
	}
	basePath := strings.TrimSuffix(base.Path, "/")
	return strings.HasPrefix(u.Path, basePath)
}

// GetCollections fetches all collections from this origin.
func (c *OriginClient) GetCollections(ctx context.Context) ([]*stac.Collection, error) {
	resp, err := c.DoRequest(ctx, "GET", "/collections", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, c.maxResponseBytes+1))
		return nil, fmt.Errorf("get collections failed with status %d: %s", resp.StatusCode, string(body))
	}

	cr := c.limitedBody(resp.Body)
	var result stac.CollectionsResponse
	if err := json.NewDecoder(cr).Decode(&result); err != nil {
		if cr.n > c.maxResponseBytes {
			return nil, fmt.Errorf("upstream collections response exceeded max %d bytes", c.maxResponseBytes)
		}
		return nil, fmt.Errorf("failed to parse collections response: %w", err)
	}
	if cr.n > c.maxResponseBytes {
		return nil, fmt.Errorf("upstream collections response exceeded max %d bytes", c.maxResponseBytes)
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
		body, _ := io.ReadAll(io.LimitReader(resp.Body, c.maxResponseBytes+1))
		return nil, fmt.Errorf("get collection failed with status %d: %s", resp.StatusCode, string(body))
	}

	cr := c.limitedBody(resp.Body)
	var collection stac.Collection
	if err := json.NewDecoder(cr).Decode(&collection); err != nil {
		if cr.n > c.maxResponseBytes {
			return nil, fmt.Errorf("upstream collection response exceeded max %d bytes", c.maxResponseBytes)
		}
		return nil, fmt.Errorf("failed to parse collection response: %w", err)
	}
	if cr.n > c.maxResponseBytes {
		return nil, fmt.Errorf("upstream collection response exceeded max %d bytes", c.maxResponseBytes)
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
		body, _ := io.ReadAll(io.LimitReader(resp.Body, c.maxResponseBytes+1))
		return nil, fmt.Errorf("get item failed with status %d: %s", resp.StatusCode, string(body))
	}

	cr := c.limitedBody(resp.Body)
	var item stac.Item
	if err := json.NewDecoder(cr).Decode(&item); err != nil {
		if cr.n > c.maxResponseBytes {
			return nil, fmt.Errorf("upstream item response exceeded max %d bytes", c.maxResponseBytes)
		}
		return nil, fmt.Errorf("failed to parse item response: %w", err)
	}
	if cr.n > c.maxResponseBytes {
		return nil, fmt.Errorf("upstream item response exceeded max %d bytes", c.maxResponseBytes)
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
	for _, coll := range collections {
		if coll == nil {
			continue
		}
		c.collections[coll.ID] = coll
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

// BaseURLParsed returns the origin's base URL as *url.URL (used by
// ReverseProxy.SetURL).
func (c *OriginClient) BaseURLParsed() *url.URL {
	return c.baseURL
}

// Transport returns the origin's RoundTripper (used by ReverseProxy so
// auth + retry are applied to proxied requests).
func (c *OriginClient) Transport() http.RoundTripper {
	return c.transport
}

// HTTPClient returns the origin's *http.Client. Exposed so collaborators
// (e.g. observability.OriginCheck) can reuse the same instrumented
// transport (retry, custom CA pool, per-origin auth) rather than
// constructing a parallel client that bypasses project-wide policy.
func (c *OriginClient) HTTPClient() *http.Client {
	return c.httpClient
}

// MaxResponseBytes returns the resolved per-call upstream response
// body cap for this client. Callers wrapping reverse-proxy responses
// (e.g. reverseProxyOnce) can use this to enforce the same cap on
// the raw byte stream.
func (c *OriginClient) MaxResponseBytes() int64 {
	return c.maxResponseBytes
}
