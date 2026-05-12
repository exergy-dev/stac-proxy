// Package proxy provides the single-origin proxy handler.
package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/yourorg/stac-proxy/internal/middleware"
	"github.com/yourorg/stac-proxy/internal/stac"
)

// Handler handles proxying requests to a single upstream STAC server.
type Handler struct {
	client       *Client
	proxyBaseURL string
}

// Config contains configuration for the proxy handler.
type Config struct {
	UpstreamURL  string
	ProxyBaseURL string
	Timeout      int // seconds
	Retry        *RetryConfig
}

// NewHandler creates a new proxy handler.
func NewHandler(cfg Config) (*Handler, error) {
	opts := []ClientOption{}

	if cfg.Timeout > 0 {
		opts = append(opts, WithTimeout(time.Duration(cfg.Timeout)*time.Second))
	}

	if cfg.Retry != nil {
		opts = append(opts, WithRetry(cfg.Retry))
	}

	client, err := NewClient(cfg.UpstreamURL, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create client: %w", err)
	}

	return &Handler{
		client:       client,
		proxyBaseURL: cfg.ProxyBaseURL,
	}, nil
}

// Handle processes a STAC request by forwarding to the upstream server.
func (h *Handler) Handle(ctx context.Context, req *middleware.STACRequest) (*middleware.STACResponse, error) {
	// Determine the path to forward
	path := req.URL.Path

	// Default forwarding: pass body and method through unchanged.
	method := req.Method
	var body io.Reader
	if req.Body != nil {
		body = req.Body
	}

	// When middleware has produced a parsed SearchReq (search and item-search
	// requests), re-serialize it as a POST body so upstream sees any
	// mutations such as CQL2 filter injection. Without this step the raw
	// GET query string would be forwarded and any middleware-applied
	// changes to SearchReq.Filter would be silently dropped.
	if req.SearchReq != nil && isSearchLike(req.RequestType) {
		marshaled, err := json.Marshal(req.SearchReq)
		if err != nil {
			return nil, fmt.Errorf("re-serialize SearchReq: %w", err)
		}
		body = bytes.NewReader(marshaled)
		method = http.MethodPost
	}

	resp, err := h.client.Do(ctx, method, path, body)
	if err != nil {
		return nil, fmt.Errorf("upstream request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Build STAC response
	stacResp := &middleware.STACResponse{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header.Clone(),
		Body:       respBody,
	}

	// Parse and transform response if successful
	if resp.StatusCode == http.StatusOK {
		stacResp = h.transformResponse(req, stacResp)
	}

	return stacResp, nil
}

// isSearchLike reports whether the request type is one that uses a
// SearchRequest body shape (i.e. /search or /collections/{id}/items).
func isSearchLike(rt middleware.RequestType) bool {
	switch rt {
	case middleware.RequestTypeSearch, middleware.RequestTypeItems:
		return true
	}
	return false
}

// transformResponse rewrites links in the response to point to the proxy.
func (h *Handler) transformResponse(req *middleware.STACRequest, resp *middleware.STACResponse) *middleware.STACResponse {
	if h.proxyBaseURL == "" {
		return resp
	}

	contentType := resp.Headers.Get("Content-Type")
	if !strings.Contains(contentType, "json") {
		return resp
	}

	// Parse as generic JSON
	var data map[string]interface{}
	if err := json.Unmarshal(resp.Body, &data); err != nil {
		return resp // Return as-is if not valid JSON
	}

	// Rewrite links
	h.rewriteLinks(data)

	// Re-encode
	newBody, err := json.Marshal(data)
	if err != nil {
		return resp
	}

	resp.Body = newBody
	return resp
}

// rewriteLinks recursively rewrites href values in the data structure.
func (h *Handler) rewriteLinks(data interface{}) {
	switch v := data.(type) {
	case map[string]interface{}:
		// Check for "links" array
		if links, ok := v["links"].([]interface{}); ok {
			for _, link := range links {
				if linkMap, ok := link.(map[string]interface{}); ok {
					if href, ok := linkMap["href"].(string); ok {
						linkMap["href"] = h.rewriteURL(href)
					}
				}
			}
		}

		// Recurse into nested objects
		for _, val := range v {
			h.rewriteLinks(val)
		}

	case []interface{}:
		for _, val := range v {
			h.rewriteLinks(val)
		}
	}
}

// rewriteURL replaces the upstream base URL with the proxy base URL.
func (h *Handler) rewriteURL(href string) string {
	upstreamBase := h.client.BaseURL()
	if strings.HasPrefix(href, upstreamBase) {
		return h.proxyBaseURL + strings.TrimPrefix(href, upstreamBase)
	}
	return href
}

// HandleSearch handles a STAC API search request.
func (h *Handler) HandleSearch(ctx context.Context, searchReq *stac.SearchRequest) (*stac.FeatureCollection, error) {
	body, err := json.Marshal(searchReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal search request: %w", err)
	}

	resp, err := h.client.Post(ctx, "/search", strings.NewReader(string(body)))
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

// HandleGetCollections handles GET /collections.
func (h *Handler) HandleGetCollections(ctx context.Context) (*stac.CollectionsResponse, error) {
	resp, err := h.client.Get(ctx, "/collections")
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

	return &result, nil
}

// HandleGetCollection handles GET /collections/{collectionId}.
func (h *Handler) HandleGetCollection(ctx context.Context, collectionID string) (*stac.Collection, error) {
	path := fmt.Sprintf("/collections/%s", collectionID)
	resp, err := h.client.Get(ctx, path)
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

// HandleGetItem handles GET /collections/{collectionId}/items/{itemId}.
func (h *Handler) HandleGetItem(ctx context.Context, collectionID, itemID string) (*stac.Item, error) {
	path := fmt.Sprintf("/collections/%s/items/%s", collectionID, itemID)
	resp, err := h.client.Get(ctx, path)
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
