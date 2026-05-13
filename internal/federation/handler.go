// Package federation provides the federation handler for multi-origin queries.
package federation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/yourorg/stac-proxy/internal/httpx"
	"github.com/yourorg/stac-proxy/internal/middleware"
	"github.com/yourorg/stac-proxy/internal/observability"
	"github.com/yourorg/stac-proxy/internal/stac"
)

// Handler orchestrates queries across all configured origins.
type Handler struct {
	origins          map[string]*OriginClient
	router           *CollectionRouter
	merger           *ResultMerger
	maxConcurrent    int
	aggregateTimeout time.Duration
	proxyBaseURL     string
	defaultPageSize  int
	maxPageSize      int
}

// HandlerConfig contains configuration for the federation handler.
type HandlerConfig struct {
	Origins          []*Origin
	ConflictStrategy ConflictStrategy
	MaxConcurrent    int
	AggregateTimeout time.Duration
	ProxyBaseURL     string
	DefaultPageSize  int
	MaxPageSize      int
}

// NewHandler creates a new federation handler.
func NewHandler(cfg HandlerConfig) (*Handler, error) {
	handler := &Handler{
		origins:          make(map[string]*OriginClient),
		router:           NewCollectionRouter(),
		merger:           NewResultMerger(cfg.ConflictStrategy),
		maxConcurrent:    cfg.MaxConcurrent,
		aggregateTimeout: cfg.AggregateTimeout,
		proxyBaseURL:     cfg.ProxyBaseURL,
		defaultPageSize:  cfg.DefaultPageSize,
		maxPageSize:      cfg.MaxPageSize,
	}

	if handler.maxConcurrent <= 0 {
		handler.maxConcurrent = 10
	}
	if handler.aggregateTimeout <= 0 {
		handler.aggregateTimeout = 60 * time.Second
	}
	if handler.defaultPageSize <= 0 {
		handler.defaultPageSize = 100
	}
	if handler.maxPageSize <= 0 {
		handler.maxPageSize = 1000
	}

	// Initialize origin clients
	for _, origin := range cfg.Origins {
		if !origin.Enabled {
			continue
		}

		client, err := NewOriginClient(origin)
		if err != nil {
			return nil, fmt.Errorf("failed to init origin %s: %w", origin.ID, err)
		}

		handler.origins[origin.ID] = client
		handler.router.Register(origin)
	}

	return handler, nil
}

// Handle processes a STAC request by routing to appropriate origins.
func (h *Handler) Handle(ctx context.Context, req *middleware.STACRequest) (*middleware.STACResponse, error) {
	switch req.RequestType {
	case middleware.RequestTypeSearch:
		return h.handleSearch(ctx, req)
	case middleware.RequestTypeCollections:
		return h.handleGetCollections(ctx, req)
	case middleware.RequestTypeCollection:
		return h.handleGetCollection(ctx, req)
	case middleware.RequestTypeItem:
		return h.handleGetItem(ctx, req)
	default:
		// For other request types, try to proxy to the first available origin
		return h.handleGenericProxy(ctx, req)
	}
}

// handleSearch handles federated search requests. When only one origin
// is routed it bypasses fan-out/merge and delegates to the
// ReverseProxy-based single-origin pass-through.
func (h *Handler) handleSearch(ctx context.Context, req *middleware.STACRequest) (*middleware.STACResponse, error) {
	searchReq := req.SearchReq
	if searchReq == nil {
		// Parse search request from body or query params
		var err error
		searchReq, err = h.parseSearchRequest(req)
		if err != nil {
			return nil, fmt.Errorf("invalid search request: %w", err)
		}
		req.SearchReq = searchReq
	}

	// Apply pagination limits
	if searchReq.Limit <= 0 {
		searchReq.Limit = h.defaultPageSize
	}
	if searchReq.Limit > h.maxPageSize {
		searchReq.Limit = h.maxPageSize
	}

	// Determine which origins to query
	origins := h.router.Route(searchReq.Collections)
	if len(origins) == 0 {
		return h.emptySearchResponse(searchReq)
	}

	// Single routed origin: ReverseProxy pass-through preserves headers,
	// streaming semantics, and hop-by-hop hygiene without the fan-out
	// path's marshal/unmarshal cycle.
	if len(origins) == 1 {
		return h.reverseProxyOnce(ctx, origins[0], req)
	}

	// Create context with aggregate timeout
	ctx, cancel := context.WithTimeout(ctx, h.aggregateTimeout)
	defer cancel()

	// Fan out requests to origins
	results := h.fanOutSearch(ctx, origins, searchReq)

	// Merge results
	fc, err := h.merger.MergeSearchResults(results, searchReq)
	if err != nil {
		return nil, err
	}

	// Build response
	return h.buildSearchResponse(fc, req)
}

// fanOutSearch executes search requests to multiple origins in parallel.
func (h *Handler) fanOutSearch(ctx context.Context, origins []*Origin,
	searchReq *stac.SearchRequest) []*OriginSearchResult {

	resultsChan := make(chan *OriginSearchResult, len(origins))
	sem := make(chan struct{}, h.maxConcurrent)

	var wg sync.WaitGroup
	for _, origin := range origins {
		wg.Add(1)
		go func(origin *Origin) {
			defer wg.Done()

			sem <- struct{}{}
			defer func() { <-sem }()

			result := h.searchOrigin(ctx, origin, searchReq)
			resultsChan <- result
		}(origin)
	}

	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	var results []*OriginSearchResult
	for result := range resultsChan {
		results = append(results, result)
	}

	return results
}

// searchOrigin executes a search against a single origin.
func (h *Handler) searchOrigin(ctx context.Context, origin *Origin,
	searchReq *stac.SearchRequest) *OriginSearchResult {

	client := h.origins[origin.ID]

	result := &OriginSearchResult{
		OriginID: origin.ID,
		Priority: origin.Priority,
	}

	// Adapt request for this origin
	adaptedReq := h.adaptRequestForOrigin(searchReq, origin)

	// Execute the search
	start := time.Now()
	fc, err := client.Search(ctx, adaptedReq)
	if m := observability.Default(); m != nil {
		m.UpstreamRequestDuration.WithLabelValues(origin.ID).Observe(time.Since(start).Seconds())
		status := observability.UpstreamStatusOK
		if err != nil {
			status = observability.UpstreamStatusError
			class := observability.ErrClassNetwork
			switch {
			case errors.Is(err, context.Canceled):
				class = observability.ErrClassCanceled
			case errors.Is(err, context.DeadlineExceeded):
				class = observability.ErrClassTimeout
			}
			m.UpstreamErrors.WithLabelValues(origin.ID, class).Inc()
		}
		m.UpstreamRequestsTotal.WithLabelValues(origin.ID, status).Inc()
		m.FederationOriginsQueried.WithLabelValues(origin.ID, status).Inc()
	}
	if err != nil {
		result.Error = err
		zap.L().Error("federation origin search failed",
			zap.String("origin", origin.ID),
			zap.Duration("duration", time.Since(start)),
			zap.Error(err))
		return result
	}

	result.Items = fc.Features
	result.Context = fc.Context
	result.Links = fc.Links

	return result
}

// adaptRequestForOrigin modifies the search request for a specific origin.
func (h *Handler) adaptRequestForOrigin(req *stac.SearchRequest, origin *Origin) *stac.SearchRequest {
	adapted := *req // Shallow copy

	// Map collection names if the origin uses different names
	if len(origin.CollectionMapping) > 0 {
		var mappedCollections []string
		for _, coll := range adapted.Collections {
			if mapped, ok := origin.CollectionMapping[coll]; ok {
				mappedCollections = append(mappedCollections, mapped)
			} else {
				mappedCollections = append(mappedCollections, coll)
			}
		}
		adapted.Collections = mappedCollections
	}

	// Remove collection prefix if origin uses prefixed names
	if origin.CollectionPrefix != "" {
		for i, coll := range adapted.Collections {
			if len(coll) > len(origin.CollectionPrefix) {
				adapted.Collections[i] = coll[len(origin.CollectionPrefix):]
			}
		}
	}

	return &adapted
}

// handleGetCollections handles GET /collections.
//
// Single-origin fast path: when only one origin is registered, forward
// end-to-end via reverseProxyOnce — preserves headers/X-Forwarded,
// suppresses stac_proxy:origin injection (dynamic-on-routed-count).
func (h *Handler) handleGetCollections(ctx context.Context,
	req *middleware.STACRequest) (*middleware.STACResponse, error) {

	if len(h.origins) == 1 {
		return h.reverseProxyOnce(ctx, h.primaryOrigin(), req)
	}

	ctx, cancel := context.WithTimeout(ctx, h.aggregateTimeout)
	defer cancel()

	var results []*OriginCollectionsResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	for originID, client := range h.origins {
		originID, client := originID, client
		origin := client.Origin()

		wg.Add(1)
		go func() {
			defer wg.Done()

			collections, err := client.GetCollections(ctx)

			mu.Lock()
			defer mu.Unlock()

			result := &OriginCollectionsResult{
				OriginID: originID,
				Error:    err,
			}

			if err == nil {
				// Apply collection prefix
				for i := range collections {
					if origin.CollectionPrefix != "" {
						collections[i].ID = origin.CollectionPrefix + collections[i].ID
					}
					// Add origin metadata
					if collections[i].Properties == nil {
						collections[i].Properties = make(map[string]interface{})
					}
					collections[i].Properties["stac_proxy:origin"] = originID
				}
				result.Collections = collections
			}

			results = append(results, result)
		}()
	}

	wg.Wait()

	// Merge collections
	collections := h.merger.MergeCollections(results)

	// Build response
	resp := &stac.CollectionsResponse{
		Collections: collections,
	}

	body, err := json.Marshal(resp)
	if err != nil {
		return nil, err
	}

	return &middleware.STACResponse{
		StatusCode: http.StatusOK,
		Headers: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body: body,
	}, nil
}

// handleGetCollection handles GET /collections/{collectionId}. Iterates
// candidate origins in priority order via reverseProxyOnce; first
// non-404 wins. Origin metadata is only injected when there is more
// than one registered origin (true federation mode).
func (h *Handler) handleGetCollection(ctx context.Context,
	req *middleware.STACRequest) (*middleware.STACResponse, error) {

	collectionID := req.Collection
	origins := h.router.RouteCollection(collectionID)

	if len(origins) == 0 {
		return notFoundResponse("Collection not found"), nil
	}

	annotate := len(h.origins) > 1

	for _, origin := range origins {
		// Optionally strip a configured collection prefix before
		// forwarding upstream.
		reqOut := req
		if origin.CollectionPrefix != "" && strings.HasPrefix(collectionID, origin.CollectionPrefix) {
			reqOut = adaptRequestStripCollectionPrefix(req, origin.CollectionPrefix)
		}

		resp, err := h.reverseProxyOnce(ctx, origin, reqOut)
		if err != nil {
			continue
		}
		if resp.StatusCode == http.StatusNotFound {
			continue
		}
		if resp.StatusCode != http.StatusOK {
			return resp, nil
		}
		if annotate {
			injectOriginMetadata(resp, "properties", origin.ID)
		}
		return resp, nil
	}

	return notFoundResponse("Collection not found"), nil
}

// handleGetItem handles GET /collections/{collectionId}/items/{itemId}.
// Same priority-order iteration as handleGetCollection.
func (h *Handler) handleGetItem(ctx context.Context,
	req *middleware.STACRequest) (*middleware.STACResponse, error) {

	collectionID := req.Collection
	origins := h.router.RouteCollection(collectionID)

	if len(origins) == 0 {
		return notFoundResponse("Item not found"), nil
	}

	annotate := len(h.origins) > 1

	for _, origin := range origins {
		reqOut := req
		if origin.CollectionPrefix != "" && strings.HasPrefix(collectionID, origin.CollectionPrefix) {
			reqOut = adaptRequestStripCollectionPrefix(req, origin.CollectionPrefix)
		}

		resp, err := h.reverseProxyOnce(ctx, origin, reqOut)
		if err != nil {
			continue
		}
		if resp.StatusCode == http.StatusNotFound {
			continue
		}
		if resp.StatusCode != http.StatusOK {
			return resp, nil
		}
		if annotate {
			injectOriginMetadata(resp, "properties", origin.ID)
		}
		return resp, nil
	}

	return notFoundResponse("Item not found"), nil
}

// notFoundResponse builds a uniform 404 STAC error response.
func notFoundResponse(description string) *middleware.STACResponse {
	return &middleware.STACResponse{
		StatusCode: http.StatusNotFound,
		Headers:    http.Header{"Content-Type": []string{"application/json"}},
		Body:       []byte(`{"code": "NotFound", "description": "` + description + `"}`),
	}
}

// handleGenericProxy proxies requests to the highest priority origin
// via ReverseProxy. Used for STAC endpoints that don't have dedicated
// federation handling (e.g. /, /conformance).
func (h *Handler) handleGenericProxy(ctx context.Context,
	req *middleware.STACRequest) (*middleware.STACResponse, error) {

	origin := h.primaryOrigin()
	if origin == nil {
		return &middleware.STACResponse{
			StatusCode: http.StatusServiceUnavailable,
			Body:       []byte(`{"code": "NoOrigins", "description": "No origins available"}`),
		}, nil
	}

	return h.reverseProxyOnce(ctx, origin, req)
}

// primaryOrigin returns the highest-priority enabled origin (or nil
// when no enabled origins are configured). Used by handleGenericProxy
// and the federation-of-1 translation in cmd/stac-proxy.
func (h *Handler) primaryOrigin() *Origin {
	origins := h.router.EnabledOrigins()
	if len(origins) == 0 {
		return nil
	}
	best := origins[0]
	for _, o := range origins[1:] {
		if o.Priority > best.Priority {
			best = o
		}
	}
	return best
}

// parseSearchRequest parses a search request from the STAC request.
func (h *Handler) parseSearchRequest(req *middleware.STACRequest) (*stac.SearchRequest, error) {
	searchReq := &stac.SearchRequest{}

	if req.Method == http.MethodPost && req.Body != nil {
		if err := json.NewDecoder(req.Body).Decode(searchReq); err != nil {
			return nil, err
		}
	} else {
		// Parse from query parameters
		q := req.URL.Query()
		if colls := q.Get("collections"); colls != "" {
			searchReq.Collections = []string{colls} // Simplified
		}
		if bbox := q.Get("bbox"); bbox != "" {
			// Parse bbox - simplified
		}
		if datetime := q.Get("datetime"); datetime != "" {
			searchReq.Datetime = datetime
		}
	}

	return searchReq, nil
}

// emptySearchResponse returns an empty feature collection.
func (h *Handler) emptySearchResponse(req *stac.SearchRequest) (*middleware.STACResponse, error) {
	fc := &stac.FeatureCollection{
		Type:     "FeatureCollection",
		Features: []stac.Item{},
		Context: &stac.SearchContext{
			Returned: 0,
			Matched:  0,
		},
	}

	body, err := json.Marshal(fc)
	if err != nil {
		return nil, err
	}

	return &middleware.STACResponse{
		StatusCode: http.StatusOK,
		Headers: http.Header{
			"Content-Type": []string{"application/geo+json"},
		},
		Body: body,
	}, nil
}

// buildSearchResponse builds the HTTP response for search results.
func (h *Handler) buildSearchResponse(fc *stac.FeatureCollection,
	req *middleware.STACRequest) (*middleware.STACResponse, error) {

	body, err := json.Marshal(fc)
	if err != nil {
		return nil, err
	}

	return &middleware.STACResponse{
		StatusCode: http.StatusOK,
		Headers: http.Header{
			"Content-Type": []string{"application/geo+json"},
		},
		Body: body,
	}, nil
}

// OriginCount returns the number of configured origins.
func (h *Handler) OriginCount() int {
	return len(h.origins)
}

// OriginIDs returns the IDs of all configured origins.
func (h *Handler) OriginIDs() []string {
	ids := make([]string, 0, len(h.origins))
	for id := range h.origins {
		ids = append(ids, id)
	}
	return ids
}

// reverseProxyOnce forwards req to a single origin via
// httputil.ReverseProxy. Auth + retry are applied transparently via
// the origin's RoundTripper chain; the captured response is returned
// as a middleware.STACResponse.
//
// When proxyBaseURL is configured and the upstream returns 2xx with a
// JSON body, links are rewritten to point at the proxy.
func (h *Handler) reverseProxyOnce(ctx context.Context, origin *Origin,
	req *middleware.STACRequest) (*middleware.STACResponse, error) {

	client := h.origins[origin.ID]
	if client == nil {
		return nil, &middleware.InternalError{Message: "unknown origin: " + origin.ID}
	}

	outReq, err := h.buildOutboundRequest(ctx, client, req)
	if err != nil {
		return nil, err
	}

	cap := httpx.NewResponseCapture()
	var upstreamErr error
	rp := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(client.BaseURLParsed())
			r.SetXForwarded()
			r.Out.Header.Set("Accept", "application/geo+json, application/json")
		},
		Transport: client.Transport(),
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			upstreamErr = err
		},
	}

	start := time.Now()
	rp.ServeHTTP(cap, outReq)
	if m := observability.Default(); m != nil {
		m.UpstreamRequestDuration.WithLabelValues(origin.ID).Observe(time.Since(start).Seconds())
		if upstreamErr != nil {
			class := observability.ErrClassNetwork
			switch {
			case errors.Is(upstreamErr, context.Canceled):
				class = observability.ErrClassCanceled
			case errors.Is(upstreamErr, context.DeadlineExceeded):
				class = observability.ErrClassTimeout
			}
			m.UpstreamErrors.WithLabelValues(origin.ID, class).Inc()
			m.UpstreamRequestsTotal.WithLabelValues(origin.ID, observability.UpstreamStatusError).Inc()
		} else {
			m.UpstreamRequestsTotal.WithLabelValues(origin.ID, fmt.Sprintf("%d", cap.Status())).Inc()
		}
	}

	if upstreamErr != nil {
		return nil, &middleware.InternalError{Message: "upstream request failed: " + upstreamErr.Error(), Cause: upstreamErr}
	}

	headers := cap.HeadersOut()
	httpx.StripHopByHopHeaders(headers)

	resp := &middleware.STACResponse{
		StatusCode: cap.Status(),
		Headers:    headers,
		Body:       cap.BodyBytes(),
	}

	if h.proxyBaseURL != "" && cap.Status() == http.StatusOK {
		resp = h.transformResponse(client, resp)
	}
	return resp, nil
}

// buildOutboundRequest constructs the *http.Request that ReverseProxy
// will dispatch. It:
//   - Re-serializes req.SearchReq as POST body for search-like routes,
//     so middleware mutations (CQL2 injection, etc.) reach upstream.
//   - Forwards the inbound request ID via the standard helper.
//
// The returned request's URL is left as the inbound path/query;
// ReverseProxy.Rewrite.SetURL composes the upstream URL at dispatch.
func (h *Handler) buildOutboundRequest(ctx context.Context, client *OriginClient,
	req *middleware.STACRequest) (*http.Request, error) {

	method := req.Method
	var body io.Reader
	if req.Body != nil {
		body = req.Body
	}

	if req.SearchReq != nil && isSearchLike(req.RequestType) {
		marshaled, err := json.Marshal(req.SearchReq)
		if err != nil {
			return nil, fmt.Errorf("re-serialize SearchReq: %w", err)
		}
		body = bytes.NewReader(marshaled)
		method = http.MethodPost
	}

	// Path+query — ReverseProxy.SetURL will rebase onto the origin.
	pathQuery := req.URL.RequestURI()

	outReq, err := http.NewRequestWithContext(ctx, method, pathQuery, body)
	if err != nil {
		return nil, fmt.Errorf("build outbound request: %w", err)
	}

	if body != nil {
		if err := httpx.BufferAndSetGetBody(outReq); err != nil {
			return nil, fmt.Errorf("buffer outbound body: %w", err)
		}
		outReq.Header.Set("Content-Type", "application/json")
	}

	// Inherit safe headers from the inbound request so things like
	// Accept-Encoding, conditional GET headers (If-None-Match), and
	// downstream-meaningful trace headers propagate.
	if req.Request != nil {
		for k, vs := range req.Header {
			// Skip hop-by-hop; ReverseProxy strips them again at
			// dispatch, but starting clean keeps the trace simple.
			if isHopByHop(k) {
				continue
			}
			for _, v := range vs {
				outReq.Header.Add(k, v)
			}
		}
		// Carry the inbound identity onto the outbound request so
		// ReverseProxy.Rewrite.SetXForwarded has values to read.
		// SetXForwarded uses RemoteAddr/Host/TLS off the inbound *req*
		// that was passed to ServeHTTP; in our flow that's outReq.
		outReq.Host = req.Host
		outReq.RemoteAddr = req.Request.RemoteAddr
		outReq.TLS = req.Request.TLS
	}

	middleware.ForwardRequestID(ctx, outReq)
	return outReq, nil
}

// transformResponse rewrites links pointing to the upstream origin so
// downstream clients follow links back through this proxy.
func (h *Handler) transformResponse(client *OriginClient, resp *middleware.STACResponse) *middleware.STACResponse {
	if h.proxyBaseURL == "" {
		return resp
	}

	contentType := resp.Headers.Get("Content-Type")
	if !strings.Contains(contentType, "json") {
		return resp
	}

	var data map[string]interface{}
	if err := json.Unmarshal(resp.Body, &data); err != nil {
		return resp // not JSON — leave as-is
	}

	h.rewriteLinks(client, data)

	newBody, err := json.Marshal(data)
	if err != nil {
		return resp
	}
	resp.Body = newBody
	return resp
}

// rewriteLinks recursively rewrites href values in the data structure.
func (h *Handler) rewriteLinks(client *OriginClient, data interface{}) {
	switch v := data.(type) {
	case map[string]interface{}:
		if links, ok := v["links"].([]interface{}); ok {
			for _, link := range links {
				if linkMap, ok := link.(map[string]interface{}); ok {
					if href, ok := linkMap["href"].(string); ok {
						linkMap["href"] = h.rewriteURL(client, href)
					}
				}
			}
		}
		for _, val := range v {
			h.rewriteLinks(client, val)
		}
	case []interface{}:
		for _, val := range v {
			h.rewriteLinks(client, val)
		}
	}
}

// rewriteURL replaces the upstream base URL prefix with the proxy
// base URL.
func (h *Handler) rewriteURL(client *OriginClient, href string) string {
	upstreamBase := client.BaseURL()
	if strings.HasPrefix(href, upstreamBase) {
		return h.proxyBaseURL + strings.TrimPrefix(href, upstreamBase)
	}
	return href
}

// isSearchLike reports whether the request type uses the SearchRequest
// body shape (i.e. /search or /collections/{id}/items).
func isSearchLike(rt middleware.RequestType) bool {
	switch rt {
	case middleware.RequestTypeSearch, middleware.RequestTypeItems:
		return true
	}
	return false
}

// isHopByHop reports whether a header name is one of the RFC 7230
// hop-by-hop headers (a small set; ReverseProxy strips Connection-listed
// names itself at dispatch).
func isHopByHop(name string) bool {
	switch http.CanonicalHeaderKey(name) {
	case "Connection", "Proxy-Connection", "Keep-Alive",
		"Proxy-Authenticate", "Proxy-Authorization", "Te",
		"Trailer", "Transfer-Encoding", "Upgrade":
		return true
	}
	return false
}

// injectOriginMetadata adds stac_proxy:origin to a JSON STAC document's
// properties (Collection.properties or Item.properties). No-op on
// parse errors — best-effort metadata.
func injectOriginMetadata(resp *middleware.STACResponse, propertiesKey, originID string) {
	var obj map[string]interface{}
	if err := json.Unmarshal(resp.Body, &obj); err != nil {
		return
	}
	props, _ := obj[propertiesKey].(map[string]interface{})
	if props == nil {
		props = make(map[string]interface{})
		obj[propertiesKey] = props
	}
	props["stac_proxy:origin"] = originID
	if b, err := json.Marshal(obj); err == nil {
		resp.Body = b
	}
}

// adaptRequestStripCollectionPrefix returns a shallow copy of req with
// the URL path and Collection field rewritten to strip the origin's
// configured collection prefix.
func adaptRequestStripCollectionPrefix(req *middleware.STACRequest, prefix string) *middleware.STACRequest {
	if req.Request == nil || prefix == "" {
		return req
	}
	stripped := strings.Replace(req.URL.Path, "/collections/"+req.Collection, "/collections/"+strings.TrimPrefix(req.Collection, prefix), 1)
	cloned := req.Clone()
	// Clone the URL so we don't mutate the inbound one.
	newURL := *cloned.URL
	newURL.Path = stripped
	newReq := cloned.Request.Clone(cloned.Context)
	newReq.URL = &newURL
	cloned.Request = newReq
	cloned.Collection = strings.TrimPrefix(req.Collection, prefix)
	return cloned
}
