// Package federation provides the federation handler for multi-origin queries.
package federation

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/yourorg/stac-proxy/internal/federation/pagecache"
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
	conformanceCaps  stac.ConformanceCaps
	// searcher is the federated paginated searcher. It is non-nil only
	// when a CursorSecret was configured; otherwise handleSearch falls
	// back to a single-page fan-out (validation warns on this so the
	// operator gets a startup-time signal).
	searcher *PaginatedSearcher
	// assetSigner is used by rewriteAssetHref when an origin has
	// `rewrite_assets: sign` configured. When nil and an origin asks
	// for "sign", the rewrite falls back to passthrough (we never
	// silently emit unsigned URLs while pretending they are gated).
	assetSigner AssetSigner
}

// AssetSigner is the minimal contract rewriteAssetHref needs from a
// URL signer when an origin opts into `rewrite_assets: sign`. The
// concrete implementation today is remap.HMACSigner; the interface
// keeps federation from depending on internal/middleware/remap.
type AssetSigner interface {
	Sign(ctx context.Context, rawURL string, ttl time.Duration) string
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
	// ConformanceCaps controls which conformance classes the proxy is
	// willing to advertise on /conformance and the landing page. The
	// actual response is the intersection of these caps with what every
	// routed origin advertises (see internal/stac.Intersect).
	ConformanceCaps stac.ConformanceCaps
	// LifetimeCtx (optional) is used to tie background goroutines
	// (auto-discovery) to the proxy's lifetime so a shutdown signal
	// aborts in-flight upstream calls. Defaults to context.Background()
	// when nil, preserving previous behavior.
	LifetimeCtx context.Context
	// Logger (optional) receives structured logs from background work
	// like auto-discovery. Defaults to slog.Default() when nil.
	Logger *slog.Logger
	// AssetSigner is invoked when an origin has rewrite_assets: sign.
	// Optional — when nil and `sign` is configured, the rewriter falls
	// back to passthrough rather than emit unsigned URLs.
	AssetSigner AssetSigner
	// CursorSecret is the HMAC key used to sign federated pagination
	// cursors. When empty the proxy still serves single-page federated
	// searches but cannot issue "next" links — config validation emits
	// a warning in that case.
	CursorSecret []byte

	// PageCache, when non-nil, stores rendered pages keyed by cursor
	// signature so the paginator can serve `rel: prev` / `rel: first`
	// navigation without re-fanning-out to origins. Construction is
	// in main; nil disables the feature.
	PageCache *pagecache.Cache
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
		conformanceCaps:  cfg.ConformanceCaps,
		assetSigner:      cfg.AssetSigner,
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

	parentCtx := cfg.LifetimeCtx
	if parentCtx == nil {
		parentCtx = context.Background()
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	// Initialize origin clients
	for _, origin := range cfg.Origins {
		if !origin.Enabled {
			continue
		}

		client, err := NewOriginClientWithContext(parentCtx, logger, origin)
		if err != nil {
			return nil, fmt.Errorf("failed to init origin %s: %w", origin.ID, err)
		}

		handler.origins[origin.ID] = client
		handler.router.Register(origin)
	}

	// Build the paginated searcher when a cursor secret is configured.
	// Without a secret, handleSearch falls back to a single-page
	// fan-out — federated multi-page pagination requires signed
	// cursors (NewPaginatedSearcher rejects an empty key).
	if len(cfg.CursorSecret) > 0 && len(handler.origins) > 0 {
		origins := make(map[string]Searcher, len(handler.origins))
		for id, c := range handler.origins {
			s, err := NewOriginClientSearcher(c, c.Origin().Pagination.ToAdapterConfig())
			if err != nil {
				return nil, fmt.Errorf("origin %q pagination adapter: %w", id, err)
			}
			origins[id] = s
		}
		searcher, err := NewPaginatedSearcher(PaginatedSearchConfig{
			Origins:         origins,
			Merger:          handler.merger,
			DefaultPageSize: handler.defaultPageSize,
			MaxPageSize:     handler.maxPageSize,
			CursorSecret:    cfg.CursorSecret,
			PageCache:       cfg.PageCache,
		})
		if err != nil {
			return nil, fmt.Errorf("paginated searcher: %w", err)
		}
		handler.searcher = searcher
	}

	return handler, nil
}

// Handle processes a STAC request by routing to appropriate origins.
func (h *Handler) Handle(ctx context.Context, req *request) (*response, error) {
	switch req.RequestType {
	case middleware.RequestTypeSearch:
		return h.handleSearch(ctx, req)
	case middleware.RequestTypeItems:
		return h.handleItems(ctx, req)
	case middleware.RequestTypeQueryables, middleware.RequestTypeCollectionQueryables:
		return h.handleQueryables(ctx, req)
	case middleware.RequestTypeCollections:
		return h.handleGetCollections(ctx, req)
	case middleware.RequestTypeCollection:
		return h.handleGetCollection(ctx, req)
	case middleware.RequestTypeItem:
		return h.handleGetItem(ctx, req)
	case middleware.RequestTypeConformance:
		return h.handleConformance(ctx, req)
	case middleware.RequestTypeLanding:
		return h.handleLanding(ctx, req)
	case middleware.RequestTypeAsset:
		// The asset endpoint streams response bytes directly; the
		// federation `*response` shape buffers them, so we cannot
		// handle this path via Handle(). The router calls
		// ServeAssetHTTP directly for /assets/.
		return nil, fmt.Errorf("asset requests must be served via ServeAssetHTTP")
	default:
		// For other request types, try to proxy to the first available origin
		return h.handleGenericProxy(ctx, req)
	}
}

// ServeHTTP makes Handler implement http.Handler. It reads STACInfo from
// the request context (populated by the router), reconstructs a
// request, delegates to Handle, then writes the
// STACResponse out to w. This is the integration point that lets
// federation be the inner handler in a chi-style middleware chain.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	info := middleware.STACInfoFromContext(r.Context())
	if info == nil {
		http.Error(w, "missing STAC info", http.StatusInternalServerError)
		return
	}
	sreq := &request{
		Request:     r,
		Context:     r.Context(),
		Collection:  info.Collection,
		ItemID:      info.ItemID,
		RequestType: info.RequestType,
		SearchReq:   info.SearchReq,
	}
	resp, err := h.Handle(r.Context(), sreq)
	if err != nil {
		writeFederationError(w, r, err)
		return
	}
	for k, vs := range resp.Headers {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "application/json")
	}
	if resp.StatusCode == 0 {
		resp.StatusCode = http.StatusOK
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(resp.Body)
}

// writeFederationError translates a federation/middleware-tier error
// into a STAC-shaped JSON response. Mirrors the router's handleError
// for the cases reachable from federation.Handle.
func writeFederationError(w http.ResponseWriter, _ *http.Request, err error) {
	type body struct {
		Code        string `json:"code"`
		Description string `json:"description"`
	}
	w.Header().Set("Content-Type", "application/json")
	var ie *middleware.InternalError
	if errors.As(err, &ie) {
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(body{Code: "BadGateway", Description: ie.Message})
		return
	}
	w.WriteHeader(http.StatusInternalServerError)
	_ = json.NewEncoder(w).Encode(body{Code: "InternalError", Description: "internal error"})
}

// handleSearch handles federated search requests. When only one origin
// is routed it bypasses fan-out/merge and delegates to the
// ReverseProxy-based single-origin pass-through.
func (h *Handler) handleSearch(ctx context.Context, req *request) (*response, error) {
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

	// Cursor-aware path: when a paginated searcher is configured,
	// route through it so multi-page searches across origins work.
	if h.searcher != nil {
		cursorStr := searchReq.Cursor
		if cursorStr == "" {
			cursorStr = searchReq.Token
		}
		// Reset pagination fields before hashing so the cursor's query
		// hash matches across pages of the same logical query.
		hashReq := *searchReq
		hashReq.Cursor = ""
		hashReq.Token = ""
		result, err := h.searcher.Search(ctx, &hashReq, cursorStr)
		if err != nil {
			return nil, fmt.Errorf("federated search: %w", err)
		}
		return h.buildPaginatedSearchResponse(result, &hashReq, req)
	}

	// Fallback: single-page fan-out when no cursor secret is set.
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
//
// Each goroutine carries a panic recovery so that a bug in one origin's
// code path cannot crash the whole proxy process: a panic is logged
// (origin + value + stack) and the offending origin is recorded with
// an Error result so the merger treats it as a failed origin.
func (h *Handler) fanOutSearch(ctx context.Context, origins []*Origin,
	searchReq *stac.SearchRequest) []*OriginSearchResult {

	resultsChan := make(chan *OriginSearchResult, len(origins))
	sem := make(chan struct{}, h.maxConcurrent)

	var wg sync.WaitGroup
	for _, origin := range origins {
		wg.Add(1)
		go func(origin *Origin) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					slog.Error("federation origin search panicked",
						"origin", origin.ID,
						"panic", r,
						"stack", string(debug.Stack()),
					)
					resultsChan <- &OriginSearchResult{
						OriginID:  origin.ID,
						OriginURL: origin.BaseURL,
						Priority:  origin.Priority,
						Error:     fmt.Errorf("origin %s panicked: %v", origin.ID, r),
					}
				}
			}()

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
		OriginID:  origin.ID,
		OriginURL: client.BaseURL(),
		Priority:  origin.Priority,
	}

	// Adapt request for this origin
	adaptedReq := h.adaptRequestForOrigin(searchReq, origin)

	// Execute the search
	start := time.Now()
	fc, _, err := client.Search(ctx, adaptedReq)
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
		slog.Error("federation origin search failed",
			"origin", origin.ID,
			"duration", time.Since(start),
			"error", err)
		return result
	}

	result.Items = fc.Features
	if sc, ok := fc.Context.(*stac.SearchContext); ok {
		result.Context = sc
	}
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
	req *request) (*response, error) {

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
			defer func() {
				if r := recover(); r != nil {
					slog.Error("federation origin GetCollections panicked",
						"origin", originID,
						"panic", r,
						"stack", string(debug.Stack()),
					)
					mu.Lock()
					results = append(results, &OriginCollectionsResult{
						OriginID:  originID,
						OriginURL: client.BaseURL(),
						Error:     fmt.Errorf("origin %s panicked: %v", originID, r),
					})
					mu.Unlock()
				}
			}()

			collections, err := client.GetCollections(ctx)

			mu.Lock()
			defer mu.Unlock()

			result := &OriginCollectionsResult{
				OriginID:  originID,
				OriginURL: client.BaseURL(),
				Error:     err,
			}

			if err == nil {
				// Apply collection prefix. The stac_proxy:origin marker
				// is attached centrally by merger.MergeCollections so
				// that mutation happens in a single goroutine after
				// wg.Wait — writing it here too would double-write the
				// map under the race detector even though it's
				// logically safe.
				for _, coll := range collections {
					if coll == nil {
						continue
					}
					if origin.CollectionPrefix != "" {
						coll.ID = origin.CollectionPrefix + coll.ID
					}
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

	return &response{
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
	req *request) (*response, error) {
	return h.handleSingleResource(ctx, req, "Collection not found")
}

// handleGetItem handles GET /collections/{collectionId}/items/{itemId}.
// Same priority-order iteration as handleGetCollection.
func (h *Handler) handleGetItem(ctx context.Context,
	req *request) (*response, error) {
	return h.handleSingleResource(ctx, req, "Item not found")
}

// handleSingleResource is the shared body of handleGetCollection and
// handleGetItem: route by collection ID, iterate candidate origins in
// priority order via reverseProxyOnce, and return the first non-404.
// Origin metadata is injected when more than one origin is configured.
// notFoundDescription is used for both the empty-routing 404 and the
// all-origins-404 fallthrough.
func (h *Handler) handleSingleResource(ctx context.Context,
	req *request, notFoundDescription string) (*response, error) {

	collectionID := req.Collection
	origins := h.router.RouteCollection(collectionID)

	if len(origins) == 0 {
		return notFoundResponse(notFoundDescription), nil
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
			injectOriginMetadata(resp, origin.ID, origin.BaseURL)
		}
		return resp, nil
	}

	return notFoundResponse(notFoundDescription), nil
}

// notFoundResponse builds a uniform 404 STAC error response.
func notFoundResponse(description string) *response {
	return &response{
		StatusCode: http.StatusNotFound,
		Headers:    http.Header{"Content-Type": []string{"application/json"}},
		Body:       []byte(`{"code": "NotFound", "description": "` + description + `"}`),
	}
}

// handleItems handles GET /collections/{collectionId}/items as a
// federated search scoped to the URL's collection ID. It delegates to
// handleSearch so multi-page cursoring, link rewriting, and the
// single-origin fast path are inherited unchanged — items federation
// is just collection-scoped search.
func (h *Handler) handleItems(ctx context.Context, req *request) (*response, error) {
	if req.Collection == "" {
		return nil, fmt.Errorf("items endpoint requires a collection id")
	}
	if req.SearchReq == nil {
		sr, err := h.parseSearchRequest(req)
		if err != nil {
			return nil, fmt.Errorf("invalid items query: %w", err)
		}
		req.SearchReq = sr
	}
	// Force scope to the URL's collection ID. Anything the client
	// passed in collections= is overridden — the URL is authoritative
	// per OGC API Features.
	req.SearchReq.Collections = []string{req.Collection}
	return h.handleSearch(ctx, req)
}

// handleQueryables handles GET /queryables and
// GET /collections/{collectionId}/queryables.
//
// The merged schema is the conservative intersection of properties
// returned by all reachable origins: a property is advertised only
// when every origin agrees on it. Origin failures are skipped (logged
// and excluded from the intersection) so a single bad upstream cannot
// block discovery of common queryables.
func (h *Handler) handleQueryables(ctx context.Context, req *request) (*response, error) {
	path := "/queryables"
	if req.Collection != "" {
		path = "/collections/" + req.Collection + "/queryables"
	}

	// Determine the candidate origin set. For collection-scoped
	// queryables, only origins that route the collection.
	var clients []*OriginClient
	if req.Collection != "" {
		for _, o := range h.router.Route([]string{req.Collection}) {
			if c, ok := h.origins[o.ID]; ok {
				clients = append(clients, c)
			}
		}
	} else {
		for _, c := range h.origins {
			clients = append(clients, c)
		}
	}
	if len(clients) == 0 {
		return &response{
			StatusCode: http.StatusServiceUnavailable,
			Headers:    http.Header{"Content-Type": []string{"application/json"}},
			Body:       []byte(`{"code":"ServiceUnavailable","description":"no origins available for queryables"}`),
		}, nil
	}

	// Single-origin shortcut: pass through transparently.
	if len(clients) == 1 {
		origin := clients[0].Origin()
		return h.reverseProxyOnce(ctx, origin, req)
	}

	type fetchResult struct {
		schema map[string]any
		ok     bool
	}
	results := make(chan fetchResult, len(clients))
	perOrigin := 5 * time.Second
	if h.aggregateTimeout > 0 && h.aggregateTimeout < perOrigin {
		perOrigin = h.aggregateTimeout
	}

	var wg sync.WaitGroup
	for _, c := range clients {
		c := c
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					slog.Error("queryables fetch panicked",
						"origin", c.Origin().ID, "panic", r,
					)
					results <- fetchResult{}
				}
			}()
			fctx, cancel := context.WithTimeout(ctx, perOrigin)
			defer cancel()
			resp, err := c.DoRequest(fctx, http.MethodGet, path, nil)
			if err != nil {
				slog.Warn("queryables fetch failed", "origin", c.Origin().ID, "error", err)
				results <- fetchResult{}
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				results <- fetchResult{}
				return
			}
			var schema map[string]any
			if err := json.NewDecoder(resp.Body).Decode(&schema); err != nil {
				slog.Warn("queryables decode failed", "origin", c.Origin().ID, "error", err)
				results <- fetchResult{}
				return
			}
			results <- fetchResult{schema: schema, ok: true}
		}()
	}
	wg.Wait()
	close(results)

	var schemas []map[string]any
	for r := range results {
		if r.ok {
			schemas = append(schemas, r.schema)
		}
	}
	if len(schemas) == 0 {
		return &response{
			StatusCode: http.StatusServiceUnavailable,
			Headers:    http.Header{"Content-Type": []string{"application/json"}},
			Body:       []byte(`{"code":"ServiceUnavailable","description":"queryables unavailable from all origins"}`),
		}, nil
	}

	merged := intersectQueryables(schemas, h.proxyBaseURL, path)
	body, err := json.Marshal(merged)
	if err != nil {
		return nil, err
	}
	return &response{
		StatusCode: http.StatusOK,
		Headers:    http.Header{"Content-Type": []string{"application/schema+json"}},
		Body:       body,
	}, nil
}

// intersectQueryables returns a JSON Schema whose `properties` is the
// per-property intersection across `schemas`: a property is kept only
// when every schema declares it. Per-property values are taken from
// the first schema that declared them, which is acceptable for the
// metadata-discovery use case the queryables endpoint exists for.
func intersectQueryables(schemas []map[string]any, proxyBase, path string) map[string]any {
	out := map[string]any{
		"$schema":              "https://json-schema.org/draft/2019-09/schema",
		"type":                 "object",
		"title":                "Queryables",
		"description":          "Federated queryables (intersection across origins)",
		"additionalProperties": false,
	}
	if proxyBase != "" {
		out["$id"] = strings.TrimRight(proxyBase, "/") + path
	}
	if len(schemas) == 0 {
		out["properties"] = map[string]any{}
		return out
	}

	// Count property occurrences across schemas.
	counts := map[string]int{}
	firstSeen := map[string]any{}
	for _, s := range schemas {
		props, _ := s["properties"].(map[string]any)
		for name, def := range props {
			counts[name]++
			if _, exists := firstSeen[name]; !exists {
				firstSeen[name] = def
			}
		}
	}
	keep := map[string]any{}
	for name, n := range counts {
		if n == len(schemas) {
			keep[name] = firstSeen[name]
		}
	}
	out["properties"] = keep
	return out
}

// handleGenericProxy proxies requests to the highest priority origin
// via ReverseProxy. Used for STAC endpoints that don't have dedicated
// federation handling.
func (h *Handler) handleGenericProxy(ctx context.Context,
	req *request) (*response, error) {

	origin := h.primaryOrigin()
	if origin == nil {
		return &response{
			StatusCode: http.StatusServiceUnavailable,
			Body:       []byte(`{"code": "NoOrigins", "description": "No origins available"}`),
		}, nil
	}

	return h.reverseProxyOnce(ctx, origin, req)
}

// handleConformance returns the intersection of the proxy's
// advertised capabilities with each routed origin's /conformance
// response. We never advertise a class the proxy itself does not
// support (per ProxyConformanceFor), and we never advertise a class
// no origin actually implements — the spec calls for honest
// conformance and our previous "passthrough first origin" behavior
// could surprise federated clients.
func (h *Handler) handleConformance(ctx context.Context,
	req *request) (*response, error) {

	classes := h.advertisedConformance(ctx)
	body, err := json.Marshal(map[string]interface{}{
		"conformsTo": classes,
	})
	if err != nil {
		return nil, err
	}
	return &response{
		StatusCode: http.StatusOK,
		Headers:    http.Header{"Content-Type": []string{"application/json"}},
		Body:       body,
	}, nil
}

// handleLanding builds a STAC Catalog landing page whose conformsTo
// reflects the intersected proxy/origin capability set, plus the five
// STAC API §1.4 required link rels (self, root, data, conformance,
// search). When ProxyBaseURL is configured links are absolute; otherwise
// they stay relative so callers behind a path-only reverse proxy still
// produce usable links.
func (h *Handler) handleLanding(ctx context.Context,
	req *request) (*response, error) {

	classes := h.advertisedConformance(ctx)
	body, err := json.Marshal(map[string]interface{}{
		"type":         "Catalog",
		"stac_version": "1.0.0",
		"id":           "stac-proxy",
		"description":  "Federated STAC proxy",
		"conformsTo":   classes,
		"links":        h.landingLinks(),
	})
	if err != nil {
		return nil, err
	}
	return &response{
		StatusCode: http.StatusOK,
		Headers:    http.Header{"Content-Type": []string{"application/json"}},
		Body:       body,
	}, nil
}

// landingLinks returns the STAC API §1.4 required link rels for the
// landing page. Hrefs are rooted at proxyBaseURL when configured;
// otherwise they are emitted as relative paths.
func (h *Handler) landingLinks() []map[string]string {
	base := strings.TrimRight(h.proxyBaseURL, "/")
	href := func(p string) string { return base + p }
	const (
		jsonType    = "application/json"
		geoJSONType = "application/geo+json"
	)
	return []map[string]string{
		{"rel": "self", "href": href("/"), "type": jsonType, "title": "Landing page"},
		{"rel": "root", "href": href("/"), "type": jsonType, "title": "Landing page"},
		{"rel": "data", "href": href("/collections"), "type": jsonType, "title": "Collections"},
		{"rel": "conformance", "href": href("/conformance"), "type": jsonType, "title": "Conformance"},
		{"rel": "search", "href": href("/search"), "type": geoJSONType, "method": "GET", "title": "STAC search (GET)"},
		{"rel": "search", "href": href("/search"), "type": geoJSONType, "method": "POST", "title": "STAC search (POST)"},
	}
}

// advertisedConformance returns the conformance classes the proxy is
// willing to advertise: the intersection of ProxyConformanceFor(caps)
// with each routed origin's /conformance response. Origins that fail
// to respond within the per-origin timeout are excluded from the
// intersection (their classes simply aren't considered as supported).
// If no origins are configured we fall back to the proxy's own caps.
func (h *Handler) advertisedConformance(ctx context.Context) []string {
	proxy := stac.ProxyConformanceFor(h.conformanceCaps)
	if len(h.origins) == 0 {
		return stac.Intersect(proxy)
	}

	perOrigin := 5 * time.Second
	if h.aggregateTimeout > 0 && h.aggregateTimeout < perOrigin {
		perOrigin = h.aggregateTimeout
	}

	type result struct {
		classes []string
		ok      bool
	}
	results := make(chan result, len(h.origins))
	var wg sync.WaitGroup
	for _, client := range h.origins {
		client := client
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				// A panic in conformance probing must not take the
				// process down — log and treat the origin as if it
				// failed to advertise.
				if r := recover(); r != nil {
					slog.Error("conformance probe panicked",
						"origin", client.Origin().ID,
						"panic", r,
					)
					results <- result{}
				}
			}()
			fetchCtx, cancel := context.WithTimeout(ctx, perOrigin)
			defer cancel()
			classes, err := stac.FetchConformance(fetchCtx, client.httpClient, client.BaseURL())
			if err != nil {
				slog.Warn("conformance probe failed",
					"origin", client.Origin().ID,
					"error", err,
				)
				results <- result{}
				return
			}
			results <- result{classes: classes, ok: true}
		}()
	}
	wg.Wait()
	close(results)

	var originSets [][]string
	for r := range results {
		if r.ok {
			originSets = append(originSets, r.classes)
		}
	}
	// If no origin responded, advertise just the proxy's caps to keep
	// the surface honest about what we can serve from cache or
	// fallback handlers.
	if len(originSets) == 0 {
		return stac.Intersect(proxy)
	}
	return stac.Intersect(proxy, originSets...)
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
//
// Defensive fallback only: the server-level searchParserMiddleware
// populates req.SearchReq before federation runs, so this code path is
// only exercised by tests / alternate routings that bypass the
// middleware. We delegate to stac.Parser so the parsing rules
// (collections split on `,`, bbox/limit strict parse, ids, filter,
// intersects, fields, sortby, etc.) match the inbound parser exactly
// instead of re-implementing a subset that drops most parameters.
func (h *Handler) parseSearchRequest(req *request) (*stac.SearchRequest, error) {
	return stac.NewParser().ParseSearchRequestFromHTTP(req.Request)
}

// emptySearchResponse returns an empty feature collection.
func (h *Handler) emptySearchResponse(req *stac.SearchRequest) (*response, error) {
	fc := &stac.FeatureCollection{
		Type:     "FeatureCollection",
		Features: []*stac.Item{},
		Context: &stac.SearchContext{
			Returned: 0,
			Matched:  0,
		},
	}

	body, err := json.Marshal(fc)
	if err != nil {
		return nil, err
	}

	return &response{
		StatusCode: http.StatusOK,
		Headers: http.Header{
			"Content-Type": []string{"application/geo+json"},
		},
		Body: body,
	}, nil
}

// buildPaginatedSearchResponse builds the HTTP response for a
// federated, cursor-aware search. The proxy's signed cursor is exposed
// as a `rel: next` link in the FeatureCollection — GET requests carry
// it as ?token=, POST requests carry it in the link's `body.token`
// AdditionalField per STAC API §8.3.
func (h *Handler) buildPaginatedSearchResponse(result *SearchResult,
	searchReq *stac.SearchRequest, req *request) (*response, error) {

	items := result.Items
	if items == nil {
		items = []*stac.Item{}
	}

	sc := &stac.SearchContext{Returned: len(items)}
	if result.Context != nil {
		sc.Limit = result.Context.Limit
		sc.Matched = result.Context.Matched
	}
	if sc.Limit == 0 && searchReq.Limit > 0 {
		sc.Limit = searchReq.Limit
	}

	fc := &stac.FeatureCollection{
		Type:     "FeatureCollection",
		Features: items,
		Context:  sc,
	}

	// Emit pagination link rels. Only emit links whose cursor is
	// non-empty: page 0 has no `self` cursor (the search was issued
	// without one), and the last page has no `next`.
	if result.SelfCursor != "" {
		fc.Links = append(fc.Links, h.cursorSearchLink(req.Request, "self", result.SelfCursor))
	}
	if result.PrevCursor != "" {
		fc.Links = append(fc.Links, h.cursorSearchLink(req.Request, "prev", result.PrevCursor))
	}
	if result.FirstCursor != "" {
		fc.Links = append(fc.Links, h.cursorSearchLink(req.Request, "first", result.FirstCursor))
	}
	if result.NextCursor != "" {
		fc.Links = append(fc.Links, h.cursorSearchLink(req.Request, "next", result.NextCursor))
	}

	body, err := json.Marshal(fc)
	if err != nil {
		return nil, err
	}

	return &response{
		StatusCode: http.StatusOK,
		Headers: http.Header{
			"Content-Type": []string{"application/geo+json"},
		},
		Body: body,
	}, nil
}

// cursorSearchLink builds a Link with the given rel carrying the
// proxy's signed pagination cursor. The href is rooted at
// proxyBaseURL when configured; otherwise it stays relative so
// callers behind path-only reverse proxies still produce usable
// links. The link shape (POST body.token vs GET ?token=) mirrors the
// inbound request method.
//
// Used for `next`, `prev`, `first`, and `self` — every cursor-bearing
// pagination link has the same wire format, only the rel differs.
func (h *Handler) cursorSearchLink(orig *http.Request, rel, cursor string) *stac.Link {
	base := strings.TrimRight(h.proxyBaseURL, "/")
	path := "/search"
	if orig != nil && orig.URL != nil && orig.URL.Path != "" {
		path = orig.URL.Path
	}

	if orig != nil && orig.Method == http.MethodPost {
		return &stac.Link{
			Rel:  rel,
			Href: base + path,
			Type: "application/json",
			AdditionalFields: map[string]any{
				"method": "POST",
				"body":   map[string]any{"token": cursor},
			},
		}
	}

	// Default: GET style — preserve existing query params, swap the
	// token. Drop any incoming cursor= so the canonical form is
	// ?token=... (matching STAC API §8.3 GET pagination).
	q := url.Values{}
	if orig != nil && orig.URL != nil {
		q = orig.URL.Query()
	}
	q.Set("token", cursor)
	q.Del("cursor")

	return &stac.Link{
		Rel:  rel,
		Href: base + path + "?" + q.Encode(),
		Type: "application/geo+json",
		AdditionalFields: map[string]any{
			"method": "GET",
		},
	}
}

// buildSearchResponse builds the HTTP response for search results.
func (h *Handler) buildSearchResponse(fc *stac.FeatureCollection,
	req *request) (*response, error) {

	body, err := json.Marshal(fc)
	if err != nil {
		return nil, err
	}

	return &response{
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

// OriginClient returns the *OriginClient for the given origin ID, or
// nil if no such origin is registered. Exposed so external collaborators
// (e.g. cmd/stac-proxy wiring observability.OriginCheck) can reuse the
// same instrumented HTTP client/transport that fan-out uses, instead
// of constructing a parallel client that bypasses retry, custom CA
// pools, etc.
func (h *Handler) OriginClient(id string) *OriginClient {
	return h.origins[id]
}

// ProxyBaseURL returns the configured external base URL the handler
// uses when rewriting links (empty when unset → relative links). Exposed
// for tests that need to verify config-to-handler wiring.
func (h *Handler) ProxyBaseURL() string {
	return h.proxyBaseURL
}

// reverseProxyOnce forwards req to a single origin via
// httputil.ReverseProxy. Auth + retry are applied transparently via
// the origin's RoundTripper chain; the captured response is returned
// as a response.
//
// When proxyBaseURL is configured and the upstream returns 2xx with a
// JSON body, links are rewritten to point at the proxy.
func (h *Handler) reverseProxyOnce(ctx context.Context, origin *Origin,
	req *request) (*response, error) {

	client := h.origins[origin.ID]
	if client == nil {
		return nil, &middleware.InternalError{Message: "unknown origin: " + origin.ID}
	}

	outReq, err := h.buildOutboundRequest(ctx, client, req)
	if err != nil {
		return nil, err
	}

	// Bound the captured upstream body so a hostile or runaway origin
	// cannot OOM the proxy via the reverse-proxy fast path. The cap
	// matches the per-origin MaxResponseBytes used by OriginClient's
	// JSON paths, falling back to defaultMaxResponseBytes (32 MiB) when
	// the origin did not configure one.
	maxBytes := client.MaxResponseBytes()
	if maxBytes <= 0 {
		maxBytes = defaultMaxResponseBytes
	}
	cap := &boundedCapture{ResponseCapture: httpx.NewResponseCaptureWithLimit(maxBytes)}
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

	// If the upstream body exceeded the cap, surface 502 Bad Gateway
	// rather than forwarding the truncated bytes (which are not a
	// valid response). Logged so operators can identify the offending
	// origin.
	if cap.overflowed() {
		slog.Error("federation: upstream response exceeded capture limit",
			slog.String("origin", origin.ID),
			slog.Int64("max_bytes", maxBytes),
		)
		body := []byte(fmt.Sprintf(`{"code":"BadGateway","description":"upstream response exceeded %d bytes"}`, maxBytes))
		return &response{
			StatusCode: http.StatusBadGateway,
			Headers:    http.Header{"Content-Type": []string{"application/json"}},
			Body:       body,
		}, nil
	}

	headers := cap.HeadersOut()
	httpx.StripHopByHopHeaders(headers)

	resp := &response{
		StatusCode: cap.Status(),
		Headers:    headers,
		Body:       cap.BodyBytes(),
	}

	if h.proxyBaseURL != "" && cap.Status() == http.StatusOK {
		resp = h.transformResponse(ctx, client, resp)
	}
	return resp, nil
}

// boundedCapture wraps an httpx.ResponseCapture and remembers whether
// any Write was rejected with ErrResponseTooLarge. ReverseProxy
// silently swallows writer errors (they only surface in its error
// log), so this side channel is needed to detect overflow at the call
// site.
type boundedCapture struct {
	httpx.ResponseCapture
	over bool
}

// Write proxies to the underlying capture and records overflow. Any
// other error is returned as-is.
func (b *boundedCapture) Write(p []byte) (int, error) {
	n, err := b.ResponseCapture.Write(p)
	if errors.Is(err, httpx.ErrResponseTooLarge) {
		b.over = true
	}
	return n, err
}

// overflowed reports whether the upstream body exceeded the configured
// cap during this capture's lifetime.
func (b *boundedCapture) overflowed() bool { return b.over }

// buildOutboundRequest constructs the *http.Request that ReverseProxy
// will dispatch. It:
//   - Re-serializes req.SearchReq as POST body for search-like routes,
//     so middleware mutations (CQL2 injection, etc.) reach upstream.
//   - Forwards the inbound request ID via the standard helper.
//
// The returned request's URL is left as the inbound path/query;
// ReverseProxy.Rewrite.SetURL composes the upstream URL at dispatch.
func (h *Handler) buildOutboundRequest(ctx context.Context, client *OriginClient,
	req *request) (*http.Request, error) {

	method := req.Request.Method
	var body io.Reader
	if req.Request.Body != nil {
		body = req.Request.Body
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
	pathQuery := req.Request.URL.RequestURI()

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
		stripAuth := !client.Origin().ForwardUserIdentity
		originAuthHeader := http.CanonicalHeaderKey(client.Origin().Auth.APIKeyHeader)
		for k, vs := range req.Request.Header {
			// Skip hop-by-hop; ReverseProxy strips them again at
			// dispatch, but starting clean keeps the trace simple.
			if isHopByHop(k) {
				continue
			}
			// Strip inbound client credentials before fan-out. The
			// proxy holds its own per-origin credentials and applies
			// them via authRoundTripper; the end user's credentials
			// (intended for the proxy) MUST NOT leak to upstreams.
			// Operators who specifically want OIDC-token-pass-through
			// must set Origin.ForwardUserIdentity=true.
			if stripAuth && isInboundAuthHeader(k) {
				continue
			}
			// Always strip a header that collides with this origin's
			// own configured API key header — letting the inbound
			// version through would override what authRoundTripper
			// injects (or, if not configured, leak something
			// unrelated upstream).
			if originAuthHeader != "" && http.CanonicalHeaderKey(k) == originAuthHeader {
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
		outReq.Host = req.Request.Host
		outReq.RemoteAddr = req.Request.RemoteAddr
		outReq.TLS = req.Request.TLS
	}

	middleware.ForwardRequestID(ctx, outReq)
	return outReq, nil
}

// isInboundAuthHeader reports whether name is an end-user credential
// header that the proxy strips before fan-out (unless the origin opts
// in via ForwardUserIdentity). These are credentials the client sent
// to the proxy; passing them to upstreams turns the proxy into a
// confused deputy and can leak tokens to untrusted origins.
func isInboundAuthHeader(name string) bool {
	switch http.CanonicalHeaderKey(name) {
	case "Authorization", "Cookie", "Set-Cookie",
		"Proxy-Authorization", "X-Api-Key":
		return true
	}
	return false
}

// transformResponse rewrites links pointing to the upstream origin so
// downstream clients follow links back through this proxy. ctx is the
// inbound request context — it is forwarded to the asset signer so that
// signing observes client cancellation, deadlines, and any
// request-scoped values (request-id, principal, etc.).
//
// Performance (M-federation-1): the decode/re-encode round-trip
// is skipped entirely when the response body has no top-level "links"
// AND no "assets" tokens — for those bodies there's nothing to
// rewrite, and large feature collections see a dramatic speedup by
// avoiding per-item map allocation.
func (h *Handler) transformResponse(ctx context.Context, client *OriginClient, resp *response) *response {
	if h.proxyBaseURL == "" {
		return resp
	}

	contentType := resp.Headers.Get("Content-Type")
	if !strings.Contains(contentType, "json") {
		return resp
	}

	// Cheap byte-scan: if the body contains no "links" or "assets"
	// JSON keys, there is nothing for rewriteLinks to do — pass the
	// bytes through unchanged. This avoids a full unmarshal/marshal
	// round-trip on bodies that don't reference the upstream origin.
	if !bodyMayContainRewritableKeys(resp.Body) {
		return resp
	}

	var data map[string]interface{}
	if err := json.Unmarshal(resp.Body, &data); err != nil {
		return resp // not JSON — leave as-is
	}

	h.rewriteLinks(ctx, client, data)

	newBody, err := json.Marshal(data)
	if err != nil {
		return resp
	}
	resp.Body = newBody
	return resp
}

// bodyMayContainRewritableKeys reports whether the JSON body contains a
// top-level key the rewriter cares about. False positives are
// acceptable (the unmarshal then no-ops); false negatives would skip
// rewriting and are not. The two byte-strings we look for are the
// quoted JSON keys for "links" and "assets".
func bodyMayContainRewritableKeys(body []byte) bool {
	return bytes.Contains(body, []byte(`"links"`)) ||
		bytes.Contains(body, []byte(`"assets"`))
}

// rewriteLinks recursively rewrites href values in the data structure.
//
// Two link rewrite passes happen here:
//
//   - `links[*].href` is always rebased onto the proxy when it points
//     into the upstream origin's base URL — this is the standard STAC
//     navigation rewrite so downstream clients keep following the
//     proxy.
//
//   - `assets[*].href` is rewritten according to the origin's
//     RewriteAssets mode (never/sign/proxy). Asset hrefs typically
//     point at object storage that the proxy does not front, so the
//     default ("never") is intentional. Operators who need authz
//     gating or audit on asset access opt into "sign" or "proxy".
//
// Recursion (M-federation-2): we descend ONLY into keys whose STAC
// shape is documented to nest more link-bearing objects. STAC items
// carry arbitrary user data under "properties" (megabytes of payload
// on dense feature collections), and that subtree by spec contains
// no proxy-rewritable links — recursing into it was pure cost. The
// allowlist below is the closed set of nesting keys; anything else
// (properties, geometry, bbox, individual asset payloads) is skipped.
// A max-depth guard provides defense-in-depth against pathological
// JSON.
func (h *Handler) rewriteLinks(ctx context.Context, client *OriginClient, data interface{}) {
	h.rewriteLinksDepth(ctx, client, data, 0)
}

// rewriteLinksMaxDepth caps recursion to defend against deeply-nested
// attacker JSON. STAC documents in the wild nest at most ~3 levels
// (catalog → collections[] → items[] → links[]); 16 is comfortably
// over that.
const rewriteLinksMaxDepth = 16

// rewriteLinksRecurseKeys is the closed set of map keys whose values
// the rewriter recurses into. Anything outside this set is left
// untouched — most importantly, STAC items' "properties" subtree
// (arbitrary user data) and "geometry"/"bbox" (large payloads with
// no STAC-meaningful link structure inside).
var rewriteLinksRecurseKeys = map[string]struct{}{
	"features":    {}, // FeatureCollection.features[] → each feature has its own links/assets
	"collections": {}, // /collections envelope
	"included":    {}, // STAC API includes (rarely seen, but spec-described)
	"items":       {}, // some catalogs nest items[] under collections in extras
	"children":    {}, // nested catalog hierarchies
}

func (h *Handler) rewriteLinksDepth(ctx context.Context, client *OriginClient, data interface{}, depth int) {
	if depth > rewriteLinksMaxDepth {
		return
	}
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
		if assets, ok := v["assets"].(map[string]interface{}); ok {
			for _, a := range assets {
				if am, ok := a.(map[string]interface{}); ok {
					if href, ok := am["href"].(string); ok {
						am["href"] = h.rewriteAssetHref(ctx, client, href)
					}
				}
			}
		}
		// Only recurse into keys known to nest more link-bearing
		// STAC objects. Skipping the rest avoids walking megabytes
		// of opaque user data under "properties".
		for k, val := range v {
			if _, ok := rewriteLinksRecurseKeys[k]; !ok {
				continue
			}
			h.rewriteLinksDepth(ctx, client, val, depth+1)
		}
	case []interface{}:
		for _, val := range v {
			h.rewriteLinksDepth(ctx, client, val, depth+1)
		}
	}
}

// rewriteAssetHref dispatches on the origin's RewriteAssets mode.
// `never` (the default) preserves backwards compatibility. ctx is the
// inbound request context — passed to the asset signer so that signing
// is cancellable with the client request and observes any
// request-scoped values.
func (h *Handler) rewriteAssetHref(ctx context.Context, client *OriginClient, href string) string {
	origin := client.Origin()
	switch origin.RewriteAssets {
	case "sign":
		if h.assetSigner == nil {
			// Signer is not wired — fall back to passthrough rather
			// than silently leaking unsigned URLs while pretending we
			// gated them.
			return href
		}
		ttl := origin.AssetSignTTL
		if ttl <= 0 {
			ttl = 15 * time.Minute
		}
		return h.assetSigner.Sign(ctx, href, ttl)
	case "proxy":
		if h.proxyBaseURL == "" {
			return href
		}
		ref := base64.RawURLEncoding.EncodeToString([]byte(href))
		return strings.TrimRight(h.proxyBaseURL, "/") + "/assets/" + origin.ID + "/" + ref
	default:
		// "" or "never": pass through unchanged.
		return href
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

// injectOriginMetadata appends a stac_proxy:origin link to a JSON
// STAC document's `links` array. Best-effort: a no-op on parse
// errors. Idempotent: if a link with the same rel + title is already
// present, it is left untouched.
//
// The link shape matches stac.OriginLink — kept in lockstep with the
// merger's links so federated-merge and single-origin-passthrough
// responses are indistinguishable to clients.
func injectOriginMetadata(resp *response, originID, originURL string) {
	var obj map[string]interface{}
	if err := json.Unmarshal(resp.Body, &obj); err != nil {
		return
	}

	links, _ := obj["links"].([]interface{})
	for _, l := range links {
		if lm, ok := l.(map[string]interface{}); ok {
			rel, _ := lm["rel"].(string)
			title, _ := lm["title"].(string)
			if rel == stac.OriginLinkRel && title == originID {
				return
			}
		}
	}

	links = append(links, map[string]interface{}{
		"href":  originURL,
		"rel":   stac.OriginLinkRel,
		"type":  "application/json",
		"title": originID,
	})
	obj["links"] = links

	if b, err := json.Marshal(obj); err == nil {
		resp.Body = b
	}
}

// Asset-streaming headers we forward in either direction.
var (
	assetRequestPassthroughHeaders = []string{
		"Range",
		"If-Match",
		"If-None-Match",
		"If-Modified-Since",
		"If-Unmodified-Since",
		"Accept",
		"Accept-Encoding",
		"User-Agent",
	}
	assetResponsePassthroughHeaders = []string{
		"Content-Type",
		"Content-Length",
		"Content-Range",
		"Content-Encoding",
		"Content-Disposition",
		"Accept-Ranges",
		"ETag",
		"Last-Modified",
		"Cache-Control",
		"Expires",
		"Vary",
	}
)

// ServeAssetHTTP handles GET /assets/{originId}/{ref}. The handler:
//
//   - validates `originId` is a configured, enabled origin
//   - base64-url-decodes `ref` into an absolute upstream URL
//   - verifies that the decoded URL starts with the origin's configured
//     base URL (so this endpoint cannot be coerced into proxying
//     arbitrary internet URLs — defense against using us as a relay)
//   - issues an authenticated, retry-wrapped request via the origin's
//     RoundTripper chain (so upstream auth is applied)
//   - streams the response body back via io.Copy, forwarding the
//     standard byte-range/conditional-GET headers in both directions
//
// Per-request authz/ratelimit gating happens in the chi middleware
// chain wrapping this handler; STACInfo carries RequestType=Asset and
// the originID so policies can key off them.
//
// The router is expected to be the caller; tests and direct callers
// must populate `STACInfo` on the request context.
func (h *Handler) ServeAssetHTTP(w http.ResponseWriter, r *http.Request, originID, ref string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	client, ok := h.origins[originID]
	if !ok {
		http.Error(w, "unknown origin", http.StatusNotFound)
		return
	}
	if client.Origin().RewriteAssets != "proxy" {
		// We only route through this endpoint when the origin opts in.
		// Treating other modes as 404 avoids leaking which origins
		// exist via differential responses.
		http.Error(w, "asset proxying not enabled for this origin", http.StatusNotFound)
		return
	}

	hrefBytes, err := base64.RawURLEncoding.DecodeString(ref)
	if err != nil {
		http.Error(w, "invalid asset reference", http.StatusBadRequest)
		return
	}
	upstreamHref := string(hrefBytes)

	// Defense: the decoded URL MUST live under the origin's configured
	// base URL host+path. Without this check the endpoint could be
	// used to fetch arbitrary internet URLs through the proxy's
	// network position.
	if !assetHrefUnderOrigin(upstreamHref, client.BaseURL()) {
		http.Error(w, "asset reference does not belong to origin", http.StatusBadRequest)
		return
	}

	upstreamURL, err := url.Parse(upstreamHref)
	if err != nil {
		http.Error(w, "invalid asset url", http.StatusBadRequest)
		return
	}

	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL.String(), nil)
	if err != nil {
		http.Error(w, "build upstream request failed", http.StatusInternalServerError)
		return
	}
	// Forward range / conditional-GET / negotiation headers verbatim.
	for _, name := range assetRequestPassthroughHeaders {
		if v := r.Header.Get(name); v != "" {
			outReq.Header.Set(name, v)
		}
	}
	middleware.ForwardRequestID(r.Context(), outReq)

	// Use the origin's RoundTripper chain (auth + retry are layered in).
	resp, err := client.transport.RoundTrip(outReq)
	if err != nil {
		// Distinguish a client disconnect from a real upstream error
		// for cleaner logs; both are surfaced as 502 to the caller
		// because the proxy cannot meaningfully serve the bytes.
		if errors.Is(err, context.Canceled) || errors.Is(r.Context().Err(), context.Canceled) {
			// Client went away mid-flight; nothing to write.
			return
		}
		slog.Error("asset upstream request failed",
			"origin", originID,
			"href", upstreamHref,
			"error", err,
		)
		http.Error(w, "upstream asset fetch failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Forward upstream response headers (after stripping hop-by-hop).
	for _, name := range assetResponsePassthroughHeaders {
		if v := resp.Header.Get(name); v != "" {
			w.Header().Set(name, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	// Stream the bytes. io.Copy honors r.Context() cancellation via
	// the http.Transport's read path, so a client disconnect aborts
	// the upstream read rather than buffering forever.
	if _, err := io.Copy(w, resp.Body); err != nil {
		// Best-effort log; the response is already partially written.
		slog.Warn("asset stream interrupted",
			"origin", originID,
			"error", err,
		)
	}
}

// assetHrefUnderOrigin reports whether href is a valid URL whose
// scheme+host+path-prefix matches the origin's base URL. We compare
// scheme+host case-insensitively and require the path of the asset
// to start with the origin's base path so origins cannot accidentally
// open the relay endpoint up to other hosts they happen to share a
// hostname suffix with.
func assetHrefUnderOrigin(href, originBase string) bool {
	hu, err := url.Parse(href)
	if err != nil {
		return false
	}
	ou, err := url.Parse(originBase)
	if err != nil {
		return false
	}
	if !strings.EqualFold(hu.Scheme, ou.Scheme) {
		return false
	}
	if !strings.EqualFold(hu.Host, ou.Host) {
		return false
	}
	basePath := strings.TrimSuffix(ou.Path, "/")
	if basePath == "" {
		return true
	}
	return hu.Path == basePath || strings.HasPrefix(hu.Path, basePath+"/")
}

// adaptRequestStripCollectionPrefix returns a shallow copy of req with
// the URL path and Collection field rewritten to strip the origin's
// configured collection prefix.
func adaptRequestStripCollectionPrefix(req *request, prefix string) *request {
	if req.Request == nil || prefix == "" {
		return req
	}
	stripped := strings.Replace(req.Request.URL.Path, "/collections/"+req.Collection, "/collections/"+strings.TrimPrefix(req.Collection, prefix), 1)
	clonedV := *req
	cloned := &clonedV
	// Clone the URL so we don't mutate the inbound one.
	newURL := *cloned.Request.URL
	newURL.Path = stripped
	newReq := cloned.Request.Clone(cloned.Context)
	newReq.URL = &newURL
	cloned.Request = newReq
	cloned.Collection = strings.TrimPrefix(req.Collection, prefix)
	return cloned
}
