package federation

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"runtime/debug"
	"strings"
	"time"

	"github.com/yourorg/stac-proxy/internal/middleware"
	"github.com/yourorg/stac-proxy/internal/stac"
)

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

	// All routed origins down → 502, not an empty 200 that reads as
	// "no matches".
	failed := originFailures(results, func(r *OriginSearchResult) (string, bool) {
		return r.OriginID, r.Error != nil
	})
	if resp, err := h.respondIfAllFailed("federated search", failed, len(results)); resp != nil || err != nil {
		return resp, err
	}

	// Merge results
	fc, err := h.merger.MergeSearchResults(results, searchReq)
	if err != nil {
		return nil, err
	}

	// Build response
	return h.buildSearchResponse(fc, req, failed)
}

// fanOutSearch executes search requests to multiple origins in parallel.
//
// Each goroutine carries a panic recovery so that a bug in one origin's
// code path cannot crash the whole proxy process: a panic is logged
// (origin + value + stack) and the offending origin is recorded with
// an Error result so the merger treats it as a failed origin.
func (h *Handler) fanOutSearch(ctx context.Context, origins []*Origin,
	searchReq *stac.SearchRequest) []*OriginSearchResult {

	return fanOut(origins, h.maxConcurrent,
		func(origin *Origin) *OriginSearchResult {
			return h.searchOrigin(ctx, origin, searchReq)
		},
		func(origin *Origin, r any) *OriginSearchResult {
			slog.Error("federation origin search panicked",
				"origin", origin.ID,
				"panic", r,
				"stack", string(debug.Stack()),
			)
			return &OriginSearchResult{
				OriginID:  origin.ID,
				OriginURL: origin.BaseURL,
				Priority:  origin.Priority,
				Error:     fmt.Errorf("origin %s panicked: %v", origin.ID, r),
			}
		})
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
	var failed []string
	if result.Context != nil {
		sc.Limit = result.Context.Limit
		sc.Matched = result.Context.Matched
		// Surface the paginator's per-origin status block — computed
		// since the first cursor implementation but previously dropped
		// here, which made origin failures invisible to clients.
		if len(result.Context.Origins) > 0 {
			sc.Origins = result.Context.Origins
			failed = failedFromStatuses(result.Context.Origins)
		}
	}
	if sc.Limit == 0 && searchReq.Limit > 0 {
		sc.Limit = searchReq.Limit
	}

	// Every routed origin failed and nothing was served (no stash
	// carry-over): 502, not an empty 200. Mid-session pages that
	// still emit stashed items stay 200-partial — hence the extra
	// len(items) guard the other two call sites don't need.
	if len(items) == 0 && result.Context != nil {
		if resp, err := h.respondIfAllFailed("paginated federated search", failed, len(result.Context.Origins)); resp != nil || err != nil {
			return resp, err
		}
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

	resp := &response{
		StatusCode: http.StatusOK,
		Headers: http.Header{
			"Content-Type": []string{"application/geo+json"},
		},
		Body: body,
	}
	h.markPartial(resp, failed)
	return resp, nil
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
	req *request, failedOrigins []string) (*response, error) {

	body, err := json.Marshal(fc)
	if err != nil {
		return nil, err
	}

	resp := &response{
		StatusCode: http.StatusOK,
		Headers: http.Header{
			"Content-Type": []string{"application/geo+json"},
		},
		Body: body,
	}
	h.markPartial(resp, failedOrigins)
	return resp, nil
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
