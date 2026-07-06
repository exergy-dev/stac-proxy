// Package federation provides multi-origin STAC federation.
package federation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/yourorg/stac-proxy/internal/federation/pageadapter"
	"github.com/yourorg/stac-proxy/internal/federation/pagecache"
	"github.com/yourorg/stac-proxy/internal/middleware"
	"github.com/yourorg/stac-proxy/internal/middleware/auth"
	"github.com/yourorg/stac-proxy/internal/stac"
)

// Searcher is the minimal interface PaginatedSearcher needs from each
// origin: execute a search request and return items plus the captured
// pagination state, plus advertise its BaseURL so the paginator can
// enforce the NextURL allowlist when decoding signed cursors.
// *OriginClient is adapted to this interface via OriginClientSearcher;
// tests provide their own implementations.
//
// The returned (nextToken, nextURL) pair is the pagination state the
// adapter (token / next_url / offset / link_header / auto) captured
// from the upstream response. adapterName is non-empty only when the
// auto adapter locked its choice on the first response; subsequent
// pages route to the named adapter via OriginCursor.AdapterName.
type Searcher interface {
	Search(ctx context.Context, req *stac.SearchRequest) (items []*stac.Item, nextToken string, nextURL string, nextBody []byte, adapterName string, err error)
	// BaseURL returns the origin's upstream base URL. Used to enforce
	// that any cursor-encoded NextURL is rooted at the configured
	// origin (preventing SSRF via tampered cursors).
	BaseURL() string
}

// OriginClientSearcher wraps a *OriginClient so it satisfies Searcher
// by:
//   - executing the upstream search (POST /search or verbatim GET when
//     the request carries an OverrideURL),
//   - invoking the configured pagination Adapter on the upstream
//     response to capture next-page state,
//   - propagating the adapter-captured state back to the paginator.
//
// The pagination Adapter is bound at construction. When the auto
// adapter is configured, the locked inner-adapter name flows back via
// the searcher's return value into OriginCursor.AdapterName, where the
// paginator stores it for the next page.
type OriginClientSearcher struct {
	Client  *OriginClient
	Adapter pageadapter.Adapter

	// Registry holds the named adapters so subsequent pages can
	// retrieve the locked adapter by name. Non-nil only when the
	// configured default is `auto`.
	Registry map[string]pageadapter.Adapter
}

// NewOriginClientSearcher builds a Searcher from an OriginClient and
// the origin's pagination config. When cfg names a specific adapter,
// that adapter handles every page. When cfg is empty or names "auto",
// the auto adapter probes on page 0 and locks its choice into the
// returned cursor.
func NewOriginClientSearcher(client *OriginClient, cfg pageadapter.Config) (*OriginClientSearcher, error) {
	adapter, err := pageadapter.New(cfg)
	if err != nil {
		return nil, err
	}
	s := &OriginClientSearcher{Client: client, Adapter: adapter}
	// Build a registry of named adapters when auto is the default —
	// subsequent pages route to the locked named adapter via
	// req.AdapterName.
	if cfg.Adapter == "" || cfg.Adapter == "auto" {
		s.Registry = make(map[string]pageadapter.Adapter, 4)
		for _, name := range []string{"token", "next_url", "offset", "link_header"} {
			sub, err := pageadapter.New(pageadapter.Config{
				Adapter:     name,
				OffsetParam: cfg.OffsetParam,
				TokenParam:  cfg.TokenParam,
			})
			if err != nil {
				return nil, err
			}
			s.Registry[name] = sub
		}
	}
	return s, nil
}

// Search executes the underlying client's search and runs the bound
// pagination adapter against the upstream response. When the cursor
// (carried via req.AdapterName) names a locked adapter, that one is
// used in place of the default — this is how `auto` honors its first-
// response decision on subsequent pages.
func (o *OriginClientSearcher) Search(ctx context.Context, req *stac.SearchRequest) ([]*stac.Item, string, string, []byte, string, error) {
	fc, hdr, err := o.Client.Search(ctx, req)
	if err != nil {
		return nil, "", "", nil, "", err
	}
	if fc == nil {
		return nil, "", "", nil, "", nil
	}
	items := append([]*stac.Item(nil), fc.Features...)

	adapter := o.pickAdapter(req)
	st, err := adapter.Capture(pageadapter.UpstreamResponse{
		FC:      fc,
		Header:  hdr,
		BaseURL: o.Client.BaseURL(),
	})
	if err != nil {
		// A capture error is non-fatal for the items we already have
		// but should retire this origin from further pagination so we
		// don't loop. Logging happens at the paginator (origin marked
		// errored on subsequent advance attempts).
		return items, "", "", nil, "", err
	}
	if st.Done {
		return items, "", "", nil, "", nil
	}
	return items, st.Token, st.URL, st.Body, st.AdapterName, nil
}

// pickAdapter returns the adapter that should handle this response:
// the locked named adapter when req.AdapterName is set and we have a
// registry (i.e. our default is `auto`); otherwise the bound default.
func (o *OriginClientSearcher) pickAdapter(req *stac.SearchRequest) pageadapter.Adapter {
	if req != nil && req.AdapterName != "" && o.Registry != nil {
		if a, ok := o.Registry[req.AdapterName]; ok {
			return a
		}
	}
	return o.Adapter
}

// BaseURL exposes the underlying OriginClient's base URL so the
// paginator can validate cursor NextURLs against the allowlist.
func (o *OriginClientSearcher) BaseURL() string {
	if o == nil || o.Client == nil {
		return ""
	}
	return o.Client.BaseURL()
}

// PaginatedSearcher handles paginated search across multiple origins.
//
// PaginatedSearcher is safe for concurrent use: each Search call builds
// its own per-page dedup map inside mergeItemsFirstWins, so concurrent
// callers never observe each other's item IDs. Cross-page deduplication
// is intentionally NOT preserved across pages — dedup is scoped to a
// single rendered page.
type PaginatedSearcher struct {
	origins        map[string]Searcher
	originBaseURLs map[string]string
	merger         *ResultMerger
	pageSize       int
	maxPageSize    int
	cursorSecret   []byte

	// pageCache stores rendered pages keyed by the cursor that
	// produced them, enabling `rel: prev` / `rel: first` navigation
	// without re-executing the upstream fan-out. Nil when the page
	// cache is disabled by config; Search treats a nil cache as
	// "feature off" and always re-executes.
	pageCache *pagecache.Cache
}

// PaginatedSearchConfig configures paginated search.
type PaginatedSearchConfig struct {
	Origins         map[string]Searcher
	Merger          *ResultMerger
	DefaultPageSize int
	MaxPageSize     int
	// CursorSecret is the HMAC key used to sign and verify federated
	// pagination cursors. Required (non-empty) — NewPaginatedSearcher
	// returns an error if it is missing.
	CursorSecret []byte
	// PageCache, when non-nil, stores rendered pages so the
	// paginator can serve `rel: prev` / `rel: first` navigation
	// without re-fanning-out to origins. Nil disables the feature.
	PageCache *pagecache.Cache
}

// NewPaginatedSearcher creates a new paginated searcher.
//
// Returns an error if CursorSecret is empty; cursors cannot be signed
// without a key and unsigned cursors are an SSRF/authz risk.
func NewPaginatedSearcher(cfg PaginatedSearchConfig) (*PaginatedSearcher, error) {
	if len(cfg.CursorSecret) == 0 {
		return nil, errors.New("paginated searcher: CursorSecret is required")
	}
	if cfg.DefaultPageSize <= 0 {
		cfg.DefaultPageSize = 100
	}
	if cfg.MaxPageSize <= 0 {
		cfg.MaxPageSize = 1000
	}

	baseURLs := make(map[string]string, len(cfg.Origins))
	for id, s := range cfg.Origins {
		if s == nil {
			continue
		}
		baseURLs[id] = s.BaseURL()
	}

	return &PaginatedSearcher{
		origins:        cfg.Origins,
		originBaseURLs: baseURLs,
		merger:         cfg.Merger,
		pageSize:       cfg.DefaultPageSize,
		maxPageSize:    cfg.MaxPageSize,
		cursorSecret:   cfg.CursorSecret,
		pageCache:      cfg.PageCache,
	}, nil
}

// SearchResult contains search results and pagination info. The
// four cursor strings carry the link chain the handler turns into
// link rels:
//
//	NextCursor   → rel: next
//	PrevCursor   → rel: prev   (empty on page 0)
//	FirstCursor  → rel: first  (empty on page 0; same as the page-0
//	                            cursor on page ≥ 1)
//	SelfCursor   → rel: self   (empty on page 0; same as the cursor
//	                            the client supplied to reach this page)
//
// Empty cursors mean "no link of that rel for this page" — the
// handler omits the corresponding link rather than emitting an empty
// href.
type SearchResult struct {
	Items       []*stac.Item
	TotalCount  int
	NextCursor  string
	PrevCursor  string
	FirstCursor string
	SelfCursor  string
	Context     *SearchContext
}

// SearchContext contains additional search context.
type SearchContext struct {
	Returned int            `json:"returned"`
	Matched  int            `json:"matched,omitempty"`
	Limit    int            `json:"limit"`
	Origins  []OriginStatus `json:"origins"`
}

// OriginStatus reports status for each origin.
type OriginStatus struct {
	ID        string `json:"id"`
	Matched   int    `json:"matched,omitempty"`
	Returned  int    `json:"returned"`
	Exhausted bool   `json:"exhausted"`
	Error     string `json:"error,omitempty"`
}

// principalHashFromContext extracts the principal hash from ctx for
// cursor binding. Returns "" when ctx carries no principal (anonymous).
func principalHashFromContext(ctx context.Context) string {
	p, ok := ctx.Value(middleware.PrincipalKey).(*auth.Principal)
	if !ok || p == nil {
		return ""
	}
	return PrincipalHash(p.ID)
}

// Search performs a paginated federated search.
//
// When a page cache is configured and the incoming cursor matches a
// stored entry, Search returns the cached page directly (the
// backwards-navigation path). On a miss, Search executes the upstream
// fan-out as usual and stores the rendered page in the cache so a
// later `rel: prev` follow can serve it.
func (s *PaginatedSearcher) Search(ctx context.Context, req *stac.SearchRequest, cursorStr string) (*SearchResult, error) {
	// Determine page size
	limit := s.pageSize
	if req.Limit > 0 && req.Limit <= s.maxPageSize {
		limit = req.Limit
	}

	principalHash := principalHashFromContext(ctx)

	// Parse or create cursor
	var cursor *FederatedCursor
	var err error

	if cursorStr != "" {
		cursor, err = DecodeCursor(cursorStr, s.cursorSecret, s.originBaseURLs, principalHash)
		if err != nil {
			return nil, err
		}
		// Validate cursor matches query
		if cursor.QueryHash != hashSearchRequest(req) {
			return nil, errors.New("cursor does not match search parameters")
		}

		// Backwards-navigation fast path: when the page cache holds
		// the page this cursor produced, return it directly. Cache
		// keys are derived from the cursor signature (already
		// HMAC-bound to principal at the cursor encoder), so a hit
		// here is safe to return verbatim.
		if cached, ok := s.pageCache.Get(ctx, pagecache.SignatureOf(cursorStr), principalHash); ok {
			return fromCachedResult(cached), nil
		}
	} else {
		// Create new cursor
		originIDs := make([]string, 0, len(s.origins))
		for id := range s.origins {
			originIDs = append(originIDs, id)
		}
		cursor = NewFederatedCursor(hashSearchRequest(req), principalHash, originIDs, nil)
	}

	// Fetch from all active origins. "Active" here means either
	// upstream has more pages OR a stash is queued — but only
	// upstream-unexhausted origins should actually be fetched. Stash-
	// only origins contribute via mergeResults reading their stash.
	activeOrigins := cursor.ActiveOrigins()
	if len(activeOrigins) == 0 {
		return &SearchResult{
			Items:   []*stac.Item{},
			Context: &SearchContext{Returned: 0, Limit: limit},
		}, nil
	}

	// Filter to origins that should actually be queried this page:
	// skip origins whose stash already has >= limit items (their
	// contribution is bounded anyway, no need to grow the stash) and
	// skip origins whose upstream is exhausted (no NextToken/URL/Body
	// to follow — a re-fetch would re-query page 0 and emit duplicates).
	toFetch := make([]string, 0, len(activeOrigins))
	for _, id := range activeOrigins {
		oc := cursor.GetOriginCursor(id)
		if oc == nil || oc.Exhausted {
			continue
		}
		if len(oc.Stash) >= limit {
			continue
		}
		toFetch = append(toFetch, id)
	}

	// Fetch pages in parallel
	results := s.fetchFromOrigins(ctx, req, cursor, toFetch, limit)

	// Merge and deduplicate results
	mergedItems := s.mergeResults(results, cursor, limit)

	// Update cursor with new state
	cursor.TotalReturned += len(mergedItems)

	// Build result. SelfCursor is the cursor the client supplied to
	// reach this page (or "" on page 0); PrevCursor and FirstCursor
	// come from the chain encoded into the incoming cursor.
	result := &SearchResult{
		Items:       mergedItems,
		TotalCount:  cursor.TotalReturned,
		PrevCursor:  cursor.PrevCursor,
		FirstCursor: cursor.FirstCursor,
		SelfCursor:  cursorStr,
		Context: &SearchContext{
			Returned: len(mergedItems),
			Limit:    limit,
		},
	}

	// Encode next cursor if there are more results. The next cursor
	// carries the prev/first chain so the downstream link emitter
	// can offer backwards navigation from page N+1.
	if cursor.HasMore() {
		nextCursor := cursor.Clone()
		// Chain pointers: prev points to the cursor that PRODUCED
		// this page; first points to page 0. cursorStr is "" on
		// page 0 itself, in which case the next cursor's
		// PrevCursor stays empty and PageSeq goes from 0 to 1.
		nextCursor.PrevCursor = cursorStr
		if cursor.PageSeq == 0 {
			// Page 0 is the first page; the cursor we're about to
			// emit (page 1's cursor) needs FirstCursor = page-0's
			// cursor. cursorStr is "" on page 0, so we record an
			// empty string; the handler treats empty FirstCursor on
			// page > 0 as "page 0 has no canonical cursor"
			// (synthetic-first behavior — see handler).
			nextCursor.FirstCursor = cursorStr
		} else {
			nextCursor.FirstCursor = cursor.FirstCursor
		}
		nextCursor.PageSeq = cursor.PageSeq + 1
		encoded, encErr := nextCursor.Encode(s.cursorSecret)
		if encErr == nil {
			result.NextCursor = encoded
		}
	}

	// Add origin status to context
	for id, origin := range cursor.Origins {
		status := OriginStatus{
			ID:        id,
			Returned:  origin.ItemCount,
			Exhausted: origin.Exhausted,
		}
		if origin.Error {
			status.Error = "fetch failed"
		}
		result.Context.Origins = append(result.Context.Origins, status)
	}

	// Store the rendered page in the cache. The key is the cursor
	// that PRODUCED this page (cursorStr) — when a client later
	// follows `rel: prev` and arrives back here with that same
	// cursorStr, the Get above hits and we serve the cached bytes
	// without re-fanning-out.
	if cursorStr != "" {
		s.putToPageCache(ctx, cursorStr, principalHash, cursor, result)
	}

	return result, nil
}

// putToPageCache serializes result and stores it under cursorStr's
// signature. Errors are non-fatal — the cache is purely an
// optimisation; a put failure means a future prev-link follow will
// fall through to a fresh fetch. TTL is bounded by the cursor's
// remaining lifetime.
func (s *PaginatedSearcher) putToPageCache(ctx context.Context, cursorStr, principalHash string, cursor *FederatedCursor, result *SearchResult) {
	if s.pageCache == nil {
		return
	}
	sig := pagecache.SignatureOf(cursorStr)
	if sig == "" {
		return
	}
	remaining := time.Until(time.Unix(cursor.ExpiresAt, 0))
	if remaining <= 0 {
		return
	}
	ctxJSON, _ := json.Marshal(result.Context)
	_ = s.pageCache.Put(ctx, sig, principalHash, &pagecache.SearchResult{
		Items:       result.Items,
		TotalCount:  result.TotalCount,
		NextCursor:  result.NextCursor,
		PrevCursor:  result.PrevCursor,
		FirstCursor: result.FirstCursor,
		SelfCursor:  result.SelfCursor,
		Context:     ctxJSON,
	}, remaining)
}

// fromCachedResult translates a pagecache.SearchResult back into the
// federation-layer SearchResult shape. The Context JSON is decoded
// into the typed *SearchContext; on decode failure we degrade
// gracefully to an empty context (the cache hit is still useful — the
// items are the load-bearing part).
func fromCachedResult(c *pagecache.SearchResult) *SearchResult {
	r := &SearchResult{
		Items:       c.Items,
		TotalCount:  c.TotalCount,
		NextCursor:  c.NextCursor,
		PrevCursor:  c.PrevCursor,
		FirstCursor: c.FirstCursor,
		SelfCursor:  c.SelfCursor,
	}
	if len(c.Context) > 0 {
		var sc SearchContext
		if err := json.Unmarshal(c.Context, &sc); err == nil {
			r.Context = &sc
		}
	}
	return r
}

// originFetchResult holds results from a single origin.
type originFetchResult struct {
	OriginID    string
	Items       []*stac.Item
	NextToken   string
	NextURL     string
	NextBody    []byte
	AdapterName string // adapter that captured this state (auto's lock decision)
	Error       error
}

// fetchFromOrigins fetches pages from all active origins in parallel.
//
// Cursor → request plumbing: OriginCursor.NextToken populates
// SearchRequest.Token (POST body.token / GET ?token=); NextURL
// populates SearchRequest.OverrideURL (instructs OriginClient to GET
// the URL verbatim); AdapterName populates SearchRequest.AdapterName
// (selects the locked pagination adapter for `auto` origins). These
// transport-private fields carry the adapter's view of pagination
// state across the Searcher boundary without changing the on-wire
// SearchRequest shape.
func (s *PaginatedSearcher) fetchFromOrigins(ctx context.Context, req *stac.SearchRequest, cursor *FederatedCursor, originIDs []string, limit int) []originFetchResult {
	var wg sync.WaitGroup
	results := make([]originFetchResult, len(originIDs))

	for i, originID := range originIDs {
		wg.Add(1)
		go func(idx int, id string) {
			defer wg.Done()

			origin, ok := s.origins[id]
			if !ok {
				results[idx] = originFetchResult{
					OriginID: id,
					Error:    errors.New("origin not found"),
				}
				return
			}

			// Build origin-specific request. Upstream limit equals the
			// page limit — over-fetching is unnecessary now that
			// un-emitted items go to the per-origin Stash on the
			// cursor (see mergeResults) rather than being silently
			// dropped past the cursor advancement boundary.
			originReq := cloneSearchRequest(req)
			originReq.Limit = limit

			// Apply cursor state. We pass the full set of pagination
			// hints; the OriginClient + adapter decide which to use.
			if oc := cursor.GetOriginCursor(id); oc != nil {
				if oc.NextToken != "" {
					originReq.Token = oc.NextToken
				}
				if oc.NextURL != "" {
					originReq.OverrideURL = oc.NextURL
				}
				if len(oc.NextBody) > 0 {
					originReq.OverrideBody = oc.NextBody
				}
				originReq.AdapterName = oc.AdapterName
			}

			// Execute search via the Searcher interface. The
			// returned adapterName, if non-empty, is `auto`'s locked
			// choice — propagated back into the cursor by mergeResults.
			items, nextToken, nextURL, nextBody, adapterName, err := origin.Search(ctx, originReq)

			results[idx] = originFetchResult{
				OriginID:    id,
				Items:       items,
				NextToken:   nextToken,
				NextURL:     nextURL,
				NextBody:    nextBody,
				AdapterName: adapterName,
				Error:       err,
			}
		}(i, originID)
	}

	wg.Wait()
	return results
}

// mergeResults updates per-origin cursor state from the fetch results
// and returns the merged page of items.
//
// Stash semantics: each origin's previously-stashed items (from the
// last page's merge-sort trim) are prepended to its freshly-fetched
// items before the merge. After merge+sort+trim, any items beyond
// the page limit are grouped back into per-origin stashes on the
// cursor, so the next page consumes them BEFORE re-fetching from
// upstream. This is what prevents the buffer-drop bug where
// per-origin cursors advanced past items the merger had not emitted.
//
// The actual item merge — dedup by collection+ID, stac_proxy:origin
// link injection — is delegated to mergeItemsFirstWins so the
// fan-out and paginated paths share one definition.
func (s *PaginatedSearcher) mergeResults(results []originFetchResult, cursor *FederatedCursor, limit int) []*stac.Item {
	// Phase 1: mark errored origins; index fresh fetches by ID so we
	// can pair them with the existing stash below.
	freshByOrigin := make(map[string]originFetchResult, len(results))
	for _, result := range results {
		if result.Error != nil {
			cursor.MarkError(result.OriginID)
			continue
		}
		freshByOrigin[result.OriginID] = result
	}

	// Phase 2: build per-origin combined item lists (stash + fresh).
	// Iterate every active origin (including stash-only ones that we
	// didn't fetch this page) so their queued items participate in
	// the merge.
	activeOrigins := cursor.ActiveOrigins()
	sort.Strings(activeOrigins) // deterministic origin order for ties
	sources := make([]itemSource, 0, len(activeOrigins))
	for _, originID := range activeOrigins {
		oc := cursor.GetOriginCursor(originID)
		if oc == nil {
			continue
		}
		fresh := freshByOrigin[originID].Items
		combined := make([]*stac.Item, 0, len(oc.Stash)+len(fresh))
		combined = append(combined, oc.Stash...)
		combined = append(combined, fresh...)
		if len(combined) == 0 {
			continue
		}
		sources = append(sources, itemSource{
			OriginID:  originID,
			OriginURL: s.originBaseURLs[originID],
			Items:     combined,
		})
	}

	merged := mergeItemsFirstWins(sources)

	// Sort by (datetime desc, id asc). The datetime-asc tiebreaker on
	// equal datetimes is required for stable cross-page merge across
	// origins: without it, items at a page boundary can shift order
	// between pages and clients see duplicates or skips.
	sort.SliceStable(merged, func(i, j int) bool {
		ti, tj := getDatetime(merged[i]), getDatetime(merged[j])
		if ti != tj {
			return ti > tj
		}
		return merged[i].ID < merged[j].ID
	})

	// Phase 3: split into emitted (top `limit`) and remainder.
	var emitted, remainder []*stac.Item
	if len(merged) > limit {
		emitted = merged[:limit]
		remainder = merged[limit:]
	} else {
		emitted = merged
	}

	// Phase 4: group remainder by origin using the stac_proxy:origin
	// link mergeItemsFirstWins injected. These become the next page's
	// per-origin stashes.
	newStash := make(map[string][]*stac.Item, len(activeOrigins))
	for _, item := range remainder {
		originID := stac.ItemOriginID(item)
		if originID == "" {
			continue // shouldn't happen; mergeItemsFirstWins always tags
		}
		newStash[originID] = append(newStash[originID], item)
	}

	// Phase 5: update each origin's cursor state. For fetched origins,
	// advance the upstream next-pointers; for all active origins,
	// overwrite the stash with the new remainder slice (possibly nil).
	for _, originID := range activeOrigins {
		oc := cursor.GetOriginCursor(originID)
		if oc == nil {
			continue
		}
		if r, ok := freshByOrigin[originID]; ok {
			var lastSort interface{}
			if len(r.Items) > 0 {
				lastItem := r.Items[len(r.Items)-1]
				if t, ok := stac.ItemDatetime(lastItem); ok {
					lastSort = t
				} else if lastItem.Properties != nil {
					if dt, ok := lastItem.Properties["datetime"]; ok {
						lastSort = dt
					}
				}
			}
			cursor.UpdateOriginState(originID, OriginUpdate{
				ItemCount:     len(r.Items),
				NextToken:     r.NextToken,
				NextURL:       r.NextURL,
				NextBody:      r.NextBody,
				AdapterName:   r.AdapterName,
				LastSortValue: lastSort,
			})
		}
		oc.Stash = newStash[originID]
	}

	return emitted
}

// getDatetime extracts datetime from item for sorting.
func getDatetime(item *stac.Item) string {
	if t, ok := stac.ItemDatetime(item); ok {
		return t.Format(time.RFC3339)
	}
	if item.Properties != nil {
		if dt, ok := item.Properties["datetime"].(string); ok {
			return dt
		}
	}
	return ""
}

// hashSearchRequest creates a stable, full-width digest of the
// semantically-relevant search parameters. Pagination fields (Cursor,
// Token) are deliberately excluded so the hash stays invariant across
// pages of the same logical query. The full 32-byte sha256 (64 hex
// chars) is returned to minimize collision probability.
func hashSearchRequest(req *stac.SearchRequest) string {
	if req == nil {
		req = &stac.SearchRequest{}
	}
	data := struct {
		Collections []string               `json:"collections"`
		IDs         []string               `json:"ids"`
		BBox        []float64              `json:"bbox"`
		Intersects  interface{}            `json:"intersects"`
		Datetime    string                 `json:"datetime"`
		Limit       int                    `json:"limit"`
		Filter      interface{}            `json:"filter"`
		FilterLang  string                 `json:"filter_lang"`
		FilterCRS   string                 `json:"filter_crs"`
		Query       map[string]interface{} `json:"query"`
		Sortby      []stac.SortSpec        `json:"sortby"`
	}{
		Collections: req.Collections,
		IDs:         req.IDs,
		BBox:        req.BBox,
		Intersects:  req.Intersects,
		Datetime:    req.Datetime,
		Limit:       req.Limit,
		Filter:      req.Filter,
		FilterLang:  req.FilterLang,
		FilterCRS:   req.FilterCRS,
		Query:       req.Query,
		Sortby:      req.Sortby,
	}

	bytes, _ := json.Marshal(data)
	hash := sha256.Sum256(bytes)
	return hex.EncodeToString(hash[:])
}

// cloneSearchRequest creates a shallow copy of a search request.
func cloneSearchRequest(req *stac.SearchRequest) *stac.SearchRequest {
	clone := *req
	if req.Collections != nil {
		clone.Collections = make([]string, len(req.Collections))
		copy(clone.Collections, req.Collections)
	}
	if req.BBox != nil {
		clone.BBox = make([]float64, len(req.BBox))
		copy(clone.BBox, req.BBox)
	}
	if req.IDs != nil {
		clone.IDs = make([]string, len(req.IDs))
		copy(clone.IDs, req.IDs)
	}
	return &clone
}
