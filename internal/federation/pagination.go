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

	"github.com/yourorg/stac-proxy/internal/middleware"
	"github.com/yourorg/stac-proxy/internal/middleware/auth"
	"github.com/yourorg/stac-proxy/internal/stac"
)

// Searcher is the minimal interface PaginatedSearcher needs from each
// origin: execute a search request and return items plus pagination
// tokens, plus advertise its BaseURL so the paginator can enforce the
// NextURL allowlist when decoding signed cursors. *OriginClient is
// adapted to this interface via OriginClientSearcher; tests provide
// their own implementations.
type Searcher interface {
	Search(ctx context.Context, req *stac.SearchRequest) (items []*stac.Item, nextToken string, nextURL string, err error)
	// BaseURL returns the origin's upstream base URL. Used to enforce
	// that any cursor-encoded NextURL is rooted at the configured
	// origin (preventing SSRF via tampered cursors).
	BaseURL() string
}

// OriginClientSearcher wraps a *OriginClient so it satisfies Searcher
// by translating the FeatureCollection return into the (items,
// nextToken, nextURL, err) shape that the paginator works in.
type OriginClientSearcher struct{ Client *OriginClient }

// Search executes the underlying client's search and extracts items
// plus the upstream's "next" link, if any. Both a token (parsed from
// the next-link URL) and the raw URL are surfaced so the paginator
// can drive subsequent requests against origins that paginate by
// token, by full URL, or both.
func (o OriginClientSearcher) Search(ctx context.Context, req *stac.SearchRequest) ([]*stac.Item, string, string, error) {
	fc, err := o.Client.Search(ctx, req)
	if err != nil || fc == nil {
		return nil, "", "", err
	}
	items := append([]*stac.Item(nil), fc.Features...)
	nextToken := stac.ExtractNextToken(fc.Links)
	var nextURL string
	for _, link := range fc.Links {
		if link != nil && link.Rel == "next" {
			nextURL = link.Href
			break
		}
	}
	return items, nextToken, nextURL, nil
}

// BaseURL exposes the underlying OriginClient's base URL so the
// paginator can validate cursor NextURLs against the allowlist.
func (o OriginClientSearcher) BaseURL() string {
	if o.Client == nil {
		return ""
	}
	return o.Client.BaseURL()
}

// PaginatedSearcher handles paginated search across multiple origins.
type PaginatedSearcher struct {
	origins        map[string]Searcher
	originBaseURLs map[string]string
	merger         *ResultMerger
	deduplicator   *ItemDeduplicator
	pageSize       int
	maxPageSize    int
	cursorSecret   []byte
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
		deduplicator:   NewItemDeduplicator(10000),
		pageSize:       cfg.DefaultPageSize,
		maxPageSize:    cfg.MaxPageSize,
		cursorSecret:   cfg.CursorSecret,
	}, nil
}

// SearchResult contains search results and pagination info.
type SearchResult struct {
	Items      []*stac.Item
	TotalCount int
	NextCursor string
	Context    *SearchContext
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
	} else {
		// Create new cursor
		originIDs := make([]string, 0, len(s.origins))
		for id := range s.origins {
			originIDs = append(originIDs, id)
		}
		cursor = NewFederatedCursor(hashSearchRequest(req), principalHash, originIDs, nil)
	}

	// Reset deduplicator for new searches
	if cursorStr == "" {
		s.deduplicator = NewItemDeduplicator(10000)
	}

	// Fetch from all active origins
	activeOrigins := cursor.ActiveOrigins()
	if len(activeOrigins) == 0 {
		return &SearchResult{
			Items:   []*stac.Item{},
			Context: &SearchContext{Returned: 0, Limit: limit},
		}, nil
	}

	// Fetch pages in parallel
	results := s.fetchFromOrigins(ctx, req, cursor, activeOrigins, limit)

	// Merge and deduplicate results
	mergedItems := s.mergeResults(results, cursor, limit)

	// Update cursor with new state
	cursor.TotalReturned += len(mergedItems)

	// Build result
	result := &SearchResult{
		Items:      mergedItems,
		TotalCount: cursor.TotalReturned,
		Context: &SearchContext{
			Returned: len(mergedItems),
			Limit:    limit,
		},
	}

	// Encode next cursor if there are more results
	if cursor.HasMore() {
		nextCursor, err := cursor.Encode(s.cursorSecret)
		if err == nil {
			result.NextCursor = nextCursor
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

	return result, nil
}

// originFetchResult holds results from a single origin.
type originFetchResult struct {
	OriginID  string
	Items     []*stac.Item
	NextToken string
	NextURL   string
	Error     error
}

// fetchFromOrigins fetches pages from all active origins in parallel.
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

			// Build origin-specific request
			originReq := cloneSearchRequest(req)
			originReq.Limit = limit * 2 // Fetch extra for merge buffer

			// Apply cursor state
			if oc := cursor.GetOriginCursor(id); oc != nil {
				if oc.NextToken != "" {
					originReq.Token = oc.NextToken
				}
			}

			// Execute search via the Searcher interface
			items, nextToken, nextURL, err := origin.Search(ctx, originReq)

			results[idx] = originFetchResult{
				OriginID:  id,
				Items:     items,
				NextToken: nextToken,
				NextURL:   nextURL,
				Error:     err,
			}
		}(i, originID)
	}

	wg.Wait()
	return results
}

// mergeResults merges results from all origins with deduplication.
func (s *PaginatedSearcher) mergeResults(results []originFetchResult, cursor *FederatedCursor, limit int) []*stac.Item {
	var allItems []*stac.Item

	for _, result := range results {
		if result.Error != nil {
			cursor.MarkError(result.OriginID)
			continue
		}

		// Update cursor state
		var lastSort interface{}
		if len(result.Items) > 0 {
			lastItem := result.Items[len(result.Items)-1]
			if t, ok := stac.ItemDatetime(lastItem); ok {
				lastSort = t
			} else if lastItem.Properties != nil {
				if dt, ok := lastItem.Properties["datetime"]; ok {
					lastSort = dt
				}
			}
		}
		cursor.UpdateOrigin(result.OriginID, len(result.Items), result.NextToken, result.NextURL, lastSort)

		// Deduplicate and add items
		for _, item := range result.Items {
			if !s.deduplicator.IsDuplicate(item.ID) {
				allItems = append(allItems, item)
			}
		}
	}

	// Sort by (datetime desc, id asc). The datetime-asc tiebreaker on
	// equal datetimes is required for stable cross-page merge across
	// origins: without it, items at a page boundary can shift order
	// between pages and clients see duplicates or skips.
	sort.SliceStable(allItems, func(i, j int) bool {
		ti, tj := getDatetime(allItems[i]), getDatetime(allItems[j])
		if ti != tj {
			return ti > tj
		}
		return allItems[i].ID < allItems[j].ID
	})

	// Apply limit
	if len(allItems) > limit {
		allItems = allItems[:limit]
	}

	return allItems
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
