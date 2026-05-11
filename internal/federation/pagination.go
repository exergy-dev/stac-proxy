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

	"github.com/yourorg/stac-proxy/internal/stac"
)

// PaginatedSearcher handles paginated search across multiple origins.
type PaginatedSearcher struct {
	origins      map[string]*OriginClient
	merger       *ResultMerger
	deduplicator *ItemDeduplicator
	pageSize     int
	maxPageSize  int
}

// PaginatedSearchConfig configures paginated search.
type PaginatedSearchConfig struct {
	Origins         map[string]*OriginClient
	Merger          *ResultMerger
	DefaultPageSize int
	MaxPageSize     int
}

// NewPaginatedSearcher creates a new paginated searcher.
func NewPaginatedSearcher(cfg PaginatedSearchConfig) *PaginatedSearcher {
	if cfg.DefaultPageSize <= 0 {
		cfg.DefaultPageSize = 100
	}
	if cfg.MaxPageSize <= 0 {
		cfg.MaxPageSize = 1000
	}

	return &PaginatedSearcher{
		origins:      cfg.Origins,
		merger:       cfg.Merger,
		deduplicator: NewItemDeduplicator(10000),
		pageSize:     cfg.DefaultPageSize,
		maxPageSize:  cfg.MaxPageSize,
	}
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
	Returned   int            `json:"returned"`
	Matched    int            `json:"matched,omitempty"`
	Limit      int            `json:"limit"`
	Origins    []OriginStatus `json:"origins"`
}

// OriginStatus reports status for each origin.
type OriginStatus struct {
	ID        string `json:"id"`
	Matched   int    `json:"matched,omitempty"`
	Returned  int    `json:"returned"`
	Exhausted bool   `json:"exhausted"`
	Error     string `json:"error,omitempty"`
}

// Search performs a paginated federated search.
func (s *PaginatedSearcher) Search(ctx context.Context, req *stac.SearchRequest, cursorStr string) (*SearchResult, error) {
	// Determine page size
	limit := s.pageSize
	if req.Limit > 0 && req.Limit <= s.maxPageSize {
		limit = req.Limit
	}

	// Parse or create cursor
	var cursor *FederatedCursor
	var err error

	if cursorStr != "" {
		cursor, err = DecodeCursor(cursorStr)
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
		cursor = NewFederatedCursor(hashSearchRequest(req), originIDs, nil)
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
		nextCursor, err := cursor.Encode()
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

			// Execute search
			fc, err := origin.Search(ctx, originReq)

			var items []*stac.Item
			var nextToken, nextURL string
			if err == nil && fc != nil {
				// Convert Features to []*stac.Item
				for i := range fc.Features {
					items = append(items, &fc.Features[i])
				}
				// Extract pagination links if present
				for _, link := range fc.Links {
					if link.Rel == "next" {
						nextURL = link.Href
						break
					}
				}
			}

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
			if lastItem.Properties.DateTime != nil {
				lastSort = lastItem.Properties.DateTime
			} else if dt, ok := lastItem.Properties.Extra["datetime"]; ok {
				lastSort = dt
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

	// Sort by datetime descending (default STAC sort)
	sort.Slice(allItems, func(i, j int) bool {
		ti := getDatetime(allItems[i])
		tj := getDatetime(allItems[j])
		return ti > tj // Descending
	})

	// Apply limit
	if len(allItems) > limit {
		allItems = allItems[:limit]
	}

	return allItems
}

// getDatetime extracts datetime from item for sorting.
func getDatetime(item *stac.Item) string {
	if item.Properties.DateTime != nil {
		return item.Properties.DateTime.Format("2006-01-02T15:04:05Z")
	}
	if dt, ok := item.Properties.Extra["datetime"].(string); ok {
		return dt
	}
	return ""
}

// hashSearchRequest creates a hash of search parameters for cursor validation.
func hashSearchRequest(req *stac.SearchRequest) string {
	// Create a deterministic representation
	data := struct {
		Collections []string
		BBox        []float64
		Datetime    string
		Intersects  interface{}
		Query       map[string]interface{}
		Sortby      []stac.SortSpec
	}{
		Collections: req.Collections,
		BBox:        req.BBox,
		Datetime:    req.Datetime,
		Intersects:  req.Intersects,
		Query:       req.Query,
		Sortby:      req.Sortby,
	}

	bytes, _ := json.Marshal(data)
	hash := sha256.Sum256(bytes)
	return hex.EncodeToString(hash[:8]) // First 8 bytes
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
