// Package federation provides result merging for federated searches.
package federation

import (
	"encoding/json"
	"sort"

	"github.com/yourorg/stac-proxy/internal/stac"
)

// ResultMerger merges search results from multiple origins.
type ResultMerger struct{}

// NewResultMerger creates a new result merger.
func NewResultMerger() *ResultMerger {
	return &ResultMerger{}
}

// itemSource is the input shape consumed by mergeItemsFirstWins: a
// single origin's items along with the metadata needed to attach the
// stac_proxy:origin link.
type itemSource struct {
	OriginID  string
	OriginURL string
	Items     []*stac.Item
}

// mergeItemsFirstWins dedups items across origin results and injects a
// stac_proxy:origin link onto each kept item.
//
// First-wins by caller-provided iteration order: callers are
// responsible for sorting sources before calling (the fan-out path
// sorts by (priority asc, originID asc); the paginated path passes
// results in fetch order). Dedup key is collection + ":" + ID, so the
// same item ID under different collections is preserved.
//
// No sort and no limit are applied here — those are caller concerns.
func mergeItemsFirstWins(sources []itemSource) []*stac.Item {
	seen := make(map[string]struct{})
	out := make([]*stac.Item, 0)

	for _, src := range sources {
		for _, item := range src.Items {
			if item == nil {
				continue
			}
			key := item.Collection + ":" + item.ID
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}

			tagged := *item // shallow copy so we don't mutate caller's item
			stac.AddItemOriginLink(&tagged, src.OriginID, src.OriginURL)
			out = append(out, &tagged)
		}
	}
	return out
}

// MergeSearchResults merges results from multiple origins into a single response.
//
// Ordering is deterministic: results are sorted by (priority asc,
// originID asc) before iteration, so a tie between origins sharing the
// same priority resolves stably rather than depending on goroutine
// completion order.
func (m *ResultMerger) MergeSearchResults(results []*OriginSearchResult,
	req *stac.SearchRequest) (*stac.FeatureCollection, error) {

	// Sort by (priority asc, originID asc) for deterministic merge.
	sort.SliceStable(results, func(i, j int) bool {
		if results[i].Priority != results[j].Priority {
			return results[i].Priority < results[j].Priority
		}
		return results[i].OriginID < results[j].OriginID
	})

	sources := make([]itemSource, 0, len(results))
	statuses := make([]OriginStatus, 0, len(results))
	var totalMatched int
	for _, result := range results {
		if result.Error != nil {
			// Failed origins contribute no items, but their absence is
			// surfaced in the per-origin status block rather than
			// silently narrowing the result set.
			statuses = append(statuses, OriginStatus{
				ID:    result.OriginID,
				Error: classifyOriginError(result.Error),
			})
			continue
		}
		status := OriginStatus{
			ID:       result.OriginID,
			Returned: len(result.Items),
		}
		if result.Context != nil {
			totalMatched += result.Context.Matched
			status.Matched = result.Context.Matched
		}
		statuses = append(statuses, status)
		sources = append(sources, itemSource{
			OriginID:  result.OriginID,
			OriginURL: result.OriginURL,
			Items:     result.Items,
		})
	}

	items := mergeItemsFirstWins(sources)
	if req.Limit > 0 && len(items) > req.Limit {
		items = items[:req.Limit]
	}

	// Build the response. The library's ItemsList.Context is `any`;
	// we store our typed SearchContext there and rely on the JSON
	// encoder to flatten it.
	sc := &stac.SearchContext{
		Returned: len(items),
		Matched:  totalMatched,
		Origins:  statuses,
	}
	if req.Limit > 0 {
		sc.Limit = req.Limit
	}
	fc := &stac.FeatureCollection{
		Type:     "FeatureCollection",
		Features: items,
		Context:  sc,
	}

	return fc, nil
}

// DeduplicateCollections removes duplicate collections by ID and
// returns them sorted by ID for stable output.
func (m *ResultMerger) DeduplicateCollections(collections []*stac.Collection) []*stac.Collection {
	seen := make(map[string]bool)
	var result []*stac.Collection

	for _, coll := range collections {
		if coll == nil {
			continue
		}
		if !seen[coll.ID] {
			seen[coll.ID] = true
			result = append(result, coll)
		}
	}

	// Sort by ID for consistent ordering
	sort.Slice(result, func(i, j int) bool {
		return result[i].ID < result[j].ID
	})

	return result
}

// MergeCollections merges collection results from multiple origins
// and attaches a stac_proxy:origin link to each (rel = origin link
// rel, href = origin BaseURL, title = origin ID).
//
// All mutation happens here, in the caller's goroutine, AFTER the
// per-origin fan-out has completed. The previous design also wrote
// the marker from each per-origin goroutine, which raced with the
// JSON-marshal step under the race detector even though the writes
// happened-before the marshal via wg.Wait. Keeping a single writer
// removes the ambiguity.
func (m *ResultMerger) MergeCollections(results []*OriginCollectionsResult) []*stac.Collection {
	var allCollections []*stac.Collection

	for _, result := range results {
		if result.Error != nil {
			continue
		}
		for _, coll := range result.Collections {
			if coll == nil {
				continue
			}
			stac.AddCollectionOriginLink(coll, result.OriginID, result.OriginURL)
			allCollections = append(allCollections, coll)
		}
	}

	return m.DeduplicateCollections(allCollections)
}

// MergeStats returns statistics about a merge operation.
type MergeStats struct {
	TotalItems      int
	UniqueItems     int
	DuplicatesFound int
	OriginsUsed     int
	OriginsFailed   int
}

// CalculateMergeStats calculates statistics for merge results.
func CalculateMergeStats(results []*OriginSearchResult, mergedCount int) MergeStats {
	stats := MergeStats{
		UniqueItems: mergedCount,
	}

	for _, result := range results {
		if result.Error != nil {
			stats.OriginsFailed++
		} else {
			stats.OriginsUsed++
			stats.TotalItems += len(result.Items)
		}
	}

	stats.DuplicatesFound = stats.TotalItems - mergedCount

	return stats
}

// ItemToJSON converts an item to JSON bytes.
func ItemToJSON(item *stac.Item) ([]byte, error) {
	return json.Marshal(item)
}

// CollectionToJSON converts a collection to JSON bytes.
func CollectionToJSON(collection *stac.Collection) ([]byte, error) {
	return json.Marshal(collection)
}
