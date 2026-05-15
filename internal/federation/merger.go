// Package federation provides result merging for federated searches.
package federation

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/yourorg/stac-proxy/internal/stac"
)

// ResultMerger merges search results from multiple origins.
type ResultMerger struct {
	strategy     ConflictStrategy
	deduplicator *ItemDeduplicator
}

// NewResultMerger creates a new result merger.
func NewResultMerger(strategy ConflictStrategy) *ResultMerger {
	return &ResultMerger{
		strategy:     strategy,
		deduplicator: NewItemDeduplicator(10000),
	}
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

	// Track items by ID for conflict resolution. itemsByID gives us
	// O(1) duplicate detection within a merge call — we don't need the
	// bloom-based deduplicator here, which is reserved for cross-page
	// dedup in paginated search.
	itemsByID := make(map[string]*itemWithOrigin)
	var keyOrder []string // insertion order so results are deterministic
	var totalMatched int

	for _, result := range results {
		if result.Error != nil {
			continue // Skip failed origins
		}

		if result.Context != nil {
			totalMatched += result.Context.Matched
		}

		for _, item := range result.Items {
			if item == nil {
				continue
			}
			key := m.itemKey(result.OriginID, item)

			if existing, exists := itemsByID[key]; exists {
				// Handle conflict and persist the merged result.
				merged, err := m.resolveConflict(existing, item, result.OriginID)
				if err != nil {
					return nil, err
				}
				existing.item = merged
			} else {
				// New item
				transformed := m.transformItem(item, result.OriginID, result.OriginURL)
				itemsByID[key] = &itemWithOrigin{
					item:     transformed,
					originID: result.OriginID,
					priority: result.Priority,
				}
				keyOrder = append(keyOrder, key)
			}
		}
	}

	// Materialise items from the canonical map so merges are observed.
	items := make([]*stac.Item, 0, len(keyOrder))
	for _, k := range keyOrder {
		items = append(items, itemsByID[k].item)
	}
	if req.Limit > 0 && len(items) > req.Limit {
		items = items[:req.Limit]
	}

	// Build the response. The library's ItemsList.Context is `any`;
	// we store our typed SearchContext there and rely on the JSON
	// encoder to flatten it.
	sc := &stac.SearchContext{
		Returned: len(items),
		Matched:  totalMatched,
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

// itemKey generates a unique key for an item.
func (m *ResultMerger) itemKey(originID string, item *stac.Item) string {
	if m.strategy == ConflictNamespace {
		return originID + ":" + item.ID
	}
	// Use collection + item ID as key (items across collections can have same ID)
	return item.Collection + ":" + item.ID
}

// resolveConflict handles duplicate items from different origins.
//
// The strategy enum has five values for config compat, but the actual
// resolver only branches three ways: Merge (combine assets), RejectDuplicates
// (error out), and "keep existing" (FirstWins / PriorityWins / Namespace).
// The semantic distinction between the three "keep existing" strategies
// lives upstream of this function: PriorityWins relies on a priority
// pre-sort, FirstWins is a race that depends on arrival order, and
// Namespace prefixes keys so duplicates never reach here in the first place.
func (m *ResultMerger) resolveConflict(existing *itemWithOrigin,
	incoming *stac.Item, incomingOrigin string) (*stac.Item, error) {

	switch m.strategy {
	case ConflictMerge:
		return m.mergeItems(existing.item, incoming, incomingOrigin), nil
	case ConflictRejectDuplicates:
		return nil, fmt.Errorf("duplicate item ID %s from origins %s and %s",
			incoming.ID, existing.originID, incomingOrigin)
	default:
		// ConflictFirstWins, ConflictPriorityWins, ConflictNamespace.
		return existing.item, nil
	}
}

// mergeItems combines two items with the same ID.
func (m *ResultMerger) mergeItems(existing, incoming *stac.Item, incomingOrigin string) *stac.Item {
	merged := *existing

	// Merge assets from both items
	if merged.Assets == nil {
		merged.Assets = make(map[string]*stac.Asset)
	}
	for key, asset := range incoming.Assets {
		// Prefix asset keys with origin to avoid overwrites
		mergedKey := key
		if _, exists := merged.Assets[key]; exists {
			mergedKey = incomingOrigin + ":" + key
		}
		merged.Assets[mergedKey] = asset
	}

	// Keep the most recent properties (by datetime).
	if incT, ok := stac.ItemDatetime(incoming); ok {
		if existT, ok := stac.ItemDatetime(existing); ok {
			if incT.After(existT) {
				merged.Properties = incoming.Properties
			}
		}
	}

	// Merge links. Defensively copy existing.Links so the append cannot
	// mutate the source slice's backing array if it has spare capacity.
	combined := make([]*stac.Link, 0, len(existing.Links)+len(incoming.Links))
	combined = append(combined, existing.Links...)
	combined = append(combined, incoming.Links...)
	merged.Links = combined

	return &merged
}

// transformItem adds origin metadata to an item via a stac_proxy:origin
// link (rel="stac_proxy:origin", href=originURL, title=originID).
// Using a link rather than a property keeps the marker in the
// standard navigational surface (links[]) so generic STAC tooling
// surfaces it the same way it surfaces self/parent/root links.
func (m *ResultMerger) transformItem(item *stac.Item, originID, originURL string) *stac.Item {
	out := *item // shallow copy so we don't mutate caller's item
	stac.AddItemOriginLink(&out, originID, originURL)

	// Namespace item ID if configured
	if m.strategy == ConflictNamespace {
		out.ID = originID + ":" + out.ID
	}

	return &out
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

// itemWithOrigin tracks an item with its origin metadata.
type itemWithOrigin struct {
	item     *stac.Item
	originID string
	priority int
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
