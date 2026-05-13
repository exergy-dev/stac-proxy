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
func (m *ResultMerger) MergeSearchResults(results []*OriginSearchResult,
	req *stac.SearchRequest) (*stac.FeatureCollection, error) {

	// Sort by priority (lower = higher priority)
	sort.Slice(results, func(i, j int) bool {
		return results[i].Priority < results[j].Priority
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
			key := m.itemKey(result.OriginID, item)

			if existing, exists := itemsByID[key]; exists {
				// Handle conflict and persist the merged result.
				merged, err := m.resolveConflict(existing, &item, result.OriginID)
				if err != nil {
					return nil, err
				}
				existing.item = merged
			} else {
				// New item
				transformed := m.transformItem(item, result.OriginID)
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
	items := make([]stac.Item, 0, len(keyOrder))
	for _, k := range keyOrder {
		items = append(items, itemsByID[k].item)
	}
	if req.Limit > 0 && len(items) > req.Limit {
		items = items[:req.Limit]
	}

	// Build the response
	fc := &stac.FeatureCollection{
		Type:     "FeatureCollection",
		Features: items,
		Context: &stac.SearchContext{
			Returned: len(items),
			Matched:  totalMatched,
		},
	}

	if req.Limit > 0 {
		fc.Context.Limit = req.Limit
	}

	return fc, nil
}

// itemKey generates a unique key for an item.
func (m *ResultMerger) itemKey(originID string, item stac.Item) string {
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
	incoming *stac.Item, incomingOrigin string) (stac.Item, error) {

	switch m.strategy {
	case ConflictMerge:
		return m.mergeItems(existing.item, *incoming, incomingOrigin), nil
	case ConflictRejectDuplicates:
		return stac.Item{}, fmt.Errorf("duplicate item ID %s from origins %s and %s",
			incoming.ID, existing.originID, incomingOrigin)
	default:
		// ConflictFirstWins, ConflictPriorityWins, ConflictNamespace.
		return existing.item, nil
	}
}

// mergeItems combines two items with the same ID.
func (m *ResultMerger) mergeItems(existing, incoming stac.Item, incomingOrigin string) stac.Item {
	merged := existing

	// Merge assets from both items
	if merged.Assets == nil {
		merged.Assets = make(map[string]stac.Asset)
	}
	for key, asset := range incoming.Assets {
		// Prefix asset keys with origin to avoid overwrites
		mergedKey := key
		if _, exists := merged.Assets[key]; exists {
			mergedKey = incomingOrigin + ":" + key
		}
		merged.Assets[mergedKey] = asset
	}

	// Keep the most recent properties (by datetime)
	if incoming.Properties.DateTime != nil && existing.Properties.DateTime != nil {
		if incoming.Properties.DateTime.After(*existing.Properties.DateTime) {
			merged.Properties = incoming.Properties
		}
	}

	// Merge links
	merged.Links = append(merged.Links, incoming.Links...)

	return merged
}

// transformItem adds origin metadata to an item.
func (m *ResultMerger) transformItem(item stac.Item, originID string) stac.Item {
	// Add origin metadata to item properties
	if item.Properties.Extra == nil {
		item.Properties.Extra = make(map[string]interface{})
	}
	item.Properties.Extra["stac_proxy:origin"] = originID

	// Namespace item ID if configured
	if m.strategy == ConflictNamespace {
		item.ID = originID + ":" + item.ID
	}

	return item
}

// DeduplicateCollections removes duplicate collections.
func (m *ResultMerger) DeduplicateCollections(collections []stac.Collection) []stac.Collection {
	seen := make(map[string]bool)
	var result []stac.Collection

	for _, coll := range collections {
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

// MergeCollections merges collection results from multiple origins.
func (m *ResultMerger) MergeCollections(results []*OriginCollectionsResult) []stac.Collection {
	var allCollections []stac.Collection

	for _, result := range results {
		if result.Error != nil {
			continue
		}

		for _, coll := range result.Collections {
			// Add origin metadata
			if coll.Properties == nil {
				coll.Properties = make(map[string]interface{})
			}
			coll.Properties["stac_proxy:origin"] = result.OriginID
			allCollections = append(allCollections, coll)
		}
	}

	return m.DeduplicateCollections(allCollections)
}

// itemWithOrigin tracks an item with its origin metadata.
type itemWithOrigin struct {
	item     stac.Item
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
