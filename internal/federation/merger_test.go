package federation

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/stac-proxy/internal/stac"
)

// Helper functions for creating test items

func testItem(id, collection string) *stac.Item {
	now := time.Now().UTC().Truncate(time.Second)
	return &stac.Item{
		Version:    "1.0.0",
		ID:         id,
		Collection: collection,
		Geometry:   json.RawMessage(`{"type":"Point","coordinates":[0,0]}`),
		Bbox:       []float64{-180, -90, 180, 90},
		Properties: map[string]any{
			"datetime": now.Format(time.RFC3339),
			"title":    "Test Item " + id,
		},
		Links: []*stac.Link{
			{Rel: "self", Href: "https://example.com/items/" + id},
		},
		Assets: map[string]*stac.Asset{
			"data": {
				Href:  "https://example.com/assets/" + id + "/data.tif",
				Type:  "image/tiff",
				Title: "Data",
				Roles: []string{"data"},
			},
		},
	}
}

func testItemWithAssets(id, collection string, assets map[string]*stac.Asset) *stac.Item {
	item := testItem(id, collection)
	item.Assets = assets
	return item
}

func testItemWithDateTime(id, collection string, dt time.Time) *stac.Item {
	item := testItem(id, collection)
	item.Properties["datetime"] = dt.Format(time.RFC3339)
	return item
}

func testCollection(id string) *stac.Collection {
	return &stac.Collection{
		Version:     "1.0.0",
		ID:          id,
		Title:       "Test Collection " + id,
		Description: "A test collection",
		License:     "MIT",
		Extent: &stac.Extent{
			Spatial:  &stac.SpatialExtent{Bbox: [][]float64{{-180, -90, 180, 90}}},
			Temporal: &stac.TemporalExtent{Interval: [][]*string{{strPtr("2020-01-01T00:00:00Z"), strPtr("2023-12-31T23:59:59Z")}}},
		},
		Links: []*stac.Link{
			{Rel: "self", Href: "https://example.com/collections/" + id},
		},
	}
}

func TestNewResultMerger(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		strategy ConflictStrategy
	}{
		{"FirstWins", ConflictFirstWins},
		{"PriorityWins", ConflictPriorityWins},
		{"Merge", ConflictMerge},
		{"Namespace", ConflictNamespace},
		{"RejectDuplicates", ConflictRejectDuplicates},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			merger := NewResultMerger(tt.strategy)
			require.NotNil(t, merger, "NewResultMerger returned nil")
			assert.Equal(t, tt.strategy, merger.strategy, "strategy")
			assert.NotNil(t, merger.deduplicator, "deduplicator is nil")
		})
	}
}

func TestMergeSearchResults_EmptyResults(t *testing.T) {
	t.Parallel()

	merger := NewResultMerger(ConflictFirstWins)
	req := &stac.SearchRequest{Limit: 10}

	fc, err := merger.MergeSearchResults([]*OriginSearchResult{}, req)
	require.NoError(t, err)

	assert.Equal(t, "FeatureCollection", fc.Type, "Type")
	assert.Empty(t, fc.Features, "Features length")
	require.NotNil(t, fc.Context, "Context is nil")
	assert.Equal(t, 0, stac.SearchContextOf(fc).Returned, "Context.Returned")
	assert.Equal(t, 0, stac.SearchContextOf(fc).Matched, "Context.Matched")
}

func TestMergeSearchResults_SingleOrigin(t *testing.T) {
	t.Parallel()

	merger := NewResultMerger(ConflictFirstWins)

	items := []*stac.Item{
		testItem("item-1", "collection-1"),
		testItem("item-2", "collection-1"),
		testItem("item-3", "collection-1"),
	}

	results := []*OriginSearchResult{
		{
			OriginID: "origin-1",
			Priority: 1,
			Items:    items,
			Context: &stac.SearchContext{
				Matched:  3,
				Returned: 3,
			},
		},
	}

	req := &stac.SearchRequest{Limit: 10}
	fc, err := merger.MergeSearchResults(results, req)
	require.NoError(t, err)

	assert.Len(t, fc.Features, 3, "Features length")
	assert.Equal(t, 3, stac.SearchContextOf(fc).Returned, "Context.Returned")
	assert.Equal(t, 3, stac.SearchContextOf(fc).Matched, "Context.Matched")

	// Check that origin metadata was added (as a stac_proxy:origin link)
	for i, item := range fc.Features {
		assert.Equalf(t, "origin-1", stac.ItemOriginID(item), "item %d: ItemOriginID", i)
	}
}

func TestMergeSearchResults_FirstWins(t *testing.T) {
	t.Parallel()

	merger := NewResultMerger(ConflictFirstWins)

	// Create duplicate items from different origins
	results := []*OriginSearchResult{
		{
			OriginID: "origin-1",
			Priority: 2, // Lower priority (should come second after sorting)
			Items: []*stac.Item{
				testItem("item-1", "collection-1"),
			},
		},
		{
			OriginID: "origin-2",
			Priority: 1, // Higher priority (should come first after sorting)
			Items: []*stac.Item{
				testItem("item-1", "collection-1"), // Same ID
				testItem("item-2", "collection-1"),
			},
		},
	}

	req := &stac.SearchRequest{Limit: 10}
	fc, err := merger.MergeSearchResults(results, req)
	require.NoError(t, err)

	assert.Len(t, fc.Features, 2, "Features length")

	// First origin to be processed (after sorting) is origin-2 (priority 1)
	// So item-1 should come from origin-2
	var item1Found bool
	for _, item := range fc.Features {
		if item.ID == "item-1" {
			item1Found = true
			assert.Equal(t, "origin-2", stac.ItemOriginID(item), "item-1 origin (first wins after priority sort)")
		}
	}
	assert.True(t, item1Found, "item-1 not found in results")
}

func TestMergeSearchResults_PriorityWins(t *testing.T) {
	t.Parallel()

	merger := NewResultMerger(ConflictPriorityWins)

	// Create duplicate items from different origins with different priorities
	results := []*OriginSearchResult{
		{
			OriginID: "origin-low",
			Priority: 5, // Lower priority
			Items: []*stac.Item{
				testItem("item-1", "collection-1"),
			},
		},
		{
			OriginID: "origin-high",
			Priority: 1, // Higher priority (lower number)
			Items: []*stac.Item{
				testItem("item-1", "collection-1"), // Same ID
			},
		},
		{
			OriginID: "origin-medium",
			Priority: 3,
			Items: []*stac.Item{
				testItem("item-1", "collection-1"), // Same ID
				testItem("item-2", "collection-1"),
			},
		},
	}

	req := &stac.SearchRequest{Limit: 10}
	fc, err := merger.MergeSearchResults(results, req)
	require.NoError(t, err)

	assert.Len(t, fc.Features, 2, "Features length")

	// item-1 should come from origin-high (priority 1)
	var item1Found bool
	for _, item := range fc.Features {
		if item.ID == "item-1" {
			item1Found = true
			assert.Equal(t, "origin-high", stac.ItemOriginID(item), "item-1 origin (highest priority wins)")
		}
	}
	assert.True(t, item1Found, "item-1 not found in results")
}

func TestMergeSearchResults_Merge(t *testing.T) {
	t.Parallel()

	merger := NewResultMerger(ConflictMerge)

	// Create items with different assets
	item1Assets1 := map[string]*stac.Asset{
		"thumbnail": {
			Href:  "https://origin1.com/thumb.jpg",
			Type:  "image/jpeg",
			Title: "Thumbnail",
			Roles: []string{"thumbnail"},
		},
	}
	item1Assets2 := map[string]*stac.Asset{
		"data": {
			Href:  "https://origin2.com/data.tif",
			Type:  "image/tiff",
			Title: "Data",
			Roles: []string{"data"},
		},
	}

	results := []*OriginSearchResult{
		{
			OriginID: "origin-1",
			Priority: 1,
			Items: []*stac.Item{
				testItemWithAssets("item-1", "collection-1", item1Assets1),
			},
		},
		{
			OriginID: "origin-2",
			Priority: 2,
			Items: []*stac.Item{
				testItemWithAssets("item-1", "collection-1", item1Assets2),
			},
		},
	}

	req := &stac.SearchRequest{Limit: 10}
	fc, err := merger.MergeSearchResults(results, req)
	require.NoError(t, err)

	require.Len(t, fc.Features, 1, "Features length")

	item := fc.Features[0]

	// Should have both assets
	assert.Len(t, item.Assets, 2, "Assets length")
	assert.Contains(t, item.Assets, "thumbnail", "thumbnail asset not found")
	assert.Contains(t, item.Assets, "data", "data asset not found")
}

func TestMergeSearchResults_MergeAssetCollision(t *testing.T) {
	t.Parallel()

	merger := NewResultMerger(ConflictMerge)

	// Create items with same asset key
	item1Assets1 := map[string]*stac.Asset{
		"data": {
			Href:  "https://origin1.com/data1.tif",
			Type:  "image/tiff",
			Title: "Data from Origin 1",
		},
	}
	item1Assets2 := map[string]*stac.Asset{
		"data": {
			Href:  "https://origin2.com/data2.tif",
			Type:  "image/tiff",
			Title: "Data from Origin 2",
		},
	}

	results := []*OriginSearchResult{
		{
			OriginID: "origin-1",
			Priority: 1,
			Items: []*stac.Item{
				testItemWithAssets("item-1", "collection-1", item1Assets1),
			},
		},
		{
			OriginID: "origin-2",
			Priority: 2,
			Items: []*stac.Item{
				testItemWithAssets("item-1", "collection-1", item1Assets2),
			},
		},
	}

	req := &stac.SearchRequest{Limit: 10}
	fc, err := merger.MergeSearchResults(results, req)
	require.NoError(t, err)

	require.Len(t, fc.Features, 1, "Features length")

	item := fc.Features[0]

	// Should have both assets - one with original key, one prefixed
	assert.Len(t, item.Assets, 2, "Assets length")
	require.Contains(t, item.Assets, "data", "data asset not found")
	require.Contains(t, item.Assets, "origin-2:data", "origin-2:data asset not found (prefixed asset missing)")

	// Verify the correct asset is in each slot
	assert.Equal(t, "https://origin1.com/data1.tif", item.Assets["data"].Href, "data asset href")
	assert.Equal(t, "https://origin2.com/data2.tif", item.Assets["origin-2:data"].Href, "origin-2:data asset href")
}

func TestMergeSearchResults_MergeDateTimeComparison(t *testing.T) {
	t.Parallel()

	merger := NewResultMerger(ConflictMerge)

	now := time.Now().UTC().Truncate(time.Second)
	older := now.Add(-24 * time.Hour)
	newer := now.Add(24 * time.Hour)

	results := []*OriginSearchResult{
		{
			OriginID: "origin-1",
			Priority: 1,
			Items: []*stac.Item{
				testItemWithDateTime("item-1", "collection-1", older),
			},
		},
		{
			OriginID: "origin-2",
			Priority: 2,
			Items: []*stac.Item{
				testItemWithDateTime("item-1", "collection-1", newer),
			},
		},
	}

	req := &stac.SearchRequest{Limit: 10}
	fc, err := merger.MergeSearchResults(results, req)
	require.NoError(t, err)

	require.Len(t, fc.Features, 1, "Features length")

	item := fc.Features[0]

	// Should use the newer datetime
	got, ok := stac.ItemDatetime(item)
	require.True(t, ok, "DateTime missing")
	assert.Truef(t, got.Equal(newer), "DateTime = %v, want %v (should use newer datetime)", got, newer)
}

func TestMergeSearchResults_Namespace(t *testing.T) {
	t.Parallel()

	merger := NewResultMerger(ConflictNamespace)

	// Create duplicate items from different origins
	results := []*OriginSearchResult{
		{
			OriginID: "origin-1",
			Priority: 1,
			Items: []*stac.Item{
				testItem("item-1", "collection-1"),
			},
		},
		{
			OriginID: "origin-2",
			Priority: 2,
			Items: []*stac.Item{
				testItem("item-1", "collection-1"), // Same ID
				testItem("item-2", "collection-1"),
			},
		},
	}

	req := &stac.SearchRequest{Limit: 10}
	fc, err := merger.MergeSearchResults(results, req)
	require.NoError(t, err)

	// With namespace strategy, both items should be present with prefixed IDs
	assert.Len(t, fc.Features, 3, "Features length (no deduplication with namespace)")

	// Check that IDs are namespaced
	foundOrigin1Item1 := false
	foundOrigin2Item1 := false
	foundOrigin2Item2 := false

	for _, item := range fc.Features {
		switch item.ID {
		case "origin-1:item-1":
			foundOrigin1Item1 = true
		case "origin-2:item-1":
			foundOrigin2Item1 = true
		case "origin-2:item-2":
			foundOrigin2Item2 = true
		default:
			t.Errorf("unexpected item ID: %s", item.ID)
		}
	}

	assert.True(t, foundOrigin1Item1, "origin-1:item-1 not found")
	assert.True(t, foundOrigin2Item1, "origin-2:item-1 not found")
	assert.True(t, foundOrigin2Item2, "origin-2:item-2 not found")
}

func TestMergeSearchResults_RejectDuplicates(t *testing.T) {
	t.Parallel()

	merger := NewResultMerger(ConflictRejectDuplicates)

	// Create duplicate items from different origins
	results := []*OriginSearchResult{
		{
			OriginID: "origin-1",
			Priority: 1,
			Items: []*stac.Item{
				testItem("item-1", "collection-1"),
			},
		},
		{
			OriginID: "origin-2",
			Priority: 2,
			Items: []*stac.Item{
				testItem("item-1", "collection-1"), // Same ID - should cause error
			},
		},
	}

	req := &stac.SearchRequest{Limit: 10}
	_, err := merger.MergeSearchResults(results, req)

	require.Error(t, err, "expected error for duplicate items")
	assert.ErrorContains(t, err, "duplicate item ID item-1", "error should mention duplicate item ID")
}

func TestMergeSearchResults_LimitZero(t *testing.T) {
	t.Parallel()

	merger := NewResultMerger(ConflictFirstWins)

	results := []*OriginSearchResult{
		{
			OriginID: "origin-1",
			Priority: 1,
			Items: []*stac.Item{
				testItem("item-1", "collection-1"),
				testItem("item-2", "collection-1"),
				testItem("item-3", "collection-1"),
			},
		},
	}

	req := &stac.SearchRequest{Limit: 0} // No limit
	fc, err := merger.MergeSearchResults(results, req)
	require.NoError(t, err)

	// Should return all items when limit is 0
	assert.Len(t, fc.Features, 3, "Features length (no limit applied)")
}

func TestMergeSearchResults_LimitPartial(t *testing.T) {
	t.Parallel()

	merger := NewResultMerger(ConflictFirstWins)

	results := []*OriginSearchResult{
		{
			OriginID: "origin-1",
			Priority: 1,
			Items: []*stac.Item{
				testItem("item-1", "collection-1"),
				testItem("item-2", "collection-1"),
				testItem("item-3", "collection-1"),
				testItem("item-4", "collection-1"),
				testItem("item-5", "collection-1"),
			},
		},
	}

	req := &stac.SearchRequest{Limit: 3}
	fc, err := merger.MergeSearchResults(results, req)
	require.NoError(t, err)

	assert.Len(t, fc.Features, 3, "Features length")
	assert.Equal(t, 3, stac.SearchContextOf(fc).Returned, "Context.Returned")
	assert.Equal(t, 3, stac.SearchContextOf(fc).Limit, "Context.Limit")
}

func TestMergeSearchResults_LimitExact(t *testing.T) {
	t.Parallel()

	merger := NewResultMerger(ConflictFirstWins)

	results := []*OriginSearchResult{
		{
			OriginID: "origin-1",
			Priority: 1,
			Items: []*stac.Item{
				testItem("item-1", "collection-1"),
				testItem("item-2", "collection-1"),
				testItem("item-3", "collection-1"),
			},
		},
	}

	req := &stac.SearchRequest{Limit: 3}
	fc, err := merger.MergeSearchResults(results, req)
	require.NoError(t, err)

	assert.Len(t, fc.Features, 3, "Features length")
}

func TestMergeSearchResults_LimitExceeding(t *testing.T) {
	t.Parallel()

	merger := NewResultMerger(ConflictFirstWins)

	results := []*OriginSearchResult{
		{
			OriginID: "origin-1",
			Priority: 1,
			Items: []*stac.Item{
				testItem("item-1", "collection-1"),
				testItem("item-2", "collection-1"),
			},
		},
	}

	req := &stac.SearchRequest{Limit: 10} // Limit exceeds available items
	fc, err := merger.MergeSearchResults(results, req)
	require.NoError(t, err)

	assert.Len(t, fc.Features, 2, "Features length (all available items)")
}

func TestMergeSearchResults_PriorityOrdering(t *testing.T) {
	t.Parallel()

	merger := NewResultMerger(ConflictPriorityWins)

	results := []*OriginSearchResult{
		{
			OriginID: "origin-low",
			Priority: 10,
			Items: []*stac.Item{
				testItem("item-low", "collection-1"),
			},
		},
		{
			OriginID: "origin-high",
			Priority: 1,
			Items: []*stac.Item{
				testItem("item-high", "collection-1"),
			},
		},
		{
			OriginID: "origin-medium",
			Priority: 5,
			Items: []*stac.Item{
				testItem("item-medium", "collection-1"),
			},
		},
	}

	req := &stac.SearchRequest{Limit: 10}
	fc, err := merger.MergeSearchResults(results, req)
	require.NoError(t, err)

	assert.Len(t, fc.Features, 3, "Features length")

	// Results should be processed in priority order (1, 5, 10)
	// But the output order depends on when items were added
	// Just verify all items are present
	foundItems := make(map[string]bool)
	for _, item := range fc.Features {
		foundItems[item.ID] = true
	}

	assert.True(t, foundItems["item-high"] && foundItems["item-medium"] && foundItems["item-low"], "not all items found in results")
}

func TestMergeSearchResults_OriginMetadata(t *testing.T) {
	t.Parallel()

	merger := NewResultMerger(ConflictFirstWins)

	results := []*OriginSearchResult{
		{
			OriginID: "test-origin-id",
			Priority: 1,
			Items: []*stac.Item{
				testItem("item-1", "collection-1"),
			},
		},
	}

	req := &stac.SearchRequest{Limit: 10}
	fc, err := merger.MergeSearchResults(results, req)
	require.NoError(t, err)

	require.Len(t, fc.Features, 1, "Features length")

	item := fc.Features[0]
	assert.Equal(t, "test-origin-id", stac.ItemOriginID(item), "ItemOriginID")
}

func TestMergeSearchResults_FailedOrigins(t *testing.T) {
	t.Parallel()

	merger := NewResultMerger(ConflictFirstWins)

	results := []*OriginSearchResult{
		{
			OriginID: "origin-failed",
			Priority: 1,
			Error:    fmt.Errorf("connection timeout"),
		},
		{
			OriginID: "origin-success",
			Priority: 2,
			Items: []*stac.Item{
				testItem("item-1", "collection-1"),
			},
			Context: &stac.SearchContext{
				Matched:  1,
				Returned: 1,
			},
		},
	}

	req := &stac.SearchRequest{Limit: 10}
	fc, err := merger.MergeSearchResults(results, req)
	require.NoError(t, err)

	// Should only have items from successful origin
	assert.Len(t, fc.Features, 1, "Features length")
	assert.Equal(t, 1, stac.SearchContextOf(fc).Matched, "Context.Matched")
}

func TestMergeSearchResults_DuplicateAcrossCollections(t *testing.T) {
	t.Parallel()

	merger := NewResultMerger(ConflictFirstWins)

	// Same item ID but different collections - should NOT be deduplicated
	results := []*OriginSearchResult{
		{
			OriginID: "origin-1",
			Priority: 1,
			Items: []*stac.Item{
				testItem("item-1", "collection-A"),
			},
		},
		{
			OriginID: "origin-2",
			Priority: 2,
			Items: []*stac.Item{
				testItem("item-1", "collection-B"),
			},
		},
	}

	req := &stac.SearchRequest{Limit: 10}
	fc, err := merger.MergeSearchResults(results, req)
	require.NoError(t, err)

	// Both items should be present since they're from different collections
	assert.Len(t, fc.Features, 2, "Features length (same ID but different collections)")
}

func TestMergeSearchResults_ContextAggregation(t *testing.T) {
	t.Parallel()

	merger := NewResultMerger(ConflictFirstWins)

	results := []*OriginSearchResult{
		{
			OriginID: "origin-1",
			Priority: 1,
			Items: []*stac.Item{
				testItem("item-1", "collection-1"),
			},
			Context: &stac.SearchContext{
				Matched:  100,
				Returned: 1,
			},
		},
		{
			OriginID: "origin-2",
			Priority: 2,
			Items: []*stac.Item{
				testItem("item-2", "collection-1"),
			},
			Context: &stac.SearchContext{
				Matched:  50,
				Returned: 1,
			},
		},
	}

	req := &stac.SearchRequest{Limit: 10}
	fc, err := merger.MergeSearchResults(results, req)
	require.NoError(t, err)

	// Matched should be sum of all origins
	assert.Equal(t, 150, stac.SearchContextOf(fc).Matched, "Context.Matched (sum of all origins)")
	// Returned should be actual count
	assert.Equal(t, 2, stac.SearchContextOf(fc).Returned, "Context.Returned")
}

func TestDeduplicateCollections(t *testing.T) {
	t.Parallel()

	merger := NewResultMerger(ConflictFirstWins)

	collections := []*stac.Collection{
		testCollection("collection-1"),
		testCollection("collection-2"),
		testCollection("collection-1"), // Duplicate
		testCollection("collection-3"),
		testCollection("collection-2"), // Duplicate
	}

	result := merger.DeduplicateCollections(collections)

	assert.Len(t, result, 3, "result length")

	// Check for expected collections
	foundCollections := make(map[string]bool)
	for _, coll := range result {
		foundCollections[coll.ID] = true
	}

	expectedCollections := []string{"collection-1", "collection-2", "collection-3"}
	for _, expected := range expectedCollections {
		assert.Truef(t, foundCollections[expected], "collection %s not found in result", expected)
	}

	// Verify sorting by ID
	for i := 0; i < len(result)-1; i++ {
		assert.LessOrEqualf(t, result[i].ID, result[i+1].ID, "collections not sorted: %s > %s", result[i].ID, result[i+1].ID)
	}
}

func TestDeduplicateCollections_Empty(t *testing.T) {
	t.Parallel()

	merger := NewResultMerger(ConflictFirstWins)

	result := merger.DeduplicateCollections([]*stac.Collection{})

	assert.Empty(t, result, "result length")
}

func TestDeduplicateCollections_AllUnique(t *testing.T) {
	t.Parallel()

	merger := NewResultMerger(ConflictFirstWins)

	collections := []*stac.Collection{
		testCollection("collection-1"),
		testCollection("collection-2"),
		testCollection("collection-3"),
	}

	result := merger.DeduplicateCollections(collections)

	assert.Len(t, result, 3, "result length")
}

func TestMergeCollections(t *testing.T) {
	t.Parallel()

	merger := NewResultMerger(ConflictFirstWins)

	results := []*OriginCollectionsResult{
		{
			OriginID: "origin-1",
			Collections: []*stac.Collection{
				testCollection("collection-1"),
				testCollection("collection-2"),
			},
		},
		{
			OriginID: "origin-2",
			Collections: []*stac.Collection{
				testCollection("collection-2"), // Duplicate
				testCollection("collection-3"),
			},
		},
	}

	merged := merger.MergeCollections(results)

	assert.Len(t, merged, 3, "merged length (deduplicated)")

	// Check that origin metadata was added (as a stac_proxy:origin link)
	for _, coll := range merged {
		origin := stac.CollectionOriginID(coll)
		if !assert.NotEmptyf(t, origin, "collection %s: stac_proxy:origin link missing", coll.ID) {
			continue
		}
		assert.Containsf(t, []string{"origin-1", "origin-2"}, origin, "collection %s: origin = %q", coll.ID, origin)
	}
}

func TestMergeCollections_FailedOrigins(t *testing.T) {
	t.Parallel()

	merger := NewResultMerger(ConflictFirstWins)

	results := []*OriginCollectionsResult{
		{
			OriginID: "origin-failed",
			Error:    fmt.Errorf("connection error"),
		},
		{
			OriginID: "origin-success",
			Collections: []*stac.Collection{
				testCollection("collection-1"),
			},
		},
	}

	merged := merger.MergeCollections(results)

	// Should only have collections from successful origin
	assert.Len(t, merged, 1, "merged length")
}

func TestMergeCollections_Empty(t *testing.T) {
	t.Parallel()

	merger := NewResultMerger(ConflictFirstWins)

	merged := merger.MergeCollections([]*OriginCollectionsResult{})

	assert.Empty(t, merged, "merged length")
}

func TestCalculateMergeStats(t *testing.T) {
	t.Parallel()

	results := []*OriginSearchResult{
		{
			OriginID: "origin-1",
			Priority: 1,
			Items: []*stac.Item{
				testItem("item-1", "collection-1"),
				testItem("item-2", "collection-1"),
			},
		},
		{
			OriginID: "origin-2",
			Priority: 2,
			Items: []*stac.Item{
				testItem("item-1", "collection-1"), // Duplicate
				testItem("item-3", "collection-1"),
			},
		},
		{
			OriginID: "origin-3",
			Priority: 3,
			Error:    fmt.Errorf("failed"),
		},
	}

	mergedCount := 3 // item-1, item-2, item-3 (one duplicate removed)

	stats := CalculateMergeStats(results, mergedCount)

	assert.Equal(t, 3, stats.UniqueItems, "UniqueItems")
	assert.Equal(t, 4, stats.TotalItems, "TotalItems")
	assert.Equal(t, 1, stats.DuplicatesFound, "DuplicatesFound")
	assert.Equal(t, 2, stats.OriginsUsed, "OriginsUsed")
	assert.Equal(t, 1, stats.OriginsFailed, "OriginsFailed")
}

func TestCalculateMergeStats_NoDuplicates(t *testing.T) {
	t.Parallel()

	results := []*OriginSearchResult{
		{
			OriginID: "origin-1",
			Items: []*stac.Item{
				testItem("item-1", "collection-1"),
			},
		},
		{
			OriginID: "origin-2",
			Items: []*stac.Item{
				testItem("item-2", "collection-1"),
			},
		},
	}

	stats := CalculateMergeStats(results, 2)

	assert.Equal(t, 0, stats.DuplicatesFound, "DuplicatesFound")
}

func TestItemToJSON(t *testing.T) {
	t.Parallel()

	item := testItem("test-item", "test-collection")

	jsonBytes, err := ItemToJSON(item)
	require.NoError(t, err)

	assert.NotEmpty(t, jsonBytes, "JSON bytes is empty")

	// Verify it's valid JSON
	var parsed map[string]interface{}
	assert.NoError(t, json.Unmarshal(jsonBytes, &parsed), "failed to parse JSON")
}

func TestCollectionToJSON(t *testing.T) {
	t.Parallel()

	collection := testCollection("test-collection")

	jsonBytes, err := CollectionToJSON(collection)
	require.NoError(t, err)

	assert.NotEmpty(t, jsonBytes, "JSON bytes is empty")

	// Verify it's valid JSON
	var parsed map[string]interface{}
	assert.NoError(t, json.Unmarshal(jsonBytes, &parsed), "failed to parse JSON")
}

func TestItemKey_DefaultStrategy(t *testing.T) {
	t.Parallel()

	merger := NewResultMerger(ConflictFirstWins)
	item := testItem("item-1", "collection-1")

	key := merger.itemKey("origin-1", item)

	assert.Equal(t, "collection-1:item-1", key, "itemKey")
}

func TestItemKey_NamespaceStrategy(t *testing.T) {
	t.Parallel()

	merger := NewResultMerger(ConflictNamespace)
	item := testItem("item-1", "collection-1")

	key := merger.itemKey("origin-1", item)

	assert.Equal(t, "origin-1:item-1", key, "itemKey")
}

func TestMergeItems_LinksAreAppended(t *testing.T) {
	t.Parallel()

	merger := NewResultMerger(ConflictMerge)

	existing := testItem("item-1", "collection-1")
	existing.Links = []*stac.Link{
		{Rel: "self", Href: "https://origin1.com/item-1"},
	}

	incoming := testItem("item-1", "collection-1")
	incoming.Links = []*stac.Link{
		{Rel: "alternate", Href: "https://origin2.com/item-1"},
	}

	merged := merger.mergeItems(existing, incoming, "origin-2")

	assert.Len(t, merged.Links, 2, "Links length")
}

func TestMergeSearchResults_MultipleOriginsSameItems(t *testing.T) {
	t.Parallel()

	merger := NewResultMerger(ConflictMerge)

	// Three origins with overlapping items
	results := []*OriginSearchResult{
		{
			OriginID: "origin-1",
			Priority: 1,
			Items: []*stac.Item{
				testItemWithAssets("item-1", "collection-1", map[string]*stac.Asset{
					"asset-a": {Href: "https://origin1.com/a", Title: "Asset A"},
				}),
			},
		},
		{
			OriginID: "origin-2",
			Priority: 2,
			Items: []*stac.Item{
				testItemWithAssets("item-1", "collection-1", map[string]*stac.Asset{
					"asset-b": {Href: "https://origin2.com/b", Title: "Asset B"},
				}),
			},
		},
		{
			OriginID: "origin-3",
			Priority: 3,
			Items: []*stac.Item{
				testItemWithAssets("item-1", "collection-1", map[string]*stac.Asset{
					"asset-c": {Href: "https://origin3.com/c", Title: "Asset C"},
				}),
			},
		},
	}

	req := &stac.SearchRequest{Limit: 10}
	fc, err := merger.MergeSearchResults(results, req)
	require.NoError(t, err)

	require.Len(t, fc.Features, 1, "Features length")

	// All three assets should be merged
	item := fc.Features[0]
	assert.Len(t, item.Assets, 3, "Assets length")

	expectedAssets := []string{"asset-a", "asset-b", "asset-c"}
	for _, assetKey := range expectedAssets {
		assert.Containsf(t, item.Assets, assetKey, "asset %s not found", assetKey)
	}
}

func TestTransformItem_AddsOriginMetadata(t *testing.T) {
	t.Parallel()

	merger := NewResultMerger(ConflictFirstWins)
	item := testItem("item-1", "collection-1")

	transformed := merger.transformItem(item, "test-origin", "https://test.example/v1")

	assert.Equal(t, "test-origin", stac.ItemOriginID(transformed), "ItemOriginID")
	// The link's href carries the upstream URL.
	var hrefSeen string
	for _, l := range transformed.Links {
		if l != nil && l.Rel == stac.OriginLinkRel {
			hrefSeen = l.Href
		}
	}
	assert.Equal(t, "https://test.example/v1", hrefSeen, "origin link href")
}

func TestTransformItem_NamespaceStrategy(t *testing.T) {
	t.Parallel()

	merger := NewResultMerger(ConflictNamespace)
	item := testItem("item-1", "collection-1")
	originalID := item.ID

	transformed := merger.transformItem(item, "test-origin", "https://test.example/v1")

	expectedID := "test-origin:" + originalID
	assert.Equal(t, expectedID, transformed.ID, "ID")
}

func TestMergeSearchResults_NilContext(t *testing.T) {
	t.Parallel()

	merger := NewResultMerger(ConflictFirstWins)

	results := []*OriginSearchResult{
		{
			OriginID: "origin-1",
			Priority: 1,
			Items: []*stac.Item{
				testItem("item-1", "collection-1"),
			},
			Context: nil, // No context
		},
	}

	req := &stac.SearchRequest{Limit: 10}
	fc, err := merger.MergeSearchResults(results, req)
	require.NoError(t, err)

	// Should handle nil context gracefully
	assert.Equal(t, 0, stac.SearchContextOf(fc).Matched, "Context.Matched (nil context)")
	assert.Equal(t, 1, stac.SearchContextOf(fc).Returned, "Context.Returned")
}

func TestMergeItems_NilDateTime(t *testing.T) {
	t.Parallel()

	merger := NewResultMerger(ConflictMerge)

	existing := testItem("item-1", "collection-1")
	delete(existing.Properties, "datetime")

	incoming := testItem("item-1", "collection-1")
	delete(incoming.Properties, "datetime")

	// Should not panic with absent datetimes
	merged := merger.mergeItems(existing, incoming, "origin-2")

	assert.Equal(t, "item-1", merged.ID, "merged item ID")
}

func TestMergeItems_OneNilDateTime(t *testing.T) {
	t.Parallel()

	merger := NewResultMerger(ConflictMerge)

	now := time.Now().UTC().Truncate(time.Second)

	existing := testItem("item-1", "collection-1")
	existing.Properties["datetime"] = now.Format(time.RFC3339)

	incoming := testItem("item-1", "collection-1")
	delete(incoming.Properties, "datetime")

	merged := merger.mergeItems(existing, incoming, "origin-2")

	// Should keep existing properties when incoming datetime is absent.
	got, ok := stac.ItemDatetime(merged)
	require.True(t, ok, "DateTime missing, should keep existing")
	assert.Truef(t, got.Equal(now), "DateTime = %v, want %v", got, now)
}

func TestMergeSearchResults_DeduplicatorReset(t *testing.T) {
	t.Parallel()

	merger := NewResultMerger(ConflictFirstWins)

	results1 := []*OriginSearchResult{
		{
			OriginID: "origin-1",
			Priority: 1,
			Items: []*stac.Item{
				testItem("item-1", "collection-1"),
			},
		},
	}

	req := &stac.SearchRequest{Limit: 10}

	// First merge
	fc1, err := merger.MergeSearchResults(results1, req)
	require.NoError(t, err, "first merge error")
	assert.Len(t, fc1.Features, 1, "first merge: Features length")

	// Second merge with same item - deduplicator should be reset
	results2 := []*OriginSearchResult{
		{
			OriginID: "origin-2",
			Priority: 1,
			Items: []*stac.Item{
				testItem("item-1", "collection-1"),
			},
		},
	}

	fc2, err := merger.MergeSearchResults(results2, req)
	require.NoError(t, err, "second merge error")
	assert.Len(t, fc2.Features, 1, "second merge: Features length (deduplicator should be reset)")
}

func TestMergeSearchResults_NilAssets(t *testing.T) {
	t.Parallel()

	merger := NewResultMerger(ConflictMerge)

	item1 := testItem("item-1", "collection-1")
	item1.Assets = nil

	item2 := testItem("item-1", "collection-1")
	item2.Assets = map[string]*stac.Asset{
		"data": {Href: "https://example.com/data.tif", Type: "image/tiff"},
	}

	results := []*OriginSearchResult{
		{
			OriginID: "origin-1",
			Priority: 1,
			Items:    []*stac.Item{item1},
		},
		{
			OriginID: "origin-2",
			Priority: 2,
			Items:    []*stac.Item{item2},
		},
	}

	req := &stac.SearchRequest{Limit: 10}
	fc, err := merger.MergeSearchResults(results, req)
	require.NoError(t, err)

	require.Len(t, fc.Features, 1, "Features length")

	// Should have the asset from the second item
	assert.Len(t, fc.Features[0].Assets, 1, "Assets length")
}

// TestMerger_RejectDuplicates_ErrorsOnConflict verifies that the
// ConflictRejectDuplicates strategy errors out (rather than silently
// picking one) when two origins return items with the same key
// (HIGH H-config-2). Previously the validation layer accepted
// "reject_duplicates" as a string but main.go's switch did not map
// it, so callers asking for the strict mode silently got
// PriorityWins instead.
func TestMerger_RejectDuplicates_ErrorsOnConflict(t *testing.T) {
	t.Parallel()

	merger := NewResultMerger(ConflictRejectDuplicates)

	results := []*OriginSearchResult{
		{
			OriginID: "origin-a",
			Priority: 1,
			Items:    []*stac.Item{testItem("dup-1", "collection-1")},
		},
		{
			OriginID: "origin-b",
			Priority: 2,
			Items:    []*stac.Item{testItem("dup-1", "collection-1")},
		},
	}

	_, err := merger.MergeSearchResults(results, &stac.SearchRequest{Limit: 10})
	require.Error(t, err, "expected error from RejectDuplicates strategy on duplicate item")
	assert.ErrorContains(t, err, "dup-1", "error should mention duplicate item ID")
}

func BenchmarkMergeSearchResults_FirstWins(b *testing.B) {
	merger := NewResultMerger(ConflictFirstWins)

	// Create test data
	items := make([]*stac.Item, 100)
	for i := 0; i < 100; i++ {
		items[i] = testItem(fmt.Sprintf("item-%d", i), "collection-1")
	}

	results := []*OriginSearchResult{
		{
			OriginID: "origin-1",
			Priority: 1,
			Items:    items[:50],
		},
		{
			OriginID: "origin-2",
			Priority: 2,
			Items:    items[25:75], // 25 duplicates
		},
		{
			OriginID: "origin-3",
			Priority: 3,
			Items:    items[50:100],
		},
	}

	req := &stac.SearchRequest{Limit: 100}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := merger.MergeSearchResults(results, req)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMergeSearchResults_Merge(b *testing.B) {
	merger := NewResultMerger(ConflictMerge)

	// Create test data with assets
	items1 := make([]*stac.Item, 50)
	items2 := make([]*stac.Item, 50)
	for i := 0; i < 50; i++ {
		items1[i] = testItemWithAssets(fmt.Sprintf("item-%d", i), "collection-1",
			map[string]*stac.Asset{
				"asset-1": {Href: "https://origin1.com/asset1", Type: "image/tiff"},
			})
		items2[i] = testItemWithAssets(fmt.Sprintf("item-%d", i), "collection-1",
			map[string]*stac.Asset{
				"asset-2": {Href: "https://origin2.com/asset2", Type: "image/tiff"},
			})
	}

	results := []*OriginSearchResult{
		{
			OriginID: "origin-1",
			Priority: 1,
			Items:    items1,
		},
		{
			OriginID: "origin-2",
			Priority: 2,
			Items:    items2,
		},
	}

	req := &stac.SearchRequest{Limit: 100}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := merger.MergeSearchResults(results, req)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDeduplicateCollections(b *testing.B) {
	merger := NewResultMerger(ConflictFirstWins)

	collections := make([]*stac.Collection, 100)
	for i := 0; i < 100; i++ {
		// Create some duplicates
		collections[i] = testCollection(fmt.Sprintf("collection-%d", i%20))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = merger.DeduplicateCollections(collections)
	}
}
