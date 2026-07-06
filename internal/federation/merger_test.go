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
	merger := NewResultMerger()
	require.NotNil(t, merger, "NewResultMerger returned nil")
}

func TestMergeSearchResults_EmptyResults(t *testing.T) {
	t.Parallel()

	merger := NewResultMerger()
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

	merger := NewResultMerger()

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

// TestMergeSearchResults_FirstWinsByPriority verifies the
// (priority asc, originID asc) pre-sort: on a duplicate, the lower
// priority number wins.
func TestMergeSearchResults_FirstWinsByPriority(t *testing.T) {
	t.Parallel()

	merger := NewResultMerger()

	results := []*OriginSearchResult{
		{
			OriginID: "origin-1",
			Priority: 2, // Lower priority (processed second)
			Items: []*stac.Item{
				testItem("item-1", "collection-1"),
			},
		},
		{
			OriginID: "origin-2",
			Priority: 1, // Higher priority (processed first)
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

	var item1Found bool
	for _, item := range fc.Features {
		if item.ID == "item-1" {
			item1Found = true
			assert.Equal(t, "origin-2", stac.ItemOriginID(item), "item-1 origin (priority 1 wins)")
		}
	}
	assert.True(t, item1Found, "item-1 not found in results")
}

func TestMergeSearchResults_Limit(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		available int
		limit     int
		want      int
		checkCtx  bool
	}{
		{"zero limit returns all", 3, 0, 3, false},
		{"partial limit truncates", 5, 3, 3, true},
		{"exact limit", 3, 3, 3, false},
		{"limit exceeds available", 2, 10, 2, false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			merger := NewResultMerger()
			items := make([]*stac.Item, tc.available)
			for i := 0; i < tc.available; i++ {
				items[i] = testItem(fmt.Sprintf("item-%d", i+1), "collection-1")
			}
			results := []*OriginSearchResult{{OriginID: "origin-1", Priority: 1, Items: items}}
			fc, err := merger.MergeSearchResults(results, &stac.SearchRequest{Limit: tc.limit})
			require.NoError(t, err)
			assert.Len(t, fc.Features, tc.want)
			if tc.checkCtx {
				assert.Equal(t, tc.want, stac.SearchContextOf(fc).Returned)
				assert.Equal(t, tc.want, stac.SearchContextOf(fc).Limit)
			}
		})
	}
}

func TestMergeSearchResults_PriorityOrdering(t *testing.T) {
	t.Parallel()

	merger := NewResultMerger()

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

	foundItems := make(map[string]bool)
	for _, item := range fc.Features {
		foundItems[item.ID] = true
	}

	assert.True(t, foundItems["item-high"] && foundItems["item-medium"] && foundItems["item-low"], "not all items found in results")
}

func TestMergeSearchResults_OriginMetadata(t *testing.T) {
	t.Parallel()

	merger := NewResultMerger()

	results := []*OriginSearchResult{
		{
			OriginID:  "test-origin-id",
			OriginURL: "https://test.example/v1",
			Priority:  1,
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

	var hrefSeen string
	for _, l := range item.Links {
		if l != nil && l.Rel == stac.OriginLinkRel {
			hrefSeen = l.Href
		}
	}
	assert.Equal(t, "https://test.example/v1", hrefSeen, "origin link href")
}

func TestMergeSearchResults_FailedOrigins(t *testing.T) {
	t.Parallel()

	merger := NewResultMerger()

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

	assert.Len(t, fc.Features, 1, "Features length")
	assert.Equal(t, 1, stac.SearchContextOf(fc).Matched, "Context.Matched")
}

// TestMergeSearchResults_DuplicateAcrossCollections verifies that the
// dedup key is collection+ID, so items sharing an ID under different
// collections are both kept.
func TestMergeSearchResults_DuplicateAcrossCollections(t *testing.T) {
	t.Parallel()

	merger := NewResultMerger()

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

	assert.Len(t, fc.Features, 2, "Features length (same ID but different collections)")
}

func TestMergeSearchResults_ContextAggregation(t *testing.T) {
	t.Parallel()

	merger := NewResultMerger()

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

	assert.Equal(t, 150, stac.SearchContextOf(fc).Matched, "Context.Matched (sum of all origins)")
	assert.Equal(t, 2, stac.SearchContextOf(fc).Returned, "Context.Returned")
}

func TestDeduplicateCollections(t *testing.T) {
	t.Parallel()

	merger := NewResultMerger()

	collections := []*stac.Collection{
		testCollection("collection-1"),
		testCollection("collection-2"),
		testCollection("collection-1"), // Duplicate
		testCollection("collection-3"),
		testCollection("collection-2"), // Duplicate
	}

	result := merger.DeduplicateCollections(collections)

	assert.Len(t, result, 3, "result length")

	foundCollections := make(map[string]bool)
	for _, coll := range result {
		foundCollections[coll.ID] = true
	}

	expectedCollections := []string{"collection-1", "collection-2", "collection-3"}
	for _, expected := range expectedCollections {
		assert.Truef(t, foundCollections[expected], "collection %s not found in result", expected)
	}

	for i := 0; i < len(result)-1; i++ {
		assert.LessOrEqualf(t, result[i].ID, result[i+1].ID, "collections not sorted: %s > %s", result[i].ID, result[i+1].ID)
	}
}

func TestMergeCollections(t *testing.T) {
	t.Parallel()

	merger := NewResultMerger()

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

	merger := NewResultMerger()

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

	assert.Len(t, merged, 1, "merged length")
}

func TestMergeCollections_Empty(t *testing.T) {
	t.Parallel()

	merger := NewResultMerger()

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

func TestMergeSearchResults_NilContext(t *testing.T) {
	t.Parallel()

	merger := NewResultMerger()

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

	assert.Equal(t, 0, stac.SearchContextOf(fc).Matched, "Context.Matched (nil context)")
	assert.Equal(t, 1, stac.SearchContextOf(fc).Returned, "Context.Returned")
}

// TestMergeSearchResults_FreshDedupPerCall ensures that two
// independent merges do not share dedup state — every call starts with
// a clean dedup map.
func TestMergeSearchResults_FreshDedupPerCall(t *testing.T) {
	t.Parallel()

	merger := NewResultMerger()

	makeResults := func(originID string) []*OriginSearchResult {
		return []*OriginSearchResult{{
			OriginID: originID,
			Priority: 1,
			Items:    []*stac.Item{testItem("item-1", "collection-1")},
		}}
	}

	req := &stac.SearchRequest{Limit: 10}

	fc1, err := merger.MergeSearchResults(makeResults("origin-1"), req)
	require.NoError(t, err, "first merge error")
	assert.Len(t, fc1.Features, 1, "first merge")

	fc2, err := merger.MergeSearchResults(makeResults("origin-2"), req)
	require.NoError(t, err, "second merge error")
	assert.Len(t, fc2.Features, 1, "second merge: fresh dedup per call")
}
