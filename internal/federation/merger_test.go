package federation

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

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
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			merger := NewResultMerger(tt.strategy)
			if merger == nil {
				t.Fatal("NewResultMerger returned nil")
			}
			if merger.strategy != tt.strategy {
				t.Errorf("strategy = %v, want %v", merger.strategy, tt.strategy)
			}
			if merger.deduplicator == nil {
				t.Error("deduplicator is nil")
			}
		})
	}
}

func TestMergeSearchResults_EmptyResults(t *testing.T) {
	t.Parallel()

	merger := NewResultMerger(ConflictFirstWins)
	req := &stac.SearchRequest{Limit: 10}

	fc, err := merger.MergeSearchResults([]*OriginSearchResult{}, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if fc.Type != "FeatureCollection" {
		t.Errorf("Type = %v, want FeatureCollection", fc.Type)
	}
	if len(fc.Features) != 0 {
		t.Errorf("Features length = %d, want 0", len(fc.Features))
	}
	if fc.Context == nil {
		t.Fatal("Context is nil")
	}
	if stac.SearchContextOf(fc).Returned != 0 {
		t.Errorf("Context.Returned = %d, want 0", stac.SearchContextOf(fc).Returned)
	}
	if stac.SearchContextOf(fc).Matched != 0 {
		t.Errorf("Context.Matched = %d, want 0", stac.SearchContextOf(fc).Matched)
	}
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
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(fc.Features) != 3 {
		t.Errorf("Features length = %d, want 3", len(fc.Features))
	}
	if stac.SearchContextOf(fc).Returned != 3 {
		t.Errorf("Context.Returned = %d, want 3", stac.SearchContextOf(fc).Returned)
	}
	if stac.SearchContextOf(fc).Matched != 3 {
		t.Errorf("Context.Matched = %d, want 3", stac.SearchContextOf(fc).Matched)
	}

	// Check that origin metadata was added (as a stac_proxy:origin link)
	for i, item := range fc.Features {
		if got := stac.ItemOriginID(item); got != "origin-1" {
			t.Errorf("item %d: ItemOriginID = %q, want origin-1", i, got)
		}
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
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(fc.Features) != 2 {
		t.Errorf("Features length = %d, want 2", len(fc.Features))
	}

	// First origin to be processed (after sorting) is origin-2 (priority 1)
	// So item-1 should come from origin-2
	var item1Found bool
	for _, item := range fc.Features {
		if item.ID == "item-1" {
			item1Found = true
			if got := stac.ItemOriginID(item); got != "origin-2" {
				t.Errorf("item-1 origin = %q, want origin-2 (first wins after priority sort)", got)
			}
		}
	}
	if !item1Found {
		t.Error("item-1 not found in results")
	}
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
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(fc.Features) != 2 {
		t.Errorf("Features length = %d, want 2", len(fc.Features))
	}

	// item-1 should come from origin-high (priority 1)
	var item1Found bool
	for _, item := range fc.Features {
		if item.ID == "item-1" {
			item1Found = true
			if got := stac.ItemOriginID(item); got != "origin-high" {
				t.Errorf("item-1 origin = %q, want origin-high (highest priority wins)", got)
			}
		}
	}
	if !item1Found {
		t.Error("item-1 not found in results")
	}
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
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(fc.Features) != 1 {
		t.Errorf("Features length = %d, want 1", len(fc.Features))
	}

	item := fc.Features[0]

	// Should have both assets
	if len(item.Assets) != 2 {
		t.Errorf("Assets length = %d, want 2", len(item.Assets))
	}
	if _, ok := item.Assets["thumbnail"]; !ok {
		t.Error("thumbnail asset not found")
	}
	if _, ok := item.Assets["data"]; !ok {
		t.Error("data asset not found")
	}
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
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(fc.Features) != 1 {
		t.Errorf("Features length = %d, want 1", len(fc.Features))
	}

	item := fc.Features[0]

	// Should have both assets - one with original key, one prefixed
	if len(item.Assets) != 2 {
		t.Errorf("Assets length = %d, want 2", len(item.Assets))
	}
	if _, ok := item.Assets["data"]; !ok {
		t.Error("data asset not found")
	}
	if _, ok := item.Assets["origin-2:data"]; !ok {
		t.Error("origin-2:data asset not found (prefixed asset missing)")
	}

	// Verify the correct asset is in each slot
	if item.Assets["data"].Href != "https://origin1.com/data1.tif" {
		t.Errorf("data asset href = %v, want https://origin1.com/data1.tif", item.Assets["data"].Href)
	}
	if item.Assets["origin-2:data"].Href != "https://origin2.com/data2.tif" {
		t.Errorf("origin-2:data asset href = %v, want https://origin2.com/data2.tif",
			item.Assets["origin-2:data"].Href)
	}
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
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(fc.Features) != 1 {
		t.Errorf("Features length = %d, want 1", len(fc.Features))
	}

	item := fc.Features[0]

	// Should use the newer datetime
	got, ok := stac.ItemDatetime(item)
	if !ok {
		t.Fatal("DateTime missing")
	}
	if !got.Equal(newer) {
		t.Errorf("DateTime = %v, want %v (should use newer datetime)", got, newer)
	}
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
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// With namespace strategy, both items should be present with prefixed IDs
	if len(fc.Features) != 3 {
		t.Errorf("Features length = %d, want 3 (no deduplication with namespace)", len(fc.Features))
	}

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

	if !foundOrigin1Item1 {
		t.Error("origin-1:item-1 not found")
	}
	if !foundOrigin2Item1 {
		t.Error("origin-2:item-1 not found")
	}
	if !foundOrigin2Item2 {
		t.Error("origin-2:item-2 not found")
	}
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

	if err == nil {
		t.Fatal("expected error for duplicate items, got nil")
	}

	expectedErr := "duplicate item ID item-1"
	if err.Error() != fmt.Sprintf("duplicate item ID item-1 from origins origin-1 and origin-2") {
		if err.Error()[:len(expectedErr)] != expectedErr {
			t.Errorf("error = %v, want error containing %q", err, expectedErr)
		}
	}
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
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should return all items when limit is 0
	if len(fc.Features) != 3 {
		t.Errorf("Features length = %d, want 3 (no limit applied)", len(fc.Features))
	}
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
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(fc.Features) != 3 {
		t.Errorf("Features length = %d, want 3", len(fc.Features))
	}
	if stac.SearchContextOf(fc).Returned != 3 {
		t.Errorf("Context.Returned = %d, want 3", stac.SearchContextOf(fc).Returned)
	}
	if stac.SearchContextOf(fc).Limit != 3 {
		t.Errorf("Context.Limit = %d, want 3", stac.SearchContextOf(fc).Limit)
	}
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
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(fc.Features) != 3 {
		t.Errorf("Features length = %d, want 3", len(fc.Features))
	}
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
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(fc.Features) != 2 {
		t.Errorf("Features length = %d, want 2 (all available items)", len(fc.Features))
	}
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
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(fc.Features) != 3 {
		t.Errorf("Features length = %d, want 3", len(fc.Features))
	}

	// Results should be processed in priority order (1, 5, 10)
	// But the output order depends on when items were added
	// Just verify all items are present
	foundItems := make(map[string]bool)
	for _, item := range fc.Features {
		foundItems[item.ID] = true
	}

	if !foundItems["item-high"] || !foundItems["item-medium"] || !foundItems["item-low"] {
		t.Error("not all items found in results")
	}
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
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(fc.Features) != 1 {
		t.Fatalf("Features length = %d, want 1", len(fc.Features))
	}

	item := fc.Features[0]
	if got := stac.ItemOriginID(item); got != "test-origin-id" {
		t.Errorf("ItemOriginID = %q, want test-origin-id", got)
	}
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
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should only have items from successful origin
	if len(fc.Features) != 1 {
		t.Errorf("Features length = %d, want 1", len(fc.Features))
	}
	if stac.SearchContextOf(fc).Matched != 1 {
		t.Errorf("Context.Matched = %d, want 1", stac.SearchContextOf(fc).Matched)
	}
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
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Both items should be present since they're from different collections
	if len(fc.Features) != 2 {
		t.Errorf("Features length = %d, want 2 (same ID but different collections)", len(fc.Features))
	}
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
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Matched should be sum of all origins
	if stac.SearchContextOf(fc).Matched != 150 {
		t.Errorf("Context.Matched = %d, want 150 (sum of all origins)", stac.SearchContextOf(fc).Matched)
	}
	// Returned should be actual count
	if stac.SearchContextOf(fc).Returned != 2 {
		t.Errorf("Context.Returned = %d, want 2", stac.SearchContextOf(fc).Returned)
	}
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

	if len(result) != 3 {
		t.Errorf("result length = %d, want 3", len(result))
	}

	// Check for expected collections
	foundCollections := make(map[string]bool)
	for _, coll := range result {
		foundCollections[coll.ID] = true
	}

	expectedCollections := []string{"collection-1", "collection-2", "collection-3"}
	for _, expected := range expectedCollections {
		if !foundCollections[expected] {
			t.Errorf("collection %s not found in result", expected)
		}
	}

	// Verify sorting by ID
	for i := 0; i < len(result)-1; i++ {
		if result[i].ID > result[i+1].ID {
			t.Errorf("collections not sorted: %s > %s", result[i].ID, result[i+1].ID)
		}
	}
}

func TestDeduplicateCollections_Empty(t *testing.T) {
	t.Parallel()

	merger := NewResultMerger(ConflictFirstWins)

	result := merger.DeduplicateCollections([]*stac.Collection{})

	if len(result) != 0 {
		t.Errorf("result length = %d, want 0", len(result))
	}
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

	if len(result) != 3 {
		t.Errorf("result length = %d, want 3", len(result))
	}
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

	if len(merged) != 3 {
		t.Errorf("merged length = %d, want 3 (deduplicated)", len(merged))
	}

	// Check that origin metadata was added (as a stac_proxy:origin link)
	for _, coll := range merged {
		origin := stac.CollectionOriginID(coll)
		if origin == "" {
			t.Errorf("collection %s: stac_proxy:origin link missing", coll.ID)
			continue
		}
		if origin != "origin-1" && origin != "origin-2" {
			t.Errorf("collection %s: origin = %q, want origin-1 or origin-2", coll.ID, origin)
		}
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
	if len(merged) != 1 {
		t.Errorf("merged length = %d, want 1", len(merged))
	}
}

func TestMergeCollections_Empty(t *testing.T) {
	t.Parallel()

	merger := NewResultMerger(ConflictFirstWins)

	merged := merger.MergeCollections([]*OriginCollectionsResult{})

	if len(merged) != 0 {
		t.Errorf("merged length = %d, want 0", len(merged))
	}
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

	if stats.UniqueItems != 3 {
		t.Errorf("UniqueItems = %d, want 3", stats.UniqueItems)
	}
	if stats.TotalItems != 4 {
		t.Errorf("TotalItems = %d, want 4", stats.TotalItems)
	}
	if stats.DuplicatesFound != 1 {
		t.Errorf("DuplicatesFound = %d, want 1", stats.DuplicatesFound)
	}
	if stats.OriginsUsed != 2 {
		t.Errorf("OriginsUsed = %d, want 2", stats.OriginsUsed)
	}
	if stats.OriginsFailed != 1 {
		t.Errorf("OriginsFailed = %d, want 1", stats.OriginsFailed)
	}
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

	if stats.DuplicatesFound != 0 {
		t.Errorf("DuplicatesFound = %d, want 0", stats.DuplicatesFound)
	}
}

func TestItemToJSON(t *testing.T) {
	t.Parallel()

	item := testItem("test-item", "test-collection")

	jsonBytes, err := ItemToJSON(item)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(jsonBytes) == 0 {
		t.Error("JSON bytes is empty")
	}

	// Verify it's valid JSON
	var parsed map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &parsed); err != nil {
		t.Errorf("failed to parse JSON: %v", err)
	}
}

func TestCollectionToJSON(t *testing.T) {
	t.Parallel()

	collection := testCollection("test-collection")

	jsonBytes, err := CollectionToJSON(collection)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(jsonBytes) == 0 {
		t.Error("JSON bytes is empty")
	}

	// Verify it's valid JSON
	var parsed map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &parsed); err != nil {
		t.Errorf("failed to parse JSON: %v", err)
	}
}

func TestItemKey_DefaultStrategy(t *testing.T) {
	t.Parallel()

	merger := NewResultMerger(ConflictFirstWins)
	item := testItem("item-1", "collection-1")

	key := merger.itemKey("origin-1", item)

	expected := "collection-1:item-1"
	if key != expected {
		t.Errorf("itemKey = %v, want %v", key, expected)
	}
}

func TestItemKey_NamespaceStrategy(t *testing.T) {
	t.Parallel()

	merger := NewResultMerger(ConflictNamespace)
	item := testItem("item-1", "collection-1")

	key := merger.itemKey("origin-1", item)

	expected := "origin-1:item-1"
	if key != expected {
		t.Errorf("itemKey = %v, want %v", key, expected)
	}
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

	if len(merged.Links) != 2 {
		t.Errorf("Links length = %d, want 2", len(merged.Links))
	}
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
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(fc.Features) != 1 {
		t.Errorf("Features length = %d, want 1", len(fc.Features))
	}

	// All three assets should be merged
	item := fc.Features[0]
	if len(item.Assets) != 3 {
		t.Errorf("Assets length = %d, want 3", len(item.Assets))
	}

	expectedAssets := []string{"asset-a", "asset-b", "asset-c"}
	for _, assetKey := range expectedAssets {
		if _, ok := item.Assets[assetKey]; !ok {
			t.Errorf("asset %s not found", assetKey)
		}
	}
}

func TestTransformItem_AddsOriginMetadata(t *testing.T) {
	t.Parallel()

	merger := NewResultMerger(ConflictFirstWins)
	item := testItem("item-1", "collection-1")

	transformed := merger.transformItem(item, "test-origin", "https://test.example/v1")

	if got := stac.ItemOriginID(transformed); got != "test-origin" {
		t.Errorf("ItemOriginID = %q, want test-origin", got)
	}
	// The link's href carries the upstream URL.
	var hrefSeen string
	for _, l := range transformed.Links {
		if l != nil && l.Rel == stac.OriginLinkRel {
			hrefSeen = l.Href
		}
	}
	if hrefSeen != "https://test.example/v1" {
		t.Errorf("origin link href = %q, want https://test.example/v1", hrefSeen)
	}
}

func TestTransformItem_NamespaceStrategy(t *testing.T) {
	t.Parallel()

	merger := NewResultMerger(ConflictNamespace)
	item := testItem("item-1", "collection-1")
	originalID := item.ID

	transformed := merger.transformItem(item, "test-origin", "https://test.example/v1")

	expectedID := "test-origin:" + originalID
	if transformed.ID != expectedID {
		t.Errorf("ID = %v, want %v", transformed.ID, expectedID)
	}
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
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should handle nil context gracefully
	if stac.SearchContextOf(fc).Matched != 0 {
		t.Errorf("Context.Matched = %d, want 0 (nil context)", stac.SearchContextOf(fc).Matched)
	}
	if stac.SearchContextOf(fc).Returned != 1 {
		t.Errorf("Context.Returned = %d, want 1", stac.SearchContextOf(fc).Returned)
	}
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

	if merged.ID != "item-1" {
		t.Errorf("merged item ID = %v, want item-1", merged.ID)
	}
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
	if !ok {
		t.Fatal("DateTime missing, should keep existing")
	}
	if !got.Equal(now) {
		t.Errorf("DateTime = %v, want %v", got, now)
	}
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
	if err != nil {
		t.Fatalf("first merge error: %v", err)
	}
	if len(fc1.Features) != 1 {
		t.Errorf("first merge: Features length = %d, want 1", len(fc1.Features))
	}

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
	if err != nil {
		t.Fatalf("second merge error: %v", err)
	}
	if len(fc2.Features) != 1 {
		t.Errorf("second merge: Features length = %d, want 1 (deduplicator should be reset)",
			len(fc2.Features))
	}
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
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(fc.Features) != 1 {
		t.Fatalf("Features length = %d, want 1", len(fc.Features))
	}

	// Should have the asset from the second item
	if len(fc.Features[0].Assets) != 1 {
		t.Errorf("Assets length = %d, want 1", len(fc.Features[0].Assets))
	}
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
