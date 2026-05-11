package federation

import (
	"container/heap"
	"fmt"
	"testing"

	"github.com/yourorg/stac-proxy/internal/stac"
)

// Test helper to create items with specific property values
// Note: Custom properties go in Properties.Extra map
func testItemWithProperty(id, collection, key string, value interface{}) *stac.Item {
	return &stac.Item{
		Type:       "Feature",
		ID:         id,
		Collection: collection,
		Properties: stac.Properties{
			Extra: map[string]interface{}{
				key: value,
			},
		},
		Links:  []stac.Link{},
		Assets: map[string]stac.Asset{},
	}
}

func testItemWithProperties(id, collection string, props map[string]interface{}) *stac.Item {
	return &stac.Item{
		Type:       "Feature",
		ID:         id,
		Collection: collection,
		Properties: stac.Properties{
			Extra: props,
		},
		Links:  []stac.Link{},
		Assets: map[string]stac.Asset{},
	}
}

func TestNewMergeHeap(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		sortKey    string
		descending bool
	}{
		{
			name:       "Ascending",
			sortKey:    "datetime",
			descending: false,
		},
		{
			name:       "Descending",
			sortKey:    "datetime",
			descending: true,
		},
		{
			name:       "CustomSortKey",
			sortKey:    "custom_field",
			descending: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := NewMergeHeap(tt.sortKey, tt.descending)

			if h == nil {
				t.Fatal("NewMergeHeap returned nil")
			}
			if h.sortKey != tt.sortKey {
				t.Errorf("sortKey = %v, want %v", h.sortKey, tt.sortKey)
			}
			if h.sortDesc != tt.descending {
				t.Errorf("sortDesc = %v, want %v", h.sortDesc, tt.descending)
			}
			if h.items == nil {
				t.Error("items slice is nil")
			}
			if h.Len() != 0 {
				t.Errorf("initial length = %d, want 0", h.Len())
			}
		})
	}
}

func TestMergeHeap_Len(t *testing.T) {
	t.Parallel()

	h := NewMergeHeap("datetime", false)

	if h.Len() != 0 {
		t.Errorf("empty heap length = %d, want 0", h.Len())
	}

	// Add items
	item1 := testItemWithProperty("item1", "coll1", "datetime", "2023-01-01")
	h.PushItem(item1, "origin1", 0)

	if h.Len() != 1 {
		t.Errorf("after push length = %d, want 1", h.Len())
	}

	item2 := testItemWithProperty("item2", "coll1", "datetime", "2023-01-02")
	h.PushItem(item2, "origin2", 0)

	if h.Len() != 2 {
		t.Errorf("after second push length = %d, want 2", h.Len())
	}

	// Pop item
	h.PopItem()

	if h.Len() != 1 {
		t.Errorf("after pop length = %d, want 1", h.Len())
	}
}

func TestMergeHeap_Less(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		sortKey    string
		descending bool
		value1     interface{}
		value2     interface{}
		expectLess bool
	}{
		{
			name:       "StringAscending_Less",
			sortKey:    "name",
			descending: false,
			value1:     "alice",
			value2:     "bob",
			expectLess: true,
		},
		{
			name:       "StringAscending_Greater",
			sortKey:    "name",
			descending: false,
			value1:     "charlie",
			value2:     "bob",
			expectLess: false,
		},
		{
			name:       "StringDescending_Less",
			sortKey:    "name",
			descending: true,
			value1:     "bob",
			value2:     "alice",
			expectLess: true,
		},
		{
			name:       "Float64Ascending_Less",
			sortKey:    "value",
			descending: false,
			value1:     1.5,
			value2:     2.5,
			expectLess: true,
		},
		{
			name:       "Float64Descending_Less",
			sortKey:    "value",
			descending: true,
			value1:     2.5,
			value2:     1.5,
			expectLess: true,
		},
		{
			name:       "IntAscending_Less",
			sortKey:    "count",
			descending: false,
			value1:     5,
			value2:     10,
			expectLess: true,
		},
		{
			name:       "IntDescending_Less",
			sortKey:    "count",
			descending: true,
			value1:     10,
			value2:     5,
			expectLess: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := NewMergeHeap(tt.sortKey, tt.descending)

			item1 := testItemWithProperty("item1", "coll1", tt.sortKey, tt.value1)
			item2 := testItemWithProperty("item2", "coll1", tt.sortKey, tt.value2)

			hi1 := &heapItem{
				Item:     item1,
				OriginID: "origin1",
				Index:    0,
				SortVal:  tt.value1,
			}
			hi2 := &heapItem{
				Item:     item2,
				OriginID: "origin2",
				Index:    0,
				SortVal:  tt.value2,
			}

			h.items = []*heapItem{hi1, hi2}

			result := h.Less(0, 1)
			if result != tt.expectLess {
				t.Errorf("Less(0, 1) = %v, want %v", result, tt.expectLess)
			}
		})
	}
}

func TestMergeHeap_Swap(t *testing.T) {
	t.Parallel()

	h := NewMergeHeap("datetime", false)

	item1 := testItemWithProperty("item1", "coll1", "datetime", "2023-01-01")
	item2 := testItemWithProperty("item2", "coll1", "datetime", "2023-01-02")

	hi1 := &heapItem{Item: item1, OriginID: "origin1", Index: 0}
	hi2 := &heapItem{Item: item2, OriginID: "origin2", Index: 1}

	h.items = []*heapItem{hi1, hi2}

	// Swap
	h.Swap(0, 1)

	if h.items[0] != hi2 {
		t.Error("items[0] should be hi2 after swap")
	}
	if h.items[1] != hi1 {
		t.Error("items[1] should be hi1 after swap")
	}
}

func TestMergeHeap_Push(t *testing.T) {
	t.Parallel()

	h := NewMergeHeap("datetime", false)

	item := testItemWithProperty("item1", "coll1", "datetime", "2023-01-01")
	hi := &heapItem{
		Item:     item,
		OriginID: "origin1",
		Index:    0,
	}

	if h.Len() != 0 {
		t.Errorf("initial length = %d, want 0", h.Len())
	}

	h.Push(hi)

	if h.Len() != 1 {
		t.Errorf("after push length = %d, want 1", h.Len())
	}
	if h.items[0] != hi {
		t.Error("pushed item not found in heap")
	}
}

func TestMergeHeap_Pop(t *testing.T) {
	t.Parallel()

	h := NewMergeHeap("datetime", false)

	item1 := testItemWithProperty("item1", "coll1", "datetime", "2023-01-01")
	item2 := testItemWithProperty("item2", "coll1", "datetime", "2023-01-02")

	hi1 := &heapItem{Item: item1, OriginID: "origin1", Index: 0}
	hi2 := &heapItem{Item: item2, OriginID: "origin2", Index: 1}

	h.items = []*heapItem{hi1, hi2}

	popped := h.Pop().(*heapItem)

	if h.Len() != 1 {
		t.Errorf("after pop length = %d, want 1", h.Len())
	}
	if popped != hi2 {
		t.Error("popped wrong item (should pop from end)")
	}
}

func TestMergeHeap_Peek(t *testing.T) {
	t.Parallel()

	h := NewMergeHeap("datetime", false)

	// Empty heap
	if peeked := h.Peek(); peeked != nil {
		t.Error("Peek on empty heap should return nil")
	}

	// Add items
	item := testItemWithProperty("item1", "coll1", "datetime", "2023-01-01")
	h.PushItem(item, "origin1", 0)

	peeked := h.Peek()
	if peeked == nil {
		t.Fatal("Peek returned nil")
	}
	if peeked.Item.ID != "item1" {
		t.Errorf("Peek item ID = %v, want item1", peeked.Item.ID)
	}

	// Verify Peek doesn't remove the item
	if h.Len() != 1 {
		t.Errorf("after Peek length = %d, want 1", h.Len())
	}
}

func TestMergeHeap_PushItem(t *testing.T) {
	t.Parallel()

	h := NewMergeHeap("datetime", false)

	item := testItemWithProperty("item1", "coll1", "datetime", "2023-01-01T00:00:00Z")
	h.PushItem(item, "origin1", 5)

	if h.Len() != 1 {
		t.Errorf("after PushItem length = %d, want 1", h.Len())
	}

	hi := h.items[0]
	if hi.Item.ID != "item1" {
		t.Errorf("heapItem.Item.ID = %v, want item1", hi.Item.ID)
	}
	if hi.OriginID != "origin1" {
		t.Errorf("heapItem.OriginID = %v, want origin1", hi.OriginID)
	}
	if hi.Index != 5 {
		t.Errorf("heapItem.Index = %d, want 5", hi.Index)
	}
	if hi.SortVal != "2023-01-01T00:00:00Z" {
		t.Errorf("heapItem.SortVal = %v, want 2023-01-01T00:00:00Z", hi.SortVal)
	}
}

func TestMergeHeap_PopItem(t *testing.T) {
	t.Parallel()

	t.Run("EmptyHeap", func(t *testing.T) {
		t.Parallel()
		h := NewMergeHeap("datetime", false)

		item, originID, idx := h.PopItem()
		if item != nil {
			t.Error("PopItem on empty heap should return nil item")
		}
		if originID != "" {
			t.Errorf("PopItem on empty heap should return empty originID, got %v", originID)
		}
		if idx != 0 {
			t.Errorf("PopItem on empty heap should return 0 index, got %d", idx)
		}
	})

	t.Run("SingleItem", func(t *testing.T) {
		t.Parallel()
		h := NewMergeHeap("datetime", false)

		item := testItemWithProperty("item1", "coll1", "datetime", "2023-01-01")
		h.PushItem(item, "origin1", 7)

		poppedItem, originID, idx := h.PopItem()
		if poppedItem == nil {
			t.Fatal("PopItem returned nil")
		}
		if poppedItem.ID != "item1" {
			t.Errorf("popped item ID = %v, want item1", poppedItem.ID)
		}
		if originID != "origin1" {
			t.Errorf("originID = %v, want origin1", originID)
		}
		if idx != 7 {
			t.Errorf("index = %d, want 7", idx)
		}
		if h.Len() != 0 {
			t.Errorf("after PopItem length = %d, want 0", h.Len())
		}
	})

	t.Run("MultipleItems", func(t *testing.T) {
		t.Parallel()
		h := NewMergeHeap("datetime", false)

		item1 := testItemWithProperty("item1", "coll1", "datetime", "2023-01-03")
		item2 := testItemWithProperty("item2", "coll1", "datetime", "2023-01-01")
		item3 := testItemWithProperty("item3", "coll1", "datetime", "2023-01-02")

		h.PushItem(item1, "origin1", 0)
		h.PushItem(item2, "origin2", 1)
		h.PushItem(item3, "origin3", 2)

		// Pop should return items in ascending order (item2, item3, item1)
		poppedItem, _, _ := h.PopItem()
		if poppedItem.ID != "item2" {
			t.Errorf("first pop ID = %v, want item2", poppedItem.ID)
		}

		poppedItem, _, _ = h.PopItem()
		if poppedItem.ID != "item3" {
			t.Errorf("second pop ID = %v, want item3", poppedItem.ID)
		}

		poppedItem, _, _ = h.PopItem()
		if poppedItem.ID != "item1" {
			t.Errorf("third pop ID = %v, want item1", poppedItem.ID)
		}
	})
}

func TestMergeHeap_HeapProperty(t *testing.T) {
	t.Parallel()

	t.Run("AscendingOrder", func(t *testing.T) {
		t.Parallel()
		h := NewMergeHeap("value", false)

		// Push items in random order
		values := []float64{5.0, 2.0, 8.0, 1.0, 9.0, 3.0, 7.0, 4.0, 6.0}
		for i, v := range values {
			item := testItemWithProperty(fmt.Sprintf("item%d", i), "coll1", "value", v)
			h.PushItem(item, fmt.Sprintf("origin%d", i), i)
		}

		// Pop all items - should come out in ascending order
		var popped []float64
		for h.Len() > 0 {
			item, _, _ := h.PopItem()
			popped = append(popped, item.Properties.Extra["value"].(float64))
		}

		for i := 1; i < len(popped); i++ {
			if popped[i] < popped[i-1] {
				t.Errorf("items not in ascending order: %v", popped)
				break
			}
		}
	})

	t.Run("DescendingOrder", func(t *testing.T) {
		t.Parallel()
		h := NewMergeHeap("value", true)

		// Push items in random order
		values := []float64{5.0, 2.0, 8.0, 1.0, 9.0, 3.0, 7.0, 4.0, 6.0}
		for i, v := range values {
			item := testItemWithProperty(fmt.Sprintf("item%d", i), "coll1", "value", v)
			h.PushItem(item, fmt.Sprintf("origin%d", i), i)
		}

		// Pop all items - should come out in descending order
		var popped []float64
		for h.Len() > 0 {
			item, _, _ := h.PopItem()
			popped = append(popped, item.Properties.Extra["value"].(float64))
		}

		for i := 1; i < len(popped); i++ {
			if popped[i] > popped[i-1] {
				t.Errorf("items not in descending order: %v", popped)
				break
			}
		}
	})
}

func TestCompareValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		a        interface{}
		b        interface{}
		expected int
	}{
		// Nil cases
		{
			name:     "BothNil",
			a:        nil,
			b:        nil,
			expected: 0,
		},
		{
			name:     "FirstNil",
			a:        nil,
			b:        "value",
			expected: -1,
		},
		{
			name:     "SecondNil",
			a:        "value",
			b:        nil,
			expected: 1,
		},
		// String comparisons
		{
			name:     "StringEqual",
			a:        "abc",
			b:        "abc",
			expected: 0,
		},
		{
			name:     "StringLess",
			a:        "abc",
			b:        "xyz",
			expected: -1,
		},
		{
			name:     "StringGreater",
			a:        "xyz",
			b:        "abc",
			expected: 1,
		},
		// Float64 comparisons
		{
			name:     "Float64Equal",
			a:        3.14,
			b:        3.14,
			expected: 0,
		},
		{
			name:     "Float64Less",
			a:        1.5,
			b:        2.5,
			expected: -1,
		},
		{
			name:     "Float64Greater",
			a:        5.5,
			b:        3.5,
			expected: 1,
		},
		// Int comparisons
		{
			name:     "IntEqual",
			a:        42,
			b:        42,
			expected: 0,
		},
		{
			name:     "IntLess",
			a:        10,
			b:        20,
			expected: -1,
		},
		{
			name:     "IntGreater",
			a:        100,
			b:        50,
			expected: 1,
		},
		// Mixed type comparisons (fallback to string comparison)
		{
			name:     "MixedTypes_StringAndInt",
			a:        "string",
			b:        42,
			expected: 1, // "string" > "" (int converted to empty string)
		},
		{
			name:     "MixedTypes_FloatAndString",
			a:        3.14,
			b:        "text",
			expected: -1, // "" (float converted) < "text"
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := compareValues(tt.a, tt.b)
			if result != tt.expected {
				t.Errorf("compareValues(%v, %v) = %d, want %d", tt.a, tt.b, result, tt.expected)
			}
		})
	}
}

func TestMergeHeap_ExtractSortValue(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		sortKey  string
		item     *stac.Item
		expected interface{}
	}{
		{
			name:    "ValidProperty",
			sortKey: "datetime",
			item: testItemWithProperty("item1", "coll1", "datetime", "2023-01-01"),
			expected: "2023-01-01",
		},
		{
			name:    "MissingProperty",
			sortKey: "missing",
			item: testItemWithProperty("item1", "coll1", "datetime", "2023-01-01"),
			expected: nil,
		},
		{
			name:     "NilItem",
			sortKey:  "datetime",
			item:     nil,
			expected: nil,
		},
		{
			name:    "NilPropertiesExtra",
			sortKey: "datetime",
			item: &stac.Item{
				ID: "item1",
				Properties: stac.Properties{
					Extra: nil,
				},
			},
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := NewMergeHeap(tt.sortKey, false)
			result := h.extractSortValue(tt.item)
			if result != tt.expected {
				t.Errorf("extractSortValue() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestMergeHeap_GetSortValue(t *testing.T) {
	t.Parallel()

	h := NewMergeHeap("datetime", false)

	t.Run("CachedValue", func(t *testing.T) {
		hi := &heapItem{
			Item: testItemWithProperty("item1", "coll1", "datetime", "2023-01-01"),
			SortVal: "cached-value",
		}

		result := h.getSortValue(hi)
		if result != "cached-value" {
			t.Errorf("getSortValue() = %v, want cached-value", result)
		}
	})

	t.Run("ExtractValue", func(t *testing.T) {
		item := testItemWithProperty("item1", "coll1", "datetime", "2023-01-01")
		hi := &heapItem{
			Item:    item,
			SortVal: nil,
		}

		result := h.getSortValue(hi)
		if result != "2023-01-01" {
			t.Errorf("getSortValue() = %v, want 2023-01-01", result)
		}
	})
}

// Mock PageFetcher for testing MergeSortIterator
type mockPageFetcher struct {
	pages map[string][][]*stac.Item
	calls map[string]int
}

func newMockPageFetcher() *mockPageFetcher {
	return &mockPageFetcher{
		pages: make(map[string][][]*stac.Item),
		calls: make(map[string]int),
	}
}

func (m *mockPageFetcher) addPages(originID string, pages [][]*stac.Item) {
	m.pages[originID] = pages
}

func (m *mockPageFetcher) FetchNextPage(originID string) ([]*stac.Item, bool, error) {
	callCount := m.calls[originID]
	m.calls[originID]++

	pages, ok := m.pages[originID]
	if !ok || callCount >= len(pages) {
		return nil, false, nil
	}

	page := pages[callCount]
	hasMore := callCount+1 < len(pages)
	return page, hasMore, nil
}

func TestNewMergeSortIterator(t *testing.T) {
	t.Parallel()

	fetcher := newMockPageFetcher()
	fetchers := map[string]PageFetcher{
		"origin1": fetcher,
	}

	it := NewMergeSortIterator("datetime", false, fetchers, 10)

	if it == nil {
		t.Fatal("NewMergeSortIterator returned nil")
	}
	if it.heap == nil {
		t.Error("heap is nil")
	}
	if it.fetchers == nil {
		t.Error("fetchers is nil")
	}
	if it.buffers == nil {
		t.Error("buffers is nil")
	}
	if it.indices == nil {
		t.Error("indices is nil")
	}
	if it.limit != 10 {
		t.Errorf("limit = %d, want 10", it.limit)
	}
}

func TestMergeSortIterator_Initialize(t *testing.T) {
	t.Parallel()

	t.Run("SingleOrigin", func(t *testing.T) {
		t.Parallel()
		fetcher := newMockPageFetcher()
		item1 := testItemWithProperty("item1", "coll1", "datetime", "2023-01-01")
		item2 := testItemWithProperty("item2", "coll1", "datetime", "2023-01-02")

		fetcher.addPages("origin1", [][]*stac.Item{{item1, item2}})

		fetchers := map[string]PageFetcher{"origin1": fetcher}
		it := NewMergeSortIterator("datetime", false, fetchers, 10)

		err := it.Initialize()
		if err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		if it.heap.Len() != 1 {
			t.Errorf("heap length = %d, want 1 (first item from origin)", it.heap.Len())
		}
		if len(it.buffers["origin1"]) != 2 {
			t.Errorf("buffer length = %d, want 2", len(it.buffers["origin1"]))
		}
	})

	t.Run("MultipleOrigins", func(t *testing.T) {
		t.Parallel()
		fetcher1 := newMockPageFetcher()
		fetcher2 := newMockPageFetcher()

		item1 := testItemWithProperty("item1", "coll1", "datetime", "2023-01-01")
		item2 := testItemWithProperty("item2", "coll1", "datetime", "2023-01-02")

		fetcher1.addPages("origin1", [][]*stac.Item{{item1}})
		fetcher2.addPages("origin2", [][]*stac.Item{{item2}})

		fetchers := map[string]PageFetcher{
			"origin1": fetcher1,
			"origin2": fetcher2,
		}
		it := NewMergeSortIterator("datetime", false, fetchers, 10)

		err := it.Initialize()
		if err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		if it.heap.Len() != 2 {
			t.Errorf("heap length = %d, want 2 (first item from each origin)", it.heap.Len())
		}
	})

	t.Run("EmptyOrigin", func(t *testing.T) {
		t.Parallel()
		fetcher := newMockPageFetcher()
		fetcher.addPages("origin1", [][]*stac.Item{{}})

		fetchers := map[string]PageFetcher{"origin1": fetcher}
		it := NewMergeSortIterator("datetime", false, fetchers, 10)

		err := it.Initialize()
		if err != nil {
			t.Fatalf("Initialize failed: %v", err)
		}

		if it.heap.Len() != 0 {
			t.Errorf("heap length = %d, want 0 (no items from empty origin)", it.heap.Len())
		}
	})
}

func TestMergeSortIterator_Next(t *testing.T) {
	t.Parallel()

	t.Run("SinglePage", func(t *testing.T) {
		t.Parallel()
		fetcher := newMockPageFetcher()
		item1 := testItemWithProperty("item1", "coll1", "datetime", "2023-01-01")
		item2 := testItemWithProperty("item2", "coll1", "datetime", "2023-01-02")

		fetcher.addPages("origin1", [][]*stac.Item{{item1, item2}})

		fetchers := map[string]PageFetcher{"origin1": fetcher}
		it := NewMergeSortIterator("datetime", false, fetchers, 10)
		it.Initialize()

		// First Next
		item, ok := it.Next()
		if !ok {
			t.Fatal("Next returned false")
		}
		if item.ID != "item1" {
			t.Errorf("first item ID = %v, want item1", item.ID)
		}

		// Second Next
		item, ok = it.Next()
		if !ok {
			t.Fatal("Next returned false for second item")
		}
		if item.ID != "item2" {
			t.Errorf("second item ID = %v, want item2", item.ID)
		}

		// Third Next (no more items)
		_, ok = it.Next()
		if ok {
			t.Error("Next should return false when no more items")
		}
	})

	t.Run("MultiplePagesFromSameOrigin", func(t *testing.T) {
		t.Parallel()
		fetcher := newMockPageFetcher()
		item1 := testItemWithProperty("item1", "coll1", "datetime", "2023-01-01")
		item2 := testItemWithProperty("item2", "coll1", "datetime", "2023-01-02")
		item3 := testItemWithProperty("item3", "coll1", "datetime", "2023-01-03")

		fetcher.addPages("origin1", [][]*stac.Item{
			{item1, item2},
			{item3},
		})

		fetchers := map[string]PageFetcher{"origin1": fetcher}
		it := NewMergeSortIterator("datetime", false, fetchers, 10)
		it.Initialize()

		var items []*stac.Item
		for {
			item, ok := it.Next()
			if !ok {
				break
			}
			items = append(items, item)
		}

		if len(items) != 3 {
			t.Errorf("got %d items, want 3", len(items))
		}
	})

	t.Run("LimitEnforced", func(t *testing.T) {
		t.Parallel()
		fetcher := newMockPageFetcher()
		items := []*stac.Item{
			testItemWithProperty("item1", "coll1", "datetime", "2023-01-01"),
			testItemWithProperty("item2", "coll1", "datetime", "2023-01-02"),
			testItemWithProperty("item3", "coll1", "datetime", "2023-01-03"),
		}

		fetcher.addPages("origin1", [][]*stac.Item{items})

		fetchers := map[string]PageFetcher{"origin1": fetcher}
		it := NewMergeSortIterator("datetime", false, fetchers, 2) // Limit to 2
		it.Initialize()

		var collected []*stac.Item
		for {
			item, ok := it.Next()
			if !ok {
				break
			}
			collected = append(collected, item)
		}

		if len(collected) != 2 {
			t.Errorf("collected %d items, want 2 (limit enforced)", len(collected))
		}
	})

	t.Run("MergedSortFromMultipleOrigins", func(t *testing.T) {
		t.Parallel()
		fetcher1 := newMockPageFetcher()
		fetcher2 := newMockPageFetcher()

		// Origin1 has items with earlier dates
		fetcher1.addPages("origin1", [][]*stac.Item{{
			testItemWithProperty("item1", "coll1", "datetime", "2023-01-01"),
			testItemWithProperty("item3", "coll1", "datetime", "2023-01-03"),
		}})

		// Origin2 has items with dates in between
		fetcher2.addPages("origin2", [][]*stac.Item{{
			testItemWithProperty("item2", "coll1", "datetime", "2023-01-02"),
			testItemWithProperty("item4", "coll1", "datetime", "2023-01-04"),
		}})

		fetchers := map[string]PageFetcher{
			"origin1": fetcher1,
			"origin2": fetcher2,
		}
		it := NewMergeSortIterator("datetime", false, fetchers, 10)
		it.Initialize()

		var items []*stac.Item
		for {
			item, ok := it.Next()
			if !ok {
				break
			}
			items = append(items, item)
		}

		if len(items) != 4 {
			t.Fatalf("got %d items, want 4", len(items))
		}

		// Verify sorted order
		expectedOrder := []string{"item1", "item2", "item3", "item4"}
		for i, expected := range expectedOrder {
			if items[i].ID != expected {
				t.Errorf("item[%d].ID = %v, want %v", i, items[i].ID, expected)
			}
		}
	})

	t.Run("EmptyHeap", func(t *testing.T) {
		t.Parallel()
		it := NewMergeSortIterator("datetime", false, map[string]PageFetcher{}, 10)
		it.Initialize()

		item, ok := it.Next()
		if ok {
			t.Error("Next should return false for empty iterator")
		}
		if item != nil {
			t.Error("Next should return nil item for empty iterator")
		}
	})
}

func TestMergeSortIterator_Collect(t *testing.T) {
	t.Parallel()

	t.Run("CollectAll", func(t *testing.T) {
		t.Parallel()
		fetcher := newMockPageFetcher()
		items := []*stac.Item{
			testItemWithProperty("item1", "coll1", "datetime", "2023-01-01"),
			testItemWithProperty("item2", "coll1", "datetime", "2023-01-02"),
			testItemWithProperty("item3", "coll1", "datetime", "2023-01-03"),
		}

		fetcher.addPages("origin1", [][]*stac.Item{items})

		fetchers := map[string]PageFetcher{"origin1": fetcher}
		it := NewMergeSortIterator("datetime", false, fetchers, 0) // No limit
		it.Initialize()

		collected := it.Collect()

		if len(collected) != 3 {
			t.Errorf("collected %d items, want 3", len(collected))
		}
	})

	t.Run("CollectWithLimit", func(t *testing.T) {
		t.Parallel()
		fetcher := newMockPageFetcher()
		items := []*stac.Item{
			testItemWithProperty("item1", "coll1", "datetime", "2023-01-01"),
			testItemWithProperty("item2", "coll1", "datetime", "2023-01-02"),
			testItemWithProperty("item3", "coll1", "datetime", "2023-01-03"),
		}

		fetcher.addPages("origin1", [][]*stac.Item{items})

		fetchers := map[string]PageFetcher{"origin1": fetcher}
		it := NewMergeSortIterator("datetime", false, fetchers, 2)
		it.Initialize()

		collected := it.Collect()

		if len(collected) != 2 {
			t.Errorf("collected %d items, want 2", len(collected))
		}
	})

	t.Run("CollectEmpty", func(t *testing.T) {
		t.Parallel()
		it := NewMergeSortIterator("datetime", false, map[string]PageFetcher{}, 10)
		it.Initialize()

		collected := it.Collect()

		if len(collected) != 0 {
			t.Errorf("collected %d items, want 0", len(collected))
		}
		// nil is ok for empty collection in Go
	})
}

func TestMergeSortIterator_AcrossPageBoundaries(t *testing.T) {
	t.Parallel()

	fetcher1 := newMockPageFetcher()
	fetcher2 := newMockPageFetcher()

	// Origin1: 3 pages
	fetcher1.addPages("origin1", [][]*stac.Item{
		{
			testItemWithProperty("item1", "coll1", "datetime", "2023-01-01"),
			testItemWithProperty("item4", "coll1", "datetime", "2023-01-04"),
		},
		{
			testItemWithProperty("item7", "coll1", "datetime", "2023-01-07"),
		},
		{
			testItemWithProperty("item10", "coll1", "datetime", "2023-01-10"),
		},
	})

	// Origin2: 2 pages
	fetcher2.addPages("origin2", [][]*stac.Item{
		{
			testItemWithProperty("item2", "coll1", "datetime", "2023-01-02"),
			testItemWithProperty("item5", "coll1", "datetime", "2023-01-05"),
		},
		{
			testItemWithProperty("item8", "coll1", "datetime", "2023-01-08"),
		},
	})

	fetchers := map[string]PageFetcher{
		"origin1": fetcher1,
		"origin2": fetcher2,
	}
	it := NewMergeSortIterator("datetime", false, fetchers, 0)
	it.Initialize()

	collected := it.Collect()

	if len(collected) != 7 {
		t.Errorf("collected %d items, want 7", len(collected))
	}

	// Verify sorted order
	expectedOrder := []string{"item1", "item2", "item4", "item5", "item7", "item8", "item10"}
	for i, expected := range expectedOrder {
		if collected[i].ID != expected {
			t.Errorf("item[%d].ID = %v, want %v", i, collected[i].ID, expected)
		}
	}
}

func TestMergeSortIterator_DescendingSort(t *testing.T) {
	t.Parallel()

	// Note: MergeSortIterator only sorts when merging multiple origins.
	// With a single origin, items come out in buffer order.
	// Test with multiple origins to verify descending sort.

	fetcher1 := newMockPageFetcher()
	fetcher2 := newMockPageFetcher()

	// Origin1 has odd-numbered dates (descending)
	fetcher1.addPages("origin1", [][]*stac.Item{{
		testItemWithProperty("item5", "coll1", "datetime", "2023-01-05"),
		testItemWithProperty("item3", "coll1", "datetime", "2023-01-03"),
		testItemWithProperty("item1", "coll1", "datetime", "2023-01-01"),
	}})

	// Origin2 has even-numbered dates (descending)
	fetcher2.addPages("origin2", [][]*stac.Item{{
		testItemWithProperty("item6", "coll1", "datetime", "2023-01-06"),
		testItemWithProperty("item4", "coll1", "datetime", "2023-01-04"),
		testItemWithProperty("item2", "coll1", "datetime", "2023-01-02"),
	}})

	fetchers := map[string]PageFetcher{
		"origin1": fetcher1,
		"origin2": fetcher2,
	}
	it := NewMergeSortIterator("datetime", true, fetchers, 0) // Descending
	it.Initialize()

	collected := it.Collect()

	// Verify descending merge order
	expectedOrder := []string{"item6", "item5", "item4", "item3", "item2", "item1"}
	if len(collected) != len(expectedOrder) {
		t.Fatalf("collected %d items, want %d", len(collected), len(expectedOrder))
	}

	for i, expected := range expectedOrder {
		if collected[i].ID != expected {
			t.Errorf("item[%d].ID = %v, want %v (descending order)", i, collected[i].ID, expected)
		}
	}
}

func TestStringVal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    interface{}
		expected string
	}{
		{
			name:     "StringValue",
			input:    "test",
			expected: "test",
		},
		{
			name:     "NonStringValue",
			input:    42,
			expected: "",
		},
		{
			name:     "NilValue",
			input:    nil,
			expected: "",
		},
		{
			name:     "FloatValue",
			input:    3.14,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := stringVal(tt.input)
			if result != tt.expected {
				t.Errorf("stringVal(%v) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestMergeHeap_MixedNilValues(t *testing.T) {
	t.Parallel()

	h := NewMergeHeap("value", false)

	// Add items with mixed nil and non-nil values
	item1 := testItemWithProperty("item1", "coll1", "value", "a")
	item2 := testItemWithProperties("item2", "coll1", map[string]interface{}{}) // No "value" property
	item3 := testItemWithProperty("item3", "coll1", "value", "c")

	h.PushItem(item1, "origin1", 0)
	h.PushItem(item2, "origin2", 0) // nil value
	h.PushItem(item3, "origin3", 0)

	// Pop items - nil should come first in ascending order
	popped1, _, _ := h.PopItem()
	if popped1.ID != "item2" {
		t.Errorf("first pop ID = %v, want item2 (nil sorts first)", popped1.ID)
	}

	popped2, _, _ := h.PopItem()
	if popped2.ID != "item1" {
		t.Errorf("second pop ID = %v, want item1", popped2.ID)
	}

	popped3, _, _ := h.PopItem()
	if popped3.ID != "item3" {
		t.Errorf("third pop ID = %v, want item3", popped3.ID)
	}
}

func TestMergeHeap_StandardHeapOperations(t *testing.T) {
	t.Parallel()

	// Verify that our heap correctly implements heap.Interface by using
	// the standard heap.Push and heap.Pop functions

	h := NewMergeHeap("value", false)

	item1 := testItemWithProperty("item1", "coll1", "value", 5.0)
	item2 := testItemWithProperty("item2", "coll1", "value", 2.0)
	item3 := testItemWithProperty("item3", "coll1", "value", 8.0)

	hi1 := &heapItem{Item: item1, SortVal: 5.0, OriginID: "origin1", Index: 0}
	hi2 := &heapItem{Item: item2, SortVal: 2.0, OriginID: "origin2", Index: 0}
	hi3 := &heapItem{Item: item3, SortVal: 8.0, OriginID: "origin3", Index: 0}

	heap.Push(h, hi1)
	heap.Push(h, hi2)
	heap.Push(h, hi3)

	if h.Len() != 3 {
		t.Errorf("heap length = %d, want 3", h.Len())
	}

	// Pop should return in ascending order
	popped := heap.Pop(h).(*heapItem)
	if popped.Item.ID != "item2" {
		t.Errorf("first pop ID = %v, want item2", popped.Item.ID)
	}

	popped = heap.Pop(h).(*heapItem)
	if popped.Item.ID != "item1" {
		t.Errorf("second pop ID = %v, want item1", popped.Item.ID)
	}

	popped = heap.Pop(h).(*heapItem)
	if popped.Item.ID != "item3" {
		t.Errorf("third pop ID = %v, want item3", popped.Item.ID)
	}
}

func BenchmarkMergeHeap_PushPop(b *testing.B) {
	h := NewMergeHeap("value", false)

	items := make([]*stac.Item, 100)
	for i := 0; i < 100; i++ {
		items[i] = testItemWithProperty(fmt.Sprintf("item%d", i), "coll1", "value", float64(i))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Push all items
		for j, item := range items {
			h.PushItem(item, fmt.Sprintf("origin%d", j), j)
		}

		// Pop all items
		for h.Len() > 0 {
			h.PopItem()
		}
	}
}

func BenchmarkCompareValues_String(b *testing.B) {
	a := "test-string-a"
	b_val := "test-string-b"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		compareValues(a, b_val)
	}
}

func BenchmarkCompareValues_Float64(b *testing.B) {
	a := 123.456
	b_val := 789.012

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		compareValues(a, b_val)
	}
}

func BenchmarkMergeSortIterator_Collect(b *testing.B) {
	fetcher := newMockPageFetcher()

	items := make([]*stac.Item, 100)
	for i := 0; i < 100; i++ {
		items[i] = testItemWithProperty(fmt.Sprintf("item%d", i), "coll1", "value", float64(i))
	}

	// Split into 10 pages of 10 items each
	pages := make([][]*stac.Item, 10)
	for i := 0; i < 10; i++ {
		pages[i] = items[i*10 : (i+1)*10]
	}
	fetcher.addPages("origin1", pages)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		// Reset fetcher state
		fetcher.calls = make(map[string]int)
		fetchers := map[string]PageFetcher{"origin1": fetcher}
		it := NewMergeSortIterator("value", false, fetchers, 0)
		it.Initialize()
		b.StartTimer()

		it.Collect()
	}
}
