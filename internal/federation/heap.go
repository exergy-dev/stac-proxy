// Package federation provides multi-origin STAC federation.
package federation

import (
	"container/heap"

	"github.com/yourorg/stac-proxy/internal/stac"
)

// MergeHeap implements a min-heap for merge-sort pagination.
// It maintains the next item from each origin, sorted by the sort key.
type MergeHeap struct {
	items    []*heapItem
	sortKey  string
	sortDesc bool
}

// heapItem wraps an item with its origin info.
type heapItem struct {
	Item     *stac.Item
	OriginID string
	Index    int // Index in the origin's result set
	SortVal  interface{}
}

// NewMergeHeap creates a new merge heap.
func NewMergeHeap(sortKey string, descending bool) *MergeHeap {
	h := &MergeHeap{
		items:    make([]*heapItem, 0),
		sortKey:  sortKey,
		sortDesc: descending,
	}
	heap.Init(h)
	return h
}

// Len returns the heap size.
func (h *MergeHeap) Len() int {
	return len(h.items)
}

// Less compares two items based on sort key.
func (h *MergeHeap) Less(i, j int) bool {
	vi := h.getSortValue(h.items[i])
	vj := h.getSortValue(h.items[j])

	cmp := compareValues(vi, vj)
	if h.sortDesc {
		return cmp > 0 // Greater values first for descending
	}
	return cmp < 0 // Lesser values first for ascending
}

// Swap swaps two items.
func (h *MergeHeap) Swap(i, j int) {
	h.items[i], h.items[j] = h.items[j], h.items[i]
}

// Push adds an item to the heap.
func (h *MergeHeap) Push(x interface{}) {
	h.items = append(h.items, x.(*heapItem))
}

// Pop removes and returns the minimum item.
func (h *MergeHeap) Pop() interface{} {
	old := h.items
	n := len(old)
	item := old[n-1]
	old[n-1] = nil // Avoid memory leak
	h.items = old[0 : n-1]
	return item
}

// Peek returns the minimum item without removing it.
func (h *MergeHeap) Peek() *heapItem {
	if len(h.items) == 0 {
		return nil
	}
	return h.items[0]
}

// PushItem adds a STAC item to the heap.
func (h *MergeHeap) PushItem(item *stac.Item, originID string, index int) {
	hi := &heapItem{
		Item:     item,
		OriginID: originID,
		Index:    index,
		SortVal:  h.extractSortValue(item),
	}
	heap.Push(h, hi)
}

// PopItem removes and returns the next item in sort order.
func (h *MergeHeap) PopItem() (*stac.Item, string, int) {
	if h.Len() == 0 {
		return nil, "", 0
	}
	hi := heap.Pop(h).(*heapItem)
	return hi.Item, hi.OriginID, hi.Index
}

// getSortValue returns the cached sort value for a heap item.
func (h *MergeHeap) getSortValue(item *heapItem) interface{} {
	if item.SortVal != nil {
		return item.SortVal
	}
	return h.extractSortValue(item.Item)
}

// extractSortValue extracts the sort value from an item.
func (h *MergeHeap) extractSortValue(item *stac.Item) interface{} {
	if item == nil || item.Properties.Extra == nil {
		return nil
	}
	return item.Properties.Extra[h.sortKey]
}

// compareValues compares two values of potentially different types.
func compareValues(a, b interface{}) int {
	if a == nil && b == nil {
		return 0
	}
	if a == nil {
		return -1
	}
	if b == nil {
		return 1
	}

	switch va := a.(type) {
	case string:
		if vb, ok := b.(string); ok {
			if va < vb {
				return -1
			}
			if va > vb {
				return 1
			}
			return 0
		}
	case float64:
		if vb, ok := b.(float64); ok {
			if va < vb {
				return -1
			}
			if va > vb {
				return 1
			}
			return 0
		}
	case int:
		if vb, ok := b.(int); ok {
			if va < vb {
				return -1
			}
			if va > vb {
				return 1
			}
			return 0
		}
	}

	// Fall back to string comparison
	sa := stringVal(a)
	sb := stringVal(b)
	if sa < sb {
		return -1
	}
	if sa > sb {
		return 1
	}
	return 0
}

// stringVal converts a value to string for comparison.
func stringVal(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// MergeSortIterator provides sorted iteration over multiple result sets.
type MergeSortIterator struct {
	heap     *MergeHeap
	fetchers map[string]PageFetcher
	buffers  map[string][]*stac.Item
	indices  map[string]int
	limit    int
	returned int
}

// PageFetcher fetches the next page for an origin.
type PageFetcher interface {
	FetchNextPage(originID string) ([]*stac.Item, bool, error)
}

// NewMergeSortIterator creates a new merge-sort iterator.
func NewMergeSortIterator(sortKey string, descending bool, fetchers map[string]PageFetcher, limit int) *MergeSortIterator {
	return &MergeSortIterator{
		heap:     NewMergeHeap(sortKey, descending),
		fetchers: fetchers,
		buffers:  make(map[string][]*stac.Item),
		indices:  make(map[string]int),
		limit:    limit,
	}
}

// Initialize loads the first page from each origin.
func (it *MergeSortIterator) Initialize() error {
	for originID, fetcher := range it.fetchers {
		items, hasMore, err := fetcher.FetchNextPage(originID)
		if err != nil {
			continue // Skip failed origins
		}

		it.buffers[originID] = items
		it.indices[originID] = 0

		// Push first item to heap
		if len(items) > 0 {
			it.heap.PushItem(items[0], originID, 0)
		}

		_ = hasMore // Track for later pages
	}
	return nil
}

// Next returns the next item in sorted order.
func (it *MergeSortIterator) Next() (*stac.Item, bool) {
	if it.limit > 0 && it.returned >= it.limit {
		return nil, false
	}

	if it.heap.Len() == 0 {
		return nil, false
	}

	// Pop the next item
	item, originID, idx := it.heap.PopItem()
	it.returned++

	// Push the next item from the same origin
	buffer := it.buffers[originID]
	nextIdx := idx + 1

	if nextIdx < len(buffer) {
		it.heap.PushItem(buffer[nextIdx], originID, nextIdx)
		it.indices[originID] = nextIdx
	} else {
		// Need to fetch next page from this origin
		if fetcher, ok := it.fetchers[originID]; ok {
			items, _, err := fetcher.FetchNextPage(originID)
			if err == nil && len(items) > 0 {
				it.buffers[originID] = items
				it.indices[originID] = 0
				it.heap.PushItem(items[0], originID, 0)
			}
		}
	}

	return item, true
}

// Collect returns all items up to the limit.
func (it *MergeSortIterator) Collect() []*stac.Item {
	var items []*stac.Item
	for {
		item, ok := it.Next()
		if !ok {
			break
		}
		items = append(items, item)
	}
	return items
}
