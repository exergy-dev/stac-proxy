// Package federation provides item deduplication for federated results.
package federation

// ItemDeduplicator provides exact item deduplication for federated
// results. The previous implementation switched to a rolling Bloom
// filter past 10 000 keys, but realistic federated pages never
// approached that bound (max page × max origins ≈ same threshold),
// so the bloom path was effectively dead and only added complexity.
// If unbounded deduplication is ever needed, reintroduce a bloom
// implementation behind an explicit opt-in.
type ItemDeduplicator struct {
	exact map[string]bool
}

// NewItemDeduplicator creates a new item deduplicator. expectedItems is
// used only to size the underlying map.
func NewItemDeduplicator(expectedItems int) *ItemDeduplicator {
	if expectedItems <= 0 {
		expectedItems = 1024
	}
	return &ItemDeduplicator{exact: make(map[string]bool, expectedItems)}
}

// IsDuplicate reports whether key has already been seen. It records key
// on first sight, so each unique key returns false exactly once.
func (d *ItemDeduplicator) IsDuplicate(key string) bool {
	if d.exact[key] {
		return true
	}
	d.exact[key] = true
	return false
}

// Reset clears the deduplicator.
func (d *ItemDeduplicator) Reset() {
	d.exact = make(map[string]bool)
}
