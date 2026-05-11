// Package federation provides bloom filter for deduplication.
package federation

import (
	"encoding/binary"
	"hash/fnv"
	"math"
)

// BloomFilter provides space-efficient probabilistic duplicate detection.
// False positives are possible (item skipped when it shouldn't be).
// False negatives are impossible (duplicate never emitted twice).
type BloomFilter struct {
	bits    []uint64
	size    uint64
	hashFns int
}

// NewBloomFilter creates a new bloom filter with the given expected items and false positive rate.
func NewBloomFilter(expectedItems int, falsePositiveRate float64) *BloomFilter {
	if expectedItems <= 0 {
		expectedItems = 1000
	}
	if falsePositiveRate <= 0 || falsePositiveRate >= 1 {
		falsePositiveRate = 0.01
	}

	// Calculate optimal size and hash functions
	m := optimalM(expectedItems, falsePositiveRate)
	k := optimalK(m, expectedItems)

	return &BloomFilter{
		bits:    make([]uint64, (m+63)/64),
		size:    m,
		hashFns: k,
	}
}

// Add adds an item to the bloom filter.
func (bf *BloomFilter) Add(item string) {
	for i := 0; i < bf.hashFns; i++ {
		idx := bf.hash(item, i) % bf.size
		bf.bits[idx/64] |= 1 << (idx % 64)
	}
}

// Contains checks if an item might be in the bloom filter.
// Returns true if the item might be present, false if definitely not present.
func (bf *BloomFilter) Contains(item string) bool {
	for i := 0; i < bf.hashFns; i++ {
		idx := bf.hash(item, i) % bf.size
		if bf.bits[idx/64]&(1<<(idx%64)) == 0 {
			return false
		}
	}
	return true
}

// hash computes the i-th hash of the item using double hashing.
func (bf *BloomFilter) hash(item string, i int) uint64 {
	h := fnv.New64a()
	h.Write([]byte(item))
	hash1 := h.Sum64()

	h.Reset()
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, hash1)
	h.Write(b)
	hash2 := h.Sum64()

	return hash1 + uint64(i)*hash2
}

// Reset clears the bloom filter.
func (bf *BloomFilter) Reset() {
	for i := range bf.bits {
		bf.bits[i] = 0
	}
}

// optimalM calculates the optimal bit array size.
func optimalM(n int, p float64) uint64 {
	m := -float64(n) * math.Log(p) / (math.Ln2 * math.Ln2)
	return uint64(math.Ceil(m))
}

// optimalK calculates the optimal number of hash functions.
func optimalK(m uint64, n int) int {
	k := float64(m) / float64(n) * math.Ln2
	return int(math.Ceil(k))
}

// RollingBloomFilter tracks recent items using a pair of bloom filters.
// When the current filter fills up, it becomes the previous filter and a new one is created.
type RollingBloomFilter struct {
	current  *BloomFilter
	previous *BloomFilter
	count    int
	maxItems int
	fpRate   float64
}

// NewRollingBloomFilter creates a new rolling bloom filter.
func NewRollingBloomFilter(maxItems int, fpRate float64) *RollingBloomFilter {
	return &RollingBloomFilter{
		current:  NewBloomFilter(maxItems, fpRate),
		maxItems: maxItems,
		fpRate:   fpRate,
	}
}

// Add adds an item to the rolling bloom filter.
func (rbf *RollingBloomFilter) Add(item string) {
	rbf.current.Add(item)
	rbf.count++

	if rbf.count >= rbf.maxItems {
		// Rotate filters
		rbf.previous = rbf.current
		rbf.current = NewBloomFilter(rbf.maxItems, rbf.fpRate)
		rbf.count = 0
	}
}

// Contains checks if an item might be in the rolling bloom filter.
func (rbf *RollingBloomFilter) Contains(item string) bool {
	if rbf.current.Contains(item) {
		return true
	}
	if rbf.previous != nil && rbf.previous.Contains(item) {
		return true
	}
	return false
}

// Reset clears both filters.
func (rbf *RollingBloomFilter) Reset() {
	rbf.current.Reset()
	if rbf.previous != nil {
		rbf.previous.Reset()
	}
	rbf.count = 0
}

// ItemDeduplicator provides item deduplication for federated results.
type ItemDeduplicator struct {
	bloom    *RollingBloomFilter
	exact    map[string]bool // For small result sets, use exact tracking
	useExact bool
	maxExact int
}

// NewItemDeduplicator creates a new item deduplicator.
func NewItemDeduplicator(expectedItems int) *ItemDeduplicator {
	d := &ItemDeduplicator{
		maxExact: 10000,
	}

	if expectedItems <= d.maxExact {
		d.useExact = true
		d.exact = make(map[string]bool, expectedItems)
	} else {
		d.bloom = NewRollingBloomFilter(expectedItems, 0.001)
	}

	return d
}

// IsDuplicate checks if an item key is a duplicate.
// Returns true if the item has been seen before.
func (d *ItemDeduplicator) IsDuplicate(key string) bool {
	if d.useExact {
		if d.exact[key] {
			return true
		}
		d.exact[key] = true

		// Switch to bloom filter if we exceed the limit
		if len(d.exact) > d.maxExact {
			d.bloom = NewRollingBloomFilter(d.maxExact*10, 0.001)
			for k := range d.exact {
				d.bloom.Add(k)
			}
			d.exact = nil
			d.useExact = false
		}
		return false
	}

	if d.bloom.Contains(key) {
		return true
	}
	d.bloom.Add(key)
	return false
}

// Reset clears the deduplicator.
func (d *ItemDeduplicator) Reset() {
	if d.useExact {
		d.exact = make(map[string]bool)
	} else {
		d.bloom.Reset()
	}
}
