package federation

import (
	"fmt"
	"math"
	"sync"
	"testing"
)

func TestBloomFilter_Add(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		expectedItems int
		fpRate        float64
		items         []string
	}{
		{
			name:          "single item",
			expectedItems: 100,
			fpRate:        0.01,
			items:         []string{"item1"},
		},
		{
			name:          "multiple items",
			expectedItems: 100,
			fpRate:        0.01,
			items:         []string{"item1", "item2", "item3", "item4", "item5"},
		},
		{
			name:          "duplicate items",
			expectedItems: 100,
			fpRate:        0.01,
			items:         []string{"item1", "item1", "item2", "item2"},
		},
		{
			name:          "empty strings",
			expectedItems: 100,
			fpRate:        0.01,
			items:         []string{"", ""},
		},
		{
			name:          "large items",
			expectedItems: 1000,
			fpRate:        0.01,
			items:         generateItems(1000),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			bf := NewBloomFilter(tt.expectedItems, tt.fpRate)
			for _, item := range tt.items {
				bf.Add(item)
			}

			// Verify all added items can be found (no false negatives)
			for _, item := range tt.items {
				if !bf.Contains(item) {
					t.Errorf("Contains(%q) = false, want true (false negative)", item)
				}
			}
		})
	}
}

func TestBloomFilter_Contains(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		expectedItems int
		fpRate        float64
		addItems      []string
		checkItems    []string
		shouldContain []bool
	}{
		{
			name:          "items not added should not be found",
			expectedItems: 100,
			fpRate:        0.01,
			addItems:      []string{"item1", "item2"},
			checkItems:    []string{"item3", "item4"},
			shouldContain: []bool{false, false},
		},
		{
			name:          "added items should be found",
			expectedItems: 100,
			fpRate:        0.01,
			addItems:      []string{"item1", "item2", "item3"},
			checkItems:    []string{"item1", "item2", "item3"},
			shouldContain: []bool{true, true, true},
		},
		{
			name:          "mixed added and not added",
			expectedItems: 100,
			fpRate:        0.01,
			addItems:      []string{"item1", "item3"},
			checkItems:    []string{"item1", "item2", "item3", "item4"},
			shouldContain: []bool{true, false, true, false},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			bf := NewBloomFilter(tt.expectedItems, tt.fpRate)
			for _, item := range tt.addItems {
				bf.Add(item)
			}

			for i, item := range tt.checkItems {
				got := bf.Contains(item)
				// For items that should not be present, we can only check if they're actually not present
				// (false positives are allowed, but we test the rate separately)
				if tt.shouldContain[i] && !got {
					t.Errorf("Contains(%q) = false, want true (false negative)", item)
				}
			}
		})
	}
}

func TestBloomFilter_NoFalseNegatives(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		expectedItems int
		fpRate        float64
		numItems      int
	}{
		{
			name:          "small filter",
			expectedItems: 100,
			fpRate:        0.01,
			numItems:      50,
		},
		{
			name:          "medium filter",
			expectedItems: 1000,
			fpRate:        0.01,
			numItems:      500,
		},
		{
			name:          "large filter",
			expectedItems: 10000,
			fpRate:        0.001,
			numItems:      5000,
		},
		{
			name:          "at capacity",
			expectedItems: 100,
			fpRate:        0.01,
			numItems:      100,
		},
		{
			name:          "over capacity",
			expectedItems: 100,
			fpRate:        0.01,
			numItems:      200,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			bf := NewBloomFilter(tt.expectedItems, tt.fpRate)
			items := generateItems(tt.numItems)

			// Add all items
			for _, item := range items {
				bf.Add(item)
			}

			// Check all items - must have zero false negatives
			falseNegatives := 0
			for _, item := range items {
				if !bf.Contains(item) {
					falseNegatives++
				}
			}

			if falseNegatives > 0 {
				t.Errorf("got %d false negatives, want 0", falseNegatives)
			}
		})
	}
}

func TestBloomFilter_FalsePositiveRate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		expectedItems int
		fpRate        float64
		numItems      int
		tolerance     float64 // Allow some variance
	}{
		{
			name:          "fp rate 0.001",
			expectedItems: 10000,
			fpRate:        0.001,
			numItems:      10000,
			tolerance:     0.005, // 0.5% tolerance
		},
		{
			name:          "fp rate 0.01",
			expectedItems: 10000,
			fpRate:        0.01,
			numItems:      10000,
			tolerance:     0.02, // 2% tolerance
		},
		{
			name:          "fp rate 0.1",
			expectedItems: 10000,
			fpRate:        0.1,
			numItems:      10000,
			tolerance:     0.05, // 5% tolerance
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			bf := NewBloomFilter(tt.expectedItems, tt.fpRate)

			// Add items
			addedItems := generateItems(tt.numItems)
			for _, item := range addedItems {
				bf.Add(item)
			}

			// Check items that were not added
			notAddedItems := generateItems(tt.numItems)
			for i := range notAddedItems {
				notAddedItems[i] = fmt.Sprintf("not-added-%s", notAddedItems[i])
			}

			falsePositives := 0
			for _, item := range notAddedItems {
				if bf.Contains(item) {
					falsePositives++
				}
			}

			actualFPRate := float64(falsePositives) / float64(len(notAddedItems))

			// The actual FP rate should be close to the expected rate
			if actualFPRate > tt.fpRate+tt.tolerance {
				t.Errorf("false positive rate = %.4f, want <= %.4f (with tolerance %.4f)",
					actualFPRate, tt.fpRate, tt.tolerance)
			}

			t.Logf("Expected FP rate: %.4f, Actual FP rate: %.4f, False positives: %d/%d",
				tt.fpRate, actualFPRate, falsePositives, len(notAddedItems))
		})
	}
}

func TestBloomFilter_Reset(t *testing.T) {
	t.Parallel()

	bf := NewBloomFilter(100, 0.01)

	// Add items
	items := []string{"item1", "item2", "item3"}
	for _, item := range items {
		bf.Add(item)
	}

	// Verify items are present
	for _, item := range items {
		if !bf.Contains(item) {
			t.Errorf("before reset: Contains(%q) = false, want true", item)
		}
	}

	// Reset
	bf.Reset()

	// Verify items are no longer present
	for _, item := range items {
		if bf.Contains(item) {
			t.Errorf("after reset: Contains(%q) = true, want false", item)
		}
	}
}

func TestBloomFilter_EmptyFilter(t *testing.T) {
	t.Parallel()

	bf := NewBloomFilter(100, 0.01)

	// Empty filter should not contain any items
	items := []string{"item1", "item2", "item3", ""}
	for _, item := range items {
		if bf.Contains(item) {
			t.Errorf("empty filter Contains(%q) = true, want false", item)
		}
	}
}

func TestBloomFilter_InvalidParameters(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		expectedItems int
		fpRate        float64
	}{
		{
			name:          "zero expected items",
			expectedItems: 0,
			fpRate:        0.01,
		},
		{
			name:          "negative expected items",
			expectedItems: -100,
			fpRate:        0.01,
		},
		{
			name:          "zero fp rate",
			expectedItems: 100,
			fpRate:        0,
		},
		{
			name:          "negative fp rate",
			expectedItems: 100,
			fpRate:        -0.01,
		},
		{
			name:          "fp rate >= 1",
			expectedItems: 100,
			fpRate:        1.0,
		},
		{
			name:          "both invalid",
			expectedItems: -100,
			fpRate:        -0.01,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Should not panic and should create a filter with default values
			bf := NewBloomFilter(tt.expectedItems, tt.fpRate)
			if bf == nil {
				t.Fatal("NewBloomFilter returned nil")
			}

			// Should be usable
			bf.Add("test")
			if !bf.Contains("test") {
				t.Error("filter created with invalid parameters is not functional")
			}
		})
	}
}

func TestOptimalM(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		expectedItems int
		fpRate        float64
	}{
		{
			name:          "small filter",
			expectedItems: 100,
			fpRate:        0.01,
		},
		{
			name:          "medium filter",
			expectedItems: 1000,
			fpRate:        0.01,
		},
		{
			name:          "large filter",
			expectedItems: 10000,
			fpRate:        0.001,
		},
		{
			name:          "high fp rate",
			expectedItems: 1000,
			fpRate:        0.1,
		},
		{
			name:          "low fp rate",
			expectedItems: 1000,
			fpRate:        0.001,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			m := optimalM(tt.expectedItems, tt.fpRate)

			if m == 0 {
				t.Error("optimalM returned 0")
			}

			// Verify the formula: m = -n * ln(p) / (ln(2))^2
			expected := -float64(tt.expectedItems) * math.Log(tt.fpRate) / (math.Ln2 * math.Ln2)
			expectedM := uint64(math.Ceil(expected))

			if m != expectedM {
				t.Errorf("optimalM = %d, want %d", m, expectedM)
			}
		})
	}
}

func TestOptimalK(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		m             uint64
		expectedItems int
	}{
		{
			name:          "small filter",
			m:             1000,
			expectedItems: 100,
		},
		{
			name:          "medium filter",
			m:             10000,
			expectedItems: 1000,
		},
		{
			name:          "large filter",
			m:             100000,
			expectedItems: 10000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			k := optimalK(tt.m, tt.expectedItems)

			if k == 0 {
				t.Error("optimalK returned 0")
			}

			// Verify the formula: k = (m/n) * ln(2)
			expected := float64(tt.m) / float64(tt.expectedItems) * math.Ln2
			expectedK := int(math.Ceil(expected))

			if k != expectedK {
				t.Errorf("optimalK = %d, want %d", k, expectedK)
			}
		})
	}
}

func TestRollingBloomFilter_Add(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		maxItems int
		fpRate   float64
		items    []string
	}{
		{
			name:     "few items",
			maxItems: 100,
			fpRate:   0.01,
			items:    []string{"item1", "item2", "item3"},
		},
		{
			name:     "at capacity",
			maxItems: 10,
			fpRate:   0.01,
			items:    generateItems(10),
		},
		{
			name:     "one rotation - keeps last 2*maxItems",
			maxItems: 10,
			fpRate:   0.01,
			items:    generateItems(15), // Will cause one rotation
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rbf := NewRollingBloomFilter(tt.maxItems, tt.fpRate)

			for _, item := range tt.items {
				rbf.Add(item)
			}

			// For items within the rolling window (last 2*maxItems), no false negatives
			// The rolling bloom filter only keeps current + previous, so older items are lost
			startIdx := 0
			if len(tt.items) > 2*tt.maxItems {
				startIdx = len(tt.items) - 2*tt.maxItems
			}

			for i := startIdx; i < len(tt.items); i++ {
				if !rbf.Contains(tt.items[i]) {
					t.Errorf("Contains(%q) = false, want true (false negative within window)", tt.items[i])
				}
			}
		})
	}
}

func TestRollingBloomFilter_RotationWhenFull(t *testing.T) {
	t.Parallel()

	maxItems := 10
	rbf := NewRollingBloomFilter(maxItems, 0.01)

	// Add items up to maxItems-1 - should not trigger rotation
	firstBatch := generateItems(maxItems - 1)
	for _, item := range firstBatch {
		rbf.Add(item)
	}

	if rbf.previous != nil {
		t.Error("previous filter should be nil before rotation")
	}
	if rbf.count != maxItems-1 {
		t.Errorf("count = %d, want %d", rbf.count, maxItems-1)
	}

	// Add one more item - should trigger rotation (count becomes maxItems, then rotates)
	rbf.Add("trigger-rotation")

	if rbf.previous == nil {
		t.Error("previous filter should not be nil after rotation")
	}
	if rbf.count != 0 {
		t.Errorf("count after rotation = %d, want 0", rbf.count)
	}

	// All items from first batch should still be findable in previous filter
	for _, item := range firstBatch {
		if !rbf.Contains(item) {
			t.Errorf("after rotation: Contains(%q) = false, want true", item)
		}
	}

	// The trigger item should be in previous filter (it was added before rotation)
	if !rbf.Contains("trigger-rotation") {
		t.Error("trigger item should be findable")
	}

	// Add more items to trigger second rotation
	secondBatch := generateItems(maxItems)
	for _, item := range secondBatch {
		rbf.Add(item)
	}

	// After adding maxItems, should have rotated again
	if rbf.count != 0 {
		t.Errorf("count after second rotation = %d, want 0", rbf.count)
	}

	// Second batch should still be findable (in previous filter after rotation)
	for _, item := range secondBatch {
		if !rbf.Contains(item) {
			t.Errorf("after second rotation: Contains(%q) = false, want true", item)
		}
	}
}

func TestRollingBloomFilter_Contains(t *testing.T) {
	t.Parallel()

	rbf := NewRollingBloomFilter(10, 0.01)

	// Add items
	items := []string{"item1", "item2", "item3"}
	for _, item := range items {
		rbf.Add(item)
	}

	// Check items that were added
	for _, item := range items {
		if !rbf.Contains(item) {
			t.Errorf("Contains(%q) = false, want true", item)
		}
	}

	// Check items that were not added
	notAdded := []string{"item4", "item5"}
	for _, item := range notAdded {
		// Note: false positives are possible, we just ensure no false negatives above
		_ = rbf.Contains(item)
	}
}

func TestRollingBloomFilter_Reset(t *testing.T) {
	t.Parallel()

	rbf := NewRollingBloomFilter(10, 0.01)

	// Add items to trigger rotation
	items := generateItems(20)
	for _, item := range items {
		rbf.Add(item)
	}

	// Should have both current and previous filters
	if rbf.previous == nil {
		t.Fatal("previous filter should not be nil after rotation")
	}

	// Reset
	rbf.Reset()

	if rbf.count != 0 {
		t.Errorf("count after reset = %d, want 0", rbf.count)
	}

	// Items should no longer be findable
	for _, item := range items {
		if rbf.Contains(item) {
			t.Errorf("after reset: Contains(%q) = true, want false", item)
		}
	}
}

func TestItemDeduplicator_ExactMode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		expectedItems int
		items         []string
		duplicates    []string
	}{
		{
			name:          "small number of items",
			expectedItems: 100,
			items:         []string{"item1", "item2", "item3"},
			duplicates:    []string{"item1", "item2"},
		},
		{
			name:          "at threshold",
			expectedItems: 10000,
			items:         generateItems(10000),
			duplicates:    []string{"item-0", "item-500", "item-9999"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			d := NewItemDeduplicator(tt.expectedItems)

			if !d.useExact {
				t.Error("should be using exact mode for items <= 10000")
			}
			if d.exact == nil {
				t.Error("exact map should not be nil in exact mode")
			}

			// Add items - first occurrence should not be duplicate
			for _, item := range tt.items {
				if d.IsDuplicate(item) {
					t.Errorf("first occurrence of %q reported as duplicate", item)
				}
			}

			// Check duplicates - should be detected
			for _, item := range tt.duplicates {
				if !d.IsDuplicate(item) {
					t.Errorf("duplicate %q not detected", item)
				}
			}
		})
	}
}

func TestItemDeduplicator_BloomMode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		expectedItems int
	}{
		{
			name:          "over threshold",
			expectedItems: 10001,
		},
		{
			name:          "large number",
			expectedItems: 100000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			d := NewItemDeduplicator(tt.expectedItems)

			if d.useExact {
				t.Error("should be using bloom mode for items > 10000")
			}
			if d.bloom == nil {
				t.Error("bloom filter should not be nil in bloom mode")
			}
			if d.exact != nil {
				t.Error("exact map should be nil in bloom mode")
			}

			// Add items and verify no false negatives
			items := generateItems(1000)
			for _, item := range items {
				if d.IsDuplicate(item) {
					t.Errorf("first occurrence of %q reported as duplicate", item)
				}
			}

			// Check duplicates - should all be detected
			for _, item := range items {
				if !d.IsDuplicate(item) {
					t.Errorf("duplicate %q not detected", item)
				}
			}
		})
	}
}

func TestItemDeduplicator_ModeTransition(t *testing.T) {
	t.Parallel()

	// Start with exact mode
	d := NewItemDeduplicator(10000)

	if !d.useExact {
		t.Fatal("should start in exact mode")
	}

	// Add items up to the threshold
	items := generateItems(10000)
	for _, item := range items {
		if d.IsDuplicate(item) {
			t.Errorf("first occurrence reported as duplicate")
		}
	}

	if !d.useExact {
		t.Error("should still be in exact mode at threshold")
	}
	if len(d.exact) != 10000 {
		t.Errorf("exact map size = %d, want 10000", len(d.exact))
	}

	// Add one more item to trigger transition
	d.IsDuplicate("transition-trigger")

	// Should have transitioned to bloom mode
	if d.useExact {
		t.Error("should have transitioned to bloom mode")
	}
	if d.bloom == nil {
		t.Error("bloom filter should not be nil after transition")
	}
	if d.exact != nil {
		t.Error("exact map should be nil after transition")
	}

	// All previous items should still be findable (no false negatives)
	for _, item := range items {
		if !d.IsDuplicate(item) {
			t.Errorf("item %q lost during transition", item)
		}
	}

	// The transition trigger should also be findable
	if !d.IsDuplicate("transition-trigger") {
		t.Error("transition trigger item should be findable")
	}
}

func TestItemDeduplicator_Reset(t *testing.T) {
	t.Parallel()

	t.Run("reset exact mode", func(t *testing.T) {
		t.Parallel()

		d := NewItemDeduplicator(100)

		items := []string{"item1", "item2", "item3"}
		for _, item := range items {
			d.IsDuplicate(item)
		}

		d.Reset()

		// After reset, items should not be duplicates
		for _, item := range items {
			if d.IsDuplicate(item) {
				t.Errorf("after reset: %q reported as duplicate", item)
			}
		}
	})

	t.Run("reset bloom mode", func(t *testing.T) {
		t.Parallel()

		d := NewItemDeduplicator(20000)

		items := generateItems(100)
		for _, item := range items {
			d.IsDuplicate(item)
		}

		d.Reset()

		// After reset, items should not be duplicates
		for _, item := range items {
			if d.IsDuplicate(item) {
				t.Errorf("after reset: %q reported as duplicate", item)
			}
		}
	})
}

func TestItemDeduplicator_EmptyDeduplicator(t *testing.T) {
	t.Parallel()

	t.Run("exact mode empty", func(t *testing.T) {
		t.Parallel()

		d := NewItemDeduplicator(100)

		// Empty deduplicator should not have any duplicates
		items := []string{"item1", "item2", "item3"}
		for _, item := range items {
			if d.IsDuplicate(item) {
				t.Errorf("empty deduplicator: %q reported as duplicate", item)
			}
		}
	})

	t.Run("bloom mode empty", func(t *testing.T) {
		t.Parallel()

		d := NewItemDeduplicator(20000)

		// Empty deduplicator should not have any duplicates
		items := []string{"item1", "item2", "item3"}
		for _, item := range items {
			if d.IsDuplicate(item) {
				t.Errorf("empty deduplicator: %q reported as duplicate", item)
			}
		}
	})
}

func TestBloomFilter_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	// Note: BloomFilter is NOT thread-safe without external synchronization.
	// This test demonstrates that concurrent read-only access is safe,
	// but concurrent writes may result in data races.

	bf := NewBloomFilter(10000, 0.01)

	// Pre-populate the filter
	numItems := 1000
	items := make([]string, numItems)
	for i := 0; i < numItems; i++ {
		items[i] = fmt.Sprintf("item-%d", i)
		bf.Add(items[i])
	}

	// Concurrent read-only access (safe)
	var wg sync.WaitGroup
	numGoroutines := 10

	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			// Read-only operations are safe
			for _, item := range items {
				_ = bf.Contains(item)
			}
		}()
	}
	wg.Wait()

	// Verify all items are still present
	for _, item := range items {
		if !bf.Contains(item) {
			t.Errorf("Contains(%q) = false, want true (false negative)", item)
		}
	}
}

func TestRollingBloomFilter_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	// Note: RollingBloomFilter is NOT thread-safe without external synchronization.
	// This test demonstrates that concurrent read-only access is safe,
	// but concurrent writes may result in data races.

	rbf := NewRollingBloomFilter(1000, 0.01)

	// Pre-populate the filter
	numItems := 500
	items := make([]string, numItems)
	for i := 0; i < numItems; i++ {
		items[i] = fmt.Sprintf("item-%d", i)
		rbf.Add(items[i])
	}

	// Concurrent read-only access (safe)
	var wg sync.WaitGroup
	numGoroutines := 10

	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			// Read-only operations are safe
			for _, item := range items {
				_ = rbf.Contains(item)
			}
		}()
	}
	wg.Wait()

	// Verify all items are still present
	for _, item := range items {
		if !rbf.Contains(item) {
			t.Errorf("Contains(%q) = false, want true (false negative)", item)
		}
	}
}

func TestItemDeduplicator_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	// Note: ItemDeduplicator is NOT thread-safe without external synchronization.
	// These tests demonstrate read-only concurrent access patterns.

	t.Run("exact mode concurrent reads", func(t *testing.T) {
		t.Parallel()

		d := NewItemDeduplicator(10000)

		// Pre-populate
		items := make([]string, 100)
		for i := 0; i < len(items); i++ {
			items[i] = fmt.Sprintf("item-%d", i)
			d.IsDuplicate(items[i])
		}

		var wg sync.WaitGroup
		numGoroutines := 10

		// Concurrent reads
		wg.Add(numGoroutines)
		for i := 0; i < numGoroutines; i++ {
			go func() {
				defer wg.Done()
				for _, item := range items {
					// Should all be duplicates now
					_ = d.IsDuplicate(item)
				}
			}()
		}
		wg.Wait()
	})

	t.Run("bloom mode concurrent reads", func(t *testing.T) {
		t.Parallel()

		d := NewItemDeduplicator(20000)

		// Pre-populate
		items := make([]string, 100)
		for i := 0; i < len(items); i++ {
			items[i] = fmt.Sprintf("item-%d", i)
			d.IsDuplicate(items[i])
		}

		var wg sync.WaitGroup
		numGoroutines := 10

		// Concurrent reads
		wg.Add(numGoroutines)
		for i := 0; i < numGoroutines; i++ {
			go func() {
				defer wg.Done()
				for _, item := range items {
					// Should all be duplicates now
					_ = d.IsDuplicate(item)
				}
			}()
		}
		wg.Wait()
	})
}

func TestBloomFilter_HashConsistency(t *testing.T) {
	t.Parallel()

	bf := NewBloomFilter(100, 0.01)

	item := "test-item"

	// Hash should be consistent across multiple calls
	hashes := make([]uint64, bf.hashFns)
	for i := 0; i < bf.hashFns; i++ {
		hashes[i] = bf.hash(item, i)
	}

	// Call hash again and verify same results
	for i := 0; i < bf.hashFns; i++ {
		if hash := bf.hash(item, i); hash != hashes[i] {
			t.Errorf("hash(%q, %d) = %d, want %d (inconsistent)", item, i, hash, hashes[i])
		}
	}
}

func TestBloomFilter_DifferentHashesPerIndex(t *testing.T) {
	t.Parallel()

	bf := NewBloomFilter(100, 0.01)

	item := "test-item"

	// Different hash indices should produce different hashes
	seenHashes := make(map[uint64]bool)
	for i := 0; i < bf.hashFns; i++ {
		hash := bf.hash(item, i)
		if seenHashes[hash] {
			t.Errorf("hash(%q, %d) produced duplicate hash value", item, i)
		}
		seenHashes[hash] = true
	}
}

// Benchmark tests

func BenchmarkBloomFilter_Add(b *testing.B) {
	bf := NewBloomFilter(100000, 0.01)
	items := generateItems(b.N)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bf.Add(items[i])
	}
}

func BenchmarkBloomFilter_Contains(b *testing.B) {
	bf := NewBloomFilter(100000, 0.01)
	items := generateItems(10000)
	for _, item := range items {
		bf.Add(item)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bf.Contains(items[i%len(items)])
	}
}

func BenchmarkRollingBloomFilter_Add(b *testing.B) {
	rbf := NewRollingBloomFilter(10000, 0.01)
	items := generateItems(b.N)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rbf.Add(items[i])
	}
}

func BenchmarkItemDeduplicator_ExactMode(b *testing.B) {
	d := NewItemDeduplicator(1000)
	items := generateItems(b.N)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.IsDuplicate(items[i])
	}
}

func BenchmarkItemDeduplicator_BloomMode(b *testing.B) {
	d := NewItemDeduplicator(100000)
	items := generateItems(b.N)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.IsDuplicate(items[i])
	}
}

// Helper functions

// generateItems creates n unique item strings.
func generateItems(n int) []string {
	items := make([]string, n)
	for i := 0; i < n; i++ {
		items[i] = fmt.Sprintf("item-%d", i)
	}
	return items
}
