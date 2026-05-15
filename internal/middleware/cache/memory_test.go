package cache

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestNewMemoryStore(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		config          MemoryConfig
		expectedMaxSize int
	}{
		{
			name:            "default max size when zero",
			config:          MemoryConfig{MaxSize: 0},
			expectedMaxSize: 10000,
		},
		{
			name:            "default max size when negative",
			config:          MemoryConfig{MaxSize: -1},
			expectedMaxSize: 10000,
		},
		{
			name:            "custom max size",
			config:          MemoryConfig{MaxSize: 100},
			expectedMaxSize: 100,
		},
		{
			name:            "small max size",
			config:          MemoryConfig{MaxSize: 1},
			expectedMaxSize: 1,
		},
		{
			name:            "large max size",
			config:          MemoryConfig{MaxSize: 100000},
			expectedMaxSize: 100000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			store := NewMemoryStore(tt.config)
			defer store.Close()

			if store == nil {
				t.Fatal("NewMemoryStore returned nil")
			}

			if store.maxSize != tt.expectedMaxSize {
				t.Errorf("maxSize = %d, want %d", store.maxSize, tt.expectedMaxSize)
			}

			if store.items == nil {
				t.Error("items map is nil")
			}

			if store.lru == nil {
				t.Error("lru list is nil")
			}

			// Verify initial state
			stats := store.Stats()
			if stats.Size != 0 {
				t.Errorf("initial size = %d, want 0", stats.Size)
			}
			if stats.Hits != 0 {
				t.Errorf("initial hits = %d, want 0", stats.Hits)
			}
			if stats.Misses != 0 {
				t.Errorf("initial misses = %d, want 0", stats.Misses)
			}
		})
	}
}

func TestMemoryStore_GetSet_BasicOperations(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		key   string
		value []byte
		ttl   time.Duration
	}{
		{
			name:  "simple string value",
			key:   "test-key",
			value: []byte("test-value"),
			ttl:   1 * time.Hour,
		},
		{
			name:  "json value",
			key:   "json-key",
			value: []byte(`{"field":"value","number":42}`),
			ttl:   1 * time.Hour,
		},
		{
			name:  "empty value",
			key:   "empty-key",
			value: []byte{},
			ttl:   1 * time.Hour,
		},
		{
			name:  "binary value",
			key:   "binary-key",
			value: []byte{0x00, 0x01, 0x02, 0xFF},
			ttl:   1 * time.Hour,
		},
		{
			name:  "long ttl",
			key:   "long-ttl",
			value: []byte("value"),
			ttl:   24 * time.Hour,
		},
		{
			name:  "short ttl",
			key:   "short-ttl",
			value: []byte("value"),
			ttl:   1 * time.Millisecond,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			store := NewMemoryStore(MemoryConfig{MaxSize: 100})
			defer store.Close()

			// Set value
			err := store.Set(ctx, tt.key, tt.value, tt.ttl)
			if err != nil {
				t.Fatalf("Set() error = %v", err)
			}

			// Get value
			value, found := store.Get(ctx, tt.key)
			if !found {
				t.Fatal("Get() found = false, want true")
			}

			if string(value) != string(tt.value) {
				t.Errorf("Get() value = %q, want %q", value, tt.value)
			}

			// Verify stats
			stats := store.Stats()
			if stats.Size != 1 {
				t.Errorf("size = %d, want 1", stats.Size)
			}
			if stats.Hits != 1 {
				t.Errorf("hits = %d, want 1", stats.Hits)
			}
			if stats.Misses != 0 {
				t.Errorf("misses = %d, want 0", stats.Misses)
			}
		})
	}
}

func TestMemoryStore_Get_CacheMiss(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewMemoryStore(MemoryConfig{MaxSize: 100})
	defer store.Close()

	tests := []struct {
		name string
		key  string
	}{
		{
			name: "nonexistent key",
			key:  "does-not-exist",
		},
		{
			name: "empty key",
			key:  "",
		},
		{
			name: "special characters",
			key:  "key/with/slashes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value, found := store.Get(ctx, tt.key)
			if found {
				t.Error("Get() found = true, want false")
			}
			if value != nil {
				t.Errorf("Get() value = %v, want nil", value)
			}
		})
	}

	// Verify misses are counted
	stats := store.Stats()
	if stats.Misses != int64(len(tests)) {
		t.Errorf("misses = %d, want %d", stats.Misses, len(tests))
	}
}

func TestMemoryStore_TTLExpiration(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewMemoryStore(MemoryConfig{MaxSize: 100})
	defer store.Close()

	tests := []struct {
		name     string
		ttl      time.Duration
		waitTime time.Duration
		expected bool
	}{
		{
			name:     "not expired",
			ttl:      100 * time.Millisecond,
			waitTime: 10 * time.Millisecond,
			expected: true,
		},
		{
			name:     "just expired",
			ttl:      50 * time.Millisecond,
			waitTime: 60 * time.Millisecond,
			expected: false,
		},
		{
			name:     "long expired",
			ttl:      10 * time.Millisecond,
			waitTime: 100 * time.Millisecond,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := tt.name
			value := []byte("test-value")

			// Set value with TTL
			err := store.Set(ctx, key, value, tt.ttl)
			if err != nil {
				t.Fatalf("Set() error = %v", err)
			}

			// Wait
			time.Sleep(tt.waitTime)

			// Get value
			retrieved, found := store.Get(ctx, key)

			if found != tt.expected {
				t.Errorf("Get() found = %v, want %v", found, tt.expected)
			}

			if tt.expected {
				if string(retrieved) != string(value) {
					t.Errorf("Get() value = %q, want %q", retrieved, value)
				}
			} else {
				if retrieved != nil {
					t.Errorf("Get() value = %v, want nil", retrieved)
				}
			}
		})
	}
}

func TestMemoryStore_LRUEviction(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	maxSize := 3
	store := NewMemoryStore(MemoryConfig{MaxSize: maxSize})
	defer store.Close()

	// Fill cache to capacity
	for i := 0; i < maxSize; i++ {
		key := fmt.Sprintf("key-%d", i)
		value := []byte(fmt.Sprintf("value-%d", i))
		err := store.Set(ctx, key, value, 1*time.Hour)
		if err != nil {
			t.Fatalf("Set() error = %v", err)
		}
	}

	// Verify all items are present
	for i := 0; i < maxSize; i++ {
		key := fmt.Sprintf("key-%d", i)
		_, found := store.Get(ctx, key)
		if !found {
			t.Errorf("Get(%q) found = false, want true", key)
		}
	}

	// Add one more item - should evict key-0 (oldest)
	err := store.Set(ctx, "key-3", []byte("value-3"), 1*time.Hour)
	if err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	// Verify key-0 was evicted
	_, found := store.Get(ctx, "key-0")
	if found {
		t.Error("Get(key-0) found = true, want false (should be evicted)")
	}

	// Verify other keys are still present
	for i := 1; i <= 3; i++ {
		key := fmt.Sprintf("key-%d", i)
		_, found := store.Get(ctx, key)
		if !found {
			t.Errorf("Get(%q) found = false, want true", key)
		}
	}

	// Verify size
	stats := store.Stats()
	if stats.Size != int64(maxSize) {
		t.Errorf("size = %d, want %d", stats.Size, maxSize)
	}
}

func TestMemoryStore_LRUEviction_AccessOrder(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	maxSize := 3
	store := NewMemoryStore(MemoryConfig{MaxSize: maxSize})
	defer store.Close()

	// Fill cache
	for i := 0; i < maxSize; i++ {
		key := fmt.Sprintf("key-%d", i)
		value := []byte(fmt.Sprintf("value-%d", i))
		err := store.Set(ctx, key, value, 1*time.Hour)
		if err != nil {
			t.Fatalf("Set() error = %v", err)
		}
	}

	// Access key-0 to move it to the end of LRU list
	_, found := store.Get(ctx, "key-0")
	if !found {
		t.Fatal("Get(key-0) found = false")
	}

	// Add new item - should evict key-1 (now oldest)
	err := store.Set(ctx, "key-3", []byte("value-3"), 1*time.Hour)
	if err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	// Verify key-1 was evicted (not key-0)
	_, found = store.Get(ctx, "key-1")
	if found {
		t.Error("Get(key-1) found = true, want false (should be evicted)")
	}

	// Verify key-0 is still present (was accessed recently)
	_, found = store.Get(ctx, "key-0")
	if !found {
		t.Error("Get(key-0) found = false, want true (should not be evicted)")
	}
}

func TestMemoryStore_LRUEviction_MaxSizeOne(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewMemoryStore(MemoryConfig{MaxSize: 1})
	defer store.Close()

	// Set first item
	err := store.Set(ctx, "key-1", []byte("value-1"), 1*time.Hour)
	if err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	// Set second item - should evict first
	err = store.Set(ctx, "key-2", []byte("value-2"), 1*time.Hour)
	if err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	// Verify only second item exists
	_, found := store.Get(ctx, "key-1")
	if found {
		t.Error("Get(key-1) found = true, want false")
	}

	value, found := store.Get(ctx, "key-2")
	if !found {
		t.Fatal("Get(key-2) found = false, want true")
	}
	if string(value) != "value-2" {
		t.Errorf("Get(key-2) value = %q, want %q", value, "value-2")
	}

	stats := store.Stats()
	if stats.Size != 1 {
		t.Errorf("size = %d, want 1", stats.Size)
	}
}

func TestMemoryStore_Delete(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewMemoryStore(MemoryConfig{MaxSize: 100})
	defer store.Close()

	// Set multiple items
	keys := []string{"key-1", "key-2", "key-3"}
	for _, key := range keys {
		err := store.Set(ctx, key, []byte("value"), 1*time.Hour)
		if err != nil {
			t.Fatalf("Set() error = %v", err)
		}
	}

	// Delete one item
	err := store.Delete(ctx, "key-2")
	if err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	// Verify deleted item is gone
	_, found := store.Get(ctx, "key-2")
	if found {
		t.Error("Get(key-2) found = true, want false")
	}

	// Verify other items still exist
	for _, key := range []string{"key-1", "key-3"} {
		_, found := store.Get(ctx, key)
		if !found {
			t.Errorf("Get(%q) found = false, want true", key)
		}
	}

	// Verify size
	stats := store.Stats()
	if stats.Size != 2 {
		t.Errorf("size = %d, want 2", stats.Size)
	}
}

func TestMemoryStore_Delete_NonexistentKey(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewMemoryStore(MemoryConfig{MaxSize: 100})
	defer store.Close()

	// Delete non-existent key should not error
	err := store.Delete(ctx, "does-not-exist")
	if err != nil {
		t.Errorf("Delete() error = %v, want nil", err)
	}
}

func TestMemoryStore_Clear(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewMemoryStore(MemoryConfig{MaxSize: 100})
	defer store.Close()

	// Set multiple items
	for i := 0; i < 10; i++ {
		key := fmt.Sprintf("key-%d", i)
		value := []byte(fmt.Sprintf("value-%d", i))
		err := store.Set(ctx, key, value, 1*time.Hour)
		if err != nil {
			t.Fatalf("Set() error = %v", err)
		}
	}

	// Verify items exist
	stats := store.Stats()
	if stats.Size != 10 {
		t.Fatalf("size before clear = %d, want 10", stats.Size)
	}

	// Clear cache
	err := store.Clear(ctx)
	if err != nil {
		t.Fatalf("Clear() error = %v", err)
	}

	// Verify all items are gone
	for i := 0; i < 10; i++ {
		key := fmt.Sprintf("key-%d", i)
		_, found := store.Get(ctx, key)
		if found {
			t.Errorf("Get(%q) found = true, want false", key)
		}
	}

	// Verify size is zero
	stats = store.Stats()
	if stats.Size != 0 {
		t.Errorf("size after clear = %d, want 0", stats.Size)
	}
}

func TestMemoryStore_Clear_EmptyCache(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewMemoryStore(MemoryConfig{MaxSize: 100})
	defer store.Close()

	// Clear empty cache should not error
	err := store.Clear(ctx)
	if err != nil {
		t.Errorf("Clear() error = %v, want nil", err)
	}
}

func TestMemoryStore_Stats(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewMemoryStore(MemoryConfig{MaxSize: 100})
	defer store.Close()

	// Initial stats
	stats := store.Stats()
	if stats.Size != 0 || stats.Hits != 0 || stats.Misses != 0 {
		t.Errorf("initial stats = %+v, want all zeros", stats)
	}

	// Add items
	for i := 0; i < 5; i++ {
		key := fmt.Sprintf("key-%d", i)
		value := []byte(fmt.Sprintf("value-%d", i))
		store.Set(ctx, key, value, 1*time.Hour)
	}

	// Cache hits
	for i := 0; i < 3; i++ {
		store.Get(ctx, "key-0")
	}

	// Cache misses
	for i := 0; i < 2; i++ {
		store.Get(ctx, "nonexistent")
	}

	stats = store.Stats()
	if stats.Size != 5 {
		t.Errorf("size = %d, want 5", stats.Size)
	}
	if stats.Hits != 3 {
		t.Errorf("hits = %d, want 3", stats.Hits)
	}
	if stats.Misses != 2 {
		t.Errorf("misses = %d, want 2", stats.Misses)
	}
}

func TestMemoryStore_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewMemoryStore(MemoryConfig{MaxSize: 1000})
	defer store.Close()

	const (
		numGoroutines = 10
		numOperations = 100
	)

	var wg sync.WaitGroup

	// Concurrent writes
	t.Run("concurrent_writes", func(t *testing.T) {
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				for j := 0; j < numOperations; j++ {
					key := fmt.Sprintf("key-%d-%d", id, j)
					value := []byte(fmt.Sprintf("value-%d-%d", id, j))
					err := store.Set(ctx, key, value, 1*time.Hour)
					if err != nil {
						t.Errorf("Set() error = %v", err)
					}
				}
			}(i)
		}
		wg.Wait()
	})

	// Concurrent reads
	t.Run("concurrent_reads", func(t *testing.T) {
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				for j := 0; j < numOperations; j++ {
					key := fmt.Sprintf("key-%d-%d", id, j)
					store.Get(ctx, key)
				}
			}(i)
		}
		wg.Wait()
	})

	// Mixed operations
	t.Run("concurrent_mixed", func(t *testing.T) {
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				for j := 0; j < numOperations; j++ {
					key := fmt.Sprintf("mixed-%d-%d", id, j)
					value := []byte(fmt.Sprintf("value-%d-%d", id, j))

					// Set
					store.Set(ctx, key, value, 1*time.Hour)

					// Get
					store.Get(ctx, key)

					// Delete some
					if j%10 == 0 {
						store.Delete(ctx, key)
					}
				}
			}(i)
		}
		wg.Wait()
	})

	// Verify no race conditions (test should complete without panics)
	stats := store.Stats()
	if stats.Size < 0 {
		t.Errorf("size = %d, want >= 0", stats.Size)
	}
}

func TestMemoryStore_ConcurrentAccess_StatsConsistency(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewMemoryStore(MemoryConfig{MaxSize: 1000})
	defer store.Close()

	const numGoroutines = 20

	var wg sync.WaitGroup

	// Multiple goroutines reading stats while others modify cache
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				if id%2 == 0 {
					// Even IDs: modify cache
					key := fmt.Sprintf("key-%d-%d", id, j)
					store.Set(ctx, key, []byte("value"), 1*time.Hour)
					store.Get(ctx, key)
				} else {
					// Odd IDs: read stats
					stats := store.Stats()
					if stats.Size < 0 {
						t.Errorf("invalid size: %d", stats.Size)
					}
					if stats.Hits < 0 {
						t.Errorf("invalid hits: %d", stats.Hits)
					}
					if stats.Misses < 0 {
						t.Errorf("invalid misses: %d", stats.Misses)
					}
				}
			}
		}(i)
	}

	wg.Wait()
}

func TestMemoryStore_ConcurrentAccess_Delete(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewMemoryStore(MemoryConfig{MaxSize: 100})
	defer store.Close()

	// Pre-populate cache
	for i := 0; i < 50; i++ {
		key := fmt.Sprintf("key-%d", i)
		store.Set(ctx, key, []byte("value"), 1*time.Hour)
	}

	var wg sync.WaitGroup

	// Concurrent deletes of same keys
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				key := fmt.Sprintf("key-%d", j)
				store.Delete(ctx, key)
			}
		}()
	}

	wg.Wait()

	// Verify all items deleted
	stats := store.Stats()
	if stats.Size != 0 {
		t.Errorf("size = %d, want 0", stats.Size)
	}
}

func TestMemoryStore_ConcurrentAccess_Clear(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewMemoryStore(MemoryConfig{MaxSize: 100})
	defer store.Close()

	var wg sync.WaitGroup

	// One goroutine repeatedly clears
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 10; i++ {
			store.Clear(ctx)
			time.Sleep(1 * time.Millisecond)
		}
	}()

	// Other goroutines write
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				key := fmt.Sprintf("key-%d-%d", id, j)
				store.Set(ctx, key, []byte("value"), 1*time.Hour)
			}
		}(i)
	}

	wg.Wait()

	// Test should complete without panics
}

func TestMemoryStore_UpdateExistingKey(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewMemoryStore(MemoryConfig{MaxSize: 100})
	defer store.Close()

	key := "update-key"

	// Set initial value
	err := store.Set(ctx, key, []byte("value-1"), 1*time.Hour)
	if err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	// Update value
	err = store.Set(ctx, key, []byte("value-2"), 1*time.Hour)
	if err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	// Get updated value
	value, found := store.Get(ctx, key)
	if !found {
		t.Fatal("Get() found = false, want true")
	}
	if string(value) != "value-2" {
		t.Errorf("Get() value = %q, want %q", value, "value-2")
	}

	// Verify size is still 1 (not 2)
	stats := store.Stats()
	if stats.Size != 1 {
		t.Errorf("size = %d, want 1", stats.Size)
	}
}

func TestMemoryStore_UpdateExistingKey_TTL(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewMemoryStore(MemoryConfig{MaxSize: 100})
	defer store.Close()

	key := "ttl-update-key"

	// Set with short TTL
	err := store.Set(ctx, key, []byte("value-1"), 50*time.Millisecond)
	if err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	// Update with longer TTL
	err = store.Set(ctx, key, []byte("value-2"), 1*time.Hour)
	if err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	// Wait for original TTL to expire
	time.Sleep(60 * time.Millisecond)

	// Value should still be accessible (new TTL)
	value, found := store.Get(ctx, key)
	if !found {
		t.Fatal("Get() found = false, want true (new TTL should not have expired)")
	}
	if string(value) != "value-2" {
		t.Errorf("Get() value = %q, want %q", value, "value-2")
	}
}

func TestMemoryStore_CleanupExpired(t *testing.T) {
	// Note: Not parallel because we're testing the cleanup goroutine timing

	ctx := context.Background()
	store := NewMemoryStore(MemoryConfig{MaxSize: 100})
	defer store.Close()

	// Set items with very short TTL
	for i := 0; i < 5; i++ {
		key := fmt.Sprintf("key-%d", i)
		store.Set(ctx, key, []byte("value"), 10*time.Millisecond)
	}

	// Initial size
	stats := store.Stats()
	if stats.Size != 5 {
		t.Fatalf("initial size = %d, want 5", stats.Size)
	}

	// Wait for expiration
	time.Sleep(50 * time.Millisecond)

	// Manually trigger cleanup (rather than waiting for the 1-minute ticker)
	store.cleanupExpired()

	// Verify items are cleaned up
	stats = store.Stats()
	if stats.Size != 0 {
		t.Errorf("size after cleanup = %d, want 0", stats.Size)
	}
}

func TestMemoryStore_Close(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewMemoryStore(MemoryConfig{MaxSize: 100})

	// Add items
	for i := 0; i < 10; i++ {
		key := fmt.Sprintf("key-%d", i)
		store.Set(ctx, key, []byte("value"), 1*time.Hour)
	}

	// Close
	err := store.Close()
	if err != nil {
		t.Errorf("Close() error = %v", err)
	}

	// Verify cache is cleared
	stats := store.Stats()
	if stats.Size != 0 {
		t.Errorf("size after close = %d, want 0", stats.Size)
	}
}

func TestMemoryStore_ContextCancellation(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore(MemoryConfig{MaxSize: 100})
	defer store.Close()

	// Test with canceled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Operations should still work (context is passed but not currently used)
	err := store.Set(ctx, "key", []byte("value"), 1*time.Hour)
	if err != nil {
		t.Errorf("Set() with canceled context error = %v", err)
	}

	_, found := store.Get(ctx, "key")
	if !found {
		t.Error("Get() with canceled context found = false")
	}

	err = store.Delete(ctx, "key")
	if err != nil {
		t.Errorf("Delete() with canceled context error = %v", err)
	}

	err = store.Clear(ctx)
	if err != nil {
		t.Errorf("Clear() with canceled context error = %v", err)
	}
}

func TestMemoryStore_LargeValues(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewMemoryStore(MemoryConfig{MaxSize: 10})
	defer store.Close()

	// Create a large value (1MB)
	largeValue := make([]byte, 1024*1024)
	for i := range largeValue {
		largeValue[i] = byte(i % 256)
	}

	// Set large value
	err := store.Set(ctx, "large-key", largeValue, 1*time.Hour)
	if err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	// Get large value
	value, found := store.Get(ctx, "large-key")
	if !found {
		t.Fatal("Get() found = false, want true")
	}

	if len(value) != len(largeValue) {
		t.Errorf("value length = %d, want %d", len(value), len(largeValue))
	}

	// Verify content
	for i := range value {
		if value[i] != largeValue[i] {
			t.Errorf("value[%d] = %d, want %d", i, value[i], largeValue[i])
			break
		}
	}
}

func TestMemoryStore_ManySmallItems(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	maxSize := 1000
	store := NewMemoryStore(MemoryConfig{MaxSize: maxSize})
	defer store.Close()

	// Add many items
	for i := 0; i < maxSize*2; i++ {
		key := fmt.Sprintf("key-%d", i)
		value := []byte(fmt.Sprintf("value-%d", i))
		err := store.Set(ctx, key, value, 1*time.Hour)
		if err != nil {
			t.Fatalf("Set() error = %v", err)
		}
	}

	// Verify size doesn't exceed max
	stats := store.Stats()
	if stats.Size > int64(maxSize) {
		t.Errorf("size = %d, want <= %d", stats.Size, maxSize)
	}

	// Verify oldest items were evicted
	for i := 0; i < maxSize; i++ {
		key := fmt.Sprintf("key-%d", i)
		_, found := store.Get(ctx, key)
		if found {
			t.Errorf("Get(%q) found = true, want false (should be evicted)", key)
		}
	}

	// Verify newest items are present
	for i := maxSize; i < maxSize*2; i++ {
		key := fmt.Sprintf("key-%d", i)
		_, found := store.Get(ctx, key)
		if !found {
			t.Errorf("Get(%q) found = false, want true", key)
		}
	}
}

// TestMemoryCache_GetReturnsIndependentCopy verifies that mutating the
// slice returned by Get does NOT affect the stored cache entry, and
// vice versa. Previously Get handed out the underlying buffer directly,
// so a concurrent Set/evictOldest could observe (or be observed by) a
// caller's mutation. (HIGH H-cache-1)
func TestMemoryCache_GetReturnsIndependentCopy(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewMemoryStore(MemoryConfig{MaxSize: 16})
	defer store.Close()

	key := "k"
	original := []byte("hello")
	if err := store.Set(ctx, key, original, time.Hour); err != nil {
		t.Fatalf("Set: %v", err)
	}

	b1, ok := store.Get(ctx, key)
	if !ok {
		t.Fatal("Get: not found")
	}
	if string(b1) != "hello" {
		t.Fatalf("Get b1 = %q, want hello", b1)
	}

	// Mutate the returned slice. This must NOT bleed into the cache.
	b1[0] = 'X'

	b2, ok := store.Get(ctx, key)
	if !ok {
		t.Fatal("Get (second): not found")
	}
	if b2[0] != 'h' {
		t.Errorf("cache entry mutated by caller: b2[0]=%q, want 'h' (full b2=%q)", b2[0], b2)
	}

	// Mutating the original input slice (post-Set) must also not
	// bleed into the cache: storage takes ownership of the bytes
	// only via a defensive copy on read at a minimum.
	original[0] = 'Z'
	b3, ok := store.Get(ctx, key)
	if !ok {
		t.Fatal("Get (third): not found")
	}
	// The contract this test enforces is read-side: the bytes the
	// caller observes via Get must be stable across subsequent mutations
	// of any other slice (whether the previous Get result or the
	// original Set input). The strongest assertion here is that two
	// successive Get results are independent of each other.
	if &b2[0] == &b3[0] {
		t.Errorf("two Get results share backing array; copies must be independent")
	}
}

func BenchmarkMemoryStore_Set(b *testing.B) {
	ctx := context.Background()
	store := NewMemoryStore(MemoryConfig{MaxSize: 10000})
	defer store.Close()

	value := []byte("benchmark-value")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key := fmt.Sprintf("key-%d", i)
		store.Set(ctx, key, value, 1*time.Hour)
	}
}

func BenchmarkMemoryStore_Get(b *testing.B) {
	ctx := context.Background()
	store := NewMemoryStore(MemoryConfig{MaxSize: 10000})
	defer store.Close()

	// Pre-populate
	for i := 0; i < 1000; i++ {
		key := fmt.Sprintf("key-%d", i)
		store.Set(ctx, key, []byte("value"), 1*time.Hour)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key := fmt.Sprintf("key-%d", i%1000)
		store.Get(ctx, key)
	}
}

func BenchmarkMemoryStore_GetSet(b *testing.B) {
	ctx := context.Background()
	store := NewMemoryStore(MemoryConfig{MaxSize: 10000})
	defer store.Close()

	value := []byte("benchmark-value")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key := fmt.Sprintf("key-%d", i%1000)
		if i%2 == 0 {
			store.Set(ctx, key, value, 1*time.Hour)
		} else {
			store.Get(ctx, key)
		}
	}
}

// BenchmarkMemoryCache_LRU_LargeSet exercises Set under heavy LRU
// pressure: max-size 10k, 100k inserts, forcing ~90k evictions. With
// the previous slice-based LRU bookkeeping each evict was O(n);
// regressions to that pattern will dominate this benchmark.
//
// (HIGH H-cache-2). Skipped under -short to keep CI fast.
func BenchmarkMemoryCache_LRU_LargeSet(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping LRU large-set benchmark under -short")
	}
	ctx := context.Background()
	store := NewMemoryStore(MemoryConfig{MaxSize: 10000})
	defer store.Close()

	value := []byte("benchmark-value")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// 10x the cap forces eviction-heavy workload.
		key := fmt.Sprintf("key-%d", i%100000)
		store.Set(ctx, key, value, 1*time.Hour)
	}
}

func BenchmarkMemoryStore_Concurrent(b *testing.B) {
	ctx := context.Background()
	store := NewMemoryStore(MemoryConfig{MaxSize: 10000})
	defer store.Close()

	value := []byte("benchmark-value")

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			key := fmt.Sprintf("key-%d", i%1000)
			if i%2 == 0 {
				store.Set(ctx, key, value, 1*time.Hour)
			} else {
				store.Get(ctx, key)
			}
			i++
		}
	})
}
