package ratelimit

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// TestLimiter_BoundsMapSizeUnderIPFlood (HIGH H-observability-1):
// inserting many distinct IPs must not grow the internal bucket map
// past the configured cap; the most-recently-used IPs should be
// retained while the oldest are evicted via LRU.
//
// Without the bound, an attacker rotating source IPs can push the
// map far past the active set before the (originally hours-long)
// cleanup ticker reclaims memory.
func TestLimiter_BoundsMapSizeUnderIPFlood(t *testing.T) {
	const cap = 50000
	const flood = 100000

	lim := NewTokenBucketLimiter(cap)
	defer lim.Stop()

	ctx := context.Background()
	q := Quota{Requests: 100, Window: time.Minute}

	for i := 0; i < flood; i++ {
		key := fmt.Sprintf("ip:198.51.100.%d", i) // RFC 5737 TEST-NET-2
		_, _, err := lim.Allow(ctx, key, q)
		if err != nil {
			t.Fatalf("Allow(%q) error: %v", key, err)
		}
	}

	lim.mu.Lock()
	size := len(lim.buckets)
	lruSize := lim.lru.Len()
	lim.mu.Unlock()

	if size > cap {
		t.Errorf("bucket map size = %d, want <= %d", size, cap)
	}
	if size != lruSize {
		t.Errorf("buckets map (%d) and LRU list (%d) out of sync", size, lruSize)
	}
	if size != cap {
		t.Errorf("bucket map size = %d, want exactly %d after flood", size, cap)
	}

	// MRU sanity: the LAST inserted key must still be present.
	mruKey := fmt.Sprintf("ip:198.51.100.%d", flood-1)
	lim.mu.Lock()
	_, mruOK := lim.buckets[mruKey]
	lim.mu.Unlock()
	if !mruOK {
		t.Errorf("most-recently-used key %q was evicted", mruKey)
	}

	// LRU sanity: the FIRST inserted key must have been evicted.
	lruKey := "ip:198.51.100.0"
	lim.mu.Lock()
	_, lruOK := lim.buckets[lruKey]
	lim.mu.Unlock()
	if lruOK {
		t.Errorf("least-recently-used key %q was retained (expected eviction)", lruKey)
	}
}

// TestLimiter_LRUBumpsOnAccess: re-accessing a near-LRU key must
// bump it to MRU so that subsequent inserts evict the next-oldest
// rather than the just-accessed key.
func TestLimiter_LRUBumpsOnAccess(t *testing.T) {
	lim := NewTokenBucketLimiter(3)
	defer lim.Stop()

	ctx := context.Background()
	q := Quota{Requests: 10, Window: time.Minute}

	for _, k := range []string{"a", "b", "c"} {
		if _, _, err := lim.Allow(ctx, k, q); err != nil {
			t.Fatalf("Allow(%q): %v", k, err)
		}
	}

	// Touch "a" so it becomes MRU.
	if _, _, err := lim.Allow(ctx, "a", q); err != nil {
		t.Fatalf("Allow(a, second): %v", err)
	}

	// Insert a fourth key — should evict "b" (now LRU), not "a".
	if _, _, err := lim.Allow(ctx, "d", q); err != nil {
		t.Fatalf("Allow(d): %v", err)
	}

	lim.mu.Lock()
	defer lim.mu.Unlock()
	if _, ok := lim.buckets["a"]; !ok {
		t.Errorf("MRU key 'a' was evicted")
	}
	if _, ok := lim.buckets["b"]; ok {
		t.Errorf("LRU key 'b' was retained")
	}
	if _, ok := lim.buckets["c"]; !ok {
		t.Errorf("key 'c' missing")
	}
	if _, ok := lim.buckets["d"]; !ok {
		t.Errorf("freshly-inserted key 'd' missing")
	}
}

// TestLimiter_DefaultMaxEntries: NewSlidingWindowLimiter applies the
// package-level defaultMaxEntries cap.
func TestLimiter_DefaultMaxEntries(t *testing.T) {
	lim := NewSlidingWindowLimiter()
	defer lim.Stop()
	if lim.maxEntries != defaultMaxEntries {
		t.Errorf("maxEntries = %d, want %d", lim.maxEntries, defaultMaxEntries)
	}
}

// TestLimiter_CleanupCutoffUsesWindow: a bucket whose lastSeen
// predates 2*Window should be evicted by cleanup, not the
// previously-hardcoded 2-hour cutoff.
func TestLimiter_CleanupCutoffUsesWindow(t *testing.T) {
	lim := NewTokenBucketLimiter(100)
	defer lim.Stop()

	ctx := context.Background()
	q := Quota{Requests: 1, Window: time.Second}

	if _, _, err := lim.Allow(ctx, "stale", q); err != nil {
		t.Fatalf("Allow: %v", err)
	}

	// Force lastSeen far enough in the past that 2*Window ago is in
	// the future of it.
	lim.mu.Lock()
	lim.buckets["stale"].lastSeen = time.Now().Add(-10 * time.Second)
	lim.mu.Unlock()

	lim.cleanup()

	lim.mu.Lock()
	_, present := lim.buckets["stale"]
	lim.mu.Unlock()
	if present {
		t.Errorf("idle bucket not reclaimed by cleanup using 2*Window cutoff")
	}
}
