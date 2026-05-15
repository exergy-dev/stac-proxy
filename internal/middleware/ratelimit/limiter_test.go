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

// TestLimiter_RemainingIsPreReservation (M-ratelimit-2): Info.Remaining
// reports the capacity the caller had *before* this Allow consumed a
// token. With a fresh bucket of burst=10, the first call sees
// Remaining=10 (not 9).
func TestLimiter_RemainingIsPreReservation(t *testing.T) {
	lim := NewTokenBucketLimiter(10)
	defer lim.Stop()

	q := Quota{Requests: 100, Window: time.Minute, Burst: 10}
	allowed, info, err := lim.Allow(context.Background(), "k", q)
	if err != nil {
		t.Fatalf("Allow: %v", err)
	}
	if !allowed {
		t.Fatalf("first Allow should succeed")
	}
	if info.Remaining != 10 {
		t.Errorf("first Allow Remaining: want 10 (pre-reservation), got %d", info.Remaining)
	}
	// Second call: bucket had 9 tokens before this consumed one.
	_, info2, err := lim.Allow(context.Background(), "k", q)
	if err != nil {
		t.Fatalf("Allow #2: %v", err)
	}
	if info2.Remaining != 9 {
		t.Errorf("second Allow Remaining: want 9 (pre-reservation), got %d", info2.Remaining)
	}
}

// TestLimiter_ResetAtReflectsBucketState (M-ratelimit-2): ResetAt
// shrinks back toward "now" as the bucket refills, not a constant
// derived from the quota shape. After fully draining the bucket the
// reset time should be roughly `burst / rate` seconds in the future;
// a fresh full bucket should reset essentially "now".
func TestLimiter_ResetAtReflectsBucketState(t *testing.T) {
	lim := NewTokenBucketLimiter(10)
	defer lim.Stop()

	// Choose a coarse rate (1 req/sec, burst 5) so deltas are
	// observable without flaky timing.
	q := Quota{Requests: 1, Window: time.Second, Burst: 5}

	// Fresh bucket: ResetAt should be ~now (no deficit to refill).
	_, info, err := lim.Allow(context.Background(), "k", q)
	if err != nil {
		t.Fatalf("Allow: %v", err)
	}
	now := time.Now().Unix()
	if info.ResetAt < now-1 || info.ResetAt > now+1 {
		t.Errorf("fresh-bucket ResetAt: want ~%d, got %d (delta=%ds)", now, info.ResetAt, info.ResetAt-now)
	}

	// Drain the bucket: 4 more allowed calls (1 already consumed +
	// 4 = burst 5).
	for i := 0; i < 4; i++ {
		_, _, _ = lim.Allow(context.Background(), "k", q)
	}
	// Next call should be denied; ResetAt should reflect the time to
	// refill from ~0 tokens to burst 5 -> 5 seconds at 1 req/sec.
	_, info2, _ := lim.Allow(context.Background(), "k", q)
	delta := info2.ResetAt - time.Now().Unix()
	if delta < 4 || delta > 6 {
		t.Errorf("drained-bucket ResetAt delta: want ~5s, got %ds", delta)
	}
}

// TestLimiter_QuotaChangeRetainsRemainingTokens (M-ratelimit-1):
// when the per-key quota changes (e.g., role change, config edit,
// non-deterministic QuotaFunc), the new bucket carries the *remaining*
// fraction of tokens proportionally rather than being reset to the
// new burst. Otherwise an attacker (or an unstable role lookup) could
// flip the quota every request and never accumulate throttle pressure.
func TestLimiter_QuotaChangeRetainsRemainingTokens(t *testing.T) {
	lim := NewTokenBucketLimiter(10)
	defer lim.Stop()

	ctx := context.Background()
	qA := Quota{Requests: 100, Window: time.Minute, Burst: 10}

	// Consume 80% of A's tokens (8 of 10).
	for i := 0; i < 8; i++ {
		allowed, _, err := lim.Allow(ctx, "k", qA)
		if err != nil {
			t.Fatalf("Allow %d: %v", i, err)
		}
		if !allowed {
			t.Fatalf("Allow %d should be allowed (under quota)", i)
		}
	}

	// Now switch quota: same per-second rate but a smaller burst.
	qB := Quota{Requests: 100, Window: time.Minute, Burst: 4}
	allowed, _, err := lim.Allow(ctx, "k", qB)
	if err != nil {
		t.Fatalf("Allow after quota change: %v", err)
	}

	// After the swap the bucket had ~2/10 of tokens left under qA;
	// scaled to qB's burst of 4 that's ~0.8 tokens carried, then
	// reduced by the just-served request to ~-0.2 (slightly below 0).
	// We cannot compare exactly because rate refills tokens, but we
	// CAN assert the bucket is NOT full: the next several requests
	// must be denied (or at least not all allowed) — a reset to a
	// fresh burst-of-4 bucket would let a subsequent burst of 4
	// through unimpeded.
	lim.mu.Lock()
	tokensAfter := lim.buckets["k"].limiter.TokensAt(time.Now())
	burstAfter := lim.buckets["k"].limiter.Burst()
	lim.mu.Unlock()

	if burstAfter != 4 {
		t.Fatalf("rebuilt bucket burst: want 4, got %d", burstAfter)
	}
	// Carried fraction was 0.2 (2/10) -> 0.2 * 4 = 0.8 tokens.
	// We then consumed 1 token in the Allow above, so expect <= 0.
	// At minimum the bucket must NOT be full (4 tokens) — that would
	// indicate a reset.
	if tokensAfter > 1.0 {
		t.Errorf("tokens after quota change = %.3f; expected <= 1 (carried fraction), reset would have given 4 (minus 1 consumed)", tokensAfter)
	}
	_ = allowed
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
