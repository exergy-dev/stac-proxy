package ratelimit

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TokenBucketLimiter is a thin wrapper around golang.org/x/time/rate
// with an LRU bucket map. These tests cover the surface this package
// adds on top of the library: the LRU cap (defense against attacker IP
// rotation), basic Allow accounting, and the deny-path RetryAfter.

// HIGH H-observability-1: inserting many distinct keys must not grow
// past the configured cap.
func TestLimiter_BoundsMapSizeUnderIPFlood(t *testing.T) {
	const max = 1024
	lim := NewTokenBucketLimiter(max)
	defer lim.Stop()

	ctx := context.Background()
	q := Quota{Requests: 100, Window: time.Minute}
	for i := 0; i < max*4; i++ {
		key := fmt.Sprintf("ip:198.51.100.%d", i)
		_, _, err := lim.Allow(ctx, key, q)
		require.NoError(t, err, "Allow(%q)", key)
	}
	require.LessOrEqual(t, lim.buckets.Len(), max, "bucket count exceeds cap")
}

func TestLimiter_DenyAfterBurst(t *testing.T) {
	lim := NewTokenBucketLimiter(0)
	defer lim.Stop()
	ctx := context.Background()
	q := Quota{Requests: 10, Window: time.Second, Burst: 2}

	ok, _, _ := lim.Allow(ctx, "k", q)
	require.True(t, ok, "first request should be allowed")
	ok, _, _ = lim.Allow(ctx, "k", q)
	require.True(t, ok, "second request (within burst) should be allowed")
	ok, info, _ := lim.Allow(ctx, "k", q)
	require.False(t, ok, "third request (over burst) should be denied")
	require.GreaterOrEqual(t, info.RetryAfter, 1, "RetryAfter should be >=1")
}

func TestLimiter_QuotaChangeRebuildsBucket(t *testing.T) {
	lim := NewTokenBucketLimiter(0)
	defer lim.Stop()
	ctx := context.Background()

	// Consume the entire burst under the first quota.
	q1 := Quota{Requests: 1, Window: time.Second, Burst: 1}
	ok, _, _ := lim.Allow(ctx, "k", q1)
	require.True(t, ok, "first request should be allowed under q1")
	ok, _, _ = lim.Allow(ctx, "k", q1)
	require.False(t, ok, "expected deny under q1 after burst exhausted")

	// New quota shape rebuilds the bucket (no carryover by design).
	q2 := Quota{Requests: 10, Window: time.Second, Burst: 5}
	ok, _, _ = lim.Allow(ctx, "k", q2)
	require.True(t, ok, "expected allow under q2 (fresh bucket)")
}

