package ratelimit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestRedisLimiter(t *testing.T) (*RedisLimiter, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr(), MaxRetries: -1})
	t.Cleanup(func() { _ = client.Close() })
	return NewRedisLimiter(client, "t:rl:", nil), mr
}

func TestRedisLimiter_BurstThenDeny(t *testing.T) {
	t.Parallel()
	l, _ := newTestRedisLimiter(t)
	ctx := context.Background()
	quota := Quota{Requests: 60, Window: time.Minute, Burst: 3}

	for i := 0; i < 3; i++ {
		allowed, info, err := l.Allow(ctx, "user:alice", quota)
		require.NoError(t, err)
		assert.True(t, allowed, "request %d within burst must be allowed", i+1)
		assert.Equal(t, 60, info.Limit)
	}
	allowed, info, err := l.Allow(ctx, "user:alice", quota)
	require.NoError(t, err)
	assert.False(t, allowed, "burst exhausted; must deny")
	assert.GreaterOrEqual(t, info.RetryAfter, 1, "deny must carry Retry-After >= 1s")

	// A different key has its own bucket.
	allowed, _, err = l.Allow(ctx, "user:bob", quota)
	require.NoError(t, err)
	assert.True(t, allowed)
}

func TestRedisLimiter_RefillOverTime(t *testing.T) {
	t.Parallel()
	l, _ := newTestRedisLimiter(t)
	ctx := context.Background()
	// 1 token/second, burst 1.
	quota := Quota{Requests: 60, Window: time.Minute, Burst: 1}

	allowed, _, err := l.Allow(ctx, "k", quota)
	require.NoError(t, err)
	require.True(t, allowed)

	allowed, _, err = l.Allow(ctx, "k", quota)
	require.NoError(t, err)
	require.False(t, allowed, "bucket drained")

	// The script's clock is ARGV-provided (real time), so refill is
	// observable by waiting real time, independent of miniredis's
	// frozen TIME.
	time.Sleep(1100 * time.Millisecond)
	allowed, _, err = l.Allow(ctx, "k", quota)
	require.NoError(t, err)
	assert.True(t, allowed, "one token must have refilled after ~1s")
}

func TestRedisLimiter_QuotaChangeStartsFreshBucket(t *testing.T) {
	t.Parallel()
	l, _ := newTestRedisLimiter(t)
	ctx := context.Background()

	small := Quota{Requests: 60, Window: time.Minute, Burst: 1}
	allowed, _, err := l.Allow(ctx, "k", small)
	require.NoError(t, err)
	require.True(t, allowed)
	allowed, _, err = l.Allow(ctx, "k", small)
	require.NoError(t, err)
	require.False(t, allowed, "small quota drained")

	// Same key, bigger quota (role change): fresh bucket — parity
	// with TokenBucketLimiter.getOrCreate's quota-mismatch reset.
	big := Quota{Requests: 600, Window: time.Minute, Burst: 10}
	allowed, _, err = l.Allow(ctx, "k", big)
	require.NoError(t, err)
	assert.True(t, allowed, "quota change must not inherit the drained bucket")
}

func TestRedisLimiter_SharedAcrossInstances(t *testing.T) {
	t.Parallel()
	mr := miniredis.RunT(t)
	clientA := redis.NewClient(&redis.Options{Addr: mr.Addr(), MaxRetries: -1})
	clientB := redis.NewClient(&redis.Options{Addr: mr.Addr(), MaxRetries: -1})
	t.Cleanup(func() { _ = clientA.Close(); _ = clientB.Close() })
	replicaA := NewRedisLimiter(clientA, "t:rl:", nil)
	replicaB := NewRedisLimiter(clientB, "t:rl:", nil)
	ctx := context.Background()
	quota := Quota{Requests: 60, Window: time.Minute, Burst: 2}

	allowed, _, err := replicaA.Allow(ctx, "user:alice", quota)
	require.NoError(t, err)
	require.True(t, allowed)
	allowed, _, err = replicaB.Allow(ctx, "user:alice", quota)
	require.NoError(t, err)
	require.True(t, allowed)

	// Third request on either replica: the bucket is global.
	allowed, _, err = replicaA.Allow(ctx, "user:alice", quota)
	require.NoError(t, err)
	assert.False(t, allowed, "quota must be enforced across replicas, not per replica")
}

func TestRedisLimiter_AtomicUnderConcurrency(t *testing.T) {
	t.Parallel()
	l, _ := newTestRedisLimiter(t)
	ctx := context.Background()
	// Burst 10, negligible refill within test runtime.
	quota := Quota{Requests: 10, Window: time.Hour, Burst: 10}

	var allowedCount atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			allowed, _, err := l.Allow(ctx, "hot-key", quota)
			if err == nil && allowed {
				allowedCount.Add(1)
			}
		}()
	}
	wg.Wait()
	assert.Equal(t, int32(10), allowedCount.Load(),
		"exactly burst-many concurrent requests may pass; more means the check-and-decrement raced")
}

func TestRedisLimiter_RedisDownReturnsError(t *testing.T) {
	t.Parallel()
	l, mr := newTestRedisLimiter(t)
	ctx := context.Background()
	quota := Quota{Requests: 10, Window: time.Minute}

	_, _, err := l.Allow(ctx, "k", quota)
	require.NoError(t, err)

	mr.Close()
	_, _, err = l.Allow(ctx, "k", quota)
	assert.Error(t, err, "outage must surface as an error so the middleware applies failure_mode")
}

func TestRedisLimiter_DegenerateQuotaDenies(t *testing.T) {
	t.Parallel()
	l, _ := newTestRedisLimiter(t)
	allowed, _, err := l.Allow(context.Background(), "k", Quota{})
	require.NoError(t, err)
	assert.False(t, allowed, "zero quota blocks everything, mirroring the memory limiter")
}

// TestMiddleware_FailureModes drives the HTTP middleware against a
// limiter whose backend is down: failure_mode open must serve the
// request, closed must refuse with 503.
func TestMiddleware_FailureModes(t *testing.T) {
	t.Parallel()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr(), MaxRetries: -1})
	t.Cleanup(func() { _ = client.Close() })
	mr.Close() // backend down from the start
	limiter := NewRedisLimiter(client, "t:rl:", nil)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	quota := Quota{Requests: 10, Window: time.Minute}

	t.Run("open serves the request", func(t *testing.T) {
		mw := NewHTTPMiddleware(Config{Limiter: limiter, DefaultQuota: quota})
		rr := httptest.NewRecorder()
		mw(inner).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/search", nil))
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("closed refuses with 503", func(t *testing.T) {
		mw := NewHTTPMiddleware(Config{Limiter: limiter, DefaultQuota: quota, FailClosed: true})
		rr := httptest.NewRecorder()
		mw(inner).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/search", nil))
		assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
		assert.Equal(t, "1", rr.Header().Get("Retry-After"))
		assert.Contains(t, rr.Body.String(), "RateLimiterUnavailable")
	})
}

// TestRedisLimiter_ResetAtParityWithMemory: X-RateLimit-Reset must not
// shift when an operator switches stores. Both backends compute it
// from PRE-consumption tokens.
func TestRedisLimiter_ResetAtParityWithMemory(t *testing.T) {
	t.Parallel()
	rl, _ := newTestRedisLimiter(t)
	ml := NewTokenBucketLimiter(0)
	ctx := context.Background()
	// 1 token/minute refill: a one-interval divergence would be 60s —
	// far larger than test scheduling jitter.
	quota := Quota{Requests: 60, Window: time.Hour, Burst: 5}

	_, rInfo, err := rl.Allow(ctx, "k", quota)
	require.NoError(t, err)
	_, mInfo, err := ml.Allow(ctx, "k", quota)
	require.NoError(t, err)

	assert.InDelta(t, mInfo.ResetAt, rInfo.ResetAt, 2,
		"ResetAt must agree across backends (both from pre-consumption tokens)")
	assert.Equal(t, mInfo.Remaining, rInfo.Remaining, "Remaining parity")
	assert.Equal(t, mInfo.Limit, rInfo.Limit, "Limit parity")
}
