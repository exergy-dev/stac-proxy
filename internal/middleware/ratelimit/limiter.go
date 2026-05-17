// Package ratelimit: token-bucket limiter backed by golang.org/x/time/rate.
//
// Per-key buckets are kept in a bounded hashicorp/golang-lru/v2 cache so
// attacker-rotated source IPs cannot grow the map unboundedly
// (HIGH H-observability-1). LRU eviction also subsumes the previous
// idle-bucket cleanup goroutine: idle keys naturally fall out as new
// ones push them down the list.
package ratelimit

import (
	"context"
	"math"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"golang.org/x/time/rate"
)

const defaultMaxEntries = 50000

// Limiter abstracts a token-bucket-style decision. Kept as an interface
// so the HTTP middleware can be tested without scheduling real time.
type Limiter interface {
	Allow(ctx context.Context, key string, quota Quota) (bool, Info, error)
}

// Quota defines the sustained rate (Requests over Window) and the
// burst capacity. Burst defaults to Requests when zero.
type Quota struct {
	Requests int
	Window   time.Duration
	Burst    int
}

// Info populates the X-RateLimit-* response headers. Remaining is the
// pre-reservation floor of available tokens; ResetAt is the unix time
// at which the bucket would refill to its burst.
type Info struct {
	Limit      int
	Remaining  int
	ResetAt    int64
	RetryAfter int
}

// TokenBucketLimiter is the default Limiter implementation.
type TokenBucketLimiter struct {
	buckets *lru.Cache[string, *bucket]
}

type bucket struct {
	limiter *rate.Limiter
	quota   Quota
}

// NewTokenBucketLimiter constructs a limiter capped at maxEntries keys.
// Values <=0 fall back to defaultMaxEntries.
func NewTokenBucketLimiter(maxEntries int) *TokenBucketLimiter {
	if maxEntries <= 0 {
		maxEntries = defaultMaxEntries
	}
	c, _ := lru.New[string, *bucket](maxEntries)
	return &TokenBucketLimiter{buckets: c}
}

// Stop is a no-op kept for API compatibility with callers that defer it.
func (l *TokenBucketLimiter) Stop() {}

// Allow consumes one token from the per-key bucket. On deny the
// reservation is cancelled so the bucket isn't permanently held down.
func (l *TokenBucketLimiter) Allow(_ context.Context, key string, quota Quota) (bool, Info, error) {
	b := l.getOrCreate(key, quota)

	now := time.Now()
	burst := quota.Burst
	if burst == 0 {
		burst = quota.Requests
	}

	preTokens := b.limiter.TokensAt(now)
	preRem := int(math.Floor(preTokens))
	if preRem < 0 {
		preRem = 0
	}
	info := Info{
		Limit:     quota.Requests,
		Remaining: preRem,
		ResetAt:   resetAt(now, preTokens, float64(burst), quota).Unix(),
	}

	res := b.limiter.ReserveN(now, 1)
	delay := res.DelayFrom(now)
	if delay > 0 {
		res.CancelAt(now)
		info.RetryAfter = int(math.Ceil(delay.Seconds()))
		if info.RetryAfter < 1 {
			info.RetryAfter = 1
		}
		return false, info, nil
	}
	return true, info, nil
}

func (l *TokenBucketLimiter) getOrCreate(key string, quota Quota) *bucket {
	if b, ok := l.buckets.Get(key); ok && b.quota == quota {
		return b
	}
	burst := quota.Burst
	if burst == 0 {
		burst = quota.Requests
	}
	limit := rate.Limit(float64(quota.Requests) / quota.Window.Seconds())
	b := &bucket{limiter: rate.NewLimiter(limit, burst), quota: quota}
	l.buckets.Add(key, b)
	return b
}

// resetAt returns when the bucket would refill from `tokens` to `burst`
// at the quota's refill rate. Returns now when already full.
func resetAt(now time.Time, tokens, burst float64, quota Quota) time.Time {
	if tokens >= burst || quota.Requests <= 0 || quota.Window <= 0 {
		return now
	}
	if tokens < 0 {
		tokens = 0
	}
	rate := float64(quota.Requests) / quota.Window.Seconds()
	if rate <= 0 {
		return now
	}
	return now.Add(time.Duration((burst - tokens) / rate * float64(time.Second)))
}

// KeyFunc generates a rate limit key from a request.
type KeyFunc func(ctx context.Context, principalID, clientIP string) string

// DefaultKeyFunc returns the principal ID if available, otherwise the client IP.
func DefaultKeyFunc(_ context.Context, principalID, clientIP string) string {
	if principalID != "" && principalID != "anonymous" {
		return "user:" + principalID
	}
	return "ip:" + clientIP
}

// QuotaFunc returns the quota for a request based on principal roles.
type QuotaFunc func(roles []string, defaultQuota Quota) Quota

// DefaultQuotaFunc returns the default quota.
func DefaultQuotaFunc(_ []string, defaultQuota Quota) Quota { return defaultQuota }
