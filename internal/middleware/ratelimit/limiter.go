// Package ratelimit provides rate limiting middleware.
package ratelimit

import (
	"context"
	"math"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Limiter defines the interface for rate limiters.
type Limiter interface {
	// Allow checks if a request is allowed for the given key.
	// Returns true if allowed, along with rate limit info.
	Allow(ctx context.Context, key string, quota Quota) (bool, Info, error)
}

// Quota defines a rate limit quota. Requests/Window sets the sustained
// rate; Burst is the maximum burst capacity (defaults to Requests when 0).
type Quota struct {
	Requests int
	Window   time.Duration
	Burst    int
}

// Info contains rate limit information for response headers.
type Info struct {
	Limit      int   // Maximum requests allowed
	Remaining  int   // Approximate remaining capacity
	ResetAt    int64 // Unix timestamp when full capacity is restored
	RetryAfter int   // Seconds until retry is allowed (if limited)
}

// TokenBucketLimiter is the default Limiter, backed by golang.org/x/time/rate.
// It maintains one rate.Limiter per key.
type TokenBucketLimiter struct {
	mu              sync.RWMutex
	buckets         map[string]*bucket
	cleanupInterval time.Duration
	stop            chan struct{}
}

type bucket struct {
	limiter  *rate.Limiter
	quota    Quota
	lastSeen time.Time
}

// NewSlidingWindowLimiter creates a TokenBucketLimiter. The historical
// constructor name is retained so existing wiring compiles unchanged;
// callers that wanted strict sliding-window semantics should evaluate
// whether the token-bucket equivalent (same sustained rate, burst-shaped
// transient capacity) is acceptable — for the common "Requests per
// Window" quota the visible behavior under typical load is identical.
func NewSlidingWindowLimiter() *TokenBucketLimiter {
	l := &TokenBucketLimiter{
		buckets:         make(map[string]*bucket),
		cleanupInterval: 10 * time.Minute,
		stop:            make(chan struct{}),
	}
	go l.cleanupLoop()
	return l
}

// Allow checks if a request is allowed under the rate limit.
func (l *TokenBucketLimiter) Allow(_ context.Context, key string, quota Quota) (bool, Info, error) {
	b := l.getOrCreate(key, quota)

	now := time.Now()
	res := b.limiter.ReserveN(now, 1)
	delay := res.DelayFrom(now)

	burst := quota.Burst
	if burst == 0 {
		burst = quota.Requests
	}

	info := Info{
		Limit:   quota.Requests,
		ResetAt: now.Add(time.Duration(burst) * quota.Window / time.Duration(quota.Requests)).Unix(),
	}

	if delay > 0 {
		// Over capacity: cancel the reservation so we don't block the
		// bucket, then report Retry-After.
		res.CancelAt(now)
		info.Remaining = 0
		info.RetryAfter = int(math.Ceil(delay.Seconds()))
		if info.RetryAfter < 1 {
			info.RetryAfter = 1
		}
		return false, info, nil
	}

	tokens := b.limiter.TokensAt(now)
	rem := int(math.Floor(tokens))
	if rem < 0 {
		rem = 0
	}
	info.Remaining = rem
	return true, info, nil
}

// getOrCreate looks up the per-key bucket or creates one. When the
// quota shape changes for an existing key (rare; happens if QuotaFunc
// returns a different Quota for the same key), the bucket is rebuilt.
func (l *TokenBucketLimiter) getOrCreate(key string, quota Quota) *bucket {
	burst := quota.Burst
	if burst == 0 {
		burst = quota.Requests
	}

	l.mu.RLock()
	b, ok := l.buckets[key]
	l.mu.RUnlock()
	if ok && b.quota == quota {
		l.mu.Lock()
		b.lastSeen = time.Now()
		l.mu.Unlock()
		return b
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok = l.buckets[key]
	if ok && b.quota == quota {
		b.lastSeen = time.Now()
		return b
	}
	limit := rate.Limit(float64(quota.Requests) / quota.Window.Seconds())
	b = &bucket{
		limiter:  rate.NewLimiter(limit, burst),
		quota:    quota,
		lastSeen: time.Now(),
	}
	l.buckets[key] = b
	return b
}

// cleanupLoop periodically evicts idle buckets to bound memory.
func (l *TokenBucketLimiter) cleanupLoop() {
	ticker := time.NewTicker(l.cleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			l.cleanup()
		case <-l.stop:
			return
		}
	}
}

func (l *TokenBucketLimiter) cleanup() {
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := time.Now().Add(-2 * time.Hour)
	for k, b := range l.buckets {
		if b.lastSeen.Before(cutoff) {
			delete(l.buckets, k)
		}
	}
}

// Reset clears all rate limit data.
func (l *TokenBucketLimiter) Reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.buckets = make(map[string]*bucket)
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
func DefaultQuotaFunc(_ []string, defaultQuota Quota) Quota {
	return defaultQuota
}
