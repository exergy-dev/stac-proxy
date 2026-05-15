// Package ratelimit provides rate limiting middleware.
package ratelimit

import (
	"container/list"
	"context"
	"math"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Default LRU bound for the per-key bucket map. Caps memory growth
// under attacker-rotated source IPs (HIGH H-observability-1).
const defaultMaxEntries = 50000

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
//
// HIGH H-observability-1: the per-key map is bounded by maxEntries
// using LRU eviction (container/list + map[string]*list.Element).
// Without the bound, attacker-rotated source IPs could grow the map
// arbitrarily before the (originally 2-hour) cleanup ran. The
// idle-bucket cleanup cutoff is also tightened to 2*Window so idle
// principals/IPs are reclaimed at the natural token-refill cadence.
type TokenBucketLimiter struct {
	mu              sync.Mutex
	buckets         map[string]*bucket
	lru             *list.List // values: string keys; front = MRU, back = LRU
	maxEntries      int
	cleanupInterval time.Duration
	stop            chan struct{}
	stopOnce        sync.Once
}

type bucket struct {
	limiter  *rate.Limiter
	quota    Quota
	lastSeen time.Time
	elem     *list.Element // points into TokenBucketLimiter.lru
}

// NewSlidingWindowLimiter creates a TokenBucketLimiter with the
// default LRU cap (defaultMaxEntries). The historical constructor
// name is retained so existing wiring compiles unchanged; callers
// that wanted strict sliding-window semantics should evaluate
// whether the token-bucket equivalent (same sustained rate, burst-shaped
// transient capacity) is acceptable -- for the common "Requests per
// Window" quota the visible behavior under typical load is identical.
func NewSlidingWindowLimiter() *TokenBucketLimiter {
	return NewTokenBucketLimiter(defaultMaxEntries)
}

// NewTokenBucketLimiter constructs a TokenBucketLimiter capped at
// maxEntries keys. Values <=0 fall back to defaultMaxEntries.
//
// (HIGH H-observability-1)
func NewTokenBucketLimiter(maxEntries int) *TokenBucketLimiter {
	if maxEntries <= 0 {
		maxEntries = defaultMaxEntries
	}
	l := &TokenBucketLimiter{
		buckets:         make(map[string]*bucket, maxEntries),
		lru:             list.New(),
		maxEntries:      maxEntries,
		cleanupInterval: 10 * time.Minute,
		stop:            make(chan struct{}),
	}
	go l.cleanupLoop()
	return l
}

// Stop terminates the background cleanup goroutine. Safe to call
// multiple times.
func (l *TokenBucketLimiter) Stop() {
	l.stopOnce.Do(func() { close(l.stop) })
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
//
// On insert, evicts the LRU bucket(s) until len(buckets) < maxEntries.
// Existing-key access bumps the bucket to MRU. (HIGH H-observability-1)
func (l *TokenBucketLimiter) getOrCreate(key string, quota Quota) *bucket {
	burst := quota.Burst
	if burst == 0 {
		burst = quota.Requests
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if b, ok := l.buckets[key]; ok && b.quota == quota {
		b.lastSeen = time.Now()
		if b.elem != nil {
			l.lru.MoveToFront(b.elem)
		}
		return b
	}

	// Either new key, or existing key with a changed quota shape.
	if existing, ok := l.buckets[key]; ok {
		// Quota shape changed: drop the old bucket so the rebuilt one
		// reflects the new limits. The LRU element is reused below.
		if existing.elem != nil {
			l.lru.Remove(existing.elem)
		}
		delete(l.buckets, key)
	}

	// Evict the LRU until we're under cap. Loop in case maxEntries
	// was lowered or multiple stale entries are present.
	for len(l.buckets) >= l.maxEntries {
		if !l.evictLRU() {
			break
		}
	}

	limit := rate.Limit(float64(quota.Requests) / quota.Window.Seconds())
	elem := l.lru.PushFront(key)
	b := &bucket{
		limiter:  rate.NewLimiter(limit, burst),
		quota:    quota,
		lastSeen: time.Now(),
		elem:     elem,
	}
	l.buckets[key] = b
	return b
}

// evictLRU removes the least-recently-used bucket. Returns false if
// the LRU list was empty. Caller must hold l.mu.
func (l *TokenBucketLimiter) evictLRU() bool {
	back := l.lru.Back()
	if back == nil {
		return false
	}
	key, _ := back.Value.(string)
	l.lru.Remove(back)
	delete(l.buckets, key)
	return true
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

// cleanup evicts buckets that haven't been seen within 2*Window of
// their per-bucket quota. The 2*Window cutoff matches the natural
// token-refill cadence (a bucket idle longer than that has refilled
// to full and carries no useful state). (HIGH H-observability-1)
//
// The previous unconditional 2-hour cutoff allowed an attacker-driven
// IP rotation to grow the map ~120x the active set before reclaim;
// the LRU cap above bounds the worst case anyway, but the shorter
// cutoff keeps steady-state memory close to the active set size.
func (l *TokenBucketLimiter) cleanup() {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	for k, b := range l.buckets {
		cutoff := now.Add(-2 * b.quota.Window)
		if b.lastSeen.Before(cutoff) {
			if b.elem != nil {
				l.lru.Remove(b.elem)
			}
			delete(l.buckets, k)
		}
	}
}

// Reset clears all rate limit data.
func (l *TokenBucketLimiter) Reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.buckets = make(map[string]*bucket, l.maxEntries)
	l.lru = list.New()
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
