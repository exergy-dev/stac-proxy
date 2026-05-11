// Package ratelimit provides rate limiting middleware.
package ratelimit

import (
	"context"
	"sync"
	"time"
)

// Limiter defines the interface for rate limiters.
type Limiter interface {
	// Allow checks if a request is allowed for the given key.
	// Returns true if allowed, along with rate limit info.
	Allow(ctx context.Context, key string, quota Quota) (bool, Info, error)
}

// Quota defines a rate limit quota.
type Quota struct {
	Requests int           // Number of requests allowed
	Window   time.Duration // Time window for the quota
	Burst    int           // Maximum burst size (0 = same as Requests)
}

// Info contains rate limit information for response headers.
type Info struct {
	Limit      int   // Maximum requests allowed
	Remaining  int   // Remaining requests in current window
	ResetAt    int64 // Unix timestamp when the limit resets
	RetryAfter int   // Seconds until retry is allowed (if limited)
}

// SlidingWindowLimiter implements rate limiting using a sliding window algorithm.
type SlidingWindowLimiter struct {
	windows         map[string]*window
	mu              sync.RWMutex
	cleanupInterval time.Duration
}

type window struct {
	current   int
	previous  int
	timestamp time.Time
	mu        sync.Mutex
}

// NewSlidingWindowLimiter creates a new sliding window rate limiter.
func NewSlidingWindowLimiter() *SlidingWindowLimiter {
	l := &SlidingWindowLimiter{
		windows:         make(map[string]*window),
		cleanupInterval: 10 * time.Minute,
	}

	// Start cleanup goroutine
	go l.cleanupLoop()

	return l
}

// Allow checks if a request is allowed under the rate limit.
func (l *SlidingWindowLimiter) Allow(ctx context.Context, key string, quota Quota) (bool, Info, error) {
	l.mu.RLock()
	w, exists := l.windows[key]
	l.mu.RUnlock()

	if !exists {
		l.mu.Lock()
		w, exists = l.windows[key]
		if !exists {
			w = &window{
				timestamp: time.Now(),
			}
			l.windows[key] = w
		}
		l.mu.Unlock()
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	now := time.Now()
	windowStart := now.Truncate(quota.Window)

	// Check if we need to slide the window
	if w.timestamp.Before(windowStart) {
		// Current window is old, slide
		if w.timestamp.Add(quota.Window).Before(windowStart) {
			// Both windows are old
			w.previous = 0
			w.current = 0
		} else {
			// Only current is old
			w.previous = w.current
			w.current = 0
		}
		w.timestamp = windowStart
	}

	// Calculate weighted count using sliding window
	elapsed := now.Sub(windowStart)
	weight := float64(quota.Window-elapsed) / float64(quota.Window)
	count := int(float64(w.previous)*weight) + w.current

	burst := quota.Burst
	if burst == 0 {
		burst = quota.Requests
	}

	info := Info{
		Limit:     quota.Requests,
		Remaining: quota.Requests - count - 1,
		ResetAt:   windowStart.Add(quota.Window).Unix(),
	}

	if info.Remaining < 0 {
		info.Remaining = 0
	}

	// Check if over limit
	if count >= burst {
		info.RetryAfter = int(quota.Window.Seconds() - elapsed.Seconds())
		if info.RetryAfter < 1 {
			info.RetryAfter = 1
		}
		return false, info, nil
	}

	// Allow and increment
	w.current++
	return true, info, nil
}

// cleanupLoop periodically removes old windows.
func (l *SlidingWindowLimiter) cleanupLoop() {
	ticker := time.NewTicker(l.cleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		l.cleanup()
	}
}

// cleanup removes expired windows.
func (l *SlidingWindowLimiter) cleanup() {
	l.mu.Lock()
	defer l.mu.Unlock()

	cutoff := time.Now().Add(-2 * time.Hour)
	for key, w := range l.windows {
		w.mu.Lock()
		if w.timestamp.Before(cutoff) {
			delete(l.windows, key)
		}
		w.mu.Unlock()
	}
}

// Reset clears all rate limit data.
func (l *SlidingWindowLimiter) Reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.windows = make(map[string]*window)
}

// KeyFunc generates a rate limit key from a request.
type KeyFunc func(ctx context.Context, principalID, clientIP string) string

// DefaultKeyFunc returns the principal ID if available, otherwise the client IP.
func DefaultKeyFunc(ctx context.Context, principalID, clientIP string) string {
	if principalID != "" && principalID != "anonymous" {
		return "user:" + principalID
	}
	return "ip:" + clientIP
}

// QuotaFunc returns the quota for a request based on principal roles.
type QuotaFunc func(roles []string, defaultQuota Quota) Quota

// DefaultQuotaFunc returns the default quota.
func DefaultQuotaFunc(roles []string, defaultQuota Quota) Quota {
	return defaultQuota
}
