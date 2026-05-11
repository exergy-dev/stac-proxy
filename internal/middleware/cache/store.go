// Package cache provides caching middleware and cache stores.
package cache

import (
	"context"
	"time"
)

// Store defines the interface for cache storage backends.
type Store interface {
	// Get retrieves a value from the cache.
	// Returns the value and true if found, nil and false otherwise.
	Get(ctx context.Context, key string) ([]byte, bool)

	// Set stores a value in the cache with the given TTL.
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error

	// Delete removes a value from the cache.
	Delete(ctx context.Context, key string) error

	// Clear removes all values from the cache.
	Clear(ctx context.Context) error

	// Close releases any resources held by the store.
	Close() error
}

// Strategy defines the interface for cache strategy decisions.
type Strategy interface {
	// ShouldCache returns true if the request should be cached.
	ShouldCache(req CacheableRequest) bool

	// CacheKey generates a cache key for the request.
	CacheKey(req CacheableRequest) string

	// TTL returns the TTL for the cached response.
	TTL(req CacheableRequest, statusCode int) time.Duration
}

// CacheableRequest contains request information for cache decisions.
type CacheableRequest struct {
	Method      string
	Path        string
	Query       string
	RequestType string // collection, item, search, etc.
	Collection  string
}

// Stats contains cache statistics.
type Stats struct {
	Hits   int64
	Misses int64
	Size   int64
}

// StoreWithStats extends Store with statistics.
type StoreWithStats interface {
	Store
	Stats() Stats
}

// CacheEntry represents a cached item with metadata.
type CacheEntry struct {
	Data      []byte    `json:"data"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// CacheStats provides cache statistics.
type CacheStats struct {
	Size   int
	Hits   int64
	Misses int64
}
