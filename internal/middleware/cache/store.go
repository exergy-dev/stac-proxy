// Package cache provides caching middleware and cache stores.
package cache

import (
	"context"
	"net/http"
	"time"
)

// Store defines the interface for cache storage backends. The unit of
// storage is an opaque []byte (currently a JSON-encoded CacheEntry; see
// middleware.go) so the same backend can hold any encodable payload.
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

// CacheEntry is the faithful representation of a cached upstream
// response. The middleware JSON-encodes it into the Store's []byte
// payload so status code and headers are restored on hit.
type CacheEntry struct {
	Status  int         `json:"s"`
	Headers http.Header `json:"h"`
	Body    []byte      `json:"b"`
}
