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
// Entries only ever leave a store by TTL expiry or LRU eviction — there
// is deliberately no Delete/Clear/Close surface, and backend lifecycle
// (the shared Redis client) is owned by main.
type Store interface {
	// Get retrieves a value from the cache.
	// Returns the value and true if found, nil and false otherwise.
	Get(ctx context.Context, key string) ([]byte, bool)

	// Set stores a value in the cache with the given TTL.
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
}

// CacheableRequest contains request information for cache decisions.
//
// PrincipalClass is an opaque per-principal namespace that the cache
// middleware derives from the request's authenticated principal (see
// principalClass in middleware.go). It is folded into the cache key
// digest so that responses cached for one principal class can never be
// served to a different one — closing the anonymous-vs-authenticated
// (and per-principal) cross-pollution path. BasicStrategy includes
// PrincipalClass in its key derivation.
type CacheableRequest struct {
	Method         string
	Path           string
	Query          string
	RequestType    string // collection, item, search, etc.
	Collection     string
	PrincipalClass string
}

// CacheEntry is the faithful representation of a cached upstream
// response. The middleware JSON-encodes it into the Store's []byte
// payload so status code and headers are restored on hit.
type CacheEntry struct {
	Status  int         `json:"s"`
	Headers http.Header `json:"h"`
	Body    []byte      `json:"b"`
}
