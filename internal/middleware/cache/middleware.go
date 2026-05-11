// Package cache provides caching middleware.
package cache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/yourorg/stac-proxy/internal/middleware"
)

// Middleware implements response caching.
type Middleware struct {
	middleware.BaseMiddleware
	store    Store
	strategy Strategy
}

// Config contains configuration for the cache middleware.
type Config struct {
	Store    Store
	Strategy Strategy
}

// NewMiddleware creates a new cache middleware.
func NewMiddleware(cfg Config) *Middleware {
	strategy := cfg.Strategy
	if strategy == nil {
		strategy = &BasicStrategy{
			CollectionTTL: 5 * time.Minute,
			ItemTTL:       1 * time.Minute,
			SearchTTL:     30 * time.Second,
		}
	}

	return &Middleware{
		BaseMiddleware: middleware.NewBaseMiddleware("cache", middleware.PriorityCache),
		store:          cfg.Store,
		strategy:       strategy,
	}
}

// ProcessRequest checks for cached responses.
func (m *Middleware) ProcessRequest(ctx context.Context, req *middleware.STACRequest) (*middleware.STACRequest, error) {
	cacheReq := CacheableRequest{
		Method:      req.Method,
		Path:        req.URL.Path,
		Query:       req.URL.RawQuery,
		RequestType: req.RequestType.String(),
		Collection:  req.Collection,
	}

	// Only cache GET requests
	if !m.strategy.ShouldCache(cacheReq) {
		return req, nil
	}

	key := m.strategy.CacheKey(cacheReq)

	// Check cache
	if data, found := m.store.Get(ctx, key); found {
		// Cache hit - store in context for response building
		ctx = context.WithValue(ctx, cacheHitKey, data)
		ctx = context.WithValue(ctx, cacheKeyKey, key)
		req.Context = ctx
	} else {
		// Cache miss - store key for later caching
		ctx = context.WithValue(ctx, cacheKeyKey, key)
		ctx = context.WithValue(ctx, cacheRequestKey, cacheReq)
		req.Context = ctx
	}

	return req, nil
}

// ProcessResponse caches successful responses or returns cached response.
func (m *Middleware) ProcessResponse(ctx context.Context, req *middleware.STACRequest,
	resp *middleware.STACResponse) (*middleware.STACResponse, error) {

	// Check for cache hit
	if cachedData, ok := ctx.Value(cacheHitKey).([]byte); ok {
		// Return cached response
		return &middleware.STACResponse{
			StatusCode: http.StatusOK,
			Headers: http.Header{
				"Content-Type":   []string{"application/json"},
				"X-Cache-Status": []string{"HIT"},
			},
			Body: cachedData,
		}, nil
	}

	// Only cache successful responses
	if resp.StatusCode != http.StatusOK {
		return resp, nil
	}

	// Get cache key and request info
	key, _ := ctx.Value(cacheKeyKey).(string)
	cacheReq, _ := ctx.Value(cacheRequestKey).(CacheableRequest)

	if key == "" {
		return resp, nil
	}

	// Calculate TTL
	ttl := m.strategy.TTL(cacheReq, resp.StatusCode)
	if ttl > 0 {
		// Cache the response
		if err := m.store.Set(ctx, key, resp.Body, ttl); err != nil {
			// Log error but don't fail the request
			fmt.Printf("cache set error: %v\n", err)
		}
	}

	// Add cache status header
	if resp.Headers == nil {
		resp.Headers = make(http.Header)
	}
	resp.Headers.Set("X-Cache-Status", "MISS")

	return resp, nil
}

// Context keys
type contextKeyType string

const (
	cacheHitKey     contextKeyType = "cache_hit"
	cacheKeyKey     contextKeyType = "cache_key"
	cacheRequestKey contextKeyType = "cache_request"
)

// BasicStrategy implements a basic caching strategy.
type BasicStrategy struct {
	CollectionTTL time.Duration
	ItemTTL       time.Duration
	SearchTTL     time.Duration
}

// ShouldCache returns true for GET requests.
func (s *BasicStrategy) ShouldCache(req CacheableRequest) bool {
	return req.Method == http.MethodGet
}

// CacheKey generates a cache key from the request.
func (s *BasicStrategy) CacheKey(req CacheableRequest) string {
	// Create a hash of the request details
	data := fmt.Sprintf("%s:%s:%s", req.Method, req.Path, req.Query)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:16]) // Use first 16 bytes
}

// TTL returns the TTL for the cached response.
func (s *BasicStrategy) TTL(req CacheableRequest, statusCode int) time.Duration {
	if statusCode != http.StatusOK {
		return 0 // Don't cache errors
	}

	switch req.RequestType {
	case "collection", "collections":
		return s.CollectionTTL
	case "item":
		return s.ItemTTL
	case "search":
		return s.SearchTTL
	default:
		return s.ItemTTL
	}
}

// NoOpStore is a cache store that doesn't cache anything.
type NoOpStore struct{}

func (s *NoOpStore) Get(ctx context.Context, key string) ([]byte, bool) { return nil, false }
func (s *NoOpStore) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	return nil
}
func (s *NoOpStore) Delete(ctx context.Context, key string) error { return nil }
func (s *NoOpStore) Clear(ctx context.Context) error              { return nil }
func (s *NoOpStore) Close() error                                 { return nil }
