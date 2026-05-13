// Package cache provides caching middleware.
package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/yourorg/stac-proxy/internal/middleware"
)

// CacheStrategy determines cache behavior for different request types.
type CacheStrategy interface {
	// ShouldCache determines if a request should be cached.
	ShouldCache(req *middleware.STACRequest) bool

	// GetTTL returns the TTL for a request type.
	GetTTL(req *middleware.STACRequest) time.Duration

	// GenerateKey generates a cache key for the request.
	GenerateKey(req *middleware.STACRequest) string
}

// DefaultStrategy provides default caching behavior.
type DefaultStrategy struct {
	CollectionTTL time.Duration
	ItemTTL       time.Duration
	SearchTTL     time.Duration
	CatalogTTL    time.Duration
}

// NewDefaultStrategy creates a default cache strategy.
func NewDefaultStrategy() *DefaultStrategy {
	return &DefaultStrategy{
		CollectionTTL: 5 * time.Minute,
		ItemTTL:       1 * time.Minute,
		SearchTTL:     30 * time.Second,
		CatalogTTL:    10 * time.Minute,
	}
}

// ShouldCache determines if the request should be cached.
func (s *DefaultStrategy) ShouldCache(req *middleware.STACRequest) bool {
	// Only cache GET requests
	if req.Request.Method != "GET" {
		return false
	}

	// Cache based on request type
	switch req.RequestType {
	case middleware.RequestTypeLanding,
		middleware.RequestTypeConformance,
		middleware.RequestTypeCollections,
		middleware.RequestTypeCollection,
		middleware.RequestTypeItem,
		middleware.RequestTypeItems,
		middleware.RequestTypeQueryables,
		middleware.RequestTypeCollectionQueryables:
		return true
	case middleware.RequestTypeSearch:
		// Only cache simple searches
		return s.isSimpleSearch(req)
	default:
		return false
	}
}

// isSimpleSearch checks if a search is simple enough to cache.
func (s *DefaultStrategy) isSimpleSearch(req *middleware.STACRequest) bool {
	// Don't cache searches with too many parameters
	q := req.Request.URL.Query()
	if len(q) > 5 {
		return false
	}

	// Don't cache searches with complex filters
	if q.Get("filter") != "" {
		return false
	}

	return true
}

// GetTTL returns the TTL for the request type.
func (s *DefaultStrategy) GetTTL(req *middleware.STACRequest) time.Duration {
	switch req.RequestType {
	case middleware.RequestTypeLanding, middleware.RequestTypeConformance:
		return s.CatalogTTL
	case middleware.RequestTypeCollections, middleware.RequestTypeCollection:
		return s.CollectionTTL
	case middleware.RequestTypeItem, middleware.RequestTypeItems:
		return s.ItemTTL
	case middleware.RequestTypeSearch:
		return s.SearchTTL
	case middleware.RequestTypeQueryables, middleware.RequestTypeCollectionQueryables:
		return s.CollectionTTL
	default:
		return s.ItemTTL
	}
}

// GenerateKey generates a unique cache key for the request.
func (s *DefaultStrategy) GenerateKey(req *middleware.STACRequest) string {
	// Build key components
	var parts []string

	// Request type
	parts = append(parts, req.RequestType.String())

	// Path
	parts = append(parts, req.Request.URL.Path)

	// Collection and item IDs
	if req.Collection != "" {
		parts = append(parts, "c:"+req.Collection)
	}
	if req.ItemID != "" {
		parts = append(parts, "i:"+req.ItemID)
	}

	// Sorted query parameters for deterministic keys
	queryKey := normalizeQuery(req.Request.URL.Query())
	if queryKey != "" {
		parts = append(parts, queryKey)
	}

	// Hash for compact key
	key := strings.Join(parts, "|")
	hash := sha256.Sum256([]byte(key))
	return hex.EncodeToString(hash[:16])
}

// normalizeQuery creates a deterministic string from query parameters.
func normalizeQuery(q url.Values) string {
	if len(q) == 0 {
		return ""
	}

	// Sort keys
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Build normalized string
	var parts []string
	for _, k := range keys {
		values := q[k]
		sort.Strings(values)
		for _, v := range values {
			parts = append(parts, fmt.Sprintf("%s=%s", k, v))
		}
	}

	return strings.Join(parts, "&")
}

// NoCacheStrategy disables caching.
type NoCacheStrategy struct{}

// ShouldCache always returns false.
func (s *NoCacheStrategy) ShouldCache(req *middleware.STACRequest) bool {
	return false
}

// GetTTL returns zero.
func (s *NoCacheStrategy) GetTTL(req *middleware.STACRequest) time.Duration {
	return 0
}

// GenerateKey returns empty string.
func (s *NoCacheStrategy) GenerateKey(req *middleware.STACRequest) string {
	return ""
}
