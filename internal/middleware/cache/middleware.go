// Package cache provides response-caching middleware.
//
// Cache is a chi-style http middleware that, on each request:
//   - reads the parsed STAC shape from r.Context() (set by the router)
//   - asks the configured Strategy whether to cache and what key to use
//   - on a cache hit, writes the cached response and short-circuits
//   - on a miss, buffers the inner handler's response via
//     httpx.ResponseCapture, writes it to the outer ResponseWriter,
//     and stores it in the cache when the status was 200.
package cache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/yourorg/stac-proxy/internal/httpx"
	"github.com/yourorg/stac-proxy/internal/middleware"
	"github.com/yourorg/stac-proxy/internal/middleware/auth"
	"github.com/yourorg/stac-proxy/internal/middleware/authz"
	"github.com/yourorg/stac-proxy/internal/observability"
)

// normalizeQuery returns a canonical form of raw with parameters sorted
// alphabetically by key (and per-key values preserved in original
// order). It is used to derive a cache key component so that
// permutations like "?a=1&b=2" and "?b=2&a=1" map to the same entry.
//
// HIGH H-cache-3: without this, the cache is keyed by the literal
// query string. An attacker can permute parameter order to bypass
// cached entries (cache poisoning vector if combined with
// per-principal entries; cache thrash for arbitrary callers).
//
// Falls back to raw on parse failure so a malformed query does not
// silently collapse into the same bucket as the empty query.
func normalizeQuery(raw string) string {
	if raw == "" {
		return ""
	}
	v, err := url.ParseQuery(raw)
	if err != nil {
		return raw
	}
	// url.Values.Encode sorts keys alphabetically and percent-encodes
	// in a single deterministic form.
	return v.Encode()
}

// principalClass returns a stable per-principal namespace string used as
// part of the cache key digest. The literal "anonymous" is returned for
// requests without a principal in context (or with the synthetic
// anonymous principal). For any other principal the principal's stable
// ID is returned, prefixed with "principal:" so it cannot collide with
// the anonymous bucket.
//
// CRITICAL (C3): the returned value MUST be hashed into the cache key
// digest. Without it, a response cached for one principal class can be
// served back to a different principal class — including the anonymous
// vs. authenticated cross-pollination case. Two distinct principals
// also occupy distinct cache buckets so that, e.g., admin-user-A and
// admin-user-B (both unconstrained but with potentially different
// upstream auth context) never share an entry.
func principalClass(ctx context.Context) string {
	p := auth.PrincipalFromContext(ctx)
	if p == nil || p.IsAnonymous() {
		return "anonymous"
	}
	if p.ID == "" {
		// Defensive: an authenticated principal with no stable ID is
		// treated as its own opaque bucket so it can never share with
		// either the anonymous bucket or another principal.
		return "principal:_unknown"
	}
	return "principal:" + p.ID
}

// cacheableResponseHeaders is the whitelist of upstream response
// headers that may be stored in a cache entry and re-emitted on a
// hit. Anything not in this set — notably Set-Cookie, Authorization,
// WWW-Authenticate, and arbitrary X-* headers from upstream — is
// dropped to avoid leaking principal-specific or origin-internal
// state to whichever caller next gets the cached response.
//
// Keys are the Go canonical form returned by http.CanonicalHeaderKey
// (e.g. "Etag", not "ETag").
var cacheableResponseHeaders = map[string]struct{}{
	"Content-Type":     {},
	"Content-Encoding": {},
	"Content-Language": {},
	"Etag":             {},
	"Last-Modified":    {},
	"Cache-Control":    {},
	"Expires":          {},
	"Vary":             {},
	"X-Cache-Status":   {},
}

// filterCacheableHeaders returns a copy of h with only the headers in
// cacheableResponseHeaders preserved (canonicalised on access). Used
// before persisting a CacheEntry so non-cacheable headers aren't
// replayed.
func filterCacheableHeaders(h http.Header) http.Header {
	out := make(http.Header, len(cacheableResponseHeaders))
	for name, vs := range h {
		if _, ok := cacheableResponseHeaders[http.CanonicalHeaderKey(name)]; ok {
			for _, v := range vs {
				out.Add(name, v)
			}
		}
	}
	return out
}

// Config contains configuration for the cache middleware.
//
// CacheableStatuses is the allowlist of HTTP status codes whose
// responses may be persisted to the store. When empty, the package
// default (defaultCacheableStatuses) is used. The default covers:
//   - 200 OK and 203 Non-Authoritative — successful payloads.
//   - 204 No Content — empty-but-valid responses (e.g. HEAD-like).
//   - 301 Moved Permanently and 308 Permanent Redirect — stable
//     redirects that are safe to remember; 302/307 are intentionally
//     excluded as they are nominally non-cacheable.
//   - 404 Not Found and 410 Gone — negative cache. Misconfigured
//     clients hammering nonexistent items would otherwise stampede the
//     upstream on every request.
//
// NegativeCacheTTL bounds the lifetime of cached 4xx responses
// (per-status; applied uniformly to all 4xx codes in the allowlist).
// It defaults to 5 minutes — long enough to absorb stampedes, short
// enough that a freshly-published item is discoverable. Successful
// 2xx and 3xx entries continue to use the Strategy's TTL.
type Config struct {
	Store             Store
	Strategy          Strategy
	CacheableStatuses []int
	NegativeCacheTTL  time.Duration
}

// defaultCacheableStatuses is the package-level default allowlist of
// statuses cached by NewHTTPMiddleware. See Config.CacheableStatuses
// for the per-status rationale.
var defaultCacheableStatuses = []int{
	http.StatusOK,                   // 200
	http.StatusNonAuthoritativeInfo, // 203
	http.StatusNoContent,            // 204
	http.StatusMovedPermanently,     // 301
	http.StatusPermanentRedirect,    // 308
	http.StatusNotFound,             // 404
	http.StatusGone,                 // 410
}

// defaultNegativeCacheTTL is the TTL applied to cached 4xx responses
// when Config.NegativeCacheTTL is unset.
const defaultNegativeCacheTTL = 5 * time.Minute

// NewHTTPMiddleware returns chi-compatible response-cache middleware.
//
// The middleware only engages when:
//  1. The router has populated a *middleware.STACInfo in r.Context().
//  2. The Strategy says the request is cacheable (default: GETs only).
//
// On a hit, the cached response is written directly with X-Cache-Status:
// HIT. On a miss, the inner handler runs into an httpx.ResponseCapture;
// the captured bytes are forwarded to the client and (when the status
// is in cfg.CacheableStatuses and the strategy returns a non-zero TTL)
// deep-copied into the store for future hits. X-Cache-Status: MISS is
// added on the miss path.
//
// 4xx entries (currently 404 and 410 in the default allowlist) are
// stored with cfg.NegativeCacheTTL rather than the Strategy's TTL —
// negative cache must expire faster than success TTL so that newly
// created items become visible without waiting for the longer
// success-bucket lifetime.
func NewHTTPMiddleware(cfg Config) func(http.Handler) http.Handler {
	strategy := cfg.Strategy
	if strategy == nil {
		strategy = &BasicStrategy{
			CollectionTTL: 5 * time.Minute,
			ItemTTL:       1 * time.Minute,
			SearchTTL:     30 * time.Second,
		}
	}
	store := cfg.Store
	if store == nil {
		store = &NoOpStore{}
	}
	statuses := cfg.CacheableStatuses
	if len(statuses) == 0 {
		statuses = defaultCacheableStatuses
	}
	cacheable := make(map[int]struct{}, len(statuses))
	for _, s := range statuses {
		cacheable[s] = struct{}{}
	}
	negTTL := cfg.NegativeCacheTTL
	if negTTL <= 0 {
		negTTL = defaultNegativeCacheTTL
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			info := middleware.STACInfoFromContext(r.Context())
			if info == nil {
				next.ServeHTTP(w, r)
				return
			}
			// Bypass the cache whenever the authz decision attached
			// any row-level constraint. The same URL can produce
			// different filtered responses for different principals
			// (different CQL2 filter / geofence / collection
			// allowlist), and including all of that in the cache key
			// is more complex than is worth in a first cut. Skipping
			// caching here is the conservative correctness choice;
			// the unauthenticated-or-unconstrained path still caches
			// normally. Requires the authz middleware to run BEFORE
			// the cache middleware in the chi chain — see main.go's
			// middleware ordering.
			if d := authz.DecisionFromContext(r.Context()); d != nil && d.HasConstraints() {
				next.ServeHTTP(w, r)
				return
			}
			cacheReq := CacheableRequest{
				Method: r.Method,
				Path:   r.URL.Path,
				// Normalize RawQuery so parameter permutations
				// (?a=1&b=2 vs ?b=2&a=1) collapse to a single
				// cache bucket. (HIGH H-cache-3)
				Query:          normalizeQuery(r.URL.RawQuery),
				RequestType:    info.RequestType.String(),
				Collection:     info.Collection,
				PrincipalClass: principalClass(r.Context()),
			}
			if !strategy.ShouldCache(cacheReq) {
				next.ServeHTTP(w, r)
				return
			}
			key := strategy.CacheKey(cacheReq)

			if data, ok := store.Get(r.Context(), key); ok {
				if entry, ok := decodeEntry(data); ok {
					writeCachedResponse(w, entry)
					if m := observability.Default(); m != nil {
						m.CacheHits.WithLabelValues(cacheReq.RequestType).Inc()
					}
					return
				}
				// Corrupt entry — fall through to upstream as if miss.
			}

			if m := observability.Default(); m != nil {
				m.CacheMisses.WithLabelValues(cacheReq.RequestType).Inc()
			}

			cap := httpx.NewResponseCapture()
			next.ServeHTTP(cap, r)

			// Forward captured headers + body to outer writer.
			for k, vs := range cap.HeadersOut() {
				for _, v := range vs {
					w.Header().Add(k, v)
				}
			}
			w.Header().Set("X-Cache-Status", "MISS")
			w.WriteHeader(cap.Status())
			body := cap.BodyBytes()
			_, _ = w.Write(body)

			status := cap.Status()
			if _, ok := cacheable[status]; !ok {
				return
			}
			// Negative-cache lifetime applies to every 4xx in the
			// allowlist; success entries take the Strategy TTL.
			var ttl time.Duration
			if status >= 400 && status < 500 {
				ttl = negTTL
			} else {
				ttl = strategy.TTL(cacheReq, status)
			}
			if ttl <= 0 {
				return
			}
			envelope, err := json.Marshal(CacheEntry{
				Status:  cap.Status(),
				Headers: filterCacheableHeaders(cap.HeadersOut()),
				Body:    append([]byte(nil), body...),
			})
			if err == nil {
				// Store failures are transient — the response went out
				// already; the next request will simply miss again.
				_ = store.Set(r.Context(), key, envelope, ttl)
			}
		})
	}
}

// NewFromConfig constructs a chi-style cache middleware from a raw
// YAML config block (the shape carried by config.MiddlewareConfig.Config).
// Currently only the in-memory store is wired; an unrecognized store
// type yields an error rather than silently falling back so
// misconfiguration is loud.
func NewFromConfig(cfg map[string]interface{}) (func(http.Handler) http.Handler, error) {
	storeType := "memory"
	if v, ok := cfg["store"].(string); ok {
		storeType = v
	}
	var store Store
	switch storeType {
	case "memory":
		maxSize := 10000
		if v, ok := cfg["max_size"].(int); ok {
			maxSize = v
		}
		store = NewMemoryStore(MemoryConfig{MaxSize: maxSize})
	default:
		return nil, fmt.Errorf("unknown cache store type: %s", storeType)
	}
	return NewHTTPMiddleware(Config{Store: store}), nil
}

// decodeEntry parses a stored cache entry envelope.
func decodeEntry(data []byte) (CacheEntry, bool) {
	var e CacheEntry
	if err := json.Unmarshal(data, &e); err != nil {
		return CacheEntry{}, false
	}
	return e, true
}

// writeCachedResponse emits a cache-hit response: restores the original
// status code and headers, adds X-Cache-Status: HIT on top.
func writeCachedResponse(w http.ResponseWriter, entry CacheEntry) {
	for k, vs := range entry.Headers {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.Header().Set("X-Cache-Status", "HIT")
	if entry.Status == 0 {
		entry.Status = http.StatusOK
	}
	w.WriteHeader(entry.Status)
	_, _ = w.Write(entry.Body)
}

// BasicStrategy implements a basic caching strategy keyed off method+path+query.
type BasicStrategy struct {
	CollectionTTL time.Duration
	ItemTTL       time.Duration
	SearchTTL     time.Duration
}

// ShouldCache returns true for GET requests other than asset
// streams. Asset bytes can be GB-scale and benefit from upstream
// Cache-Control / CDN caching rather than the proxy's in-memory store.
func (s *BasicStrategy) ShouldCache(req CacheableRequest) bool {
	if req.Method != http.MethodGet {
		return false
	}
	if req.RequestType == "asset" {
		return false
	}
	return true
}

// CacheKey generates a cache key from the request.
//
// PrincipalClass is folded into the digest so cache entries are
// partitioned by principal — see CacheableRequest.PrincipalClass for
// the security rationale (CRITICAL C3). The principal class is hashed
// (not concatenated raw into a logged key) so cache stats / metrics
// labels never leak principal IDs. A separator that cannot appear
// inside any of the components is used between fields so two distinct
// inputs cannot produce the same pre-hash byte sequence.
func (s *BasicStrategy) CacheKey(req CacheableRequest) string {
	data := fmt.Sprintf("%s\x00%s\x00%s\x00%s",
		req.PrincipalClass, req.Method, req.Path, req.Query)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:16])
}

// TTL returns the TTL for the cached response, varying by request type.
//
// For statuses outside the 2xx/3xx success-cache range BasicStrategy
// returns 0 — the middleware uses Config.NegativeCacheTTL for 4xx
// entries, so 0 here is the correct "do not use the success TTL"
// sentinel. 5xx are not cached at all (they fail the allowlist gate).
func (s *BasicStrategy) TTL(req CacheableRequest, statusCode int) time.Duration {
	if statusCode < 200 || statusCode >= 400 {
		return 0
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
