package cache

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/stac-proxy/internal/middleware"
	"github.com/yourorg/stac-proxy/internal/middleware/auth"
	"github.com/yourorg/stac-proxy/internal/middleware/authz"
)

// withSTACInfo returns r wrapped in a context carrying the given info,
// matching what the router does before the chi chain runs.
func withSTACInfo(r *http.Request, info *middleware.STACInfo) *http.Request {
	return r.WithContext(middleware.WithSTACInfo(r.Context(), info))
}

// upstreamWriter returns an http.Handler that writes the given status,
// headers, and body. Used as the inner handler in tests.
func upstreamWriter(status int, headers map[string]string, body []byte) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		for k, v := range headers {
			w.Header().Set(k, v)
		}
		w.WriteHeader(status)
		_, _ = w.Write(body)
	})
}

// TestCacheHit_RestoresStatusAndHeaders (C-4): a second request for the
// same key returns the upstream response's original status code and
// Content-Type rather than hardcoded values.
func TestCacheHit_RestoresStatusAndHeaders(t *testing.T) {
	store := NewMemoryStore(MemoryConfig{MaxSize: 16})
	// ETag is in the cacheable-headers whitelist; X-Custom is NOT
	// (the proxy deliberately drops arbitrary upstream headers from
	// cache entries to avoid leaking principal-specific state on a
	// hit). The "stays on hit" assertion below uses ETag.
	h := NewHTTPMiddleware(Config{Store: store})(upstreamWriter(
		http.StatusOK,
		map[string]string{"Content-Type": "application/geo+json", "ETag": `"v1"`},
		[]byte(`{"type":"FeatureCollection","features":[]}`),
	))

	info := &middleware.STACInfo{RequestType: middleware.RequestTypeItems, Collection: "x"}

	// Miss: response flows to client + lands in cache.
	rr1 := httptest.NewRecorder()
	h.ServeHTTP(rr1, withSTACInfo(httptest.NewRequest("GET", "/collections/x/items", nil), info))
	require.Equal(t, http.StatusOK, rr1.Code, "first request status")
	require.Equal(t, "MISS", rr1.Header().Get("X-Cache-Status"), "first request X-Cache-Status")

	// Hit: cached response served without invoking upstream again.
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, withSTACInfo(httptest.NewRequest("GET", "/collections/x/items", nil), info))
	require.Equal(t, http.StatusOK, rr2.Code, "hit status")
	assert.Equal(t, "HIT", rr2.Header().Get("X-Cache-Status"), "X-Cache-Status")
	assert.Equal(t, "application/geo+json", rr2.Header().Get("Content-Type"), "Content-Type on hit")
	assert.Equal(t, `"v1"`, rr2.Header().Get("ETag"), "ETag on hit")
}

// TestCache_NonGetByPasses: a POST is not cached, regardless of status.
func TestCache_NonGetByPasses(t *testing.T) {
	store := NewMemoryStore(MemoryConfig{MaxSize: 16})
	h := NewHTTPMiddleware(Config{Store: store})(upstreamWriter(http.StatusOK, nil, []byte(`{}`)))
	info := &middleware.STACInfo{RequestType: middleware.RequestTypeSearch}

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, withSTACInfo(httptest.NewRequest("POST", "/search", nil), info))
	assert.Empty(t, rr.Header().Get("X-Cache-Status"), "POST request engaged cache")
}

// TestCache_NoSTACInfoPassesThrough: when the router didn't attach
// STACInfo (e.g., a non-STAC route), the middleware short-circuits to
// the inner handler.
func TestCache_NoSTACInfoPassesThrough(t *testing.T) {
	store := NewMemoryStore(MemoryConfig{MaxSize: 16})
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})
	h := NewHTTPMiddleware(Config{Store: store})(inner)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	assert.Equal(t, http.StatusTeapot, rr.Code, "status")
}

// --- C2 cache-bypass on authz constraints ---------------------------------

// TestCache_BypassedWhenAuthzConstrained verifies that when the authz
// middleware has attached a per-principal constraint (CQL2 filter,
// geofence, etc.) to the request context, the cache middleware does
// NOT consult its store. Otherwise the same URL could serve a
// principal-A-filtered response to principal B.
func TestCache_BypassedWhenAuthzConstrained(t *testing.T) {
	store := NewMemoryStore(MemoryConfig{MaxSize: 100})

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	mw := NewHTTPMiddleware(Config{Store: store})

	decision := &authz.AuthzDecision{
		Allowed: true,
		Constraints: &authz.AuthzConstraints{
			CQL2Filter: "eo:cloud_cover < 10",
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/collections/x/items", nil)
	ctx := middleware.WithSTACInfo(req.Context(), &middleware.STACInfo{
		RequestType: middleware.RequestTypeItems,
		Collection:  "x",
	})
	ctx = context.WithValue(ctx, middleware.AuthzDecisionKey, decision)
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()
	mw(inner).ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code, "first request status")

	// Hit cache: the entry should NOT have been stored. Confirm via
	// a second request that the X-Cache-Status header is "MISS"
	// again (would be "HIT" if the entry had been persisted).
	req2 := httptest.NewRequest(http.MethodGet, "/collections/x/items", nil)
	req2 = req2.WithContext(ctx)
	rr2 := httptest.NewRecorder()
	mw(inner).ServeHTTP(rr2, req2)
	assert.NotEqual(t, "HIT", rr2.Header().Get("X-Cache-Status"), "expected no cache (constrained request)")
}

// TestCache_FiltersSensitiveHeadersFromEntry verifies that Set-Cookie
// and other non-cacheable headers from the upstream response are NOT
// persisted into the cache entry. Otherwise a cache hit would replay
// principal-specific headers to every subsequent caller.
func TestCache_FiltersSensitiveHeadersFromEntry(t *testing.T) {
	store := NewMemoryStore(MemoryConfig{MaxSize: 100})

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Upstream tries to set a Set-Cookie + Authorization on the
		// response. Neither should survive into the cache entry.
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Set-Cookie", "session=secret; HttpOnly")
		w.Header().Set("Authorization", "Bearer upstream-secret")
		w.Header().Set("ETag", `"v1"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	mw := NewHTTPMiddleware(Config{Store: store})

	// First request: populate cache.
	req := httptest.NewRequest(http.MethodGet, "/collections/x", nil)
	ctx := middleware.WithSTACInfo(req.Context(), &middleware.STACInfo{
		RequestType: middleware.RequestTypeCollection,
		Collection:  "x",
	})
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()
	mw(inner).ServeHTTP(rr, req)

	// Second request: should be a cache hit. The cached headers
	// must NOT include Set-Cookie or Authorization.
	req2 := httptest.NewRequest(http.MethodGet, "/collections/x", nil)
	req2 = req2.WithContext(ctx)
	rr2 := httptest.NewRecorder()
	mw(inner).ServeHTTP(rr2, req2)

	require.Equal(t, "HIT", rr2.Header().Get("X-Cache-Status"), "expected HIT on second request")
	assert.Empty(t, rr2.Header().Get("Set-Cookie"), "Set-Cookie leaked through cache")
	assert.Empty(t, rr2.Header().Get("Authorization"), "Authorization leaked through cache")
	// ETag is in the allowlist — should survive.
	assert.Equal(t, `"v1"`, rr2.Header().Get("ETag"), "ETag dropped from cache")
}

// TestCache_QueryParamOrderInvariant (HIGH H-cache-3): two requests
// with the same query parameters in different order must hit the same
// cache entry. Otherwise an attacker can permute parameters to bypass
// the cache (and force expensive upstream work) and benign callers can
// thrash the cache for no benefit.
func TestCache_QueryParamOrderInvariant(t *testing.T) {
	store := NewMemoryStore(MemoryConfig{MaxSize: 16})
	defer store.Close()

	var upstreamHits int
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHits++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	mw := NewHTTPMiddleware(Config{Store: store})(inner)

	info := &middleware.STACInfo{RequestType: middleware.RequestTypeSearch}

	// First request: ?a=1&b=2  -> MISS, populates cache.
	rr1 := httptest.NewRecorder()
	mw.ServeHTTP(rr1, withSTACInfo(httptest.NewRequest("GET", "/search?a=1&b=2", nil), info))
	require.Equal(t, "MISS", rr1.Header().Get("X-Cache-Status"), "first request X-Cache-Status")

	// Second request: ?b=2&a=1 -> must HIT the same entry.
	rr2 := httptest.NewRecorder()
	mw.ServeHTTP(rr2, withSTACInfo(httptest.NewRequest("GET", "/search?b=2&a=1", nil), info))
	require.Equal(t, "HIT", rr2.Header().Get("X-Cache-Status"), "permuted-query request X-Cache-Status (cache key must be order-invariant)")
	assert.Equal(t, 1, upstreamHits, "upstream hits (second request should not have reached upstream)")
}

// TestCache_DoesNotMixAnonymousAndAuthenticated (C3): the cache key
// must include a principal-class component so an anonymous response
// can never be served back to an authenticated caller (or vice
// versa), and so two different authenticated principals occupy
// distinct cache buckets.
//
// The test exercises four sequential requests against the same URL,
// alternating principal class. Each principal class should see its
// own body on first miss, then HIT on subsequent visits — without
// any cross-pollination.
func TestCache_DoesNotMixAnonymousAndAuthenticated(t *testing.T) {
	store := NewMemoryStore(MemoryConfig{MaxSize: 100})

	// The "upstream" handler returns a body that depends on which
	// principal class is in context. If the cache is correctly
	// partitioned by principal, the first MISS for each class records
	// that class's body and subsequent HITs serve the same.
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := "anon-body"
		if p := auth.PrincipalFromContext(r.Context()); p != nil && !p.IsAnonymous() {
			body = p.ID + "-body"
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	})
	mw := NewHTTPMiddleware(Config{Store: store})(inner)

	info := &middleware.STACInfo{RequestType: middleware.RequestTypeSearch}

	newReq := func(principalID string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/search?bbox=1,2,3,4", nil)
		ctx := middleware.WithSTACInfo(r.Context(), info)
		if principalID != "" {
			ctx = context.WithValue(ctx, middleware.PrincipalKey, &auth.Principal{
				ID:   principalID,
				Type: "user",
			})
		}
		return r.WithContext(ctx)
	}

	// 1. Anonymous: MISS, body "anon-body" cached under anon bucket.
	rr1 := httptest.NewRecorder()
	mw.ServeHTTP(rr1, newReq(""))
	require.Equal(t, http.StatusOK, rr1.Code, "anon first request status")
	require.Equal(t, "anon-body", rr1.Body.String(), "anon first request body")
	require.Equal(t, "MISS", rr1.Header().Get("X-Cache-Status"), "anon first request X-Cache-Status")

	// 2. Authenticated as "alice", same URL/method: must NOT see
	//    "anon-body". Should MISS its own bucket and get "alice-body".
	rr2 := httptest.NewRecorder()
	mw.ServeHTTP(rr2, newReq("alice"))
	require.Equal(t, "alice-body", rr2.Body.String(), "alice first request body (cache MUST be partitioned by principal class)")
	require.Equal(t, "MISS", rr2.Header().Get("X-Cache-Status"), "alice first request X-Cache-Status")

	// 3. Anonymous again: MUST hit the anon bucket, not Alice's.
	//    The anon entry must NOT have been overwritten by step 2.
	rr3 := httptest.NewRecorder()
	mw.ServeHTTP(rr3, newReq(""))
	require.Equal(t, "anon-body", rr3.Body.String(), "anon second request body (anon entry must be preserved)")
	require.Equal(t, "HIT", rr3.Header().Get("X-Cache-Status"), "anon second request X-Cache-Status")

	// 4. Alice again: hits Alice's bucket from step 2.
	rr4 := httptest.NewRecorder()
	mw.ServeHTTP(rr4, newReq("alice"))
	require.Equal(t, "alice-body", rr4.Body.String(), "alice second request body (alice entry must be preserved)")
	require.Equal(t, "HIT", rr4.Header().Get("X-Cache-Status"), "alice second request X-Cache-Status")
}

// TestCache_404IsCachedWithNegativeTTL (M-cache-1): a 404 from
// upstream is persisted into the store so subsequent identical
// requests for the missing item are served from the cache and the
// inner handler is NOT re-invoked. Real STAC traffic includes
// misconfigured clients that hammer nonexistent items; without
// negative cache the upstream pays for every request.
func TestCache_404IsCachedWithNegativeTTL(t *testing.T) {
	store := NewMemoryStore(MemoryConfig{MaxSize: 16})
	defer store.Close()

	var inner uint32
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddUint32(&inner, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"code":"NotFound"}`))
	})
	mw := NewHTTPMiddleware(Config{Store: store, NegativeCacheTTL: time.Minute})(h)

	info := &middleware.STACInfo{RequestType: middleware.RequestTypeItem, Collection: "x"}

	rr1 := httptest.NewRecorder()
	mw.ServeHTTP(rr1, withSTACInfo(httptest.NewRequest("GET", "/collections/x/items/missing", nil), info))
	require.Equal(t, http.StatusNotFound, rr1.Code, "first request status")
	require.Equal(t, "MISS", rr1.Header().Get("X-Cache-Status"), "first request X-Cache-Status")

	rr2 := httptest.NewRecorder()
	mw.ServeHTTP(rr2, withSTACInfo(httptest.NewRequest("GET", "/collections/x/items/missing", nil), info))
	require.Equal(t, http.StatusNotFound, rr2.Code, "second request status (from cache)")
	require.Equal(t, "HIT", rr2.Header().Get("X-Cache-Status"), "second request X-Cache-Status")
	assert.Equal(t, uint32(1), atomic.LoadUint32(&inner), "inner handler invocations (negative cache hit)")
}

// TestCache_5xxNotCached (M-cache-1): 5xx responses are NOT in the
// cacheable allowlist; a second request for the same URL re-invokes
// the inner handler so transient upstream failures don't poison the
// cache.
func TestCache_5xxNotCached(t *testing.T) {
	store := NewMemoryStore(MemoryConfig{MaxSize: 16})
	defer store.Close()

	var inner uint32
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddUint32(&inner, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`{"code":"BadGateway"}`))
	})
	mw := NewHTTPMiddleware(Config{Store: store})(h)

	info := &middleware.STACInfo{RequestType: middleware.RequestTypeCollection, Collection: "x"}

	rr1 := httptest.NewRecorder()
	mw.ServeHTTP(rr1, withSTACInfo(httptest.NewRequest("GET", "/collections/x", nil), info))
	require.Equal(t, http.StatusBadGateway, rr1.Code, "first request status")

	rr2 := httptest.NewRecorder()
	mw.ServeHTTP(rr2, withSTACInfo(httptest.NewRequest("GET", "/collections/x", nil), info))
	assert.Equal(t, "MISS", rr2.Header().Get("X-Cache-Status"), "5xx leaked into cache: want MISS on second request")
	assert.Equal(t, uint32(2), atomic.LoadUint32(&inner), "inner handler invocations (5xx must re-fetch)")
}

func TestNewFromConfig_RejectsUnknownStore(t *testing.T) {
	t.Parallel()

	_, err := NewFromConfig(map[string]interface{}{"store": "bogus"})
	require.Error(t, err, "NewFromConfig(bogus) returned nil error; want explicit rejection")
	assert.ErrorContains(t, err, `unknown cache store type "bogus"`)
}

func TestNewFromConfig_AcceptsMemory(t *testing.T) {
	t.Parallel()

	mw, err := NewFromConfig(map[string]interface{}{"store": "memory", "max_size": 100})
	require.NoError(t, err, "NewFromConfig(memory)")
	require.NotNil(t, mw, "middleware is nil")
}

func TestNewFromConfigWithStore_RedisRequiresInjectedStore(t *testing.T) {
	t.Parallel()

	_, err := NewFromConfigWithStore(map[string]interface{}{"store": "redis"}, nil)
	require.Error(t, err, "store: redis with nil store must be a wiring error")
	assert.ErrorContains(t, err, "no store was provided")
}

func TestNewFromConfigWithStore_UsesInjectedStore(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore(MemoryConfig{MaxSize: 10})
	mw, err := NewFromConfigWithStore(map[string]interface{}{"store": "redis"}, store)
	require.NoError(t, err, "injected store must satisfy store: redis")
	require.NotNil(t, mw)
}
