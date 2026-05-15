package cache

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

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
	if rr1.Code != http.StatusOK || rr1.Header().Get("X-Cache-Status") != "MISS" {
		t.Fatalf("first request: status=%d X-Cache-Status=%q", rr1.Code, rr1.Header().Get("X-Cache-Status"))
	}

	// Hit: cached response served without invoking upstream again.
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, withSTACInfo(httptest.NewRequest("GET", "/collections/x/items", nil), info))
	if rr2.Code != http.StatusOK {
		t.Fatalf("hit status: want 200, got %d", rr2.Code)
	}
	if got := rr2.Header().Get("X-Cache-Status"); got != "HIT" {
		t.Errorf("X-Cache-Status: want HIT, got %q", got)
	}
	if got := rr2.Header().Get("Content-Type"); got != "application/geo+json" {
		t.Errorf("Content-Type on hit: want application/geo+json, got %q", got)
	}
	if got := rr2.Header().Get("ETag"); got != `"v1"` {
		t.Errorf("ETag on hit: want \"v1\", got %q", got)
	}
}

// TestCacheMiss_NonOKNotCached: a 500 from upstream should NOT land in
// the store; a subsequent request still misses.
func TestCacheMiss_NonOKNotCached(t *testing.T) {
	store := NewMemoryStore(MemoryConfig{MaxSize: 16})
	h := NewHTTPMiddleware(Config{Store: store})(upstreamWriter(
		http.StatusInternalServerError, nil, []byte(`{"error":"boom"}`),
	))
	info := &middleware.STACInfo{RequestType: middleware.RequestTypeCollection, Collection: "x"}

	rr1 := httptest.NewRecorder()
	h.ServeHTTP(rr1, withSTACInfo(httptest.NewRequest("GET", "/collections/x", nil), info))
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, withSTACInfo(httptest.NewRequest("GET", "/collections/x", nil), info))
	if rr2.Header().Get("X-Cache-Status") != "MISS" {
		t.Errorf("error response leaked into cache; want MISS, got %q", rr2.Header().Get("X-Cache-Status"))
	}
}

// TestCache_NonGetByPasses: a POST is not cached, regardless of status.
func TestCache_NonGetByPasses(t *testing.T) {
	store := NewMemoryStore(MemoryConfig{MaxSize: 16})
	h := NewHTTPMiddleware(Config{Store: store})(upstreamWriter(http.StatusOK, nil, []byte(`{}`)))
	info := &middleware.STACInfo{RequestType: middleware.RequestTypeSearch}

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, withSTACInfo(httptest.NewRequest("POST", "/search", nil), info))
	if got := rr.Header().Get("X-Cache-Status"); got != "" {
		t.Errorf("POST request engaged cache: X-Cache-Status=%q", got)
	}
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
	if rr.Code != http.StatusTeapot {
		t.Errorf("status: want 418, got %d", rr.Code)
	}
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

	if rr.Code != http.StatusOK {
		t.Fatalf("first request status = %d", rr.Code)
	}

	// Hit cache: the entry should NOT have been stored. Confirm via
	// a second request that the X-Cache-Status header is "MISS"
	// again (would be "HIT" if the entry had been persisted).
	req2 := httptest.NewRequest(http.MethodGet, "/collections/x/items", nil)
	req2 = req2.WithContext(ctx)
	rr2 := httptest.NewRecorder()
	mw(inner).ServeHTTP(rr2, req2)
	if got := rr2.Header().Get("X-Cache-Status"); got == "HIT" {
		t.Errorf("expected no cache (constrained request); got X-Cache-Status=HIT")
	}
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

	if got := rr2.Header().Get("X-Cache-Status"); got != "HIT" {
		t.Fatalf("expected HIT on second request, got %q", got)
	}
	if got := rr2.Header().Get("Set-Cookie"); got != "" {
		t.Errorf("Set-Cookie leaked through cache: %q", got)
	}
	if got := rr2.Header().Get("Authorization"); got != "" {
		t.Errorf("Authorization leaked through cache: %q", got)
	}
	// ETag is in the allowlist — should survive.
	if got := rr2.Header().Get("ETag"); got != `"v1"` {
		t.Errorf("ETag dropped from cache: %q", got)
	}
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
	if got := rr1.Header().Get("X-Cache-Status"); got != "MISS" {
		t.Fatalf("first request X-Cache-Status: want MISS, got %q", got)
	}

	// Second request: ?b=2&a=1 -> must HIT the same entry.
	rr2 := httptest.NewRecorder()
	mw.ServeHTTP(rr2, withSTACInfo(httptest.NewRequest("GET", "/search?b=2&a=1", nil), info))
	if got := rr2.Header().Get("X-Cache-Status"); got != "HIT" {
		t.Fatalf("permuted-query request X-Cache-Status: want HIT (cache key must be order-invariant), got %q", got)
	}
	if upstreamHits != 1 {
		t.Errorf("upstream hits = %d, want 1 (second request should not have reached upstream)", upstreamHits)
	}
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
	if rr1.Code != http.StatusOK {
		t.Fatalf("anon first request: status=%d", rr1.Code)
	}
	if got := rr1.Body.String(); got != "anon-body" {
		t.Fatalf("anon first request body: want anon-body, got %q", got)
	}
	if got := rr1.Header().Get("X-Cache-Status"); got != "MISS" {
		t.Fatalf("anon first request X-Cache-Status: want MISS, got %q", got)
	}

	// 2. Authenticated as "alice", same URL/method: must NOT see
	//    "anon-body". Should MISS its own bucket and get "alice-body".
	rr2 := httptest.NewRecorder()
	mw.ServeHTTP(rr2, newReq("alice"))
	if got := rr2.Body.String(); got != "alice-body" {
		t.Fatalf("alice first request body: want alice-body (cache MUST be partitioned by principal class), got %q", got)
	}
	if got := rr2.Header().Get("X-Cache-Status"); got != "MISS" {
		t.Fatalf("alice first request X-Cache-Status: want MISS, got %q", got)
	}

	// 3. Anonymous again: MUST hit the anon bucket, not Alice's.
	//    The anon entry must NOT have been overwritten by step 2.
	rr3 := httptest.NewRecorder()
	mw.ServeHTTP(rr3, newReq(""))
	if got := rr3.Body.String(); got != "anon-body" {
		t.Fatalf("anon second request body: want anon-body (anon entry must be preserved), got %q", got)
	}
	if got := rr3.Header().Get("X-Cache-Status"); got != "HIT" {
		t.Fatalf("anon second request X-Cache-Status: want HIT, got %q", got)
	}

	// 4. Alice again: hits Alice's bucket from step 2.
	rr4 := httptest.NewRecorder()
	mw.ServeHTTP(rr4, newReq("alice"))
	if got := rr4.Body.String(); got != "alice-body" {
		t.Fatalf("alice second request body: want alice-body (alice entry must be preserved), got %q", got)
	}
	if got := rr4.Header().Get("X-Cache-Status"); got != "HIT" {
		t.Fatalf("alice second request X-Cache-Status: want HIT, got %q", got)
	}
}
