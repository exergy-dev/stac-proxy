package cache

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yourorg/stac-proxy/internal/middleware"
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
	h := NewHTTPMiddleware(Config{Store: store})(upstreamWriter(
		http.StatusOK,
		map[string]string{"Content-Type": "application/geo+json", "X-Custom": "stac-value"},
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
	if got := rr2.Header().Get("X-Custom"); got != "stac-value" {
		t.Errorf("X-Custom on hit: want stac-value, got %q", got)
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
