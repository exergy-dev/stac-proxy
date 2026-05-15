package federation

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yourorg/stac-proxy/internal/middleware"
	"github.com/yourorg/stac-proxy/internal/stac"
)

// newFederationOfOne wires a single-origin federation handler for
// pass-through tests. Mirrors how cmd/stac-proxy builds single-origin
// mode: one synthetic "primary" origin, ReverseProxy path only.
func newFederationOfOne(t *testing.T, upstreamURL string) *Handler {
	t.Helper()
	h, err := NewHandler(HandlerConfig{
		Origins: []*Origin{{
			ID:         "primary",
			BaseURL:    upstreamURL,
			Enabled:    true,
			Priority:   100,
			Searchable: true,
		}},
		ConflictStrategy: ConflictPriorityWins,
	})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	return h
}

// TestHandle_StripsHopByHopHeadersFromUpstream verifies H-1: hop-by-hop
// headers from the upstream MUST NOT be forwarded to the client.
func TestHandle_StripsHopByHopHeadersFromUpstream(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		w.Header().Set("Keep-Alive", "timeout=5")
		w.Header().Set("Transfer-Encoding", "chunked")
		w.Header().Set("X-Custom", "kept")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer upstream.Close()

	handler := newFederationOfOne(t, upstream.URL)

	httpReq := httptest.NewRequest("GET", "/collections", nil)
	stacReq := &request{
		Request:     httpReq,
		Context:     context.Background(),
		RequestType: middleware.RequestTypeCollections,
	}

	resp, err := handler.Handle(stacReq.Context, stacReq)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	for _, name := range []string{"Connection", "Keep-Alive", "Transfer-Encoding", "Proxy-Connection"} {
		if v := resp.Headers.Get(name); v != "" {
			t.Errorf("hop-by-hop header %s leaked from upstream: %q", name, v)
		}
	}
	if v := resp.Headers.Get("X-Custom"); v != "kept" {
		t.Errorf("end-to-end header X-Custom dropped: %q", v)
	}
}

// TestHandle_StripsConnectionListedHeaders verifies hop-by-hop hygiene
// covers headers named in the upstream's Connection header.
func TestHandle_StripsConnectionListedHeaders(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "X-Private")
		w.Header().Set("X-Private", "secret")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	handler := newFederationOfOne(t, upstream.URL)
	resp, err := handler.Handle(context.Background(), &request{
		Request:     httptest.NewRequest("GET", "/", nil),
		Context:     context.Background(),
		RequestType: middleware.RequestTypeQueryables,
	})
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if v := resp.Headers.Get("X-Private"); v != "" {
		t.Errorf("Connection-listed header X-Private leaked: %q", v)
	}
}

// TestHandle_ETagPassesThrough verifies M-14: caching/validation
// headers (ETag, Last-Modified, Cache-Control) on the upstream
// response are not stripped — they're end-to-end headers, not
// hop-by-hop. Uses /queryables as the passthrough route since the
// proxy now owns the landing page and /conformance directly (those
// responses are synthesized from the configured ConformanceCaps and
// no longer pass through upstream headers).
func TestHandle_ETagPassesThrough(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"v42"`)
		w.Header().Set("Last-Modified", "Tue, 12 May 2026 12:00:00 GMT")
		w.Header().Set("Cache-Control", "max-age=60, public")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	handler := newFederationOfOne(t, upstream.URL)
	resp, err := handler.Handle(context.Background(), &request{
		Request:     httptest.NewRequest("GET", "/queryables", nil),
		Context:     context.Background(),
		RequestType: middleware.RequestTypeQueryables,
	})
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	for k, want := range map[string]string{
		"ETag":          `"v42"`,
		"Last-Modified": "Tue, 12 May 2026 12:00:00 GMT",
		"Cache-Control": "max-age=60, public",
	} {
		if got := resp.Headers.Get(k); got != want {
			t.Errorf("%s: want %q, got %q", k, want, got)
		}
	}
}

// TestHandle_SetsXForwardedHeaders verifies X-Forwarded-* are set on the
// outbound request so upstream sees the originating client identity.
func TestHandle_SetsXForwardedHeaders(t *testing.T) {
	var seen http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	handler := newFederationOfOne(t, upstream.URL)

	httpReq := httptest.NewRequest("GET", "/collections", nil)
	httpReq.RemoteAddr = "203.0.113.10:54321"
	httpReq.Host = "edge.example.com"

	_, err := handler.Handle(context.Background(), &request{
		Request:     httpReq,
		Context:     context.Background(),
		RequestType: middleware.RequestTypeCollections,
	})
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if got := seen.Get("X-Forwarded-For"); !strings.Contains(got, "203.0.113.10") {
		t.Errorf("X-Forwarded-For: want 203.0.113.10, got %q", got)
	}
	if got := seen.Get("X-Forwarded-Host"); got != "edge.example.com" {
		t.Errorf("X-Forwarded-Host: want edge.example.com, got %q", got)
	}
	if got := seen.Get("X-Forwarded-Proto"); got != "http" {
		t.Errorf("X-Forwarded-Proto: want http, got %q", got)
	}
}

// --- C4 / H6 regression tests ----------------------------------------------

// TestHandle_StripsAuthorizationHeader (C4): the inbound client's
// Authorization header must NOT be forwarded to an origin that has
// no own auth configured and has not opted into ForwardUserIdentity.
func TestHandle_StripsAuthorizationHeader(t *testing.T) {
	var seen sync.RWMutex
	var got string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.Lock()
		got = r.Header.Get("Authorization")
		seen.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	handler := newFederationOfOne(t, upstream.URL)
	httpReq := httptest.NewRequest("GET", "/", nil)
	httpReq.Header.Set("Authorization", "Bearer client-user-token")

	if _, err := handler.Handle(context.Background(), &request{
		Request:     httpReq,
		Context:     context.Background(),
		RequestType: middleware.RequestTypeQueryables,
	}); err != nil {
		t.Fatalf("Handle: %v", err)
	}

	seen.RLock()
	defer seen.RUnlock()
	if got != "" {
		t.Errorf("Authorization leaked upstream: %q", got)
	}
}

// TestHandle_StripsCookieHeader (C4).
func TestHandle_StripsCookieHeader(t *testing.T) {
	var seen sync.RWMutex
	var got string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.Lock()
		got = r.Header.Get("Cookie")
		seen.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	handler := newFederationOfOne(t, upstream.URL)
	httpReq := httptest.NewRequest("GET", "/", nil)
	httpReq.Header.Set("Cookie", "session=abc123")

	if _, err := handler.Handle(context.Background(), &request{
		Request:     httpReq,
		Context:     context.Background(),
		RequestType: middleware.RequestTypeQueryables,
	}); err != nil {
		t.Fatalf("Handle: %v", err)
	}

	seen.RLock()
	defer seen.RUnlock()
	if got != "" {
		t.Errorf("Cookie leaked upstream: %q", got)
	}
}

// TestHandle_StripsXAPIKeyHeader (C4).
func TestHandle_StripsXAPIKeyHeader(t *testing.T) {
	var seen sync.RWMutex
	var got string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.Lock()
		got = r.Header.Get("X-Api-Key")
		seen.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	handler := newFederationOfOne(t, upstream.URL)
	httpReq := httptest.NewRequest("GET", "/", nil)
	httpReq.Header.Set("X-Api-Key", "client-supplied-key")

	if _, err := handler.Handle(context.Background(), &request{
		Request:     httpReq,
		Context:     context.Background(),
		RequestType: middleware.RequestTypeQueryables,
	}); err != nil {
		t.Fatalf("Handle: %v", err)
	}

	seen.RLock()
	defer seen.RUnlock()
	if got != "" {
		t.Errorf("X-Api-Key leaked upstream: %q", got)
	}
}

// TestHandle_ForwardsAuthWhenConfigured (C4 opt-in).
func TestHandle_ForwardsAuthWhenConfigured(t *testing.T) {
	var seen sync.RWMutex
	var got string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.Lock()
		got = r.Header.Get("Authorization")
		seen.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	handler, err := NewHandler(HandlerConfig{
		Origins: []*Origin{{
			ID:                  "primary",
			BaseURL:             upstream.URL,
			Enabled:             true,
			Priority:            100,
			Searchable:          true,
			Timeout:             5 * time.Second,
			ForwardUserIdentity: true,
		}},
		ConflictStrategy: ConflictPriorityWins,
	})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	httpReq := httptest.NewRequest("GET", "/", nil)
	httpReq.Header.Set("Authorization", "Bearer client-user-token")
	if _, err := handler.Handle(context.Background(), &request{
		Request:     httpReq,
		Context:     context.Background(),
		RequestType: middleware.RequestTypeQueryables,
	}); err != nil {
		t.Fatalf("Handle: %v", err)
	}

	seen.RLock()
	defer seen.RUnlock()
	if got != "Bearer client-user-token" {
		t.Errorf("Authorization not forwarded when ForwardUserIdentity=true: got %q", got)
	}
}

// TestFanOutSearch_PanicRecovery (H6): a panic inside one origin's
// search must not crash the proxy; the origin is recorded as failed
// and the merger continues with the other origins.
func TestFanOutSearch_PanicRecovery(t *testing.T) {
	// Build a Handler with a real OriginClient pointed at a stub
	// httptest server, then replace the merger with a stub that
	// records what fanOutSearch returned. The panic is induced
	// inside the searchOrigin path by giving the OriginClient a
	// broken transport.

	// Stub upstream that returns valid empty FC for the healthy origin.
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"type":"FeatureCollection","features":[]}`))
	}))
	defer good.Close()

	// Use a deliberately unparseable BaseURL on the "bad" origin so
	// NewOriginClient errors. We side-step that by manually building
	// a Handler with both origins via NewHandler against a server
	// that 500s, since real panic injection requires monkey-patching
	// the transport. The 500 path doesn't exercise H6 directly; for
	// a real panic test, we inject via a panicking RoundTripper at
	// the OriginClient layer.

	h, err := NewHandler(HandlerConfig{
		Origins: []*Origin{
			{ID: "good", BaseURL: good.URL, Enabled: true, Searchable: true, Priority: 5, Timeout: 2 * time.Second},
			{ID: "bad", BaseURL: good.URL, Enabled: true, Searchable: true, Priority: 10, Timeout: 2 * time.Second},
		},
		ConflictStrategy: ConflictPriorityWins,
		AggregateTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	// Replace the "bad" origin's transport with one that panics.
	h.origins["bad"].transport = panicRoundTripper{}

	// Drive a real search; the bad origin should panic, get recovered,
	// and the handler should return 200 (the good origin handles the
	// merge).
	searchReq := &stac.SearchRequest{Collections: []string{"x"}, Limit: 5}
	resp, err := h.Handle(context.Background(), &request{
		Request:     httptest.NewRequest("POST", "/search", nil),
		Context:     context.Background(),
		RequestType: middleware.RequestTypeSearch,
		SearchReq:   searchReq,
	})
	if err != nil {
		t.Fatalf("Handle returned error after panic: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (panic should not propagate)", resp.StatusCode)
	}
}

// panicRoundTripper panics from inside RoundTrip — used to exercise
// the H6 fan-out panic-recovery path.
type panicRoundTripper struct{}

func (panicRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	panic("simulated panic inside upstream RoundTrip")
}
