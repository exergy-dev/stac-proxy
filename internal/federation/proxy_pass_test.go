package federation

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	})
	require.NoError(t, err, "NewHandler")
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
	require.NoError(t, err, "Handle")
	for _, name := range []string{"Connection", "Keep-Alive", "Transfer-Encoding", "Proxy-Connection"} {
		assert.Emptyf(t, resp.Headers.Get(name), "hop-by-hop header %s leaked from upstream", name)
	}
	assert.Equal(t, "kept", resp.Headers.Get("X-Custom"), "end-to-end header X-Custom dropped")
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
	require.NoError(t, err, "Handle")
	assert.Empty(t, resp.Headers.Get("X-Private"), "Connection-listed header X-Private leaked")
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
	require.NoError(t, err, "Handle")
	for k, want := range map[string]string{
		"ETag":          `"v42"`,
		"Last-Modified": "Tue, 12 May 2026 12:00:00 GMT",
		"Cache-Control": "max-age=60, public",
	} {
		assert.Equalf(t, want, resp.Headers.Get(k), "%s mismatch", k)
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
	require.NoError(t, err, "Handle")
	assert.Containsf(t, seen.Get("X-Forwarded-For"), "203.0.113.10", "X-Forwarded-For")
	assert.Equal(t, "edge.example.com", seen.Get("X-Forwarded-Host"), "X-Forwarded-Host")
	assert.Equal(t, "http", seen.Get("X-Forwarded-Proto"), "X-Forwarded-Proto")
}

// --- C4 / H6 regression tests ----------------------------------------------

// TestHandle_StripsSensitiveHeaders (C4): the inbound client's
// Authorization / Cookie / X-Api-Key headers must NOT be forwarded to
// an origin that has no own auth configured and has not opted into
// ForwardUserIdentity.
func TestHandle_StripsSensitiveHeaders(t *testing.T) {
	cases := []struct {
		name, header, value string
	}{
		{"Authorization", "Authorization", "Bearer client-user-token"},
		{"Cookie", "Cookie", "session=abc123"},
		{"X-Api-Key", "X-Api-Key", "client-supplied-key"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var seen sync.RWMutex
			var got string
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen.Lock()
				got = r.Header.Get(tc.header)
				seen.Unlock()
				w.WriteHeader(http.StatusOK)
			}))
			defer upstream.Close()

			handler := newFederationOfOne(t, upstream.URL)
			httpReq := httptest.NewRequest("GET", "/", nil)
			httpReq.Header.Set(tc.header, tc.value)

			_, err := handler.Handle(context.Background(), &request{
				Request:     httpReq,
				Context:     context.Background(),
				RequestType: middleware.RequestTypeQueryables,
			})
			require.NoError(t, err, "Handle")

			seen.RLock()
			defer seen.RUnlock()
			assert.Emptyf(t, got, "%s leaked upstream: %q", tc.header, got)
		})
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
	})
	require.NoError(t, err, "NewHandler")

	httpReq := httptest.NewRequest("GET", "/", nil)
	httpReq.Header.Set("Authorization", "Bearer client-user-token")
	_, err = handler.Handle(context.Background(), &request{
		Request:     httpReq,
		Context:     context.Background(),
		RequestType: middleware.RequestTypeQueryables,
	})
	require.NoError(t, err, "Handle")

	seen.RLock()
	defer seen.RUnlock()
	assert.Equalf(t, "Bearer client-user-token", got, "Authorization not forwarded when ForwardUserIdentity=true")
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
		AggregateTimeout: 5 * time.Second,
	})
	require.NoError(t, err, "NewHandler")
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
	require.NoError(t, err, "Handle returned error after panic")
	require.Equalf(t, http.StatusOK, resp.StatusCode, "status; want 200 (panic should not propagate)")
}

// panicRoundTripper panics from inside RoundTrip — used to exercise
// the H6 fan-out panic-recovery path.
type panicRoundTripper struct{}

func (panicRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	panic("simulated panic inside upstream RoundTrip")
}

// TestReverseProxy_OversizedUpstreamReturns502 guards Fix C6: the
// reverse-proxy fast path used to call httpx.NewResponseCapture() with
// no byte cap, so a hostile or runaway upstream could OOM the proxy.
// The handler now uses NewResponseCaptureWithLimit(MaxResponseBytes)
// (falling back to defaultMaxResponseBytes) and surfaces a 502 when the
// captured body would exceed the cap.
func TestReverseProxy_OversizedUpstreamReturns502(t *testing.T) {
	const maxCap = 256 * 1024 // 256 KiB cap
	const body = 1024 * 1024 // 1 MiB upstream body

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Stream the oversized body.
		buf := make([]byte, 4096)
		for i := range buf {
			buf[i] = 'A'
		}
		written := 0
		for written < body {
			n := len(buf)
			if body-written < n {
				n = body - written
			}
			m, err := w.Write(buf[:n])
			written += m
			if err != nil {
				return
			}
		}
	}))
	defer upstream.Close()

	handler, err := NewHandler(HandlerConfig{
		Origins: []*Origin{{
			ID:               "primary",
			BaseURL:          upstream.URL,
			Enabled:          true,
			Priority:         100,
			Searchable:       true,
			MaxResponseBytes: maxCap,
		}},
	})
	require.NoError(t, err, "NewHandler")

	resp, err := handler.Handle(context.Background(), &request{
		Request:     httptest.NewRequest("GET", "/queryables", nil),
		Context:     context.Background(),
		RequestType: middleware.RequestTypeQueryables,
	})
	require.NoError(t, err, "Handle returned error")

	assert.Equalf(t, http.StatusBadGateway, resp.StatusCode, "status (oversized upstream must surface 502)")

	// The proxy must not have buffered the full upstream body. Even
	// allowing for the small JSON error envelope, the response body
	// MUST be far below the upstream's 1 MiB.
	assert.LessOrEqualf(t, len(resp.Body), maxCap, "response body length %d exceeds cap %d — capture was not bounded", len(resp.Body), maxCap)
}
