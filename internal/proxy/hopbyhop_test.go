package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yourorg/stac-proxy/internal/middleware"
)

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

	handler, err := NewHandler(Config{UpstreamURL: upstream.URL})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	httpReq := httptest.NewRequest("GET", "/collections", nil)
	stacReq := &middleware.STACRequest{
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

	handler, _ := NewHandler(Config{UpstreamURL: upstream.URL})
	resp, err := handler.Handle(context.Background(), &middleware.STACRequest{
		Request:     httptest.NewRequest("GET", "/", nil),
		Context:     context.Background(),
		RequestType: middleware.RequestTypeLanding,
	})
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if v := resp.Headers.Get("X-Private"); v != "" {
		t.Errorf("Connection-listed header X-Private leaked: %q", v)
	}
}

// TestHandle_ETagPassesThrough verifies M-14: caching/validation
// headers (ETag, Last-Modified, Cache-Control) on the upstream response
// are not stripped — they're end-to-end headers, not hop-by-hop.
func TestHandle_ETagPassesThrough(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"v42"`)
		w.Header().Set("Last-Modified", "Tue, 12 May 2026 12:00:00 GMT")
		w.Header().Set("Cache-Control", "max-age=60, public")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	handler, _ := NewHandler(Config{UpstreamURL: upstream.URL})
	resp, err := handler.Handle(context.Background(), &middleware.STACRequest{
		Request:     httptest.NewRequest("GET", "/", nil),
		Context:     context.Background(),
		RequestType: middleware.RequestTypeLanding,
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

	handler, _ := NewHandler(Config{UpstreamURL: upstream.URL})

	httpReq := httptest.NewRequest("GET", "/collections", nil)
	httpReq.RemoteAddr = "203.0.113.10:54321"
	httpReq.Host = "edge.example.com"

	_, err := handler.Handle(context.Background(), &middleware.STACRequest{
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
