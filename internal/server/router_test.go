package server

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/yourorg/stac-proxy/internal/middleware"
	"github.com/yourorg/stac-proxy/internal/observability"
)

func TestBodyLimitMiddleware_LargeBodyRejected(t *testing.T) {
	// Stand up a chi router with the body-limit middleware and a
	// handler that tries to read the whole body. Sending more than
	// the limit should fail the read; the standard library returns
	// http.ErrAbortHandler, which manifests as a 500/empty response.
	const limit = 1024
	mux := http.NewServeMux()
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, limit+1)
		n, err := r.Body.Read(b)
		if err == nil && n > limit {
			t.Errorf("expected read to fail past %d bytes, got n=%d err=nil", limit, n)
		}
		w.WriteHeader(http.StatusOK)
	})
	wrapped := bodyLimitMiddleware(limit)(mux)

	big := bytes.Repeat([]byte("x"), 4096)
	req := httptest.NewRequest("POST", "/echo", bytes.NewReader(big))
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)
}

func TestBodyLimitMiddleware_SmallBodyPasses(t *testing.T) {
	const limit = 1024
	mux := http.NewServeMux()
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		b, err := readAll(r.Body)
		if err != nil {
			t.Fatalf("unexpected read error: %v", err)
		}
		if !strings.HasPrefix(string(b), "tiny") {
			t.Errorf("body mismatch: %q", b)
		}
		w.WriteHeader(http.StatusOK)
	})
	wrapped := bodyLimitMiddleware(limit)(mux)

	req := httptest.NewRequest("POST", "/echo", strings.NewReader("tiny payload"))
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
}

func readAll(r interface {
	Read([]byte) (int, error)
}) ([]byte, error) {
	out := make([]byte, 0, 64)
	buf := make([]byte, 64)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			out = append(out, buf[:n]...)
		}
		if err != nil {
			if err.Error() == "EOF" {
				return out, nil
			}
			return out, err
		}
	}
}

// TestRouter_MetricsLabelsAreBounded is the C3 regression test:
// firing requests against /collections/{X}/items/{Y} with many distinct
// X, Y values must not produce many distinct metric series. The path
// label is the chi route pattern, so all such requests collapse to a
// single series.
//
// Without the fix, every distinct (collectionID, itemID) combination
// produced its own time series — an unbounded cardinality DoS against
// Prometheus.
func TestRouter_MetricsLabelsAreBounded(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	metrics := observability.NewMetrics("test_router_cardinality")
	r := NewRouter(RouterConfig{
		Handler: inner,
		Metrics: metrics,
	})

	// Fire 50 distinct (collectionID, itemID) combinations against the
	// items-by-id route. Without the fix this generates 50 series;
	// with the fix it's 1 (the pattern).
	for i := 0; i < 50; i++ {
		req := httptest.NewRequest(http.MethodGet,
			"/collections/coll-"+strings.Repeat("x", i+1)+"/items/item-"+strings.Repeat("y", i+1),
			nil)
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
	}

	// The pattern slot should have accumulated all 50 requests.
	const wantPattern = "/collections/{collectionId}/items/{itemId}"
	got := testutil.ToFloat64(metrics.RequestsTotal.WithLabelValues(http.MethodGet, wantPattern, "200"))
	if got < 50 {
		t.Errorf("pattern label %q only accumulated %v of 50 requests — raw path probably leaked into label",
			wantPattern, got)
	}
}

// --- H7 trusted-proxy XFF tests --------------------------------------------

// TestClientIP_IgnoresUntrustedXFF: when the immediate TCP peer is
// NOT in trusted_proxies, the X-Forwarded-For header must be ignored
// even if present — otherwise an internet-exposed listener lets any
// caller spoof its IP.
func TestClientIP_IgnoresUntrustedXFF(t *testing.T) {
	var captured string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = middleware.ClientIPFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	r := NewRouter(RouterConfig{
		Handler:        inner,
		TrustedProxies: nil, // empty — untrusted everywhere
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.5:54321"
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if captured != "203.0.113.5" {
		t.Errorf("client IP = %q, want %q (XFF should be ignored when not trusted)", captured, "203.0.113.5")
	}
}

// TestClientIP_ParsesTrustedXFF: when the immediate TCP peer IS in
// trusted_proxies, X-Forwarded-For's right-most untrusted entry is
// honored. This is the deployment-behind-LB path.
func TestClientIP_ParsesTrustedXFF(t *testing.T) {
	var captured string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = middleware.ClientIPFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	r := NewRouter(RouterConfig{
		Handler:        inner,
		TrustedProxies: []string{"10.0.0.0/8"},
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.5:54321"
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 10.0.0.1")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if captured != "1.2.3.4" {
		t.Errorf("client IP = %q, want %q (right-most untrusted XFF entry)", captured, "1.2.3.4")
	}
}

// TestClientIP_FallsBackToRemoteAddrWhenXFFAllTrusted: every XFF
// entry is itself in a trusted CIDR; nothing untrusted to pick →
// falls back to the peer's RemoteAddr.
func TestClientIP_FallsBackToRemoteAddrWhenXFFAllTrusted(t *testing.T) {
	var captured string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = middleware.ClientIPFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	r := NewRouter(RouterConfig{
		Handler:        inner,
		TrustedProxies: []string{"10.0.0.0/8"},
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.5:54321"
	req.Header.Set("X-Forwarded-For", "10.0.0.1, 10.0.0.2") // all trusted
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if captured != "10.0.0.5" {
		t.Errorf("client IP = %q, want %q (fallback to RemoteAddr)", captured, "10.0.0.5")
	}
}
