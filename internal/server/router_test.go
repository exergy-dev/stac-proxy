package server

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
		if err == nil {
			assert.LessOrEqual(t, n, limit, "expected read to fail past %d bytes, got n=%d err=nil", limit, n)
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
		require.NoError(t, err, "unexpected read error")
		assert.True(t, strings.HasPrefix(string(b), "tiny"), "body mismatch: %q", b)
		w.WriteHeader(http.StatusOK)
	})
	wrapped := bodyLimitMiddleware(limit)(mux)

	req := httptest.NewRequest("POST", "/echo", strings.NewReader("tiny payload"))
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code, "want 200")
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

// --- chi RealIP wiring ------------------------------------------------------

// TestRealIP_RewritesRemoteAddrFromXFF confirms chi/middleware.RealIP
// is wired before the inner handler so r.RemoteAddr reflects the
// X-Forwarded-For / X-Real-IP / True-Client-IP source.
func TestRealIP_RewritesRemoteAddrFromXFF(t *testing.T) {
	var captured string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = r.RemoteAddr
		w.WriteHeader(http.StatusOK)
	})
	r := NewRouter(RouterConfig{Handler: inner})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.5:54321"
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	r.ServeHTTP(httptest.NewRecorder(), req)

	assert.Equal(t, "1.2.3.4", captured)
}

// TestRealIP_FallsBackToRemoteAddr: with no spoof headers present,
// r.RemoteAddr stays as the TCP peer.
func TestRealIP_FallsBackToRemoteAddr(t *testing.T) {
	var captured string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = r.RemoteAddr
		w.WriteHeader(http.StatusOK)
	})
	r := NewRouter(RouterConfig{Handler: inner})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.5:54321"
	r.ServeHTTP(httptest.NewRecorder(), req)

	assert.Equal(t, "10.0.0.5:54321", captured)
}
