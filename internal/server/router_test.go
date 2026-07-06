package server

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
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

// TestRealIP_Smoke confirms chi/middleware.RealIP is wired in NewRouter
// (also exercises NewRouter/dispatch/handleLanding for coverage).
func TestRealIP_Smoke(t *testing.T) {
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

