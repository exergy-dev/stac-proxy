package server

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/exergy-dev/stac-proxy/internal/config"
	"github.com/exergy-dev/stac-proxy/internal/middleware"
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

// TestClientIP_Wiring confirms NewRouter wires the client-IP
// middleware selected by server.client_ip and that downstream
// consumers reading middleware.ClientIP see the right value. The
// default (remote_addr) must IGNORE forgeable headers — the old
// chi RealIP trusted X-Forwarded-For unconditionally (GO-2026-5777).
func TestClientIP_Wiring(t *testing.T) {
	cases := []struct {
		name    string
		cfg     config.ClientIPConfig
		headers map[string]string
		want    string
	}{
		{
			name:    "default remote_addr ignores spoofed XFF",
			cfg:     config.ClientIPConfig{},
			headers: map[string]string{"X-Forwarded-For": "1.2.3.4"},
			want:    "10.0.0.5",
		},
		{
			name:    "header source reads the proxy-owned header",
			cfg:     config.ClientIPConfig{Source: "header", Header: "CF-Connecting-IP"},
			headers: map[string]string{"CF-Connecting-IP": "203.0.113.9", "X-Forwarded-For": "1.2.3.4"},
			want:    "203.0.113.9",
		},
		{
			name:    "xff walks past trusted proxy CIDRs",
			cfg:     config.ClientIPConfig{Source: "xff", TrustedProxies: []string{"172.16.0.0/12"}},
			headers: map[string]string{"X-Forwarded-For": "1.2.3.4, 203.0.113.9, 172.16.0.7"},
			want:    "203.0.113.9",
		},
		{
			name:    "header source falls back to TCP peer when header absent",
			cfg:     config.ClientIPConfig{Source: "header", Header: "CF-Connecting-IP"},
			headers: nil,
			want:    "10.0.0.5",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var captured string
			inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				captured = middleware.ClientIP(r)
				w.WriteHeader(http.StatusOK)
			})
			r := NewRouter(RouterConfig{Handler: inner, ClientIP: tc.cfg})

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = "10.0.0.5:54321"
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			r.ServeHTTP(httptest.NewRecorder(), req)

			assert.Equal(t, tc.want, captured)
		})
	}
}
