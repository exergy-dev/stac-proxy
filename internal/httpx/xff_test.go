package httpx

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSetXForwarded_EmptyChain_SetsSingleHop(t *testing.T) {
	in := httptest.NewRequest(http.MethodGet, "http://example.com/p", nil)
	in.RemoteAddr = "10.0.0.1:54321"

	out, _ := http.NewRequest(http.MethodGet, "http://upstream/p", nil)
	SetXForwarded(out, in)

	require.Equal(t, "10.0.0.1", out.Header.Get("X-Forwarded-For"), "XFF")
}

func TestSetXForwarded_ExistingChain_Appends(t *testing.T) {
	in := httptest.NewRequest(http.MethodGet, "http://example.com/p", nil)
	in.RemoteAddr = "10.0.0.2:1111"

	out, _ := http.NewRequest(http.MethodGet, "http://upstream/p", nil)
	out.Header.Set("X-Forwarded-For", "203.0.113.7")

	SetXForwarded(out, in)

	require.Equal(t, "203.0.113.7, 10.0.0.2", out.Header.Get("X-Forwarded-For"), "XFF")
}

func TestSetXForwarded_ProtoHTTP(t *testing.T) {
	in := httptest.NewRequest(http.MethodGet, "http://example.com/p", nil)
	in.RemoteAddr = "10.0.0.1:1"
	in.TLS = nil

	out, _ := http.NewRequest(http.MethodGet, "http://upstream/p", nil)
	SetXForwarded(out, in)

	require.Equal(t, "http", out.Header.Get("X-Forwarded-Proto"), "Proto")
}

func TestSetXForwarded_ProtoHTTPS_WhenTLS(t *testing.T) {
	in := httptest.NewRequest(http.MethodGet, "http://example.com/p", nil)
	in.RemoteAddr = "10.0.0.1:1"
	in.TLS = &tls.ConnectionState{}

	out, _ := http.NewRequest(http.MethodGet, "http://upstream/p", nil)
	SetXForwarded(out, in)

	require.Equal(t, "https", out.Header.Get("X-Forwarded-Proto"), "Proto")
}

func TestSetXForwarded_PreservesInboundProto(t *testing.T) {
	in := httptest.NewRequest(http.MethodGet, "http://example.com/p", nil)
	in.RemoteAddr = "10.0.0.1:1"
	in.TLS = nil // edge terminates TLS
	in.Header.Set("X-Forwarded-Proto", "https")

	out, _ := http.NewRequest(http.MethodGet, "http://upstream/p", nil)
	SetXForwarded(out, in)

	require.Equal(t, "https", out.Header.Get("X-Forwarded-Proto"), "Proto (preserved)")
}

func TestSetXForwarded_SetsHost(t *testing.T) {
	in := httptest.NewRequest(http.MethodGet, "http://example.com/p", nil)
	in.RemoteAddr = "10.0.0.1:1"
	in.Host = "edge.example.com"

	out, _ := http.NewRequest(http.MethodGet, "http://upstream/p", nil)
	SetXForwarded(out, in)

	require.Equal(t, "edge.example.com", out.Header.Get("X-Forwarded-Host"), "Host")
}

func TestSetXForwarded_NoRemoteAddr_DoesNotSetXFF(t *testing.T) {
	in := httptest.NewRequest(http.MethodGet, "http://example.com/p", nil)
	in.RemoteAddr = ""

	out, _ := http.NewRequest(http.MethodGet, "http://upstream/p", nil)
	SetXForwarded(out, in)

	require.Empty(t, out.Header.Get("X-Forwarded-For"), "XFF unexpectedly set")

	// RemoteAddr without a port falls back to the raw value via the
	// SplitHostPort error path.
	in.RemoteAddr = "10.0.0.1" // no port
	out2, _ := http.NewRequest(http.MethodGet, "http://upstream/p", nil)
	SetXForwarded(out2, in)
	require.Equal(t, "10.0.0.1", out2.Header.Get("X-Forwarded-For"), "XFF (no port)")
}

