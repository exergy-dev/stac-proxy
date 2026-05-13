package httpx

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSetXForwarded_EmptyChain_SetsSingleHop(t *testing.T) {
	in := httptest.NewRequest(http.MethodGet, "http://example.com/p", nil)
	in.RemoteAddr = "10.0.0.1:54321"

	out, _ := http.NewRequest(http.MethodGet, "http://upstream/p", nil)
	SetXForwarded(out, in)

	if got := out.Header.Get("X-Forwarded-For"); got != "10.0.0.1" {
		t.Fatalf("XFF = %q, want 10.0.0.1", got)
	}
}

func TestSetXForwarded_ExistingChain_Appends(t *testing.T) {
	in := httptest.NewRequest(http.MethodGet, "http://example.com/p", nil)
	in.RemoteAddr = "10.0.0.2:1111"

	out, _ := http.NewRequest(http.MethodGet, "http://upstream/p", nil)
	out.Header.Set("X-Forwarded-For", "203.0.113.7")

	SetXForwarded(out, in)

	want := "203.0.113.7, 10.0.0.2"
	if got := out.Header.Get("X-Forwarded-For"); got != want {
		t.Fatalf("XFF = %q, want %q", got, want)
	}
}

func TestSetXForwarded_ProtoHTTP(t *testing.T) {
	in := httptest.NewRequest(http.MethodGet, "http://example.com/p", nil)
	in.RemoteAddr = "10.0.0.1:1"
	in.TLS = nil

	out, _ := http.NewRequest(http.MethodGet, "http://upstream/p", nil)
	SetXForwarded(out, in)

	if got := out.Header.Get("X-Forwarded-Proto"); got != "http" {
		t.Fatalf("Proto = %q, want http", got)
	}
}

func TestSetXForwarded_ProtoHTTPS_WhenTLS(t *testing.T) {
	in := httptest.NewRequest(http.MethodGet, "http://example.com/p", nil)
	in.RemoteAddr = "10.0.0.1:1"
	in.TLS = &tls.ConnectionState{}

	out, _ := http.NewRequest(http.MethodGet, "http://upstream/p", nil)
	SetXForwarded(out, in)

	if got := out.Header.Get("X-Forwarded-Proto"); got != "https" {
		t.Fatalf("Proto = %q, want https", got)
	}
}

func TestSetXForwarded_PreservesInboundProto(t *testing.T) {
	in := httptest.NewRequest(http.MethodGet, "http://example.com/p", nil)
	in.RemoteAddr = "10.0.0.1:1"
	in.TLS = nil // edge terminates TLS
	in.Header.Set("X-Forwarded-Proto", "https")

	out, _ := http.NewRequest(http.MethodGet, "http://upstream/p", nil)
	SetXForwarded(out, in)

	if got := out.Header.Get("X-Forwarded-Proto"); got != "https" {
		t.Fatalf("Proto = %q, want https (preserved)", got)
	}
}

func TestSetXForwarded_SetsHost(t *testing.T) {
	in := httptest.NewRequest(http.MethodGet, "http://example.com/p", nil)
	in.RemoteAddr = "10.0.0.1:1"
	in.Host = "edge.example.com"

	out, _ := http.NewRequest(http.MethodGet, "http://upstream/p", nil)
	SetXForwarded(out, in)

	if got := out.Header.Get("X-Forwarded-Host"); got != "edge.example.com" {
		t.Fatalf("Host = %q, want edge.example.com", got)
	}
}

func TestSetXForwarded_NoRemoteAddr_DoesNotSetXFF(t *testing.T) {
	in := httptest.NewRequest(http.MethodGet, "http://example.com/p", nil)
	in.RemoteAddr = ""

	out, _ := http.NewRequest(http.MethodGet, "http://upstream/p", nil)
	SetXForwarded(out, in)

	if got := out.Header.Get("X-Forwarded-For"); got != "" {
		t.Fatalf("XFF unexpectedly set to %q", got)
	}
}

func TestSetXForwarded_RemoteAddrWithoutPort(t *testing.T) {
	in := httptest.NewRequest(http.MethodGet, "http://example.com/p", nil)
	in.RemoteAddr = "10.0.0.1" // no port

	out, _ := http.NewRequest(http.MethodGet, "http://upstream/p", nil)
	SetXForwarded(out, in)

	if got := out.Header.Get("X-Forwarded-For"); got != "10.0.0.1" {
		t.Fatalf("XFF = %q, want 10.0.0.1", got)
	}
}
