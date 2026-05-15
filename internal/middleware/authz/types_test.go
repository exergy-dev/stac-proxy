package authz

import (
	"net/http/httptest"
	"testing"

	"github.com/yourorg/stac-proxy/internal/middleware"
)

// TestBuildAuthzInput_ReadsClientIPFromContext verifies M-authz-4: the
// authz input's ClientIP comes from the trusted-proxy-aware client-IP
// middleware (via middleware.ClientIPKey on the context), not from the
// raw r.RemoteAddr (which carries a port and ignores XFF).
func TestBuildAuthzInput_ReadsClientIPFromContext(t *testing.T) {
	r := httptest.NewRequest("GET", "/collections", nil)
	r.RemoteAddr = "10.0.0.1:54321" // would have been used pre-fix
	ctx := middleware.WithClientIP(r.Context(), "1.2.3.4")
	r = r.WithContext(ctx)

	input := BuildAuthzInput(r, nil, nil)
	if got, want := input.Request.ClientIP, "1.2.3.4"; got != want {
		t.Fatalf("ClientIP: got %q, want %q (must come from ClientIPKey, not RemoteAddr)", got, want)
	}
}

// TestBuildAuthzInput_FallbackStripsPort ensures that when no
// client-IP middleware ran, BuildAuthzInput still produces a clean
// host (no `:port`) so policy ip_range conditions parse it.
func TestBuildAuthzInput_FallbackStripsPort(t *testing.T) {
	r := httptest.NewRequest("GET", "/collections", nil)
	r.RemoteAddr = "10.0.0.1:54321"

	input := BuildAuthzInput(r, nil, nil)
	if got, want := input.Request.ClientIP, "10.0.0.1"; got != want {
		t.Fatalf("ClientIP fallback: got %q, want %q", got, want)
	}
}

// TestExtractHeaders_AllowlistOnly verifies M-authz-5: only headers
// on the default allowlist (User-Agent, Accept, etc.) are surfaced
// to the policy. Authorization, Cookie, custom bearer tokens, and
// any other novel auth header are dropped — the previous denylist
// happily forwarded e.g. X-Custom-Token to OPA / audit logs.
func TestExtractHeaders_AllowlistOnly(t *testing.T) {
	headers := map[string][]string{
		"User-Agent":      {"curl/7.0"},
		"Authorization":   {"Bearer secret"},
		"X-Custom-Token":  {"super-secret"},
		"X-Auth-Token":    {"another-secret"},
		"Accept":          {"application/json"},
		"Cookie":          {"session=abc"},
		"Proxy-Authorization": {"Basic xxx"},
	}

	got := extractHeaders(headers)

	if v, ok := got["User-Agent"]; !ok || v != "curl/7.0" {
		t.Fatalf("want User-Agent in output, got %v", got)
	}
	if v, ok := got["Accept"]; !ok || v != "application/json" {
		t.Fatalf("want Accept in output, got %v", got)
	}
	for _, banned := range []string{"Authorization", "X-Custom-Token", "X-Auth-Token", "Cookie", "Proxy-Authorization"} {
		if _, present := got[banned]; present {
			t.Fatalf("%s must NOT be forwarded by allowlist; got %v", banned, got)
		}
	}
}

// TestConfigureHeaderAllowlist_Extends confirms operators can opt in
// to additional headers via configuration without resurrecting the
// previous denylist behaviour.
func TestConfigureHeaderAllowlist_Extends(t *testing.T) {
	t.Cleanup(func() { ConfigureHeaderAllowlist(nil) })
	ConfigureHeaderAllowlist([]string{"X-Tenant-Id"})

	got := extractHeaders(map[string][]string{
		"X-Tenant-Id":    {"acme"},
		"Authorization":  {"Bearer secret"},
	})
	if v, ok := got["X-Tenant-Id"]; !ok || v != "acme" {
		t.Fatalf("want extended X-Tenant-Id, got %v", got)
	}
	if _, ok := got["Authorization"]; ok {
		t.Fatalf("Authorization must remain dropped after extending allowlist; got %v", got)
	}
}
