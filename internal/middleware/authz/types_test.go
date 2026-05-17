package authz

import (
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestBuildAuthzInput_StripsPortFromRemoteAddr ensures BuildAuthzInput
// always produces a clean host (no `:port`) for the ClientIP field so
// policy ip_range conditions parse it. After the chi RealIP swap,
// r.RemoteAddr is the only source — RealIP overwrites it from
// X-Real-IP / X-Forwarded-For / True-Client-IP when present.
func TestBuildAuthzInput_StripsPortFromRemoteAddr(t *testing.T) {
	r := httptest.NewRequest("GET", "/collections", nil)
	r.RemoteAddr = "10.0.0.1:54321"

	input := BuildAuthzInput(r, nil, nil)
	require.Equal(t, "10.0.0.1", input.Request.ClientIP, "ClientIP")
}

// TestExtractHeaders_AllowlistOnly verifies M-authz-5: only headers
// on the default allowlist (User-Agent, Accept, etc.) are surfaced
// to the policy. Authorization, Cookie, custom bearer tokens, and
// any other novel auth header are dropped — the previous denylist
// happily forwarded e.g. X-Custom-Token to OPA / audit logs.
func TestExtractHeaders_AllowlistOnly(t *testing.T) {
	headers := map[string][]string{
		"User-Agent":          {"curl/7.0"},
		"Authorization":       {"Bearer secret"},
		"X-Custom-Token":      {"super-secret"},
		"X-Auth-Token":        {"another-secret"},
		"Accept":              {"application/json"},
		"Cookie":              {"session=abc"},
		"Proxy-Authorization": {"Basic xxx"},
	}

	got := extractHeaders(headers)

	v, ok := got["User-Agent"]
	require.True(t, ok, "want User-Agent in output, got %v", got)
	require.Equal(t, "curl/7.0", v, "want User-Agent in output, got %v", got)

	v, ok = got["Accept"]
	require.True(t, ok, "want Accept in output, got %v", got)
	require.Equal(t, "application/json", v, "want Accept in output, got %v", got)

	for _, banned := range []string{"Authorization", "X-Custom-Token", "X-Auth-Token", "Cookie", "Proxy-Authorization"} {
		_, present := got[banned]
		require.False(t, present, "%s must NOT be forwarded by allowlist; got %v", banned, got)
	}
}

// TestConfigureHeaderAllowlist_Extends confirms operators can opt in
// to additional headers via configuration without resurrecting the
// previous denylist behaviour.
func TestConfigureHeaderAllowlist_Extends(t *testing.T) {
	t.Cleanup(func() { ConfigureHeaderAllowlist(nil) })
	ConfigureHeaderAllowlist([]string{"X-Tenant-Id"})

	got := extractHeaders(map[string][]string{
		"X-Tenant-Id":   {"acme"},
		"Authorization": {"Bearer secret"},
	})
	v, ok := got["X-Tenant-Id"]
	require.True(t, ok, "want extended X-Tenant-Id, got %v", got)
	require.Equal(t, "acme", v, "want extended X-Tenant-Id, got %v", got)

	_, ok = got["Authorization"]
	require.False(t, ok, "Authorization must remain dropped after extending allowlist; got %v", got)
}
