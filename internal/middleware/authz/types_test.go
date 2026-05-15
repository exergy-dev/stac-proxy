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
