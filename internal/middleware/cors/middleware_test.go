package cors

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// These tests cover the config-coercion + safety-rule surface owned by
// this package. Behavioural CORS semantics (preflight short-circuit,
// Vary handling, origin matching) are the responsibility of the
// underlying github.com/go-chi/cors library and are not retested here.

func TestNewFromConfig_RejectsCredentialsWithWildcard(t *testing.T) {
	_, err := NewFromConfig(map[string]interface{}{
		"allowed_origins":   []interface{}{"*"},
		"allow_credentials": true,
	})
	if err == nil {
		t.Fatal("expected error for credentials+wildcard, got nil")
	}
	if !strings.Contains(err.Error(), "wildcard") {
		t.Fatalf("error should mention wildcard; got %v", err)
	}
}

func TestNewFromConfig_RejectsNonStringOrigin(t *testing.T) {
	_, err := NewFromConfig(map[string]interface{}{
		"allowed_origins": []interface{}{"https://example.org", 42},
	})
	if err == nil {
		t.Fatal("expected error for non-string origin element")
	}
}

func TestNewFromConfig_MaxAgeAcceptsIntAndFloat(t *testing.T) {
	for name, v := range map[string]interface{}{
		"int":     120,
		"int64":   int64(120),
		"float64": float64(120),
	} {
		t.Run(name, func(t *testing.T) {
			mw, err := NewFromConfig(map[string]interface{}{
				"allowed_origins": []interface{}{"*"},
				"max_age":         v,
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if mw == nil {
				t.Fatal("nil middleware")
			}
		})
	}
}

func TestNewFromConfig_MaxAgeRejectsBadType(t *testing.T) {
	_, err := NewFromConfig(map[string]interface{}{
		"allowed_origins": []interface{}{"*"},
		"max_age":         "ten-minutes",
	})
	if err == nil {
		t.Fatal("expected error for non-numeric max_age")
	}
}

func TestNewFromConfig_AcceptsEmptyConfig(t *testing.T) {
	// Empty config (no origins) is permitted; chi/cors will simply
	// refuse to set ACAO on any request. Config validation in
	// internal/config/validation.go is the gatekeeper for "did the
	// operator forget to list origins"; this layer only fails on
	// type errors.
	mw, err := NewFromConfig(map[string]interface{}{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mw == nil {
		t.Fatal("nil middleware")
	}
}

func TestNewFromConfig_AppliesPreflightOnAllowedOrigin(t *testing.T) {
	// Smoke test that the adapter wires through to chi/cors and the
	// resulting middleware short-circuits a preflight from an allowed
	// origin. This is the integration check between our config layer
	// and the library — not a re-test of the library itself.
	mw, err := NewFromConfig(map[string]interface{}{
		"allowed_origins": []interface{}{"https://example.org"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	calls := 0
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++ })

	r := httptest.NewRequest(http.MethodOptions, "/collections", nil)
	r.Header.Set("Origin", "https://example.org")
	r.Header.Set("Access-Control-Request-Method", "GET")
	w := httptest.NewRecorder()
	mw(inner).ServeHTTP(w, r)

	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "https://example.org" {
		t.Fatalf("ACAO=%q", got)
	}
	if calls != 0 {
		t.Fatalf("preflight must not invoke inner handler; got %d calls", calls)
	}
}
