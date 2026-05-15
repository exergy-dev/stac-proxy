package observability

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestHealth_NoDetailsByDefault is the C5 regression test: by default,
// /health responses must not include per-check Message or Details
// fields, since those would leak upstream URLs and error strings to
// whoever can reach the endpoint.
func TestHealth_NoDetailsByDefault(t *testing.T) {
	h := NewHealthChecker()
	h.AddCheckFunc("upstream-secret-host", func(ctx context.Context) error {
		return errors.New("dial tcp 10.0.0.42:8080: connection refused")
	})

	rr := httptest.NewRecorder()
	h.HealthHandler().ServeHTTP(rr, httptest.NewRequest("GET", "/health", nil))

	body := rr.Body.String()

	// The secret-y bits must NOT be in the body.
	for _, leak := range []string{
		"10.0.0.42",
		"connection refused",
		"dial tcp",
	} {
		if strings.Contains(body, leak) {
			t.Errorf("health body leaked %q in default (Verbose=false) mode: %s", leak, body)
		}
	}

	// The status enum is still present.
	var resp HealthResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Status != StatusUnhealthy {
		t.Errorf("Status = %q, want %q", resp.Status, StatusUnhealthy)
	}
	for _, c := range resp.Checks {
		if c.Message != "" {
			t.Errorf("per-check Message leaked: %q", c.Message)
		}
		if c.Details != nil {
			t.Errorf("per-check Details leaked: %v", c.Details)
		}
	}
}

// TestHealth_VerboseEmitsDetails confirms the opt-in works: with
// Verbose=true the full payload comes through for operators on
// trusted networks.
func TestHealth_VerboseEmitsDetails(t *testing.T) {
	h := NewHealthChecker()
	h.Verbose = true
	h.AddCheckFunc("upstream", func(ctx context.Context) error {
		return errors.New("dial tcp 10.0.0.42:8080: connection refused")
	})

	rr := httptest.NewRecorder()
	h.HealthHandler().ServeHTTP(rr, httptest.NewRequest("GET", "/health", nil))

	if !strings.Contains(rr.Body.String(), "10.0.0.42") {
		t.Errorf("Verbose mode dropped check details: %s", rr.Body.String())
	}
}
