package authz

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestExternalOPA_OnErrorDeny_ReturnsExplicitDeny verifies that an
// OPA server that is unreachable / returns 5xx produces an explicit
// deny decision (not a bare error) when OnError=deny. The decision
// MUST also be marked Final so CompositeEnforcer.authorizeAny cannot
// silently fall through to a more permissive enforcer (M-authz-2).
func TestExternalOPA_OnErrorDeny_ReturnsExplicitDeny(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	enf, err := NewOPAEnforcer(OPAConfig{
		Name:      "test-opa",
		ServerURL: srv.URL,
		OnError:   OPAErrorDeny,
		Timeout:   200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewOPAEnforcer: %v", err)
	}

	dec, err := enf.Authorize(context.Background(), &AuthzInput{
		Request: &RequestInfo{Method: "GET", Path: "/"},
	})
	if err != nil {
		t.Fatalf("want explicit decision, got error: %v", err)
	}
	if dec == nil {
		t.Fatal("want non-nil decision")
	}
	if dec.Allowed {
		t.Fatalf("want deny on OPA outage with OnError=deny, got allow: %+v", dec)
	}
	if !dec.Final {
		t.Fatalf("want Final=true so authorizeAny cannot fall through, got false: %+v", dec)
	}
	if len(dec.Reasons) == 0 || dec.Reasons[0] != "external-opa unavailable: deny on error" {
		t.Fatalf("want reason 'external-opa unavailable: deny on error', got %v", dec.Reasons)
	}
}

// TestExternalOPA_OnErrorAllow_ReturnsExplicitAllow verifies fail-open
// mode produces an explicit (Final) allow decision so operators can
// keep service up during a planned OPA outage.
func TestExternalOPA_OnErrorAllow_ReturnsExplicitAllow(t *testing.T) {
	// No server -- connection refused exercises the transport-error path.
	enf, err := NewOPAEnforcer(OPAConfig{
		Name:      "test-opa",
		ServerURL: "http://127.0.0.1:1", // reserved port; refuses connections
		OnError:   OPAErrorAllow,
		Timeout:   200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewOPAEnforcer: %v", err)
	}

	dec, err := enf.Authorize(context.Background(), &AuthzInput{
		Request: &RequestInfo{Method: "GET", Path: "/"},
	})
	if err != nil {
		t.Fatalf("want explicit decision, got error: %v", err)
	}
	if dec == nil || !dec.Allowed {
		t.Fatalf("want allow on outage with OnError=allow, got %+v", dec)
	}
	if !dec.Final {
		t.Fatalf("want Final=true, got false: %+v", dec)
	}
	if len(dec.Reasons) == 0 || dec.Reasons[0] != "external-opa unavailable: allow on error" {
		t.Fatalf("want reason 'external-opa unavailable: allow on error', got %v", dec.Reasons)
	}
}

// TestNewOPAEnforcer_DefaultsToDeny ensures the zero-value OnError is
// fail-closed.
func TestNewOPAEnforcer_DefaultsToDeny(t *testing.T) {
	enf, err := NewOPAEnforcer(OPAConfig{
		Name:      "test-opa",
		ServerURL: "http://127.0.0.1:1",
		Timeout:   100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewOPAEnforcer: %v", err)
	}
	if enf.onError != OPAErrorDeny {
		t.Fatalf("want default OnError=deny, got %q", enf.onError)
	}
}

// TestNewOPAEnforcer_RejectsInvalidOnError ensures typos are caught at
// construction time rather than silently defaulting.
func TestNewOPAEnforcer_RejectsInvalidOnError(t *testing.T) {
	_, err := NewOPAEnforcer(OPAConfig{
		Name:      "test-opa",
		ServerURL: "http://127.0.0.1:1",
		OnError:   "permit", // typo
	})
	if err == nil {
		t.Fatal("want error on invalid OnError, got nil")
	}
}

// TestCompositeAny_FinalDenyShortCircuits verifies that a Final deny
// from one enforcer prevents authorizeAny from falling through to a
// more permissive enforcer — the integration point that actually
// closes the OPA-outage fail-open hole.
func TestCompositeAny_FinalDenyShortCircuits(t *testing.T) {
	finalDeny := &stubEnforcer{decision: &AuthzDecision{
		Allowed: false,
		Final:   true,
		Reasons: []string{"external-opa unavailable: deny on error"},
	}}
	allowAll := &AlwaysAllowEnforcer{}
	composite := NewCompositeEnforcer(CompositeModeAny, finalDeny, allowAll)

	dec, err := composite.Authorize(context.Background(), &AuthzInput{})
	if err != nil {
		t.Fatalf("Authorize error: %v", err)
	}
	if dec == nil || dec.Allowed {
		t.Fatalf("want Final deny to short-circuit AlwaysAllow, got %+v", dec)
	}
}
