package authz

import (
	"context"
	"testing"
)

// TestCompositeAny_FinalDenyShortCircuits verifies that a Final deny
// from one enforcer prevents authorizeAny from falling through to a
// more permissive enforcer.
func TestCompositeAny_FinalDenyShortCircuits(t *testing.T) {
	finalDeny := &stubEnforcer{decision: &AuthzDecision{
		Allowed: false,
		Final:   true,
		Reasons: []string{"upstream authz unavailable: deny on error"},
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
