package authz

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
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
	require.NoError(t, err, "Authorize error")
	require.NotNil(t, dec, "want Final deny to short-circuit AlwaysAllow, got nil decision")
	require.False(t, dec.Allowed, "want Final deny to short-circuit AlwaysAllow, got %+v", dec)
}
