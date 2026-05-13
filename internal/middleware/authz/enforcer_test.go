package authz

import (
	"context"
	"errors"
	"testing"
)

// namedStubEnforcer returns a fixed decision for testing the composite
// layer. Separate from stubEnforcer in middleware_test.go because it
// needs a per-instance name (composite reasons reference Name()).
type namedStubEnforcer struct {
	name     string
	decision *AuthzDecision
}

func (s *namedStubEnforcer) Name() string { return s.name }
func (s *namedStubEnforcer) Authorize(_ context.Context, _ *AuthzInput) (*AuthzDecision, error) {
	return s.decision, nil
}

// TestCompositeEnforcer_ConflictingGeofencesReturnsError verifies H-7:
// when two enforcers each contribute an AllowedArea geofence we must
// not silently drop one of them. The error propagates up so the authz
// middleware turns it into a structured 500 (rather than the previous
// panic, which bypassed structured error handling).
func TestCompositeEnforcer_ConflictingGeofencesReturnsError(t *testing.T) {
	allowed := func(area string) *AuthzDecision {
		return &AuthzDecision{
			Allowed: true,
			Constraints: &AuthzConstraints{
				Geofence: &GeofenceConstraint{AllowedArea: area},
			},
		}
	}
	composite := NewCompositeEnforcer(
		CompositeModeAll,
		&namedStubEnforcer{name: "a", decision: allowed("region-A")},
		&namedStubEnforcer{name: "b", decision: allowed("region-B")},
	)

	_, err := composite.Authorize(context.Background(), &AuthzInput{})
	if err == nil {
		t.Fatalf("conflicting geofences must return an error, got nil")
	}
	if !errors.Is(err, ErrGeofenceMergeUnsupported) {
		t.Fatalf("error must wrap ErrGeofenceMergeUnsupported, got %v", err)
	}
}

// TestCompositeEnforcer_NonConflictingGeofencesMergeCleanly verifies the
// success path: one AllowedArea + one FilterMode-only is mergeable.
func TestCompositeEnforcer_NonConflictingGeofencesMergeCleanly(t *testing.T) {
	composite := NewCompositeEnforcer(
		CompositeModeAll,
		&namedStubEnforcer{name: "a", decision: &AuthzDecision{
			Allowed: true,
			Constraints: &AuthzConstraints{
				Geofence: &GeofenceConstraint{AllowedArea: "region-A"},
			},
		}},
		&namedStubEnforcer{name: "b", decision: &AuthzDecision{
			Allowed: true,
			Constraints: &AuthzConstraints{
				Geofence: &GeofenceConstraint{FilterMode: true},
			},
		}},
	)

	decision, err := composite.Authorize(context.Background(), &AuthzInput{})
	if err != nil {
		t.Fatalf("non-conflicting merge: %v", err)
	}
	if !decision.Allowed {
		t.Fatalf("expected allowed, got denied: %v", decision.Reasons)
	}
	if decision.Constraints.Geofence.AllowedArea != "region-A" {
		t.Errorf("AllowedArea: want region-A, got %v", decision.Constraints.Geofence.AllowedArea)
	}
	if !decision.Constraints.Geofence.FilterMode {
		t.Errorf("FilterMode should be true (OR of inputs)")
	}
}
