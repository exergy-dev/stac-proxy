// Package authz provides authorization middleware.
package authz

import (
	"context"
	"errors"
	"fmt"
)

// CompositeEnforcer combines multiple enforcers.
type CompositeEnforcer struct {
	enforcers []Enforcer
	mode      CompositeMode
}

// CompositeMode defines how multiple enforcers are combined.
type CompositeMode string

const (
	// CompositeModeAll requires all enforcers to allow (AND).
	CompositeModeAll CompositeMode = "all"

	// CompositeModeAny requires any enforcer to allow (OR).
	CompositeModeAny CompositeMode = "any"

	// CompositeModeFirst uses the first enforcer that returns a decision.
	CompositeModeFirst CompositeMode = "first"
)

// NewCompositeEnforcer creates a new composite enforcer.
func NewCompositeEnforcer(mode CompositeMode, enforcers ...Enforcer) *CompositeEnforcer {
	return &CompositeEnforcer{
		enforcers: enforcers,
		mode:      mode,
	}
}

// Name returns the enforcer name.
func (e *CompositeEnforcer) Name() string {
	return "composite"
}

// Authorize makes an authorization decision using all configured enforcers.
func (e *CompositeEnforcer) Authorize(ctx context.Context, input *AuthzInput) (*AuthzDecision, error) {
	if len(e.enforcers) == 0 {
		return &AuthzDecision{Allowed: true}, nil
	}

	switch e.mode {
	case CompositeModeAll:
		return e.authorizeAll(ctx, input)
	case CompositeModeAny:
		return e.authorizeAny(ctx, input)
	case CompositeModeFirst:
		return e.authorizeFirst(ctx, input)
	default:
		return nil, errors.New("invalid composite mode")
	}
}

// authorizeAll requires all enforcers to allow.
func (e *CompositeEnforcer) authorizeAll(ctx context.Context, input *AuthzInput) (*AuthzDecision, error) {
	var allReasons []string
	var mergedConstraints *AuthzConstraints

	for _, enforcer := range e.enforcers {
		decision, err := enforcer.Authorize(ctx, input)
		if err != nil {
			return nil, err
		}

		if !decision.Allowed {
			return &AuthzDecision{
				Allowed: false,
				Reasons: append([]string{"denied by " + enforcer.Name()}, decision.Reasons...),
			}, nil
		}

		allReasons = append(allReasons, decision.Reasons...)
		mergedConstraints, err = mergeConstraints(mergedConstraints, decision.Constraints)
		if err != nil {
			return nil, fmt.Errorf("merge constraints from %s: %w", enforcer.Name(), err)
		}
	}

	return &AuthzDecision{
		Allowed:     true,
		Reasons:     allReasons,
		Constraints: mergedConstraints,
	}, nil
}

// authorizeAny requires any enforcer to allow. Per-enforcer errors do
// not short-circuit (so a transient OPA outage doesn't deny everything
// when another enforcer would have allowed), but they ARE surfaced in
// the final Reasons so operators can diagnose silent fall-throughs.
//
// An enforcer that returns a decision with Final=true is treated as
// authoritative and short-circuits the loop in either direction —
// notably the external OPA enforcer marks its OnError-deny decision
// Final so an OPA outage cannot fall through to a more permissive
// fallback enforcer (M-authz-2).
func (e *CompositeEnforcer) authorizeAny(ctx context.Context, input *AuthzInput) (*AuthzDecision, error) {
	var allReasons []string
	var errs []error

	for _, enforcer := range e.enforcers {
		decision, err := enforcer.Authorize(ctx, input)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", enforcer.Name(), err))
			allReasons = append(allReasons, fmt.Sprintf("enforcer %s errored: %v", enforcer.Name(), err))
			continue
		}

		if decision.Allowed {
			return decision, nil
		}

		// A Final deny short-circuits the OR loop: the enforcer has
		// declared its decision authoritative (e.g. OPA outage with
		// OnError=deny). Falling through to another enforcer would
		// reintroduce the fail-open the Final marker exists to prevent.
		if decision.Final {
			return decision, errors.Join(errs...)
		}

		allReasons = append(allReasons, decision.Reasons...)
	}

	return &AuthzDecision{
		Allowed: false,
		Reasons: allReasons,
	}, errors.Join(errs...)
}

// authorizeFirst uses the first enforcer that provides a decision.
// Errors are surfaced (joined) so a misconfigured front enforcer does
// not silently mask the result.
func (e *CompositeEnforcer) authorizeFirst(ctx context.Context, input *AuthzInput) (*AuthzDecision, error) {
	var errs []error
	for _, enforcer := range e.enforcers {
		decision, err := enforcer.Authorize(ctx, input)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", enforcer.Name(), err))
			continue
		}
		return decision, nil
	}

	return &AuthzDecision{
		Allowed: false,
		Reasons: []string{"no enforcer could make a decision"},
	}, errors.Join(errs...)
}

// mergeConstraints merges two sets of constraints (intersection). It
// can fail when merging geofences with overlapping AllowedAreas (see
// mergeGeofences); the caller surfaces the error as a 500.
func mergeConstraints(a, b *AuthzConstraints) (*AuthzConstraints, error) {
	if a == nil {
		return b, nil
	}
	if b == nil {
		return a, nil
	}

	merged := &AuthzConstraints{}

	// Merge allowed collections (intersection)
	if len(a.AllowedCollections) > 0 && len(b.AllowedCollections) > 0 {
		merged.AllowedCollections = intersectStrings(a.AllowedCollections, b.AllowedCollections)
	} else if len(a.AllowedCollections) > 0 {
		merged.AllowedCollections = a.AllowedCollections
	} else {
		merged.AllowedCollections = b.AllowedCollections
	}

	// Merge denied collections (union)
	merged.DeniedCollections = unionStrings(a.DeniedCollections, b.DeniedCollections)

	// Use stricter max results
	if a.MaxResults > 0 && b.MaxResults > 0 {
		if a.MaxResults < b.MaxResults {
			merged.MaxResults = a.MaxResults
		} else {
			merged.MaxResults = b.MaxResults
		}
	} else if a.MaxResults > 0 {
		merged.MaxResults = a.MaxResults
	} else {
		merged.MaxResults = b.MaxResults
	}

	if a.Geofence != nil || b.Geofence != nil {
		gf, err := mergeGeofences(a.Geofence, b.Geofence)
		if err != nil {
			return nil, err
		}
		merged.Geofence = gf
	}

	return merged, nil
}

// intersectStrings returns the intersection of two string slices.
func intersectStrings(a, b []string) []string {
	set := make(map[string]bool)
	for _, s := range a {
		set[s] = true
	}

	var result []string
	for _, s := range b {
		if set[s] {
			result = append(result, s)
		}
	}
	return result
}

// removeStrings returns the elements of a that are not in b.
func removeStrings(a, b []string) []string {
	deny := make(map[string]bool, len(b))
	for _, s := range b {
		deny[s] = true
	}
	out := make([]string, 0, len(a))
	for _, s := range a {
		if !deny[s] {
			out = append(out, s)
		}
	}
	return out
}

// unionStrings returns the union of two string slices.
func unionStrings(a, b []string) []string {
	set := make(map[string]bool)
	for _, s := range a {
		set[s] = true
	}
	for _, s := range b {
		set[s] = true
	}

	result := make([]string, 0, len(set))
	for s := range set {
		result = append(result, s)
	}
	return result
}

// ErrGeofenceMergeUnsupported is returned when two enforcers each
// contribute a geofence AllowedArea — merging would require geometric
// intersection, which isn't implemented. Operators must restrict
// configuration to a single geofence-bearing enforcer until that lands.
var ErrGeofenceMergeUnsupported = errors.New("authz: cannot merge multiple enforcers each contributing an AllowedArea geofence (geometric intersection not implemented)")

// mergeGeofences merges two geofence constraints. Returns
// ErrGeofenceMergeUnsupported rather than silently dropping a
// restriction when both sides contribute an AllowedArea — callers
// surface this as a 500 so misconfiguration is loud, not fail-open.
func mergeGeofences(a, b *GeofenceConstraint) (*GeofenceConstraint, error) {
	if a == nil {
		return b, nil
	}
	if b == nil {
		return a, nil
	}
	if a.AllowedArea != nil && b.AllowedArea != nil {
		return nil, ErrGeofenceMergeUnsupported
	}

	merged := &GeofenceConstraint{
		FilterMode: a.FilterMode || b.FilterMode,
	}
	if a.AllowedArea != nil {
		merged.AllowedArea = a.AllowedArea
	} else if b.AllowedArea != nil {
		merged.AllowedArea = b.AllowedArea
	}
	return merged, nil
}

// AlwaysAllowEnforcer always allows requests.
type AlwaysAllowEnforcer struct{}

// Name returns the enforcer name.
func (e *AlwaysAllowEnforcer) Name() string {
	return "always-allow"
}

// Authorize always returns allowed.
func (e *AlwaysAllowEnforcer) Authorize(ctx context.Context, input *AuthzInput) (*AuthzDecision, error) {
	return &AuthzDecision{Allowed: true}, nil
}

// AlwaysDenyEnforcer always denies requests.
type AlwaysDenyEnforcer struct {
	Reason string
}

// Name returns the enforcer name.
func (e *AlwaysDenyEnforcer) Name() string {
	return "always-deny"
}

// Authorize always returns denied.
func (e *AlwaysDenyEnforcer) Authorize(ctx context.Context, input *AuthzInput) (*AuthzDecision, error) {
	reason := e.Reason
	if reason == "" {
		reason = "access denied"
	}
	return &AuthzDecision{
		Allowed: false,
		Reasons: []string{reason},
	}, nil
}
