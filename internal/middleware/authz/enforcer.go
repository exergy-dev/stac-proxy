// Package authz provides authorization middleware.
package authz

import (
	"context"
	"errors"
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
		mergedConstraints = mergeConstraints(mergedConstraints, decision.Constraints)
	}

	return &AuthzDecision{
		Allowed:     true,
		Reasons:     allReasons,
		Constraints: mergedConstraints,
	}, nil
}

// authorizeAny requires any enforcer to allow.
func (e *CompositeEnforcer) authorizeAny(ctx context.Context, input *AuthzInput) (*AuthzDecision, error) {
	var allReasons []string

	for _, enforcer := range e.enforcers {
		decision, err := enforcer.Authorize(ctx, input)
		if err != nil {
			continue // Try next enforcer
		}

		if decision.Allowed {
			return decision, nil
		}

		allReasons = append(allReasons, decision.Reasons...)
	}

	return &AuthzDecision{
		Allowed: false,
		Reasons: allReasons,
	}, nil
}

// authorizeFirst uses the first enforcer that provides a decision.
func (e *CompositeEnforcer) authorizeFirst(ctx context.Context, input *AuthzInput) (*AuthzDecision, error) {
	for _, enforcer := range e.enforcers {
		decision, err := enforcer.Authorize(ctx, input)
		if err != nil {
			continue // Try next enforcer
		}
		return decision, nil
	}

	return &AuthzDecision{
		Allowed: false,
		Reasons: []string{"no enforcer could make a decision"},
	}, nil
}

// mergeConstraints merges two sets of constraints (intersection).
func mergeConstraints(a, b *AuthzConstraints) *AuthzConstraints {
	if a == nil {
		return b
	}
	if b == nil {
		return a
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

	// Merge geofences (intersection of areas)
	if a.Geofence != nil || b.Geofence != nil {
		merged.Geofence = mergeGeofences(a.Geofence, b.Geofence)
	}

	return merged
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

// mergeGeofences merges two geofence constraints.
func mergeGeofences(a, b *GeofenceConstraint) *GeofenceConstraint {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}

	// In a real implementation, this would compute the geometric
	// intersection of allowed areas and union of denied areas
	merged := &GeofenceConstraint{
		FilterMode: a.FilterMode || b.FilterMode,
	}

	// For now, prefer the more restrictive constraint
	if a.AllowedArea != nil {
		merged.AllowedArea = a.AllowedArea
	}
	if b.AllowedArea != nil && merged.AllowedArea == nil {
		merged.AllowedArea = b.AllowedArea
	}

	return merged
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
