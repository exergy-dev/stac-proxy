// Package authz provides authorization middleware.
package authz

import (
	"context"

	"github.com/yourorg/stac-proxy/internal/middleware"
	"github.com/yourorg/stac-proxy/internal/middleware/auth"
)

// AuthzMiddleware enforces authorization policies.
type AuthzMiddleware struct {
	enforcer       Enforcer
	allowAnonymous bool
	priority       int
}

// AuthzMiddlewareConfig configures the authorization middleware.
type AuthzMiddlewareConfig struct {
	Enforcer       Enforcer
	AllowAnonymous bool
	Priority       int
}

// NewAuthzMiddleware creates a new authorization middleware.
func NewAuthzMiddleware(cfg AuthzMiddlewareConfig) *AuthzMiddleware {
	return &AuthzMiddleware{
		enforcer:       cfg.Enforcer,
		allowAnonymous: cfg.AllowAnonymous,
		priority:       cfg.Priority,
	}
}

// Name returns the middleware name.
func (m *AuthzMiddleware) Name() string {
	return "authz"
}

// Priority returns the middleware priority.
func (m *AuthzMiddleware) Priority() int {
	return m.priority
}

// ProcessRequest checks authorization before passing to upstream.
func (m *AuthzMiddleware) ProcessRequest(ctx context.Context, req *middleware.STACRequest) (*middleware.STACResponse, error) {
	// Get principal from context
	principal := auth.PrincipalFromContext(ctx)

	// Check if anonymous access is allowed
	if principal == nil && !m.allowAnonymous {
		return nil, &middleware.AuthError{
			Message: "authentication required",
		}
	}

	// Build authorization input
	input := BuildAuthzInput(req, principal)

	// Evaluate authorization
	decision, err := m.enforcer.Authorize(ctx, input)
	if err != nil {
		return nil, &middleware.InternalError{
			Message: "authorization check failed",
			Cause:   err,
		}
	}

	if !decision.Allowed {
		reason := "access denied"
		if len(decision.Reasons) > 0 {
			reason = decision.Reasons[0]
		}
		return nil, &middleware.ForbiddenError{
			Reason: reason,
		}
	}

	// Store decision in context for downstream use
	req.Context = context.WithValue(ctx, middleware.AuthzDecisionKey, decision)

	// Apply constraints to request if present
	if decision.Constraints != nil {
		applyConstraints(req, decision.Constraints)
	}

	return nil, nil
}

// ProcessResponse optionally filters response based on authorization constraints.
func (m *AuthzMiddleware) ProcessResponse(ctx context.Context, req *middleware.STACRequest, resp *middleware.STACResponse) (*middleware.STACResponse, error) {
	// Get decision from context
	decision, ok := ctx.Value(middleware.AuthzDecisionKey).(*AuthzDecision)
	if !ok || decision == nil || decision.Constraints == nil {
		return resp, nil
	}

	// If geofence filtering is enabled, filter results
	if decision.Constraints.Geofence != nil && decision.Constraints.Geofence.FilterMode {
		return filterResponseByGeofence(resp, decision.Constraints.Geofence)
	}

	return resp, nil
}

// applyConstraints applies authorization constraints to the request.
func applyConstraints(req *middleware.STACRequest, constraints *AuthzConstraints) {
	// Apply max results constraint
	if constraints.MaxResults > 0 {
		if currentLimit, ok := req.Params["limit"].(int); ok {
			if currentLimit > constraints.MaxResults {
				req.Params["limit"] = constraints.MaxResults
			}
		} else {
			req.Params["limit"] = constraints.MaxResults
		}
	}

	// Store constraints in request params for downstream use
	if len(constraints.AllowedCollections) > 0 {
		req.Params["_allowed_collections"] = constraints.AllowedCollections
	}
	if len(constraints.DeniedCollections) > 0 {
		req.Params["_denied_collections"] = constraints.DeniedCollections
	}
}

// filterResponseByGeofence filters response items by geofence.
func filterResponseByGeofence(resp *middleware.STACResponse, geofence *GeofenceConstraint) (*middleware.STACResponse, error) {
	// This would use the geo package to filter items
	// For now, return response unchanged
	return resp, nil
}

// DecisionFromContext retrieves the authorization decision from context.
func DecisionFromContext(ctx context.Context) *AuthzDecision {
	if decision, ok := ctx.Value(middleware.AuthzDecisionKey).(*AuthzDecision); ok {
		return decision
	}
	return nil
}
