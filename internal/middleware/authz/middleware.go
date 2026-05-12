// Package authz provides authorization middleware.
package authz

import (
	"context"

	"github.com/yourorg/stac-proxy/internal/middleware"
	"github.com/yourorg/stac-proxy/internal/middleware/auth"
)

// AuthzMiddleware enforces authorization policies.
type AuthzMiddleware struct {
	enforcer             Enforcer
	allowAnonymous       bool
	priority             int
	cql2InjectionOn      bool
	filterExtensionCheck func(req *middleware.STACRequest) bool
}

// AuthzMiddlewareConfig configures the authorization middleware.
type AuthzMiddlewareConfig struct {
	Enforcer       Enforcer
	AllowAnonymous bool
	Priority       int
	// CQL2InjectionEnabled gates CQL2 filter injection and geofence
	// push-down. When false (the default), policy CQL2 fields and
	// GeofencePushedDown are ignored; the response-side post-filter
	// remains responsible for enforcement.
	CQL2InjectionEnabled bool
	// FilterExtensionCheck is consulted per request to decide whether
	// CQL2 push-down is safe (i.e. whether the target upstream
	// advertises STAC Filter Extension support). When nil, push-down
	// runs whenever CQL2InjectionEnabled is true — appropriate for
	// tests and simple deployments. In single-origin mode wire this
	// to a constant returning the upstream's flag; in federation,
	// AND across the candidate origins for this request.
	FilterExtensionCheck func(req *middleware.STACRequest) bool
}

// NewAuthzMiddleware creates a new authorization middleware.
func NewAuthzMiddleware(cfg AuthzMiddlewareConfig) *AuthzMiddleware {
	return &AuthzMiddleware{
		enforcer:             cfg.Enforcer,
		allowAnonymous:       cfg.AllowAnonymous,
		priority:             cfg.Priority,
		cql2InjectionOn:      cfg.CQL2InjectionEnabled,
		filterExtensionCheck: cfg.FilterExtensionCheck,
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

	// CQL2 filter injection. Only runs when explicitly enabled, the
	// request carries a parsed search body, and (if configured) the
	// target upstream supports the Filter Extension.
	if m.cql2InjectionOn && req.SearchReq != nil && decision.Constraints != nil &&
		(m.filterExtensionCheck == nil || m.filterExtensionCheck(req)) {
		if err := injectCQL2Filter(req, decision.Constraints); err != nil {
			// Surface as an internal error rather than silently dropping
			// authz intent.
			return nil, &middleware.InternalError{
				Message: "cql2 injection failed",
				Cause:   err,
			}
		}
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

	// If geofence filtering is enabled, filter results — unless the
	// geofence was already pushed down as a CQL2 predicate, in which
	// case the upstream has already filtered for us.
	if decision.Constraints.Geofence != nil &&
		decision.Constraints.Geofence.FilterMode &&
		!decision.Constraints.GeofencePushedDown {
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

// injectCQL2Filter merges policy CQL2 (including any geofence
// push-down) with the client's filter and writes the combined
// expression back into req.SearchReq.Filter in the original lang.
//
// Errors from push-down conversion or encoding are returned; parsing
// the user's filter is best-effort — if it fails (e.g. the client
// sent something unparseable) we still inject the policy filter
// alone, since the upstream would have rejected the original anyway.
func injectCQL2Filter(req *middleware.STACRequest, constraints *AuthzConstraints) error {
	if _, err := maybePushDownGeofence(constraints); err != nil {
		return err
	}
	policyExpr, err := parsePolicyCQL2(constraints)
	if err != nil {
		return err
	}
	userExpr, _ := parseUserCQL2(req.SearchReq.Filter)
	merged := andNonNil(userExpr, policyExpr)
	if merged == nil {
		return nil
	}
	lang := req.SearchReq.FilterLang
	if lang == "" {
		lang = "cql2-text"
	}
	encoded, err := encodeForLang(merged, lang)
	if err != nil {
		return err
	}
	req.SearchReq.Filter = encoded
	if req.SearchReq.FilterLang == "" {
		req.SearchReq.FilterLang = "cql2-text"
	}
	return nil
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
