// Package authz provides authorization middleware.
package authz

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/yourorg/stac-proxy/internal/geo"
	"github.com/yourorg/stac-proxy/internal/middleware"
	"github.com/yourorg/stac-proxy/internal/middleware/auth"
	"github.com/yourorg/stac-proxy/internal/observability"
	"github.com/yourorg/stac-proxy/internal/stac"
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
func (m *AuthzMiddleware) ProcessRequest(ctx context.Context, req *middleware.STACRequest) (*middleware.STACRequest, error) {
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

	return req, nil
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
		var err error
		resp, err = filterResponseByGeofence(resp, decision.Constraints.Geofence)
		if err != nil {
			return nil, err
		}
	}

	// Single-record GET validation: when the policy emits a CQL2
	// filter (or geofence push-down isn't possible), evaluate the
	// combined predicate locally against the response body and
	// convert a non-match into a 404. CQL2InjectionEnabled gates the
	// whole feature.
	if m.cql2InjectionOn && req != nil && req.RequestType == middleware.RequestTypeItem {
		return validateSingleRecord(req, resp, decision.Constraints)
	}

	return resp, nil
}

// applyConstraints clamps the parsed SearchRequest's Limit to the
// authz-decided MaxResults (when smaller). The legacy writes of
// _allowed_collections/_denied_collections into Params had no
// downstream readers and were removed along with the Params field.
func applyConstraints(req *middleware.STACRequest, constraints *AuthzConstraints) {
	if constraints.MaxResults <= 0 || req.SearchReq == nil {
		return
	}
	if req.SearchReq.Limit <= 0 || req.SearchReq.Limit > constraints.MaxResults {
		req.SearchReq.Limit = constraints.MaxResults
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
	if mt := observability.Default(); mt != nil {
		reason := observability.CQL2ReasonPolicy
		switch {
		case constraints.GeofencePushedDown && userExpr != nil:
			reason = observability.CQL2ReasonMerged
		case constraints.GeofencePushedDown:
			reason = observability.CQL2ReasonGeofence
		}
		mt.CQL2Injected.WithLabelValues(req.SearchReq.FilterLang, reason).Inc()
	}
	return nil
}

// validateSingleRecord parses the response body as a STAC item and
// evaluates the combined policy + geofence CQL2 predicate against
// it. A non-match (or any evaluator error) is converted into a 404,
// hiding the existence of the record from the caller. The original
// response is returned unchanged if there's no predicate to apply,
// the response isn't a 2xx, or the body isn't valid JSON.
func validateSingleRecord(req *middleware.STACRequest, resp *middleware.STACResponse, c *AuthzConstraints) (*middleware.STACResponse, error) {
	if resp == nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp, nil
	}
	if c == nil {
		return resp, nil
	}
	// Build a combined predicate covering both the policy filter and
	// the geofence (if any). maybePushDownGeofence mutates c, but
	// since we're in ProcessResponse the request has already been
	// dispatched — the side-effect is harmless.
	if _, err := maybePushDownGeofence(c); err != nil {
		return resp, err
	}
	expr, err := parsePolicyCQL2(c)
	if err != nil {
		return resp, err
	}
	if expr == nil {
		return resp, nil
	}
	var item map[string]interface{}
	if err := json.Unmarshal(resp.Body, &item); err != nil {
		return resp, nil // not JSON; pass through
	}
	ok, err := stac.EvalCQL2(expr.N, item)
	if err != nil || !ok {
		return notFound(req), nil
	}
	return resp, nil
}

func notFound(req *middleware.STACRequest) *middleware.STACResponse {
	body := `{"code":"NotFound","description":"item not found"}`
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	return &middleware.STACResponse{
		StatusCode: http.StatusNotFound,
		Headers:    h,
		Body:       []byte(body),
	}
}

// filterResponseByGeofence post-filters a FeatureCollection response
// against a geofence: items whose geometry doesn't intersect the
// allowed area (or that fall entirely inside a denied area) are
// removed in place. Items with missing/invalid geometry are dropped
// conservatively. The response is returned unchanged when the body
// isn't a FeatureCollection, the geofence is empty, or the response
// status indicates an upstream error.
//
// This is the fallback path for upstreams that don't support the
// STAC Filter Extension. Origins that do support it get the
// equivalent predicate pushed down via maybePushDownGeofence in
// ProcessRequest, and ProcessResponse skips this branch via the
// GeofencePushedDown gate.
func filterResponseByGeofence(resp *middleware.STACResponse, geofence *GeofenceConstraint) (*middleware.STACResponse, error) {
	if resp == nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp, nil
	}
	if len(resp.Body) == 0 || geofence == nil {
		return resp, nil
	}
	allowed, denied, err := parseGeofenceAreas(geofence)
	if err != nil {
		return resp, nil // unparseable geofence — fail open at this layer
	}
	if allowed == nil && denied == nil {
		return resp, nil
	}

	var fc map[string]interface{}
	if err := json.Unmarshal(resp.Body, &fc); err != nil {
		return resp, nil // not JSON; pass through
	}
	features, ok := fc["features"].([]interface{})
	if !ok {
		return resp, nil // not a FeatureCollection shape; pass through
	}

	kept := make([]interface{}, 0, len(features))
	for _, f := range features {
		item, ok := f.(map[string]interface{})
		if !ok {
			continue
		}
		geomVal := item["geometry"]
		if geomVal == nil {
			continue
		}
		itemGeom, err := geo.ParseGeoJSON(geomVal)
		if err != nil || itemGeom == nil {
			continue
		}
		if allowed != nil && !allowed.Intersects(itemGeom) {
			continue
		}
		if denied != nil && denied.Contains(itemGeom) {
			continue
		}
		kept = append(kept, item)
	}
	fc["features"] = kept
	if _, has := fc["numberReturned"]; has {
		fc["numberReturned"] = len(kept)
	}
	if _, has := fc["numberMatched"]; has {
		// numberMatched is an upstream estimate of total hits across
		// pages. After post-filtering we can only honestly say "at
		// most this many" — clamp to current page size.
		fc["numberMatched"] = len(kept)
	}

	newBody, err := json.Marshal(fc)
	if err != nil {
		return resp, err
	}
	out := *resp
	out.Body = newBody
	return &out, nil
}

// parseGeofenceAreas parses the geofence's optional allowed and
// denied GeoJSON into *geo.Geometry pairs. Either side may be nil
// (absent from the constraint); only a parse error on the allowed
// side is propagated since the allowed area gates filtering.
func parseGeofenceAreas(g *GeofenceConstraint) (allowed, denied *geo.Geometry, err error) {
	if g.AllowedArea != nil {
		allowed, err = geo.ParseGeoJSON(g.AllowedArea)
		if err != nil {
			return nil, nil, err
		}
	}
	if g.DeniedArea != nil {
		denied, _ = geo.ParseGeoJSON(g.DeniedArea)
	}
	return allowed, denied, nil
}

// DecisionFromContext retrieves the authorization decision from context.
func DecisionFromContext(ctx context.Context) *AuthzDecision {
	if decision, ok := ctx.Value(middleware.AuthzDecisionKey).(*AuthzDecision); ok {
		return decision
	}
	return nil
}
