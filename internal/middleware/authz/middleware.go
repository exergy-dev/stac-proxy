// Package authz provides authorization middleware.
//
// Authz is a chi-style http middleware that:
//   - reads the parsed STAC shape from r.Context() and the authenticated
//     Principal set by the auth middleware,
//   - asks the Enforcer to decide,
//   - on deny, writes 401/403 and short-circuits,
//   - on allow, optionally clamps SearchReq.Limit (applyConstraints) and
//     injects a combined CQL2 filter (injectCQL2Filter) so the upstream
//     does as much work as possible,
//   - buffers the inner handler's response via httpx.ResponseCapture and
//     applies the response-side enforcement: geofence post-filtering of
//     FeatureCollections and single-record CQL2 validation that turns a
//     non-match into a 404.
package authz

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/yourorg/stac-proxy/internal/geo"
	"github.com/yourorg/stac-proxy/internal/httpx"
	"github.com/yourorg/stac-proxy/internal/middleware"
	"github.com/yourorg/stac-proxy/internal/middleware/auth"
	"github.com/yourorg/stac-proxy/internal/stac"
)

// HTTPConfig configures the chi-style authz middleware.
type HTTPConfig struct {
	Enforcer       Enforcer
	AllowAnonymous bool
	// CQL2InjectionEnabled gates CQL2 filter injection and geofence
	// push-down. When false (the default), policy CQL2 fields and
	// GeofencePushedDown are ignored; the response-side post-filter
	// remains responsible for enforcement.
	CQL2InjectionEnabled bool
	// FilterExtensionCheck is consulted per request to decide whether
	// CQL2 push-down is safe (i.e. whether the target upstream
	// advertises STAC Filter Extension support). When nil, push-down
	// runs whenever CQL2InjectionEnabled is true — appropriate for
	// tests and simple deployments. In federation, AND across the
	// candidate origins for this request.
	FilterExtensionCheck func(r *http.Request, info *middleware.STACInfo) bool
	// SpatialFilterCheck reports whether the routed upstream(s)
	// advertise CQL2 spatial-predicate support (basic-spatial-functions
	// or similar). When false, geofence push-down is skipped and the
	// response-side post-filter stays responsible. When nil, push-down
	// is allowed whenever FilterExtensionCheck (or, if also nil,
	// CQL2InjectionEnabled) permits — the historical behaviour.
	SpatialFilterCheck func(r *http.Request, info *middleware.STACInfo) bool
}

// NewHTTPMiddleware returns chi-compatible authorization middleware.
func NewHTTPMiddleware(cfg HTTPConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			principal := auth.PrincipalFromContext(ctx)
			info := middleware.STACInfoFromContext(ctx)

			if principal == nil && !cfg.AllowAnonymous {
				middleware.WriteJSONError(w, http.StatusUnauthorized, "Unauthorized", "authentication required")
				return
			}

			input := BuildAuthzInput(r, info, principal)
			decision, err := cfg.Enforcer.Authorize(ctx, input)
			if err != nil {
				middleware.WriteJSONError(w, http.StatusInternalServerError, "InternalError", "authorization check failed")
				return
			}
			if !decision.Allowed {
				reason := "access denied"
				if len(decision.Reasons) > 0 {
					reason = decision.Reasons[0]
				}
				middleware.WriteJSONError(w, http.StatusForbidden, "Forbidden", reason)
				return
			}

			// Stash decision for downstream code paths (filtering,
			// observability) that may want it.
			ctx = context.WithValue(ctx, middleware.AuthzDecisionKey, decision)
			r = r.WithContext(ctx)

			// Pre-upstream request mutations. Only fire when there's a
			// parsed search body to mutate AND there are constraints.
			// The search-body parser middleware in internal/server runs
			// before this middleware so info.SearchReq is populated for
			// search-like routes; non-search routes still hit nil here
			// and the constraint application is skipped (only the
			// response-side enforcement runs in that case).
			if info != nil && info.SearchReq != nil && decision.Constraints != nil {
				if err := applyConstraints(info.SearchReq, decision.Constraints); err != nil {
					middleware.WriteJSONError(w, http.StatusForbidden, "Forbidden", err.Error())
					return
				}
				if cfg.CQL2InjectionEnabled &&
					(cfg.FilterExtensionCheck == nil || cfg.FilterExtensionCheck(r, info)) {
					spatialOK := cfg.SpatialFilterCheck == nil || cfg.SpatialFilterCheck(r, info)
					updated, err := injectCQL2Filter(info.SearchReq, decision.Constraints, spatialOK)
					if err != nil {
						// A user-supplied CQL2 filter that fails to parse
						// is a client error, not an internal one. Surface
						// it as 400 with a STAC-style error code so callers
						// can correct their request.
						if isUserCQL2ParseError(err) {
							middleware.WriteJSONError(w, http.StatusBadRequest, "InvalidParameterValue",
								"invalid filter: "+err.Error())
							return
						}
						middleware.WriteJSONError(w, http.StatusInternalServerError, "InternalError", "cql2 injection failed")
						return
					}
					// Replace the decision's constraints with the
					// (possibly new) constraint produced by push-down so
					// the response-side branches below see GeofencePushedDown
					// without us having mutated the shared object.
					decision.Constraints = updated
				}
			}

			// Capture the inner response so we can post-filter it.
			cap := httpx.NewResponseCapture()
			next.ServeHTTP(cap, r)

			status := cap.Status()
			body := cap.BodyBytes()

			// Geofence post-filter: only when allowed-area is set,
			// filter-mode is on, and the geofence wasn't pushed down as
			// a CQL2 predicate. A malformed FeatureCollection on a 2xx
			// upstream response now fails closed (502) instead of being
			// forwarded unfiltered — see filterByGeofence.
			if decision.Constraints != nil &&
				decision.Constraints.Geofence != nil &&
				decision.Constraints.Geofence.FilterMode &&
				!decision.Constraints.GeofencePushedDown &&
				status >= 200 && status < 300 {
				filtered, fstatus := filterByGeofence(body, decision.Constraints.Geofence)
				switch fstatus {
				case geofenceFiltered:
					body = filtered
				case geofenceMalformed:
					middleware.WriteJSONError(w, http.StatusBadGateway, "BadGateway",
						"upstream returned malformed FeatureCollection; geofence cannot enforce")
					return
				case geofenceNotApplicable:
					// Body wasn't a FeatureCollection (e.g. a singular
					// Item or a JSON error wrapped in 200) — pass through
					// unchanged. The single-record validation branch
					// below will catch policy violations on items.
				}
			}

			// Single-record GET validation: when the policy emits any
			// constraint (CQL2 filter or geofence), evaluate the
			// combined predicate locally against the response body and
			// convert a non-match into a 404, hiding existence.
			//
			// This is intentionally NOT gated on CQL2InjectionEnabled.
			// CQL2InjectionEnabled controls whether we push CQL2 down
			// to the upstream search; for a single-item GET there is no
			// push-down to do, only local enforcement of an authz
			// constraint we already received from the policy. Gating
			// validation on the injection switch caused single-item GETs
			// to silently bypass policy CQL2 + geofence whenever the
			// operator preferred response-side filtering for searches.
			if info != nil && info.RequestType == middleware.RequestTypeItem &&
				status >= 200 && status < 300 && decision.Constraints != nil {
				if matched, _ := validateSingleRecord(body, decision.Constraints); !matched {
					middleware.WriteJSONError(w, http.StatusNotFound, "NotFound", "item not found")
					return
				}
			}

			// Forward to outer writer.
			for k, vs := range cap.Header() {
				for _, v := range vs {
					w.Header().Add(k, v)
				}
			}
			w.WriteHeader(status)
			_, _ = w.Write(body)
		})
	}
}

// DecisionFromContext retrieves the authorization decision from context.
func DecisionFromContext(ctx context.Context) *AuthzDecision {
	if decision, ok := ctx.Value(middleware.AuthzDecisionKey).(*AuthzDecision); ok {
		return decision
	}
	return nil
}

// applyConstraints enforces collection-scope and result-limit decisions
// against the parsed SearchRequest, and defaults Geofence.FilterMode
// when an operator forgot to set it. RequiredFilters are NOT applied
// here — they're translated and AND-merged inside injectCQL2Filter
// alongside policy CQL2 + the user filter, which keeps the shared
// AuthzConstraints object immutable across requests.
//
// Returns errCollectionsDenied when no requested collection survives
// AllowedCollections ∩ ¬DeniedCollections; the caller writes 403.
//
// Known limitation: when AllowedCollections is empty, DeniedCollections
// is non-empty, and the request specifies no collections, this function
// cannot enumerate "all collections except denied" — the response-side
// post-filter and any pushed-down CQL2 predicate become responsible.
// Operators relying on DeniedCollections should also enumerate the
// safe set in AllowedCollections.
func applyConstraints(sr *stac.SearchRequest, constraints *AuthzConstraints) error {
	if sr == nil || constraints == nil {
		return nil
	}

	if constraints.MaxResults > 0 {
		if sr.Limit <= 0 || sr.Limit > constraints.MaxResults {
			sr.Limit = constraints.MaxResults
		}
	}

	if len(constraints.AllowedCollections) > 0 {
		if len(sr.Collections) > 0 {
			sr.Collections = intersectStrings(constraints.AllowedCollections, sr.Collections)
			if len(sr.Collections) == 0 {
				return errCollectionsDenied
			}
		} else {
			sr.Collections = append([]string(nil), constraints.AllowedCollections...)
		}
	}

	if len(constraints.DeniedCollections) > 0 && len(sr.Collections) > 0 {
		sr.Collections = removeStrings(sr.Collections, constraints.DeniedCollections)
		if len(sr.Collections) == 0 {
			return errCollectionsDenied
		}
	}

	if constraints.Geofence != nil &&
		constraints.Geofence.AllowedArea != nil &&
		!constraints.Geofence.FilterMode &&
		!constraints.GeofencePushedDown {
		constraints.Geofence.FilterMode = true
	}

	return nil
}

var errCollectionsDenied = errors.New("no collections in request are permitted by policy")

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

// userCQL2ParseError wraps a parse failure on the *client-supplied*
// filter so the chi-style middleware can return 400 BadRequest
// (InvalidParameterValue) instead of an opaque 500. Policy-side parse
// failures (operator misconfiguration) keep returning 500 — the
// distinction is made at the call site that wraps the error.
type userCQL2ParseError struct{ err error }

func (e *userCQL2ParseError) Error() string { return e.err.Error() }
func (e *userCQL2ParseError) Unwrap() error { return e.err }

// isUserCQL2ParseError reports whether err originated from a malformed
// client filter (vs. a policy-side or encoding failure).
func isUserCQL2ParseError(err error) bool {
	var u *userCQL2ParseError
	return errors.As(err, &u)
}

// injectCQL2Filter merges policy CQL2 (including any geofence
// push-down) with the client's filter and writes the combined
// expression back into sr.Filter in the original lang.
//
// spatialSupported gates geofence push-down: when false, the geofence
// stays out of the upstream filter and the post-response filter
// remains responsible. The CQL2 portion of the policy filter is still
// merged regardless.
//
// Returns the constraint that should be installed on the decision
// going forward: maybePushDownGeofence returns a fresh constraint
// when push-down applies (so we don't mutate the shared decision
// constraint pointer), and we propagate that here.
func injectCQL2Filter(sr *stac.SearchRequest, constraints *AuthzConstraints, spatialSupported bool) (*AuthzConstraints, error) {
	updated, _, err := maybePushDownGeofence(constraints, spatialSupported)
	if err != nil {
		return constraints, err
	}
	policyExpr, err := parsePolicyCQL2(updated)
	if err != nil {
		return updated, err
	}
	requiredExpr, err := requiredFiltersToCQL2(updated.RequiredFilters)
	if err != nil {
		return updated, err
	}
	userExpr, err := parseUserCQL2(sr.Filter)
	if err != nil {
		// Wrap so the chi-style middleware can distinguish a
		// client-side filter syntax error (return 400) from a
		// server-side encoding/policy failure (return 500).
		return updated, &userCQL2ParseError{err: err}
	}
	merged := andNonNil(userExpr, policyExpr, requiredExpr)
	if merged == nil {
		return updated, nil
	}
	lang := sr.FilterLang
	if lang == "" {
		lang = "cql2-text"
	}
	encoded, err := encodeForLang(merged, lang)
	if err != nil {
		return updated, err
	}
	sr.Filter = encoded
	if sr.FilterLang == "" {
		sr.FilterLang = "cql2-text"
	}
	return updated, nil
}

// validateSingleRecord parses body as a STAC item and evaluates the
// combined policy + geofence CQL2 predicate against it. Returns
// (matched, error). A nil predicate is treated as a match.
//
// maybePushDownGeofence returns a fresh constraint when push-down
// applies; we use that locally and never mutate the caller's
// constraint pointer (which is shared via the AuthzDecision on the
// request context).
func validateSingleRecord(body []byte, c *AuthzConstraints) (bool, error) {
	if c == nil || len(body) == 0 {
		return true, nil
	}
	// Local evaluation always uses spatial predicates regardless of
	// upstream support — stac.EvalCQL2 implements S_INTERSECTS.
	updated, _, err := maybePushDownGeofence(c, true)
	if err != nil {
		return true, err
	}
	policyExpr, err := parsePolicyCQL2(updated)
	if err != nil {
		return true, err
	}
	requiredExpr, err := requiredFiltersToCQL2(updated.RequiredFilters)
	if err != nil {
		return true, err
	}
	expr := andNonNil(policyExpr, requiredExpr)
	if expr == nil {
		return true, nil
	}
	var item map[string]interface{}
	if err := json.Unmarshal(body, &item); err != nil {
		return true, nil // not JSON; pass through
	}
	ok, err := stac.EvalCQL2(expr.N, item)
	if err != nil {
		return false, err
	}
	return ok, nil
}

// geofenceFilterStatus distinguishes the three outcomes of
// filterByGeofence so the caller can make the correct enforcement
// decision instead of conflating "no filter applied" (pass-through)
// with "we couldn't parse the body" (fail-open).
type geofenceFilterStatus int

const (
	// geofenceNotApplicable means the body wasn't FeatureCollection-shaped
	// JSON (e.g. a singular Item, an error wrapped in 200, or a non-JSON
	// payload). The caller should forward the body unchanged.
	geofenceNotApplicable geofenceFilterStatus = iota
	// geofenceFiltered means the body was a FeatureCollection and the
	// returned bytes contain the filtered version.
	geofenceFiltered
	// geofenceMalformed means the body claimed to be a FeatureCollection
	// (top-level type=="FeatureCollection") but parsing failed or the
	// "features" array was missing/wrong-typed. The caller MUST NOT
	// forward the original body — the geofence cannot be enforced —
	// and should return 502 to the client.
	geofenceMalformed
)

// filterByGeofence post-filters a FeatureCollection response against a
// geofence. The returned status drives caller enforcement:
//
//   - geofenceFiltered:     bytes contains the filtered FC.
//   - geofenceNotApplicable: body wasn't a FeatureCollection; pass
//     through (single-record validation may still apply downstream).
//   - geofenceMalformed:    body looked like a FeatureCollection but
//     was unparsable; caller MUST return 502 — the prior behaviour
//     of forwarding the original body would have unrestricted-leaked
//     data the geofence was supposed to constrain.
//
// We discriminate "looked like a FC but malformed" by checking
// fc["type"] == "FeatureCollection" before deciding which bucket to
// bin a parse failure into.
func filterByGeofence(body []byte, geofence *GeofenceConstraint) ([]byte, geofenceFilterStatus) {
	if len(body) == 0 || geofence == nil {
		return nil, geofenceNotApplicable
	}
	allowed, denied, err := parseGeofenceAreas(geofence)
	if err != nil || (allowed == nil && denied == nil) {
		return nil, geofenceNotApplicable
	}

	// Cheap top-level shape sniff: if the body claims to be a
	// FeatureCollection, any subsequent parse/structure failure is a
	// fail-closed event — the upstream told us this is the protected
	// shape and we couldn't extract it.
	looksLikeFC := bodyClaimsFeatureCollection(body)

	var fc map[string]interface{}
	if err := json.Unmarshal(body, &fc); err != nil {
		if looksLikeFC {
			return nil, geofenceMalformed
		}
		return nil, geofenceNotApplicable
	}
	typeStr, _ := fc["type"].(string)
	if typeStr != "FeatureCollection" {
		return nil, geofenceNotApplicable
	}
	features, ok := fc["features"].([]interface{})
	if !ok {
		// type=FeatureCollection but features array missing or
		// wrong-typed — malformed.
		return nil, geofenceMalformed
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
		fc["numberMatched"] = len(kept)
	}
	out, err := json.Marshal(fc)
	if err != nil {
		return nil, geofenceMalformed
	}
	return out, geofenceFiltered
}

// bodyClaimsFeatureCollection inspects the first ~2KB of body for a
// top-level "type":"FeatureCollection" pair without fully parsing.
// We use this to decide whether a subsequent parse failure should be
// treated as malformed (fail-closed) or as not-applicable
// (pass-through). The check tolerates whitespace and either quote
// style inside the value.
func bodyClaimsFeatureCollection(body []byte) bool {
	const limit = 2048
	if len(body) > limit {
		body = body[:limit]
	}
	// crude but cheap; full parse handles the canonical case.
	return bytes.Contains(body, []byte("\"FeatureCollection\""))
}

// parseGeofenceAreas parses the geofence's optional allowed and denied
// GeoJSON into *geo.Geometry pairs. Either side may be nil (absent
// from the constraint); only a parse error on the allowed side is
// propagated since the allowed area gates filtering.
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
