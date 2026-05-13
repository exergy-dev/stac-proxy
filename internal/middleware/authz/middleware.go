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
	"context"
	"encoding/json"
	"net/http"

	"github.com/yourorg/stac-proxy/internal/geo"
	"github.com/yourorg/stac-proxy/internal/httpx"
	"github.com/yourorg/stac-proxy/internal/middleware"
	"github.com/yourorg/stac-proxy/internal/middleware/auth"
	"github.com/yourorg/stac-proxy/internal/observability"
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
}

// NewHTTPMiddleware returns chi-compatible authorization middleware.
func NewHTTPMiddleware(cfg HTTPConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			principal := auth.PrincipalFromContext(ctx)
			info := middleware.STACInfoFromContext(ctx)

			if principal == nil && !cfg.AllowAnonymous {
				writeError(w, http.StatusUnauthorized, "Unauthorized", "authentication required")
				return
			}

			input := BuildAuthzInput(r, info, principal)
			decision, err := cfg.Enforcer.Authorize(ctx, input)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "InternalError", "authorization check failed")
				return
			}
			if !decision.Allowed {
				reason := "access denied"
				if len(decision.Reasons) > 0 {
					reason = decision.Reasons[0]
				}
				writeError(w, http.StatusForbidden, "Forbidden", reason)
				return
			}

			// Stash decision for downstream code paths (filtering,
			// observability) that may want it.
			ctx = context.WithValue(ctx, middleware.AuthzDecisionKey, decision)
			r = r.WithContext(ctx)

			// Pre-upstream request mutations. Only fire when there's a
			// parsed search body to mutate AND there are constraints.
			// (In production, info.SearchReq is populated by federation
			// AFTER this middleware runs, so these paths are exercised
			// mainly via tests that pre-populate. Migration to a
			// pre-authz search parser is out of scope.)
			if info != nil && info.SearchReq != nil && decision.Constraints != nil {
				applyConstraints(info.SearchReq, decision.Constraints)
				if cfg.CQL2InjectionEnabled &&
					(cfg.FilterExtensionCheck == nil || cfg.FilterExtensionCheck(r, info)) {
					if err := injectCQL2Filter(info.SearchReq, decision.Constraints); err != nil {
						writeError(w, http.StatusInternalServerError, "InternalError", "cql2 injection failed")
						return
					}
				}
			}

			// Capture the inner response so we can post-filter it.
			cap := httpx.NewResponseCapture()
			next.ServeHTTP(cap, r)

			status := cap.Status()
			body := cap.BodyBytes()

			// Geofence post-filter: only when allowed-area is set,
			// filter-mode is on, and the geofence wasn't pushed down as
			// a CQL2 predicate.
			if decision.Constraints != nil &&
				decision.Constraints.Geofence != nil &&
				decision.Constraints.Geofence.FilterMode &&
				!decision.Constraints.GeofencePushedDown &&
				status >= 200 && status < 300 {
				if filtered, ok := filterByGeofence(body, decision.Constraints.Geofence); ok {
					body = filtered
				}
			}

			// Single-record GET validation: when the policy emits a
			// CQL2 filter, evaluate the combined predicate locally
			// against the response body and convert a non-match into a
			// 404, hiding existence.
			if cfg.CQL2InjectionEnabled && info != nil && info.RequestType == middleware.RequestTypeItem &&
				status >= 200 && status < 300 && decision.Constraints != nil {
				if matched, _ := validateSingleRecord(body, decision.Constraints); !matched {
					writeError(w, http.StatusNotFound, "NotFound", "item not found")
					return
				}
			}

			// Forward to outer writer.
			for k, vs := range cap.HeadersOut() {
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

// writeError emits a structured STAC-style JSON error response.
func writeError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"code":        code,
		"description": description,
	})
}

// applyConstraints clamps the parsed SearchRequest's Limit to the
// authz-decided MaxResults (when smaller).
func applyConstraints(sr *stac.SearchRequest, constraints *AuthzConstraints) {
	if constraints.MaxResults <= 0 || sr == nil {
		return
	}
	if sr.Limit <= 0 || sr.Limit > constraints.MaxResults {
		sr.Limit = constraints.MaxResults
	}
}

// injectCQL2Filter merges policy CQL2 (including any geofence
// push-down) with the client's filter and writes the combined
// expression back into sr.Filter in the original lang.
func injectCQL2Filter(sr *stac.SearchRequest, constraints *AuthzConstraints) error {
	if _, err := maybePushDownGeofence(constraints); err != nil {
		return err
	}
	policyExpr, err := parsePolicyCQL2(constraints)
	if err != nil {
		return err
	}
	userExpr, _ := parseUserCQL2(sr.Filter)
	merged := andNonNil(userExpr, policyExpr)
	if merged == nil {
		return nil
	}
	lang := sr.FilterLang
	if lang == "" {
		lang = "cql2-text"
	}
	encoded, err := encodeForLang(merged, lang)
	if err != nil {
		return err
	}
	sr.Filter = encoded
	if sr.FilterLang == "" {
		sr.FilterLang = "cql2-text"
	}
	if mt := observability.Default(); mt != nil {
		reason := observability.CQL2ReasonPolicy
		switch {
		case constraints.GeofencePushedDown && userExpr != nil:
			reason = observability.CQL2ReasonMerged
		case constraints.GeofencePushedDown:
			reason = observability.CQL2ReasonGeofence
		}
		mt.CQL2Injected.WithLabelValues(sr.FilterLang, reason).Inc()
	}
	return nil
}

// validateSingleRecord parses body as a STAC item and evaluates the
// combined policy + geofence CQL2 predicate against it. Returns
// (matched, error). A nil predicate is treated as a match.
func validateSingleRecord(body []byte, c *AuthzConstraints) (bool, error) {
	if c == nil || len(body) == 0 {
		return true, nil
	}
	if _, err := maybePushDownGeofence(c); err != nil {
		return true, err
	}
	expr, err := parsePolicyCQL2(c)
	if err != nil {
		return true, err
	}
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

// filterByGeofence post-filters a FeatureCollection response against a
// geofence. Returns (mutated, ok); ok=false means body wasn't a
// FeatureCollection (or couldn't be parsed) and should pass through.
func filterByGeofence(body []byte, geofence *GeofenceConstraint) ([]byte, bool) {
	if len(body) == 0 || geofence == nil {
		return nil, false
	}
	allowed, denied, err := parseGeofenceAreas(geofence)
	if err != nil || (allowed == nil && denied == nil) {
		return nil, false
	}

	var fc map[string]interface{}
	if err := json.Unmarshal(body, &fc); err != nil {
		return nil, false
	}
	features, ok := fc["features"].([]interface{})
	if !ok {
		return nil, false
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
		return nil, false
	}
	return out, true
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
