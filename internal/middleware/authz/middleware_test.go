package authz

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/exergy-dev/stac-proxy/internal/middleware"
	"github.com/exergy-dev/stac-proxy/internal/middleware/auth"
	"github.com/exergy-dev/stac-proxy/internal/stac"
	"github.com/stretchr/testify/require"
)

// stubEnforcer returns a fixed decision regardless of input.
type stubEnforcer struct {
	decision *AuthzDecision
}

func (s *stubEnforcer) Name() string { return "stub" }
func (s *stubEnforcer) Authorize(_ context.Context, _ *AuthzInput) (*AuthzDecision, error) {
	return s.decision, nil
}

// withInfo returns r wrapped in a context carrying STACInfo and an
// anonymous principal so the chi-style authz middleware proceeds.
func withInfo(r *http.Request, info *middleware.STACInfo) *http.Request {
	ctx := middleware.WithSTACInfo(r.Context(), info)
	ctx = context.WithValue(ctx, middleware.PrincipalKey, &auth.Principal{ID: "anon", Type: "anonymous"})
	return r.WithContext(ctx)
}

// runMW invokes mw against a no-op inner handler and returns the recorder.
func runMW(mw func(http.Handler) http.Handler, r *http.Request) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, r)
	return rr
}

// runMWWithBody invokes mw against an inner handler that writes status+body.
func runMWWithBody(mw func(http.Handler) http.Handler, r *http.Request, status int, body []byte) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write(body)
	})).ServeHTTP(rr, r)
	return rr
}

func TestAuthz_CQL2InjectionDisabled_NoOp(t *testing.T) {
	mw := NewHTTPMiddleware(HTTPConfig{
		Enforcer: &stubEnforcer{decision: &AuthzDecision{
			Allowed:     true,
			Constraints: &AuthzConstraints{CQL2Filter: "eo:cloud_cover < 20"},
		}},
		AllowAnonymous:       true,
		CQL2InjectionEnabled: false,
	})
	sr := &stac.SearchRequest{}
	info := &middleware.STACInfo{RequestType: middleware.RequestTypeSearch, SearchReq: sr}
	r := withInfo(httptest.NewRequest("GET", "/search", nil), info)
	runMW(mw, r)
	require.Nil(t, sr.Filter, "want untouched Filter when disabled, got %v", sr.Filter)
}

func TestAuthz_PolicyCQL2Only(t *testing.T) {
	mw := NewHTTPMiddleware(HTTPConfig{
		Enforcer: &stubEnforcer{decision: &AuthzDecision{
			Allowed:     true,
			Constraints: &AuthzConstraints{CQL2Filter: "eo:cloud_cover < 20"},
		}},
		AllowAnonymous:       true,
		CQL2InjectionEnabled: true,
	})
	sr := &stac.SearchRequest{}
	info := &middleware.STACInfo{RequestType: middleware.RequestTypeSearch, SearchReq: sr}
	r := withInfo(httptest.NewRequest("GET", "/search", nil), info)
	runMW(mw, r)

	s, ok := sr.Filter.(string)
	require.True(t, ok, "want string filter (cql2-text), got %T %v", sr.Filter, sr.Filter)
	require.Contains(t, s, "eo:cloud_cover", "want policy filter in output, got %q", s)
	require.Equal(t, "cql2-text", sr.FilterLang, "want FilterLang=cql2-text")
}

func TestAuthz_UserAndPolicyANDCombined(t *testing.T) {
	mw := NewHTTPMiddleware(HTTPConfig{
		Enforcer: &stubEnforcer{decision: &AuthzDecision{
			Allowed:     true,
			Constraints: &AuthzConstraints{CQL2Filter: "eo:cloud_cover < 20"},
		}},
		AllowAnonymous:       true,
		CQL2InjectionEnabled: true,
	})
	sr := &stac.SearchRequest{
		Filter:     "datetime > '2025-01-01'",
		FilterLang: "cql2-text",
	}
	info := &middleware.STACInfo{RequestType: middleware.RequestTypeSearch, SearchReq: sr}
	r := withInfo(httptest.NewRequest("GET", "/search", nil), info)
	runMW(mw, r)

	s, ok := sr.Filter.(string)
	require.True(t, ok, "want string filter, got %T %v", sr.Filter, sr.Filter)
	require.Contains(t, s, "eo:cloud_cover", "want both predicates, got %q", s)
	require.Contains(t, s, "datetime", "want both predicates, got %q", s)
	require.Contains(t, s, "AND", "want AND-combined, got %q", s)
}

func TestAuthz_PreservesCQL2JSONLang(t *testing.T) {
	mw := NewHTTPMiddleware(HTTPConfig{
		Enforcer: &stubEnforcer{decision: &AuthzDecision{
			Allowed:     true,
			Constraints: &AuthzConstraints{CQL2Filter: "eo:cloud_cover < 20"},
		}},
		AllowAnonymous:       true,
		CQL2InjectionEnabled: true,
	})
	sr := &stac.SearchRequest{FilterLang: "cql2-json"}
	info := &middleware.STACInfo{RequestType: middleware.RequestTypeSearch, SearchReq: sr}
	r := withInfo(httptest.NewRequest("POST", "/search", nil), info)
	runMW(mw, r)

	_, ok := sr.Filter.(map[string]interface{})
	require.True(t, ok, "want cql2-json map output, got %T %v", sr.Filter, sr.Filter)
	require.Equal(t, "cql2-json", sr.FilterLang, "want FilterLang preserved")
}

func TestAuthz_GeofencePushDown(t *testing.T) {
	polygon := map[string]interface{}{
		"type": "Polygon",
		"coordinates": []interface{}{
			[]interface{}{
				[]interface{}{0.0, 0.0},
				[]interface{}{10.0, 0.0},
				[]interface{}{10.0, 10.0},
				[]interface{}{0.0, 10.0},
				[]interface{}{0.0, 0.0},
			},
		},
	}
	enforcer := &stubEnforcer{decision: &AuthzDecision{
		Allowed: true,
		Constraints: &AuthzConstraints{
			Geofence: &GeofenceConstraint{AllowedArea: polygon, FilterMode: true},
		},
	}}
	mw := NewHTTPMiddleware(HTTPConfig{
		Enforcer:             enforcer,
		AllowAnonymous:       true,
		CQL2InjectionEnabled: true,
	})
	sr := &stac.SearchRequest{}
	info := &middleware.STACInfo{RequestType: middleware.RequestTypeSearch, SearchReq: sr}
	r := withInfo(httptest.NewRequest("GET", "/search", nil), info)
	runMW(mw, r)

	s, ok := sr.Filter.(string)
	require.True(t, ok, "want cql2-text output, got %T %v", sr.Filter, sr.Filter)
	require.Contains(t, strings.ToUpper(s), "S_INTERSECTS", "want S_INTERSECTS, got %q", s)
	require.True(t, enforcer.decision.Constraints.GeofencePushedDown, "want GeofencePushedDown=true after push-down")
}

func TestParseOPAConstraints_CQL2Fields(t *testing.T) {
	raw := map[string]interface{}{
		"cql2_filter": "a = 1",
		"cql2_filter_json": map[string]interface{}{
			"op":   "=",
			"args": []interface{}{map[string]interface{}{"property": "b"}, float64(2)},
		},
	}
	c := parseOPAConstraints(raw)
	require.Equal(t, "a = 1", c.CQL2Filter, "want cql2_filter passthrough")
	require.NotNil(t, c.CQL2FilterJSON, "want cql2_filter_json populated")
}

func TestAuthz_FilterExtensionCheck_SkipsWhenUnsupported(t *testing.T) {
	mw := NewHTTPMiddleware(HTTPConfig{
		Enforcer: &stubEnforcer{decision: &AuthzDecision{
			Allowed:     true,
			Constraints: &AuthzConstraints{CQL2Filter: "eo:cloud_cover < 20"},
		}},
		AllowAnonymous:       true,
		CQL2InjectionEnabled: true,
		FilterExtensionCheck: func(_ *http.Request, _ *middleware.STACInfo) bool { return false },
	})
	sr := &stac.SearchRequest{}
	info := &middleware.STACInfo{RequestType: middleware.RequestTypeSearch, SearchReq: sr}
	r := withInfo(httptest.NewRequest("GET", "/search", nil), info)
	runMW(mw, r)
	require.Nil(t, sr.Filter, "want no injection when upstream lacks Filter Extension, got %v", sr.Filter)
}

func TestAuthz_SingleRecord_AllowMatching(t *testing.T) {
	mw := NewHTTPMiddleware(HTTPConfig{
		Enforcer: &stubEnforcer{decision: &AuthzDecision{
			Allowed:     true,
			Constraints: &AuthzConstraints{CQL2Filter: "eo:cloud_cover < 20"},
		}},
		AllowAnonymous:       true,
		CQL2InjectionEnabled: true,
	})
	info := &middleware.STACInfo{RequestType: middleware.RequestTypeItem, Collection: "x", ItemID: "abc"}
	r := withInfo(httptest.NewRequest("GET", "/collections/x/items/abc", nil), info)
	body := []byte(`{"id":"abc","collection":"x","properties":{"eo:cloud_cover":12.5}}`)
	rr := runMWWithBody(mw, r, http.StatusOK, body)
	require.Equal(t, http.StatusOK, rr.Code, "want 200 for matching item")
}

func TestAuthz_SingleRecord_404OnMismatch(t *testing.T) {
	mw := NewHTTPMiddleware(HTTPConfig{
		Enforcer: &stubEnforcer{decision: &AuthzDecision{
			Allowed:     true,
			Constraints: &AuthzConstraints{CQL2Filter: "eo:cloud_cover < 5"},
		}},
		AllowAnonymous:       true,
		CQL2InjectionEnabled: true,
	})
	info := &middleware.STACInfo{RequestType: middleware.RequestTypeItem, Collection: "x", ItemID: "abc"}
	r := withInfo(httptest.NewRequest("GET", "/collections/x/items/abc", nil), info)
	body := []byte(`{"id":"abc","collection":"x","properties":{"eo:cloud_cover":12.5}}`)
	rr := runMWWithBody(mw, r, http.StatusOK, body)
	require.Equal(t, http.StatusNotFound, rr.Code, "want 404 for non-matching item")
}

// TestAuthz_SingleItem_HonorsConstraintsEvenWhenInjectionDisabled
// is the H-authz-2 regression: CQL2InjectionEnabled gates push-down
// for searches, but single-item GETs must still honour policy CQL2 +
// geofence locally regardless. The operator's intent ("don't rewrite
// outbound queries") must not become "skip enforcement on the way
// back".
func TestAuthz_SingleItem_HonorsConstraintsEvenWhenInjectionDisabled(t *testing.T) {
	mw := NewHTTPMiddleware(HTTPConfig{
		Enforcer: &stubEnforcer{decision: &AuthzDecision{
			Allowed:     true,
			Constraints: &AuthzConstraints{CQL2Filter: "platform = 'sentinel-2'"},
		}},
		AllowAnonymous: true,
		// CQL2InjectionEnabled left false intentionally.
	})
	info := &middleware.STACInfo{RequestType: middleware.RequestTypeItem, Collection: "x", ItemID: "abc"}
	r := withInfo(httptest.NewRequest("GET", "/collections/x/items/abc", nil), info)
	body := []byte(`{"id":"abc","collection":"x","properties":{"platform":"landsat-8"}}`)
	rr := runMWWithBody(mw, r, http.StatusOK, body)
	require.Equal(t, http.StatusNotFound, rr.Code, "want 404 (single-item validation runs without injection), body=%s", rr.Body.String())
}

func TestEmbeddedOPA_EmitsCQL2Filter(t *testing.T) {
	policy := `package stac.authz

default allow := true

result := {
    "allow": allow,
    "reasons": [],
    "constraints": {
        "cql2_filter": "eo:cloud_cover < 15"
    }
}
`
	enf, err := NewEmbeddedOPAEnforcer(context.Background(), EmbeddedOPAConfig{
		Name:    "test",
		Modules: map[string]string{"test.rego": policy},
	})
	require.NoError(t, err, "NewEmbeddedOPAEnforcer")

	d, err := enf.Authorize(context.Background(), &AuthzInput{
		Request:  &RequestInfo{Method: "GET", Path: "/search"},
		Resource: &ResourceInfo{Type: "search"},
	})
	require.NoError(t, err, "Authorize")
	require.True(t, d.Allowed, "decision not allowed")
	require.NotNil(t, d.Constraints, "no constraints on decision")
	require.Equal(t, "eo:cloud_cover < 15", d.Constraints.CQL2Filter, "want CQL2Filter passthrough")
}

func TestAuthz_NonSearchRequest_NoInject(t *testing.T) {
	mw := NewHTTPMiddleware(HTTPConfig{
		Enforcer: &stubEnforcer{decision: &AuthzDecision{
			Allowed:     true,
			Constraints: &AuthzConstraints{CQL2Filter: "eo:cloud_cover < 20"},
		}},
		AllowAnonymous:       true,
		CQL2InjectionEnabled: true,
	})
	info := &middleware.STACInfo{RequestType: middleware.RequestTypeCollection, Collection: "foo"}
	r := withInfo(httptest.NewRequest("GET", "/collections/foo", nil), info)
	rr := runMW(mw, r)
	require.Equal(t, http.StatusOK, rr.Code, "want 200 pass-through")
}

// --- C2 regression tests: AllowedCollections / DeniedCollections /
// RequiredFilters / Geofence FilterMode default. The audit reported C2
// as DONE, but applyConstraints only clamped MaxResults — these tests
// fail without the corrected enforcement.

func TestAuthz_Collections_HappyPath(t *testing.T) {
	cases := []struct {
		name        string
		constraints *AuthzConstraints
		requested   []string
		wantFinal   []string
	}{
		{
			name:        "AllowedCollections intersects request",
			constraints: &AuthzConstraints{AllowedCollections: []string{"a", "b"}},
			requested:   []string{"a", "c", "d"},
			wantFinal:   []string{"a"},
		},
		{
			name:        "AllowedCollections empty request populates",
			constraints: &AuthzConstraints{AllowedCollections: []string{"a", "b"}},
			requested:   nil,
			wantFinal:   []string{"a", "b"},
		},
		{
			name:        "DeniedCollections removes from request",
			constraints: &AuthzConstraints{DeniedCollections: []string{"b"}},
			requested:   []string{"a", "b", "c"},
			wantFinal:   []string{"a", "c"},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			mw := NewHTTPMiddleware(HTTPConfig{
				Enforcer: &stubEnforcer{decision: &AuthzDecision{
					Allowed:     true,
					Constraints: tc.constraints,
				}},
				AllowAnonymous: true,
			})
			sr := &stac.SearchRequest{Collections: tc.requested}
			info := &middleware.STACInfo{RequestType: middleware.RequestTypeSearch, SearchReq: sr}
			r := withInfo(httptest.NewRequest("POST", "/search", nil), info)
			rr := runMW(mw, r)
			require.Equal(t, http.StatusOK, rr.Code, "want 200, body=%s", rr.Body.String())
			require.Equal(t, tc.wantFinal, sr.Collections, "final collections")
		})
	}
}

func TestAuthz_AllowedCollections_NoIntersection_Denies403(t *testing.T) {
	mw := NewHTTPMiddleware(HTTPConfig{
		Enforcer: &stubEnforcer{decision: &AuthzDecision{
			Allowed: true,
			Constraints: &AuthzConstraints{
				AllowedCollections: []string{"a", "b"},
			},
		}},
		AllowAnonymous: true,
	})
	sr := &stac.SearchRequest{Collections: []string{"c", "d"}}
	info := &middleware.STACInfo{RequestType: middleware.RequestTypeSearch, SearchReq: sr}
	r := withInfo(httptest.NewRequest("POST", "/search", nil), info)
	rr := runMW(mw, r)
	require.Equal(t, http.StatusForbidden, rr.Code, "want 403")
}

func TestAuthz_DeniedCollections_RemovesAll_Denies403(t *testing.T) {
	mw := NewHTTPMiddleware(HTTPConfig{
		Enforcer: &stubEnforcer{decision: &AuthzDecision{
			Allowed: true,
			Constraints: &AuthzConstraints{
				DeniedCollections: []string{"b", "c"},
			},
		}},
		AllowAnonymous: true,
	})
	sr := &stac.SearchRequest{Collections: []string{"b", "c"}}
	info := &middleware.STACInfo{RequestType: middleware.RequestTypeSearch, SearchReq: sr}
	r := withInfo(httptest.NewRequest("POST", "/search", nil), info)
	rr := runMW(mw, r)
	require.Equal(t, http.StatusForbidden, rr.Code, "want 403")
}

func TestAuthz_RequiredFilters_TranslatedToCQL2(t *testing.T) {
	mw := NewHTTPMiddleware(HTTPConfig{
		Enforcer: &stubEnforcer{decision: &AuthzDecision{
			Allowed: true,
			Constraints: &AuthzConstraints{
				RequiredFilters: map[string]interface{}{
					"cloud_cover": map[string]interface{}{"lte": 20},
					"platform":    "sentinel-2",
				},
			},
		}},
		AllowAnonymous:       true,
		CQL2InjectionEnabled: true,
	})
	sr := &stac.SearchRequest{}
	info := &middleware.STACInfo{RequestType: middleware.RequestTypeSearch, SearchReq: sr}
	r := withInfo(httptest.NewRequest("POST", "/search", nil), info)
	rr := runMW(mw, r)
	require.Equal(t, http.StatusOK, rr.Code, "want 200, body=%s", rr.Body.String())
	s, ok := sr.Filter.(string)
	require.True(t, ok, "want cql2-text filter, got %T %v", sr.Filter, sr.Filter)
	require.Contains(t, s, "cloud_cover", "want cloud_cover <= 20 in filter, got %q", s)
	require.Contains(t, s, "<=", "want cloud_cover <= 20 in filter, got %q", s)
	require.Contains(t, s, "20", "want cloud_cover <= 20 in filter, got %q", s)
	require.Contains(t, s, "platform", "want platform = 'sentinel-2' in filter, got %q", s)
	require.Contains(t, s, "'sentinel-2'", "want platform = 'sentinel-2' in filter, got %q", s)
}

func TestAuthz_GeofenceFilterModeDefaultsTrueWhenAllowedAreaSet(t *testing.T) {
	polygon := map[string]interface{}{
		"type": "Polygon",
		"coordinates": []interface{}{[]interface{}{
			[]interface{}{0.0, 0.0},
			[]interface{}{1.0, 0.0},
			[]interface{}{1.0, 1.0},
			[]interface{}{0.0, 1.0},
			[]interface{}{0.0, 0.0},
		}},
	}
	cons := &AuthzConstraints{
		Geofence: &GeofenceConstraint{AllowedArea: polygon, FilterMode: false},
	}
	mw := NewHTTPMiddleware(HTTPConfig{
		Enforcer:       &stubEnforcer{decision: &AuthzDecision{Allowed: true, Constraints: cons}},
		AllowAnonymous: true,
	})
	sr := &stac.SearchRequest{}
	info := &middleware.STACInfo{RequestType: middleware.RequestTypeSearch, SearchReq: sr}
	r := withInfo(httptest.NewRequest("POST", "/search", nil), info)
	runMW(mw, r)
	require.True(t, cons.Geofence.FilterMode, "FilterMode must default to true when AllowedArea is set; an operator who forgets the flag must not get a silently disabled geofence")
}

// TestAuthz_Geofence_MalformedFeatureCollection_Returns502 asserts
// the H-authz-3 behaviour: a 2xx upstream response that *claims*
// to be a FeatureCollection but is unparseable must surface as 502
// rather than be forwarded as-is. The previous fail-open path
// shipped unrestricted bytes despite the geofence having no chance
// to enforce.
func TestAuthz_Geofence_MalformedFeatureCollection_Returns502(t *testing.T) {
	polygon := map[string]interface{}{
		"type": "Polygon",
		"coordinates": []interface{}{[]interface{}{
			[]interface{}{0.0, 0.0},
			[]interface{}{10.0, 0.0},
			[]interface{}{10.0, 10.0},
			[]interface{}{0.0, 10.0},
			[]interface{}{0.0, 0.0},
		}},
	}
	mw := NewHTTPMiddleware(HTTPConfig{
		Enforcer: &stubEnforcer{decision: &AuthzDecision{
			Allowed: true,
			Constraints: &AuthzConstraints{
				Geofence: &GeofenceConstraint{AllowedArea: polygon, FilterMode: true},
			},
		}},
		AllowAnonymous: true,
	})
	info := &middleware.STACInfo{RequestType: middleware.RequestTypeSearch}
	r := withInfo(httptest.NewRequest("POST", "/search", nil), info)
	body := []byte(`{"type":"FeatureCollection","features":INVALID}`)
	rr := runMWWithBody(mw, r, http.StatusOK, body)
	require.Equal(t, http.StatusBadGateway, rr.Code, "want 502 for malformed FeatureCollection, body=%s", rr.Body.String())
}

// TestAuthz_Geofence_NonFeatureCollection200_PassesThrough asserts
// the symmetric case: a 2xx upstream response whose body is a
// singular Item (not a FeatureCollection) must be forwarded
// unchanged — geofence post-filtering doesn't apply, and any
// single-record enforcement happens via validateSingleRecord on
// item GET routes.
func TestAuthz_Geofence_NonFeatureCollection200_PassesThrough(t *testing.T) {
	polygon := map[string]interface{}{
		"type": "Polygon",
		"coordinates": []interface{}{[]interface{}{
			[]interface{}{0.0, 0.0},
			[]interface{}{10.0, 0.0},
			[]interface{}{10.0, 10.0},
			[]interface{}{0.0, 10.0},
			[]interface{}{0.0, 0.0},
		}},
	}
	mw := NewHTTPMiddleware(HTTPConfig{
		Enforcer: &stubEnforcer{decision: &AuthzDecision{
			Allowed: true,
			Constraints: &AuthzConstraints{
				Geofence: &GeofenceConstraint{AllowedArea: polygon, FilterMode: true},
			},
		}},
		AllowAnonymous: true,
	})
	info := &middleware.STACInfo{RequestType: middleware.RequestTypeSearch}
	r := withInfo(httptest.NewRequest("POST", "/search", nil), info)
	body := []byte(`{"type":"Item","id":"x"}`)
	rr := runMWWithBody(mw, r, http.StatusOK, body)
	require.Equal(t, http.StatusOK, rr.Code, "want 200 pass-through, body=%s", rr.Body.String())
	require.Equal(t, string(body), rr.Body.String(), "body mutated")
}

// TestAuthz_UnparseableUserFilter_Returns400 verifies that a syntactically
// invalid client-supplied CQL2 filter is rejected with a 400 BadRequest
// (InvalidParameterValue), not an opaque 500. Prior to M-authz-1 the
// parse error from parseUserCQL2 was discarded, so the broken filter
// silently dropped out of the merged predicate and the upstream saw
// only the policy filter — masking the client mistake.
func TestAuthz_UnparseableUserFilter_Returns400(t *testing.T) {
	mw := NewHTTPMiddleware(HTTPConfig{
		Enforcer: &stubEnforcer{decision: &AuthzDecision{
			Allowed:     true,
			Constraints: &AuthzConstraints{CQL2Filter: "eo:cloud_cover < 20"},
		}},
		AllowAnonymous:       true,
		CQL2InjectionEnabled: true,
	})
	sr := &stac.SearchRequest{Filter: "this is not cql2 syntax %%%"}
	info := &middleware.STACInfo{RequestType: middleware.RequestTypeSearch, SearchReq: sr}
	r := withInfo(httptest.NewRequest("GET", "/search", nil), info)
	rr := runMW(mw, r)
	require.Equal(t, http.StatusBadRequest, rr.Code, "want 400 BadRequest, body=%s", rr.Body.String())
	require.Contains(t, rr.Body.String(), "InvalidParameterValue", "want InvalidParameterValue code")
}
