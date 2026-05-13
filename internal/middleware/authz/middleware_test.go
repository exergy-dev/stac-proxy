package authz

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yourorg/stac-proxy/internal/middleware"
	"github.com/yourorg/stac-proxy/internal/middleware/auth"
	"github.com/yourorg/stac-proxy/internal/stac"
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
	if sr.Filter != nil {
		t.Fatalf("want untouched Filter when disabled, got %v", sr.Filter)
	}
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
	if !ok {
		t.Fatalf("want string filter (cql2-text), got %T %v", sr.Filter, sr.Filter)
	}
	if !strings.Contains(s, "eo:cloud_cover") {
		t.Fatalf("want policy filter in output, got %q", s)
	}
	if sr.FilterLang != "cql2-text" {
		t.Fatalf("want FilterLang=cql2-text, got %q", sr.FilterLang)
	}
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
	if !ok {
		t.Fatalf("want string filter, got %T %v", sr.Filter, sr.Filter)
	}
	if !strings.Contains(s, "eo:cloud_cover") || !strings.Contains(s, "datetime") {
		t.Fatalf("want both predicates, got %q", s)
	}
	if !strings.Contains(s, "AND") {
		t.Fatalf("want AND-combined, got %q", s)
	}
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

	if _, ok := sr.Filter.(map[string]interface{}); !ok {
		t.Fatalf("want cql2-json map output, got %T %v", sr.Filter, sr.Filter)
	}
	if sr.FilterLang != "cql2-json" {
		t.Fatalf("want FilterLang preserved, got %q", sr.FilterLang)
	}
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
	if !ok {
		t.Fatalf("want cql2-text output, got %T %v", sr.Filter, sr.Filter)
	}
	if !strings.Contains(strings.ToUpper(s), "S_INTERSECTS") {
		t.Fatalf("want S_INTERSECTS, got %q", s)
	}
	if !enforcer.decision.Constraints.GeofencePushedDown {
		t.Fatal("want GeofencePushedDown=true after push-down")
	}
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
	if c.CQL2Filter != "a = 1" {
		t.Fatalf("want cql2_filter passthrough, got %q", c.CQL2Filter)
	}
	if c.CQL2FilterJSON == nil {
		t.Fatal("want cql2_filter_json populated")
	}
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
	if sr.Filter != nil {
		t.Fatalf("want no injection when upstream lacks Filter Extension, got %v", sr.Filter)
	}
}

func TestAuthz_FilterExtensionCheck_AllowsWhenSupported(t *testing.T) {
	mw := NewHTTPMiddleware(HTTPConfig{
		Enforcer: &stubEnforcer{decision: &AuthzDecision{
			Allowed:     true,
			Constraints: &AuthzConstraints{CQL2Filter: "eo:cloud_cover < 20"},
		}},
		AllowAnonymous:       true,
		CQL2InjectionEnabled: true,
		FilterExtensionCheck: func(_ *http.Request, _ *middleware.STACInfo) bool { return true },
	})
	sr := &stac.SearchRequest{}
	info := &middleware.STACInfo{RequestType: middleware.RequestTypeSearch, SearchReq: sr}
	r := withInfo(httptest.NewRequest("GET", "/search", nil), info)
	runMW(mw, r)
	if sr.Filter == nil {
		t.Fatal("want injection to happen when target supports Filter Extension")
	}
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
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200 for matching item, got %d", rr.Code)
	}
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
	if rr.Code != http.StatusNotFound {
		t.Fatalf("want 404 for non-matching item, got %d", rr.Code)
	}
}

func TestAuthz_SingleRecord_DisabledIsPassthrough(t *testing.T) {
	mw := NewHTTPMiddleware(HTTPConfig{
		Enforcer: &stubEnforcer{decision: &AuthzDecision{
			Allowed:     true,
			Constraints: &AuthzConstraints{CQL2Filter: "eo:cloud_cover < 5"},
		}},
		AllowAnonymous: true,
		// CQL2InjectionEnabled: false
	})
	info := &middleware.STACInfo{RequestType: middleware.RequestTypeItem, Collection: "x", ItemID: "abc"}
	r := withInfo(httptest.NewRequest("GET", "/collections/x/items/abc", nil), info)
	body := []byte(`{"id":"abc","properties":{"eo:cloud_cover":12.5}}`)
	rr := runMWWithBody(mw, r, http.StatusOK, body)
	if rr.Code != http.StatusOK {
		t.Fatalf("disabled injection should not gate single-record GETs; got %d", rr.Code)
	}
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
	enf, err := NewEmbeddedOPAEnforcer(EmbeddedOPAConfig{
		Name:    "test",
		Modules: map[string]string{"test.rego": policy},
	})
	if err != nil {
		t.Fatalf("NewEmbeddedOPAEnforcer: %v", err)
	}

	d, err := enf.Authorize(context.Background(), &AuthzInput{
		Request:  &RequestInfo{Method: "GET", Path: "/search"},
		Resource: &ResourceInfo{Type: "search"},
	})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if !d.Allowed {
		t.Fatalf("decision not allowed")
	}
	if d.Constraints == nil {
		t.Fatal("no constraints on decision")
	}
	if d.Constraints.CQL2Filter != "eo:cloud_cover < 15" {
		t.Fatalf("want CQL2Filter passthrough, got %q", d.Constraints.CQL2Filter)
	}
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
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200 pass-through, got %d", rr.Code)
	}
}
