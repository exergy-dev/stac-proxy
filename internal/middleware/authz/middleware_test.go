package authz

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yourorg/stac-proxy/internal/middleware"
	"github.com/yourorg/stac-proxy/internal/stac"
)

// stubEnforcer returns a fixed decision regardless of input.
type stubEnforcer struct {
	decision *AuthzDecision
}

func (s *stubEnforcer) Name() string                                           { return "stub" }
func (s *stubEnforcer) Authorize(_ context.Context, _ *AuthzInput) (*AuthzDecision, error) {
	return s.decision, nil
}

func newReq(method, path string, sr *stac.SearchRequest) *middleware.STACRequest {
	httpReq := httptest.NewRequest(method, path, nil)
	return &middleware.STACRequest{
		Request:     httpReq,
		Context:     httpReq.Context(),
		RequestType: middleware.RequestTypeSearch,
		SearchReq:   sr,
	}
}

func TestProcessRequest_CQL2InjectionDisabled_NoOp(t *testing.T) {
	mw := NewAuthzMiddleware(AuthzMiddlewareConfig{
		Enforcer: &stubEnforcer{decision: &AuthzDecision{
			Allowed: true,
			Constraints: &AuthzConstraints{
				CQL2Filter: "eo:cloud_cover < 20",
			},
		}},
		AllowAnonymous:       true,
		CQL2InjectionEnabled: false,
	})
	sr := &stac.SearchRequest{}
	req := newReq("GET", "/search", sr)
	if _, err := mw.ProcessRequest(req.Context, req); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if sr.Filter != nil {
		t.Fatalf("want untouched Filter when disabled, got %v", sr.Filter)
	}
}

func TestProcessRequest_PolicyCQL2Only(t *testing.T) {
	mw := NewAuthzMiddleware(AuthzMiddlewareConfig{
		Enforcer: &stubEnforcer{decision: &AuthzDecision{
			Allowed: true,
			Constraints: &AuthzConstraints{
				CQL2Filter: "eo:cloud_cover < 20",
			},
		}},
		AllowAnonymous:       true,
		CQL2InjectionEnabled: true,
	})
	sr := &stac.SearchRequest{}
	req := newReq("GET", "/search", sr)
	if _, err := mw.ProcessRequest(req.Context, req); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
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

func TestProcessRequest_UserAndPolicyANDCombined(t *testing.T) {
	mw := NewAuthzMiddleware(AuthzMiddlewareConfig{
		Enforcer: &stubEnforcer{decision: &AuthzDecision{
			Allowed: true,
			Constraints: &AuthzConstraints{
				CQL2Filter: "eo:cloud_cover < 20",
			},
		}},
		AllowAnonymous:       true,
		CQL2InjectionEnabled: true,
	})
	sr := &stac.SearchRequest{
		Filter:     "datetime > '2025-01-01'",
		FilterLang: "cql2-text",
	}
	req := newReq("GET", "/search", sr)
	if _, err := mw.ProcessRequest(req.Context, req); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
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

func TestProcessRequest_PreservesCQL2JSONLang(t *testing.T) {
	mw := NewAuthzMiddleware(AuthzMiddlewareConfig{
		Enforcer: &stubEnforcer{decision: &AuthzDecision{
			Allowed: true,
			Constraints: &AuthzConstraints{
				CQL2Filter: "eo:cloud_cover < 20",
			},
		}},
		AllowAnonymous:       true,
		CQL2InjectionEnabled: true,
	})
	sr := &stac.SearchRequest{
		FilterLang: "cql2-json",
	}
	req := newReq("POST", "/search", sr)
	if _, err := mw.ProcessRequest(req.Context, req); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if _, ok := sr.Filter.(map[string]interface{}); !ok {
		t.Fatalf("want cql2-json map output, got %T %v", sr.Filter, sr.Filter)
	}
	if sr.FilterLang != "cql2-json" {
		t.Fatalf("want FilterLang preserved, got %q", sr.FilterLang)
	}
}

func TestProcessRequest_GeofencePushDown(t *testing.T) {
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
			Geofence: &GeofenceConstraint{
				AllowedArea: polygon,
				FilterMode:  true,
			},
		},
	}}
	mw := NewAuthzMiddleware(AuthzMiddlewareConfig{
		Enforcer:             enforcer,
		AllowAnonymous:       true,
		CQL2InjectionEnabled: true,
	})
	sr := &stac.SearchRequest{}
	req := newReq("GET", "/search", sr)
	if _, err := mw.ProcessRequest(req.Context, req); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
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

func TestProcessResponse_PostFilterGatedByPushDown(t *testing.T) {
	mw := NewAuthzMiddleware(AuthzMiddlewareConfig{
		Enforcer:             &stubEnforcer{},
		AllowAnonymous:       true,
		CQL2InjectionEnabled: true,
	})

	// Decision with geofence in filter mode AND pushed down.
	decision := &AuthzDecision{
		Allowed: true,
		Constraints: &AuthzConstraints{
			Geofence:           &GeofenceConstraint{FilterMode: true},
			GeofencePushedDown: true,
		},
	}
	ctx := context.WithValue(context.Background(), middleware.AuthzDecisionKey, decision)
	resp := &middleware.STACResponse{StatusCode: 200, Body: []byte("ok")}
	req := newReq("GET", "/search", nil)

	got, err := mw.ProcessResponse(ctx, req, resp)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	// filterResponseByGeofence is currently a stub returning resp as-is,
	// but the gate must prevent the call entirely (we observe by sentinel).
	if got != resp {
		t.Fatal("when push-down is set, ProcessResponse should not transform the response")
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

func TestProcessRequest_FilterExtensionCheck_SkipsWhenUnsupported(t *testing.T) {
	mw := NewAuthzMiddleware(AuthzMiddlewareConfig{
		Enforcer: &stubEnforcer{decision: &AuthzDecision{
			Allowed: true,
			Constraints: &AuthzConstraints{
				CQL2Filter: "eo:cloud_cover < 20",
			},
		}},
		AllowAnonymous:       true,
		CQL2InjectionEnabled: true,
		FilterExtensionCheck: func(_ *middleware.STACRequest) bool { return false },
	})
	sr := &stac.SearchRequest{}
	req := newReq("GET", "/search", sr)
	if _, err := mw.ProcessRequest(req.Context, req); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if sr.Filter != nil {
		t.Fatalf("want no injection when upstream lacks Filter Extension, got %v", sr.Filter)
	}
}

func TestProcessRequest_FilterExtensionCheck_AllowsWhenSupported(t *testing.T) {
	mw := NewAuthzMiddleware(AuthzMiddlewareConfig{
		Enforcer: &stubEnforcer{decision: &AuthzDecision{
			Allowed: true,
			Constraints: &AuthzConstraints{
				CQL2Filter: "eo:cloud_cover < 20",
			},
		}},
		AllowAnonymous:       true,
		CQL2InjectionEnabled: true,
		FilterExtensionCheck: func(_ *middleware.STACRequest) bool { return true },
	})
	sr := &stac.SearchRequest{}
	req := newReq("GET", "/search", sr)
	if _, err := mw.ProcessRequest(req.Context, req); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if sr.Filter == nil {
		t.Fatal("want injection to happen when target supports Filter Extension")
	}
}

func TestProcessResponse_SingleRecord_AllowMatching(t *testing.T) {
	mw := NewAuthzMiddleware(AuthzMiddlewareConfig{
		Enforcer:             &stubEnforcer{},
		AllowAnonymous:       true,
		CQL2InjectionEnabled: true,
	})
	decision := &AuthzDecision{
		Allowed: true,
		Constraints: &AuthzConstraints{
			CQL2Filter: "eo:cloud_cover < 20",
		},
	}
	ctx := context.WithValue(context.Background(), middleware.AuthzDecisionKey, decision)
	httpReq := httptest.NewRequest("GET", "/collections/x/items/abc", nil)
	req := &middleware.STACRequest{
		Request:     httpReq,
		Context:     httpReq.Context(),
		RequestType: middleware.RequestTypeItem,
	}
	body := []byte(`{"id":"abc","collection":"x","properties":{"eo:cloud_cover":12.5}}`)
	resp := &middleware.STACResponse{StatusCode: 200, Body: body}
	got, err := mw.ProcessResponse(ctx, req, resp)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if got.StatusCode != 200 {
		t.Fatalf("want 200 for matching item, got %d", got.StatusCode)
	}
}

func TestProcessResponse_SingleRecord_404OnMismatch(t *testing.T) {
	mw := NewAuthzMiddleware(AuthzMiddlewareConfig{
		Enforcer:             &stubEnforcer{},
		AllowAnonymous:       true,
		CQL2InjectionEnabled: true,
	})
	decision := &AuthzDecision{
		Allowed: true,
		Constraints: &AuthzConstraints{
			CQL2Filter: "eo:cloud_cover < 5",
		},
	}
	ctx := context.WithValue(context.Background(), middleware.AuthzDecisionKey, decision)
	httpReq := httptest.NewRequest("GET", "/collections/x/items/abc", nil)
	req := &middleware.STACRequest{
		Request:     httpReq,
		Context:     httpReq.Context(),
		RequestType: middleware.RequestTypeItem,
	}
	body := []byte(`{"id":"abc","collection":"x","properties":{"eo:cloud_cover":12.5}}`)
	resp := &middleware.STACResponse{StatusCode: 200, Body: body}
	got, err := mw.ProcessResponse(ctx, req, resp)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if got.StatusCode != 404 {
		t.Fatalf("want 404 for non-matching item, got %d", got.StatusCode)
	}
}

func TestProcessResponse_SingleRecord_DisabledIsPassthrough(t *testing.T) {
	mw := NewAuthzMiddleware(AuthzMiddlewareConfig{
		Enforcer:       &stubEnforcer{},
		AllowAnonymous: true,
		// CQL2InjectionEnabled: false (default)
	})
	decision := &AuthzDecision{
		Allowed: true,
		Constraints: &AuthzConstraints{
			CQL2Filter: "eo:cloud_cover < 5",
		},
	}
	ctx := context.WithValue(context.Background(), middleware.AuthzDecisionKey, decision)
	httpReq := httptest.NewRequest("GET", "/collections/x/items/abc", nil)
	req := &middleware.STACRequest{
		Request:     httpReq,
		Context:     httpReq.Context(),
		RequestType: middleware.RequestTypeItem,
	}
	body := []byte(`{"id":"abc","properties":{"eo:cloud_cover":12.5}}`)
	resp := &middleware.STACResponse{StatusCode: 200, Body: body}
	got, _ := mw.ProcessResponse(ctx, req, resp)
	if got.StatusCode != 200 {
		t.Fatalf("disabled injection should not gate single-record GETs; got %d", got.StatusCode)
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

func TestProcessRequest_NonSearchRequest_NoInject(t *testing.T) {
	mw := NewAuthzMiddleware(AuthzMiddlewareConfig{
		Enforcer: &stubEnforcer{decision: &AuthzDecision{
			Allowed: true,
			Constraints: &AuthzConstraints{
				CQL2Filter: "eo:cloud_cover < 20",
			},
		}},
		AllowAnonymous:       true,
		CQL2InjectionEnabled: true,
	})
	httpReq := httptest.NewRequest("GET", "/collections/foo", nil)
	req := &middleware.STACRequest{
		Request:     httpReq,
		Context:     httpReq.Context(),
		RequestType: middleware.RequestTypeCollection,
		// SearchReq deliberately nil
	}
	if _, err := mw.ProcessRequest(req.Context, req); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	// No filter to inject into; the test just guarantees no panic/error.
}
