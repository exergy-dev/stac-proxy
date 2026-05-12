package authz

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/yourorg/stac-proxy/internal/middleware"
)

func TestFilterResponseByGeofence_DropsOutsideItems(t *testing.T) {
	// Allow polygon (-10..10). Items inside should pass; outside drops.
	g := &GeofenceConstraint{
		AllowedArea: map[string]interface{}{
			"type": "Polygon",
			"coordinates": []interface{}{
				[]interface{}{
					[]interface{}{-10.0, -10.0},
					[]interface{}{10.0, -10.0},
					[]interface{}{10.0, 10.0},
					[]interface{}{-10.0, 10.0},
					[]interface{}{-10.0, -10.0},
				},
			},
		},
		FilterMode: true,
	}
	body, _ := json.Marshal(map[string]interface{}{
		"type": "FeatureCollection",
		"features": []map[string]interface{}{
			{"id": "inside", "geometry": map[string]interface{}{"type": "Point", "coordinates": []interface{}{0.0, 0.0}}},
			{"id": "outside", "geometry": map[string]interface{}{"type": "Point", "coordinates": []interface{}{50.0, 50.0}}},
		},
		"numberReturned": 2,
	})

	resp := &middleware.STACResponse{StatusCode: 200, Body: body}
	got, err := filterResponseByGeofence(resp, g)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var fc map[string]interface{}
	if err := json.Unmarshal(got.Body, &fc); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	feats := fc["features"].([]interface{})
	if len(feats) != 1 {
		t.Fatalf("want 1 feature after filter, got %d", len(feats))
	}
	if id := feats[0].(map[string]interface{})["id"]; id != "inside" {
		t.Fatalf("want kept item 'inside', got %v", id)
	}
	if n, _ := fc["numberReturned"].(float64); int(n) != 1 {
		t.Fatalf("want numberReturned=1, got %v", fc["numberReturned"])
	}
}

func TestFilterResponseByGeofence_PassThroughOnNonOK(t *testing.T) {
	g := &GeofenceConstraint{
		AllowedArea: map[string]interface{}{"type": "Point", "coordinates": []interface{}{0.0, 0.0}},
	}
	resp := &middleware.STACResponse{StatusCode: 500, Body: []byte(`{"error":"boom"}`)}
	got, err := filterResponseByGeofence(resp, g)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if got != resp {
		t.Fatal("non-2xx response should pass through unchanged")
	}
}

func TestEvaluateCondition_TimeRange(t *testing.T) {
	e := &PolicyEnforcer{}
	in := &AuthzInput{}
	// Always-inside: past start, future end.
	cond := Condition{Type: "time_range", Config: map[string]interface{}{
		"start": "2000-01-01T00:00:00Z",
		"end":   "2999-12-31T23:59:59Z",
	}}
	if !e.evaluateCondition(cond, in) {
		t.Fatal("want pass for in-range window")
	}
	// Future-only window
	cond.Config = map[string]interface{}{"start": "2999-01-01T00:00:00Z"}
	if e.evaluateCondition(cond, in) {
		t.Fatal("want fail for future-only window")
	}
}

func TestEvaluateCondition_IPRange(t *testing.T) {
	e := &PolicyEnforcer{}
	in := &AuthzInput{Request: &RequestInfo{ClientIP: "10.0.0.42:12345"}}
	cond := Condition{Type: "ip_range", Config: map[string]interface{}{
		"cidrs": []interface{}{"10.0.0.0/8"},
	}}
	if !e.evaluateCondition(cond, in) {
		t.Fatal("want pass for matching CIDR")
	}
	cond.Config = map[string]interface{}{"cidrs": []interface{}{"192.168.0.0/16"}}
	if e.evaluateCondition(cond, in) {
		t.Fatal("want fail for non-matching CIDR")
	}
}

func TestEvaluateCondition_Attribute(t *testing.T) {
	e := &PolicyEnforcer{}
	in := &AuthzInput{Principal: &PrincipalInfo{
		Attributes: map[string]interface{}{"dept": "research"},
	}}
	cond := Condition{Type: "attribute", Config: map[string]interface{}{
		"key": "dept", "value": "research",
	}}
	if !e.evaluateCondition(cond, in) {
		t.Fatal("want pass for matching attribute")
	}
	cond.Config = map[string]interface{}{"key": "dept", "value": "ops"}
	if e.evaluateCondition(cond, in) {
		t.Fatal("want fail for wrong attribute value")
	}
}

func TestEvaluateCondition_UnknownTypeFailsClosed(t *testing.T) {
	e := &PolicyEnforcer{}
	in := &AuthzInput{}
	cond := Condition{Type: "made_up", Config: map[string]interface{}{}}
	if e.evaluateCondition(cond, in) {
		t.Fatal("unknown condition type must fail closed")
	}
}

// TestProcessResponse_GeofencePostFilter ensures the middleware
// pipeline runs the geofence post-filter when push-down didn't fire.
func TestProcessResponse_GeofencePostFilter(t *testing.T) {
	mw := NewAuthzMiddleware(AuthzMiddlewareConfig{
		Enforcer: &stubEnforcer{},
		// CQL2InjectionEnabled left false; geofence won't push down,
		// but ProcessResponse should still post-filter.
	})
	decision := &AuthzDecision{
		Allowed: true,
		Constraints: &AuthzConstraints{
			Geofence: &GeofenceConstraint{
				AllowedArea: map[string]interface{}{
					"type": "Polygon",
					"coordinates": []interface{}{
						[]interface{}{
							[]interface{}{-10.0, -10.0},
							[]interface{}{10.0, -10.0},
							[]interface{}{10.0, 10.0},
							[]interface{}{-10.0, 10.0},
							[]interface{}{-10.0, -10.0},
						},
					},
				},
				FilterMode: true,
			},
		},
	}
	ctx := context.WithValue(context.Background(), middleware.AuthzDecisionKey, decision)
	body, _ := json.Marshal(map[string]interface{}{
		"type": "FeatureCollection",
		"features": []map[string]interface{}{
			{"id": "in", "geometry": map[string]interface{}{"type": "Point", "coordinates": []interface{}{1.0, 1.0}}},
			{"id": "out", "geometry": map[string]interface{}{"type": "Point", "coordinates": []interface{}{50.0, 50.0}}},
		},
	})
	httpReq := httptest.NewRequest("GET", "/search", nil)
	req := &middleware.STACRequest{
		Request:     httpReq,
		Context:     httpReq.Context(),
		RequestType: middleware.RequestTypeSearch,
	}
	resp := &middleware.STACResponse{StatusCode: 200, Body: body}
	got, err := mw.ProcessResponse(ctx, req, resp)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	var fc map[string]interface{}
	if err := json.Unmarshal(got.Body, &fc); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	feats := fc["features"].([]interface{})
	if len(feats) != 1 {
		t.Fatalf("want 1 kept after post-filter, got %d", len(feats))
	}
}
