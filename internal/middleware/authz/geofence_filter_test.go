package authz

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yourorg/stac-proxy/internal/middleware"
	"github.com/yourorg/stac-proxy/internal/middleware/auth"
)

func TestFilterByGeofence_DropsOutsideItems(t *testing.T) {
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

	out, status := filterByGeofence(body, g)
	if status != geofenceFiltered {
		t.Fatalf("filterByGeofence: want geofenceFiltered, got %v", status)
	}
	var fc map[string]interface{}
	if err := json.Unmarshal(out, &fc); err != nil {
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

func TestFilterByGeofence_NonFeatureCollectionPassesThrough(t *testing.T) {
	g := &GeofenceConstraint{
		AllowedArea: map[string]interface{}{"type": "Point", "coordinates": []interface{}{0.0, 0.0}},
	}
	if _, status := filterByGeofence([]byte(`{"error":"boom"}`), g); status != geofenceNotApplicable {
		t.Fatalf("non-FeatureCollection body should be NotApplicable, got %v", status)
	}
}

// TestFilterByGeofence_MalformedFeatureCollectionFailsClosed asserts
// the H-authz-3 fail-closed path: a body whose top-level type claims
// FeatureCollection but is otherwise unparseable returns
// geofenceMalformed so the caller can surface 502 instead of
// fail-opening the original bytes.
func TestFilterByGeofence_MalformedFeatureCollectionFailsClosed(t *testing.T) {
	g := &GeofenceConstraint{
		AllowedArea: map[string]interface{}{
			"type": "Polygon",
			"coordinates": []interface{}{
				[]interface{}{
					[]interface{}{0.0, 0.0},
					[]interface{}{1.0, 0.0},
					[]interface{}{1.0, 1.0},
					[]interface{}{0.0, 1.0},
					[]interface{}{0.0, 0.0},
				},
			},
		},
	}
	cases := []struct {
		name string
		body []byte
	}{
		{"unparseable features array", []byte(`{"type":"FeatureCollection","features":INVALID}`)},
		{"features wrong type", []byte(`{"type":"FeatureCollection","features":42}`)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, status := filterByGeofence(c.body, g); status != geofenceMalformed {
				t.Fatalf("want geofenceMalformed, got %v", status)
			}
		})
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

// TestAuthz_GeofencePostFilter ensures the middleware pipeline runs the
// geofence post-filter when push-down didn't fire (CQL2InjectionEnabled=false).
func TestAuthz_GeofencePostFilter(t *testing.T) {
	polygon := map[string]interface{}{
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
	}
	mw := NewHTTPMiddleware(HTTPConfig{
		Enforcer: &stubEnforcer{decision: &AuthzDecision{
			Allowed: true,
			Constraints: &AuthzConstraints{
				Geofence: &GeofenceConstraint{AllowedArea: polygon, FilterMode: true},
			},
		}},
		AllowAnonymous: true,
		// CQL2InjectionEnabled left false; post-filter is the path under test.
	})

	body, _ := json.Marshal(map[string]interface{}{
		"type": "FeatureCollection",
		"features": []map[string]interface{}{
			{"id": "in", "geometry": map[string]interface{}{"type": "Point", "coordinates": []interface{}{1.0, 1.0}}},
			{"id": "out", "geometry": map[string]interface{}{"type": "Point", "coordinates": []interface{}{50.0, 50.0}}},
		},
	})

	info := &middleware.STACInfo{RequestType: middleware.RequestTypeSearch}
	r := httptest.NewRequest("GET", "/search", nil)
	ctx := middleware.WithSTACInfo(r.Context(), info)
	ctx = context.WithValue(ctx, middleware.PrincipalKey, &auth.Principal{ID: "anon", Type: "anonymous"})
	r = r.WithContext(ctx)

	rr := httptest.NewRecorder()
	mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/geo+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	})).ServeHTTP(rr, r)

	var fc map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &fc); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	feats := fc["features"].([]interface{})
	if len(feats) != 1 {
		t.Fatalf("want 1 kept after post-filter, got %d", len(feats))
	}
}
