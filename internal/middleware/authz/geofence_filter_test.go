package authz

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/exergy-dev/stac-proxy/internal/middleware"
	"github.com/exergy-dev/stac-proxy/internal/middleware/auth"
	"github.com/stretchr/testify/require"
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
	require.Equal(t, geofenceFiltered, status, "filterByGeofence")
	var fc map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &fc), "body not JSON")
	feats := fc["features"].([]interface{})
	require.Len(t, feats, 1, "want 1 feature after filter")
	require.Equal(t, "inside", feats[0].(map[string]interface{})["id"], "want kept item 'inside'")
	n, _ := fc["numberReturned"].(float64)
	require.Equal(t, 1, int(n), "want numberReturned=1, got %v", fc["numberReturned"])
}

func TestFilterByGeofence_NonFeatureCollectionPassesThrough(t *testing.T) {
	g := &GeofenceConstraint{
		AllowedArea: map[string]interface{}{"type": "Point", "coordinates": []interface{}{0.0, 0.0}},
	}
	_, status := filterByGeofence([]byte(`{"error":"boom"}`), g)
	require.Equal(t, geofenceNotApplicable, status, "non-FeatureCollection body should be NotApplicable")
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
			_, status := filterByGeofence(c.body, g)
			require.Equal(t, geofenceMalformed, status, "want geofenceMalformed")
		})
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
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &fc), "body not JSON")
	feats := fc["features"].([]interface{})
	require.Len(t, feats, 1, "want 1 kept after post-filter")
}

// TestFilterByGeofence_HonorsGeometryProperty: when the constraint
// names a non-canonical geometry field (as push-down's S_INTERSECTS
// would target), the post-filter must judge the same field — and
// fail closed (drop) for features missing it, matching the existing
// nil-geometry handling.
func TestFilterByGeofence_HonorsGeometryProperty(t *testing.T) {
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
		FilterMode:       true,
		GeometryProperty: "the_geom",
	}
	body, _ := json.Marshal(map[string]interface{}{
		"type": "FeatureCollection",
		"features": []map[string]interface{}{
			{"id": "inside", "the_geom": map[string]interface{}{"type": "Point", "coordinates": []interface{}{1.0, 1.0}}},
			{"id": "outside", "the_geom": map[string]interface{}{"type": "Point", "coordinates": []interface{}{50.0, 50.0}}},
			// Canonical geometry only — missing the configured
			// property, must be dropped (fail-closed).
			{"id": "wrong-key", "geometry": map[string]interface{}{"type": "Point", "coordinates": []interface{}{0.0, 0.0}}},
		},
	})

	out, status := filterByGeofence(body, g)
	require.Equal(t, geofenceFiltered, status)
	var fc map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &fc))
	feats := fc["features"].([]interface{})
	require.Len(t, feats, 1, "only the in-area the_geom feature survives")
	require.Equal(t, "inside", feats[0].(map[string]interface{})["id"])
}
