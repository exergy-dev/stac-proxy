package authz

import (
	"strings"
	"testing"

	cql2 "github.com/exergy-dev/go-cql2"
	_ "github.com/exergy-dev/go-cql2/codecs"
	"github.com/stretchr/testify/require"
)

func encText(t *testing.T, e *cql2.Expr) string {
	t.Helper()
	if e == nil {
		return ""
	}
	b, err := cql2.Encode(e.N, cql2.EncodingText)
	require.NoError(t, err, "encode")
	return string(b)
}

func TestAndNonNil_AllNil(t *testing.T) {
	require.Nil(t, andNonNil(nil, nil, nil), "want nil")
}

func TestAndNonNil_SingleNonNil(t *testing.T) {
	e := cql2.Eq("a", 1)
	got := andNonNil(nil, &e, nil)
	require.NotNil(t, got, "want non-nil")
	require.Equal(t, "a = 1", encText(t, got))
}

func TestAndNonNil_TwoNonNil(t *testing.T) {
	a := cql2.Eq("a", 1)
	b := cql2.Eq("b", 2)
	got := andNonNil(&a, nil, &b)
	s := encText(t, got)
	require.Contains(t, s, "a = 1", "want both predicates AND-combined, got %q", s)
	require.Contains(t, s, "b = 2", "want both predicates AND-combined, got %q", s)
	require.Contains(t, s, "AND", "want both predicates AND-combined, got %q", s)
}

func TestGeofenceToCQL2_Nil(t *testing.T) {
	got, err := geofenceToCQL2(nil)
	require.NoError(t, err, "want nil/nil")
	require.Nil(t, got, "want nil/nil")

	got, err = geofenceToCQL2(&GeofenceConstraint{})
	require.NoError(t, err, "want nil/nil for empty constraint")
	require.Nil(t, got, "want nil/nil for empty constraint")
}

func TestGeofenceToCQL2_AreaShapes(t *testing.T) {
	smallPoly := map[string]interface{}{
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
	}
	largePoly := map[string]interface{}{
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
	cases := []struct {
		name      string
		g         *GeofenceConstraint
		wantSubs  []string
		wantProps []string
	}{
		{
			name:     "denied area only",
			g:        &GeofenceConstraint{DeniedArea: smallPoly},
			wantSubs: []string{"S_INTERSECTS", "NOT"},
		},
		{
			name:     "allowed and denied",
			g:        &GeofenceConstraint{AllowedArea: largePoly, DeniedArea: smallPoly},
			wantSubs: []string{"AND", "NOT"},
		},
		{
			name:      "allowed polygon",
			g:         &GeofenceConstraint{AllowedArea: smallPoly},
			wantSubs:  []string{"S_INTERSECTS"},
			wantProps: []string{"geometry"},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got, err := geofenceToCQL2(tc.g)
			require.NoError(t, err, "unexpected error")
			require.NotNil(t, got, "expected non-nil expression")
			s := encText(t, got)
			up := strings.ToUpper(s)
			for _, sub := range tc.wantSubs {
				require.Contains(t, up, sub, "want %q in %q", sub, s)
			}
			for _, p := range tc.wantProps {
				require.Contains(t, s, p, "want property %q in %q", p, s)
			}
		})
	}
}

func TestMaybePushDownGeofence_CombinesWithExistingPolicyFilter(t *testing.T) {
	c := &AuthzConstraints{
		CQL2Filter: "eo:cloud_cover < 20",
		Geofence: &GeofenceConstraint{
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
		},
	}
	out, applied, err := maybePushDownGeofence(c, true)
	require.NoError(t, err, "unexpected error")
	require.True(t, applied, "expected push-down to be applied")
	s := strings.ToUpper(out.CQL2Filter)
	require.Contains(t, s, "S_INTERSECTS", "want S_INTERSECTS, got %q", out.CQL2Filter)
	require.Contains(t, s, "EO:CLOUD_COVER", "want existing policy filter retained, got %q", out.CQL2Filter)
	require.Contains(t, s, "AND", "want AND-combined output, got %q", out.CQL2Filter)
	require.Nil(t, out.CQL2FilterJSON, "want CQL2FilterJSON cleared after text-merge, got %v", out.CQL2FilterJSON)
}

func TestMaybePushDownGeofence_NoOpWhenAbsent(t *testing.T) {
	c := &AuthzConstraints{}
	out, applied, err := maybePushDownGeofence(c, true)
	require.NoError(t, err, "want no-op for absent geofence")
	require.False(t, applied, "want no-op for absent geofence")
	require.Same(t, c, out, "want input pointer returned when no push-down happened")
	require.False(t, c.GeofencePushedDown, "GeofencePushedDown must not be set when no push-down happened")
}

// TestMaybePushDownGeofence_DoesNotMutateInput exercises the exact
// regression that motivated H-authz-4: callers must not see
// CQL2Filter or GeofencePushedDown change on the constraint they
// passed in.
func TestMaybePushDownGeofence_DoesNotMutateInput(t *testing.T) {
	const origFilter = "eo:cloud_cover < 20"
	in := &AuthzConstraints{
		CQL2Filter: origFilter,
		Geofence: &GeofenceConstraint{
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
		},
	}
	out, applied, err := maybePushDownGeofence(in, true)
	require.NoError(t, err, "unexpected error")
	require.True(t, applied, "expected push-down to apply")
	require.NotSame(t, in, out, "returned constraint must be a fresh value, not the input pointer")
	require.Equal(t, origFilter, in.CQL2Filter, "input CQL2Filter was mutated")
	require.False(t, in.GeofencePushedDown, "input GeofencePushedDown was mutated")
	require.Contains(t, strings.ToUpper(out.CQL2Filter), "S_INTERSECTS", "expected merged filter on returned constraint, got %q", out.CQL2Filter)
	// A second call on the original input must still apply push-down
	// (i.e. push-down is not gated by the prior call's mutation).
	out2, applied2, err := maybePushDownGeofence(in, true)
	require.NoError(t, err, "second call should still apply push-down")
	require.True(t, applied2, "second call should still apply push-down")
	require.NotSame(t, in, out2, "second call must also return a fresh value")
}

func TestParseUserCQL2_StringAndJSON(t *testing.T) {
	e, err := parseUserCQL2("a = 1")
	require.NoError(t, err, "text parse")
	require.NotNil(t, e, "text parse")

	e, err = parseUserCQL2(map[string]interface{}{
		"op":   "=",
		"args": []interface{}{map[string]interface{}{"property": "a"}, float64(1)},
	})
	require.NoError(t, err, "json parse")
	require.NotNil(t, e, "json parse")

	e, err = parseUserCQL2(nil)
	require.NoError(t, err, "nil parse")
	require.Nil(t, e, "nil parse")

	e, err = parseUserCQL2("")
	require.NoError(t, err, "empty-string parse")
	require.Nil(t, e, "empty-string parse")
}

func TestEncodeForLang_RoundTrip(t *testing.T) {
	e := cql2.Eq("a", 1)
	out, err := encodeForLang(&e, "cql2-text")
	require.NoError(t, err, "text encode")
	s, ok := out.(string)
	require.True(t, ok, "text: want 'a = 1', got %v", out)
	require.Equal(t, "a = 1", s, "text")

	out, err = encodeForLang(&e, "cql2-json")
	require.NoError(t, err, "json encode")
	_, ok = out.(map[string]interface{})
	require.True(t, ok, "json: want map, got %T %v", out, out)

	out, err = encodeForLang(&e, "")
	require.NoError(t, err, "default encode")
	_, ok = out.(string)
	require.True(t, ok, "default: want text string, got %T", out)
}

func TestGeofenceToCQL2_InvalidGeoJSON(t *testing.T) {
	g := &GeofenceConstraint{
		AllowedArea: map[string]interface{}{
			"type": "NotAGeometry",
		},
	}
	_, err := geofenceToCQL2(g)
	require.Error(t, err, "want error for invalid GeoJSON")
}

// TestGeofenceToCQL2_RespectsConfiguredProperty asserts the emitted
// S_INTERSECTS uses the configured property name rather than the
// hardcoded "geometry" — required when federating to backends like
// PostGIS/STAC that expose the geometry as "the_geom" or "footprint".
func TestGeofenceToCQL2_RespectsConfiguredProperty(t *testing.T) {
	g := &GeofenceConstraint{
		GeometryProperty: "the_geom",
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
	got, err := geofenceToCQL2(g)
	require.NoError(t, err, "geofenceToCQL2")
	require.NotNil(t, got, "geofenceToCQL2")
	s := encText(t, got)
	require.Contains(t, s, "the_geom", "want the_geom property reference, got %q", s)
	require.NotContains(t, s, "geometry", "expected configured property to replace 'geometry', got %q", s)
}

// TestMaybePushDownGeofence_SkipsPushDownWhenSpatialNotSupported
// asserts that when the caller signals the upstream lacks CQL2
// spatial-predicate support, push-down is skipped entirely. The
// response-side post-filter stays responsible.
func TestMaybePushDownGeofence_SkipsPushDownWhenSpatialNotSupported(t *testing.T) {
	c := &AuthzConstraints{
		Geofence: &GeofenceConstraint{
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
		},
	}
	out, applied, err := maybePushDownGeofence(c, false)
	require.NoError(t, err, "unexpected error")
	require.False(t, applied, "push-down must not run when spatialSupported=false")
	require.Same(t, c, out, "expected input pointer returned unchanged when push-down is skipped")
	require.False(t, out.GeofencePushedDown, "GeofencePushedDown must remain false so the post-filter stays responsible")
	require.Empty(t, out.CQL2Filter, "CQL2Filter must remain empty (no push-down)")
}
