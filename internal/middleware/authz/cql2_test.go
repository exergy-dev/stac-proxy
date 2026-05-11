package authz

import (
	"strings"
	"testing"

	cql2 "github.com/exergy-dev/go-cql2"
	_ "github.com/exergy-dev/go-cql2/codecs"
)

func encText(t *testing.T, e *cql2.Expr) string {
	t.Helper()
	if e == nil {
		return ""
	}
	b, err := cql2.Encode(e.N, cql2.EncodingText)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return string(b)
}

func TestAndNonNil_AllNil(t *testing.T) {
	if got := andNonNil(nil, nil, nil); got != nil {
		t.Fatalf("want nil, got %v", got)
	}
}

func TestAndNonNil_SingleNonNil(t *testing.T) {
	e := cql2.Eq("a", 1)
	got := andNonNil(nil, &e, nil)
	if got == nil {
		t.Fatal("want non-nil")
	}
	if s := encText(t, got); s != "a = 1" {
		t.Fatalf("want %q, got %q", "a = 1", s)
	}
}

func TestAndNonNil_TwoNonNil(t *testing.T) {
	a := cql2.Eq("a", 1)
	b := cql2.Eq("b", 2)
	got := andNonNil(&a, nil, &b)
	s := encText(t, got)
	if !strings.Contains(s, "a = 1") || !strings.Contains(s, "b = 2") || !strings.Contains(s, "AND") {
		t.Fatalf("want both predicates AND-combined, got %q", s)
	}
}

func TestGeofenceToCQL2_Nil(t *testing.T) {
	got, err := geofenceToCQL2(nil)
	if err != nil || got != nil {
		t.Fatalf("want nil/nil, got %v / %v", got, err)
	}
	got, err = geofenceToCQL2(&GeofenceConstraint{})
	if err != nil || got != nil {
		t.Fatalf("want nil/nil for empty constraint, got %v / %v", got, err)
	}
}

func TestGeofenceToCQL2_DeniedAreaSkipped(t *testing.T) {
	g := &GeofenceConstraint{
		DeniedArea: map[string]interface{}{
			"type":        "Point",
			"coordinates": []interface{}{0.0, 0.0},
		},
	}
	got, err := geofenceToCQL2(g)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Fatalf("denied-area push-down should not be supported yet; got %s", encText(t, got))
	}
}

func TestGeofenceToCQL2_Polygon(t *testing.T) {
	g := &GeofenceConstraint{
		AllowedArea: map[string]interface{}{
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
		},
	}
	got, err := geofenceToCQL2(g)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("want non-nil expression for polygon allowed area")
	}
	s := encText(t, got)
	if !strings.Contains(strings.ToUpper(s), "S_INTERSECTS") {
		t.Fatalf("want S_INTERSECTS in encoded form, got %q", s)
	}
	if !strings.Contains(s, "geometry") {
		t.Fatalf("want property reference to geometry, got %q", s)
	}
}

func TestMaybePushDownGeofence_Polygon(t *testing.T) {
	c := &AuthzConstraints{
		Geofence: &GeofenceConstraint{
			AllowedArea: map[string]interface{}{
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
			},
		},
	}
	applied, err := maybePushDownGeofence(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !applied {
		t.Fatal("expected push-down to be applied")
	}
	if !c.GeofencePushedDown {
		t.Fatal("expected GeofencePushedDown=true")
	}
	if !strings.Contains(strings.ToUpper(c.CQL2Filter), "S_INTERSECTS") {
		t.Fatalf("want S_INTERSECTS in CQL2Filter, got %q", c.CQL2Filter)
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
	applied, err := maybePushDownGeofence(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !applied {
		t.Fatal("expected push-down to be applied")
	}
	s := strings.ToUpper(c.CQL2Filter)
	if !strings.Contains(s, "S_INTERSECTS") {
		t.Fatalf("want S_INTERSECTS, got %q", c.CQL2Filter)
	}
	if !strings.Contains(s, "EO:CLOUD_COVER") {
		t.Fatalf("want existing policy filter retained, got %q", c.CQL2Filter)
	}
	if !strings.Contains(s, "AND") {
		t.Fatalf("want AND-combined output, got %q", c.CQL2Filter)
	}
	if c.CQL2FilterJSON != nil {
		t.Fatalf("want CQL2FilterJSON cleared after text-merge, got %v", c.CQL2FilterJSON)
	}
}

func TestMaybePushDownGeofence_NoOpWhenAbsent(t *testing.T) {
	c := &AuthzConstraints{}
	applied, err := maybePushDownGeofence(c)
	if err != nil || applied {
		t.Fatalf("want no-op for absent geofence, got applied=%v err=%v", applied, err)
	}
	if c.GeofencePushedDown {
		t.Fatal("GeofencePushedDown must not be set when no push-down happened")
	}
}

func TestParseUserCQL2_StringAndJSON(t *testing.T) {
	e, err := parseUserCQL2("a = 1")
	if err != nil || e == nil {
		t.Fatalf("text parse: e=%v err=%v", e, err)
	}
	e, err = parseUserCQL2(map[string]interface{}{
		"op":   "=",
		"args": []interface{}{map[string]interface{}{"property": "a"}, float64(1)},
	})
	if err != nil || e == nil {
		t.Fatalf("json parse: e=%v err=%v", e, err)
	}
	e, err = parseUserCQL2(nil)
	if err != nil || e != nil {
		t.Fatalf("nil parse: e=%v err=%v", e, err)
	}
	e, err = parseUserCQL2("")
	if err != nil || e != nil {
		t.Fatalf("empty-string parse: e=%v err=%v", e, err)
	}
}

func TestEncodeForLang_RoundTrip(t *testing.T) {
	e := cql2.Eq("a", 1)
	out, err := encodeForLang(&e, "cql2-text")
	if err != nil {
		t.Fatalf("text encode: %v", err)
	}
	if s, ok := out.(string); !ok || s != "a = 1" {
		t.Fatalf("text: want 'a = 1', got %v", out)
	}
	out, err = encodeForLang(&e, "cql2-json")
	if err != nil {
		t.Fatalf("json encode: %v", err)
	}
	if _, ok := out.(map[string]interface{}); !ok {
		t.Fatalf("json: want map, got %T %v", out, out)
	}
	out, err = encodeForLang(&e, "")
	if err != nil {
		t.Fatalf("default encode: %v", err)
	}
	if _, ok := out.(string); !ok {
		t.Fatalf("default: want text string, got %T", out)
	}
}

func TestGeofenceToCQL2_InvalidGeoJSON(t *testing.T) {
	g := &GeofenceConstraint{
		AllowedArea: map[string]interface{}{
			"type": "NotAGeometry",
		},
	}
	if _, err := geofenceToCQL2(g); err == nil {
		t.Fatal("want error for invalid GeoJSON, got nil")
	}
}
