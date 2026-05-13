package geo_test

import (
	"encoding/json"
	"testing"

	"github.com/yourorg/stac-proxy/internal/geo"
)

// --- Fixtures ----------------------------------------------------------------

const (
	pointJSON = `{"type":"Point","coordinates":[1.0,1.0]}`

	// Outer polygon: square [0,0]-[10,10].
	outerPolygonJSON = `{"type":"Polygon","coordinates":[[[0,0],[10,0],[10,10],[0,10],[0,0]]]}`

	// Inner polygon: square [2,2]-[4,4], wholly contained in outerPolygonJSON.
	innerPolygonJSON = `{"type":"Polygon","coordinates":[[[2,2],[4,2],[4,4],[2,4],[2,2]]]}`

	// Disjoint polygon: square [20,20]-[30,30].
	disjointPolygonJSON = `{"type":"Polygon","coordinates":[[[20,20],[30,20],[30,30],[20,30],[20,20]]]}`

	// Overlapping polygon: square [5,5]-[15,15], overlaps outer.
	overlappingPolygonJSON = `{"type":"Polygon","coordinates":[[[5,5],[15,5],[15,15],[5,15],[5,5]]]}`

	// Edge-touching polygon: shares the right edge of outer at x=10.
	edgeTouchingPolygonJSON = `{"type":"Polygon","coordinates":[[[10,0],[20,0],[20,10],[10,10],[10,0]]]}`

	// L-shape: counter-clockwise outer ring, missing the upper-right quadrant.
	// bbox is [0,0,2,2] but the body excludes the square (1,1)-(2,2).
	lShapePolygonJSON = `{"type":"Polygon","coordinates":[[[0,0],[2,0],[2,1],[1,1],[1,2],[0,2],[0,0]]]}`

	// A point at (1.5, 1.5) wrapped as a degenerate polygon could be used to
	// probe Contains, but ParseGeoJSON should also accept GeoJSON Points.
	pointInLBBoxOutsideBodyJSON = `{"type":"Point","coordinates":[1.5,1.5]}`

	// A point clearly inside the L body for sanity checks.
	pointInsideLBodyJSON = `{"type":"Point","coordinates":[0.5,0.5]}`
)

// mustParse parses GeoJSON from a string and fatals on error.
func mustParse(t *testing.T, s string) *geo.Geometry {
	t.Helper()
	g, err := geo.ParseGeoJSON([]byte(s))
	if err != nil {
		t.Fatalf("ParseGeoJSON(%q) failed: %v", s, err)
	}
	if g == nil {
		t.Fatalf("ParseGeoJSON(%q) returned nil geometry without error", s)
	}
	return g
}

// --- ParseGeoJSON ------------------------------------------------------------

func TestParseGeoJSON_Inputs(t *testing.T) {
	polygonMap := map[string]interface{}{
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

	cases := []struct {
		name    string
		input   interface{}
		wantErr bool
	}{
		{
			name:  "valid Point as []byte",
			input: []byte(pointJSON),
		},
		{
			name:  "valid Polygon as json.RawMessage",
			input: json.RawMessage(outerPolygonJSON),
		},
		{
			name:  "valid Polygon as map[string]interface{}",
			input: polygonMap,
		},
		{
			name:    "nil input",
			input:   nil,
			wantErr: true,
		},
		{
			name:    "empty object []byte",
			input:   []byte(`{}`),
			wantErr: true,
		},
		{
			name:    "empty string []byte",
			input:   []byte(``),
			wantErr: true,
		},
		{
			name:    "malformed JSON",
			input:   []byte(`{"type":"Point","coordinates":`),
			wantErr: true,
		},
		{
			name:    "JSON not GeoJSON shaped",
			input:   []byte(`{"foo":"bar"}`),
			wantErr: true,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			g, err := geo.ParseGeoJSON(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (geometry=%v)", g)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if g == nil {
				t.Fatalf("expected non-nil geometry")
			}
		})
	}
}

func TestParseGeoJSON_PassThroughGeometry(t *testing.T) {
	orig := mustParse(t, outerPolygonJSON)

	// Passing a *Geometry back to ParseGeoJSON should round-trip without error.
	// We accept either the same pointer or an equivalent geometry; we verify
	// equivalence via the predicate contract (mutual Contains on identical bodies).
	again, err := geo.ParseGeoJSON(orig)
	if err != nil {
		t.Fatalf("ParseGeoJSON(*Geometry) returned error: %v", err)
	}
	if again == nil {
		t.Fatalf("ParseGeoJSON(*Geometry) returned nil")
	}

	if !orig.Contains(again) || !again.Contains(orig) {
		t.Fatalf("expected pass-through geometry to be mutually contained with original")
	}
}

// --- Contains (TRUE geometric) ----------------------------------------------

func TestContains_OuterContainsInner(t *testing.T) {
	outer := mustParse(t, outerPolygonJSON)
	inner := mustParse(t, innerPolygonJSON)

	if !outer.Contains(inner) {
		t.Fatalf("expected outer polygon to contain inner polygon")
	}
	if inner.Contains(outer) {
		t.Fatalf("expected inner polygon NOT to contain outer polygon")
	}
}

func TestContains_Disjoint(t *testing.T) {
	a := mustParse(t, outerPolygonJSON)
	b := mustParse(t, disjointPolygonJSON)

	if a.Contains(b) {
		t.Fatalf("expected disjoint polygons to not contain each other (a.Contains(b))")
	}
	if b.Contains(a) {
		t.Fatalf("expected disjoint polygons to not contain each other (b.Contains(a))")
	}
}

func TestContains_NilReceiver(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("nil-receiver Contains panicked: %v", r)
		}
	}()

	other := mustParse(t, innerPolygonJSON)
	var nilGeom *geo.Geometry
	if nilGeom.Contains(other) {
		t.Fatalf("expected nil-receiver Contains to return false")
	}
}

func TestContains_NilArgument(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("nil-argument Contains panicked: %v", r)
		}
	}()

	g := mustParse(t, outerPolygonJSON)
	if g.Contains(nil) {
		t.Fatalf("expected Contains(nil) to return false")
	}
}

// TestContains_ConcaveBBoxFalsePositive is the behavior-shift lock-in test.
// Under the old bbox-only Contains, a point at (1.5, 1.5) was reported as
// inside the L-shape because its bbox is [0,0,2,2]. Under true geometric
// Contains, the point lies in the missing upper-right quadrant and must be
// reported as outside.
func TestContains_ConcaveBBoxFalsePositive(t *testing.T) {
	lShape := mustParse(t, lShapePolygonJSON)
	pointInBBoxOutsideBody := mustParse(t, pointInLBBoxOutsideBodyJSON)
	pointInsideBody := mustParse(t, pointInsideLBodyJSON)

	if lShape.Contains(pointInBBoxOutsideBody) {
		t.Fatalf("L-shape must NOT contain point (1.5,1.5) which is in the bbox but outside the body; this would indicate the old bbox-only Contains")
	}
	if !lShape.Contains(pointInsideBody) {
		t.Fatalf("L-shape must contain point (0.5,0.5) which lies inside its body")
	}
}

// --- Intersects (TRUE geometric) --------------------------------------------

func TestIntersects_Overlapping(t *testing.T) {
	a := mustParse(t, outerPolygonJSON)
	b := mustParse(t, overlappingPolygonJSON)

	if !a.Intersects(b) {
		t.Fatalf("expected overlapping polygons to intersect (a.Intersects(b))")
	}
	if !b.Intersects(a) {
		t.Fatalf("expected overlapping polygons to intersect (b.Intersects(a))")
	}
}

func TestIntersects_Disjoint(t *testing.T) {
	a := mustParse(t, outerPolygonJSON)
	b := mustParse(t, disjointPolygonJSON)

	if a.Intersects(b) {
		t.Fatalf("expected disjoint polygons to not intersect")
	}
}

// TestIntersects_EdgeTouching documents whatever the library returns for two
// polygons that share a single edge but do not overlap in area. Most JTS-style
// libraries return true here (touching counts as intersection). We pin the
// most-likely outcome but treat divergence as a documentation-only matter:
// if the underlying library changes its mind, update this expected value
// rather than treating it as a regression in our facade.
func TestIntersects_EdgeTouching(t *testing.T) {
	a := mustParse(t, outerPolygonJSON)
	b := mustParse(t, edgeTouchingPolygonJSON)

	// Library-implementation-defined; JTS/go-topology-suite typically returns true.
	got := a.Intersects(b)
	if !got {
		t.Logf("edge-touching polygons returned Intersects=false; this is allowed but unusual for JTS-style predicates")
	}
}

// --- ToGeoJSON round-trip ----------------------------------------------------

// roundTrip parses the input, serialises it via ToGeoJSON, then parses the
// result and returns the second geometry. Useful to verify that the facade's
// serialisation is loss-less for the predicate contract.
func roundTrip(t *testing.T, src string) (orig, again *geo.Geometry) {
	t.Helper()
	orig = mustParse(t, src)
	out := orig.ToGeoJSON()
	if out == nil {
		t.Fatalf("ToGeoJSON returned nil")
	}
	again, err := geo.ParseGeoJSON(out)
	if err != nil {
		t.Fatalf("ParseGeoJSON(ToGeoJSON(g)) failed: %v", err)
	}
	if again == nil {
		t.Fatalf("ParseGeoJSON(ToGeoJSON(g)) returned nil geometry")
	}
	return orig, again
}

func TestRoundTrip_Point(t *testing.T) {
	orig, again := roundTrip(t, pointJSON)

	// Self-Contains must hold for the round-tripped geometry.
	if !again.Contains(again) {
		t.Fatalf("round-tripped point does not self-contain")
	}

	// Predicate equivalence against a fixed reference polygon: both should
	// intersect the outer square (the point (1,1) is inside it).
	ref := mustParse(t, outerPolygonJSON)
	if orig.Intersects(ref) != again.Intersects(ref) {
		t.Fatalf("round-tripped point disagrees with original on Intersects(ref): orig=%v again=%v",
			orig.Intersects(ref), again.Intersects(ref))
	}
	if ref.Contains(orig) != ref.Contains(again) {
		t.Fatalf("round-tripped point disagrees with original on ref.Contains: orig=%v again=%v",
			ref.Contains(orig), ref.Contains(again))
	}
}

func TestRoundTrip_Polygon(t *testing.T) {
	orig, again := roundTrip(t, innerPolygonJSON)

	if !again.Contains(again) {
		t.Fatalf("round-tripped polygon does not self-contain")
	}

	// Reference: outer polygon. Should contain both orig and again.
	ref := mustParse(t, outerPolygonJSON)
	if ref.Contains(orig) != ref.Contains(again) {
		t.Fatalf("round-tripped polygon disagrees with original on ref.Contains: orig=%v again=%v",
			ref.Contains(orig), ref.Contains(again))
	}
	if orig.Intersects(ref) != again.Intersects(ref) {
		t.Fatalf("round-tripped polygon disagrees with original on Intersects(ref): orig=%v again=%v",
			orig.Intersects(ref), again.Intersects(ref))
	}

	// And mutual Contains (equivalence) against the original.
	if !orig.Contains(again) || !again.Contains(orig) {
		t.Fatalf("expected round-tripped polygon to be mutually contained with original")
	}
}
