package authz

import (
	"encoding/json"
	"fmt"

	cql2 "github.com/exergy-dev/go-cql2"
	_ "github.com/exergy-dev/go-cql2/codecs"
	"github.com/exergy-dev/go-cql2/geojson"
)

// andNonNil ANDs the supplied expressions, skipping nil entries. Returns
// nil iff every input is nil; returns the sole non-nil entry when only
// one is non-nil (avoiding a unary And which the library rejects).
//
// Use this to combine a possibly-nil user filter with a possibly-nil
// policy filter without special-casing in callers.
func andNonNil(exprs ...*cql2.Expr) *cql2.Expr {
	var nonNil []cql2.Expr
	for _, e := range exprs {
		if e != nil {
			nonNil = append(nonNil, *e)
		}
	}
	switch len(nonNil) {
	case 0:
		return nil
	case 1:
		out := nonNil[0]
		return &out
	default:
		out := cql2.And(nonNil...)
		return &out
	}
}

// geofenceToCQL2 builds a CQL2 expression that enforces a geofence:
//   - AllowedArea (if present) becomes S_INTERSECTS(<prop>, allowed).
//   - DeniedArea (if present) becomes NOT S_INTERSECTS(<prop>, denied).
//   - When both are set the two predicates are AND-combined.
//
// The property name comes from g.GeometryProperty (default "geometry"
// when empty). STAC items canonically hold geometry under "geometry",
// but federation targets may expose it as e.g. "the_geom" or
// "footprint"; the policy can override per geofence.
//
// Returns nil if g is nil or has neither an allowed nor a denied area.
//
// Each area is expected to be a GeoJSON geometry (Point, Polygon,
// MultiPolygon, etc.) as a Go value that json-marshals to a valid
// GeoJSON object — typically a map[string]interface{}.
func geofenceToCQL2(g *GeofenceConstraint) (*cql2.Expr, error) {
	if g == nil {
		return nil, nil
	}
	prop := g.GeometryProperty
	if prop == "" {
		prop = "geometry"
	}
	var allowed, denied *cql2.Expr
	if g.AllowedArea != nil {
		raw, err := json.Marshal(g.AllowedArea)
		if err != nil {
			return nil, fmt.Errorf("geofence: marshal allowed area: %w", err)
		}
		geom, err := geojson.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("geofence: parse allowed area as GeoJSON: %w", err)
		}
		e := cql2.SIntersects(prop, geom)
		allowed = &e
	}
	if g.DeniedArea != nil {
		raw, err := json.Marshal(g.DeniedArea)
		if err != nil {
			return nil, fmt.Errorf("geofence: marshal denied area: %w", err)
		}
		geom, err := geojson.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("geofence: parse denied area as GeoJSON: %w", err)
		}
		inter := cql2.SIntersects(prop, geom)
		notExpr := cql2.Not(inter)
		denied = &notExpr
	}
	return andNonNil(allowed, denied), nil
}

// parsePolicyCQL2 turns the CQL2 fields on AuthzConstraints into an Expr.
// Prefers the JSON variant when both are set. Returns nil if neither is
// set.
func parsePolicyCQL2(c *AuthzConstraints) (*cql2.Expr, error) {
	if c == nil {
		return nil, nil
	}
	var raw []byte
	switch {
	case c.CQL2FilterJSON != nil:
		b, err := json.Marshal(c.CQL2FilterJSON)
		if err != nil {
			return nil, fmt.Errorf("cql2: marshal policy filter json: %w", err)
		}
		raw = b
	case c.CQL2Filter != "":
		raw = []byte(c.CQL2Filter)
	default:
		return nil, nil
	}
	n, err := cql2.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("cql2: parse policy filter: %w", err)
	}
	out := cql2.Expr{N: n}
	return &out, nil
}

// parseUserCQL2 turns a search request's user-supplied filter into an
// Expr. The value may be a string (cql2-text) or a map/slice
// (cql2-json); both are auto-detected by the underlying library. nil
// input returns nil/nil.
func parseUserCQL2(filter interface{}) (*cql2.Expr, error) {
	if filter == nil {
		return nil, nil
	}
	var raw []byte
	switch v := filter.(type) {
	case string:
		if v == "" {
			return nil, nil
		}
		raw = []byte(v)
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("cql2: marshal user filter: %w", err)
		}
		raw = b
	}
	n, err := cql2.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("cql2: parse user filter: %w", err)
	}
	out := cql2.Expr{N: n}
	return &out, nil
}

// encodeForLang re-encodes expr in the encoding that matches lang. An
// empty or "cql2-text" lang produces cql2-text (string). "cql2-json"
// produces cql2-json (decoded into a map[string]any for transparent
// JSON-marshal downstream).
func encodeForLang(expr *cql2.Expr, lang string) (interface{}, error) {
	if expr == nil {
		return nil, nil
	}
	enc := cql2.EncodingText
	if lang == "cql2-json" {
		enc = cql2.EncodingJSON
	}
	b, err := cql2.Encode(expr.N, enc)
	if err != nil {
		return nil, fmt.Errorf("cql2: encode: %w", err)
	}
	if enc == cql2.EncodingText {
		return string(b), nil
	}
	var out interface{}
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("cql2: re-decode encoded json: %w", err)
	}
	return out, nil
}

// maybePushDownGeofence converts a geofence (if present and amenable to
// push-down) into a CQL2 predicate and AND-combines it into the
// constraints' CQL2 filter. The input constraint is NOT mutated;
// instead a shallow copy is returned with GeofencePushedDown=true and
// the merged CQL2Filter installed. Callers must use the returned
// constraint for downstream operations and check GeofencePushedDown
// to decide whether to skip the post-response geofence filter.
//
// Returning a fresh value protects against double-application: both
// injectCQL2Filter and validateSingleRecord invoke this helper, and a
// shared *AuthzConstraints lives on the AuthzDecision attached to the
// request context. In-place mutation caused the second caller to see
// a constraint already containing the geofence predicate, with the
// risk of double-AND'ing it (and breaking observability counters that
// branch on GeofencePushedDown).
//
// The returned bool is true iff push-down was applied (a new constraint
// was synthesized). When false the original *c is returned unchanged
// and the post-response geofence filter remains responsible.
//
// spatialSupported tells the helper whether the upstream advertises
// CQL2 spatial-predicate support (e.g. basic-spatial-functions). When
// false, push-down is skipped — emitting an S_INTERSECTS predicate
// that the upstream silently ignores would unrestricted-leak data,
// since GeofencePushedDown=true would also disable the post-filter.
// Local evaluation paths (validateSingleRecord) should pass true: the
// in-process evaluator implements S_INTERSECTS regardless of upstream.
//
// It is a no-op (returns c, false, nil) when:
//   - constraints is nil
//   - the geofence is absent or yields no spatial predicate
//   - the geofence has already been pushed down on this constraint
//   - spatialSupported is false (caller signalled the upstream lacks
//     the CQL2 spatial class)
//   - encoding fails (the caller will see the error and the post-filter
//     stays as the safety net)
func maybePushDownGeofence(c *AuthzConstraints, spatialSupported bool) (*AuthzConstraints, bool, error) {
	if c == nil || c.Geofence == nil {
		return c, false, nil
	}
	if c.GeofencePushedDown {
		return c, false, nil
	}
	if !spatialSupported {
		return c, false, nil
	}
	geofenceExpr, err := geofenceToCQL2(c.Geofence)
	if err != nil {
		return c, false, err
	}
	if geofenceExpr == nil {
		return c, false, nil
	}
	existing, err := parsePolicyCQL2(c)
	if err != nil {
		return c, false, err
	}
	combined := andNonNil(existing, geofenceExpr)
	if combined == nil {
		return c, false, nil
	}
	b, err := cql2.Encode(combined.N, cql2.EncodingText)
	if err != nil {
		return c, false, fmt.Errorf("cql2: encode geofence push-down: %w", err)
	}
	out := *c
	out.CQL2Filter = string(b)
	out.CQL2FilterJSON = nil
	out.GeofencePushedDown = true
	return &out, true, nil
}
