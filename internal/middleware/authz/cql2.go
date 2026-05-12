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
//   - AllowedArea (if present) becomes S_INTERSECTS(geometry, allowed).
//   - DeniedArea (if present) becomes NOT S_INTERSECTS(geometry, denied).
//   - When both are set the two predicates are AND-combined.
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
		e := cql2.SIntersects("geometry", geom)
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
		inter := cql2.SIntersects("geometry", geom)
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
// push-down) into a CQL2 predicate, AND-combines it into the
// constraints' CQL2 filter, and sets GeofencePushedDown=true. Returns
// true if push-down was applied. When false, the post-response
// geofence filter remains responsible for enforcement.
//
// It is a no-op when:
//   - constraints is nil
//   - the geofence is absent or has only a DeniedArea
//   - encoding fails (the caller will see the error and the post-filter
//     stays as the safety net)
func maybePushDownGeofence(c *AuthzConstraints) (bool, error) {
	if c == nil || c.Geofence == nil {
		return false, nil
	}
	geofenceExpr, err := geofenceToCQL2(c.Geofence)
	if err != nil {
		return false, err
	}
	if geofenceExpr == nil {
		return false, nil
	}
	existing, err := parsePolicyCQL2(c)
	if err != nil {
		return false, err
	}
	combined := andNonNil(existing, geofenceExpr)
	if combined == nil {
		return false, nil
	}
	b, err := cql2.Encode(combined.N, cql2.EncodingText)
	if err != nil {
		return false, fmt.Errorf("cql2: encode geofence push-down: %w", err)
	}
	c.CQL2Filter = string(b)
	c.CQL2FilterJSON = nil
	c.GeofencePushedDown = true
	return true, nil
}
