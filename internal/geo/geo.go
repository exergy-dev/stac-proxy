// Package geo is a thin facade over github.com/exergy-dev/go-topology-suite
// that exposes the small surface stac-proxy needs: GeoJSON in/out and the
// Contains/Intersects predicates, with STAC's implicit WGS84 CRS attached to
// every parsed geometry.
package geo

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/exergy-dev/go-topology-suite/crs"
	"github.com/exergy-dev/go-topology-suite/geojson"
	"github.com/exergy-dev/go-topology-suite/geom"
	"github.com/exergy-dev/go-topology-suite/predicate"
)

// Geometry wraps a go-topology-suite geometry. Callers treat it as opaque;
// construct via ParseGeoJSON and consume via ToGeoJSON / Contains / Intersects.
type Geometry struct {
	g geom.Geometry
}

// ParseGeoJSON accepts a raw GeoJSON document ([]byte / json.RawMessage), an
// already-decoded GeoJSON object (map[string]interface{}), or a *Geometry
// (pass-through). The returned geometry is tagged with crs.WGS84 since STAC
// is always lon/lat per RFC 7946.
func ParseGeoJSON(data interface{}) (*Geometry, error) {
	if data == nil {
		return nil, errors.New("geo: nil input")
	}
	var raw []byte
	switch v := data.(type) {
	case *Geometry:
		if v == nil {
			return nil, errors.New("geo: nil *Geometry")
		}
		return v, nil
	case []byte:
		raw = v
	case json.RawMessage:
		raw = []byte(v)
	case map[string]interface{}:
		// Re-marshal rather than hand-walking the map: the library's decoder
		// already handles every GeoJSON geometry type, layout (XY/XYZ),
		// GeometryCollection nesting, and bbox/CRS quirks.
		b, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("geo: marshal map: %w", err)
		}
		raw = b
	default:
		return nil, fmt.Errorf("geo: unsupported input type %T", data)
	}
	if len(raw) == 0 {
		return nil, errors.New("geo: empty input")
	}
	g, err := geojson.UnmarshalWithCRS(raw, crs.WGS84)
	if err != nil {
		return nil, err
	}
	return &Geometry{g: g}, nil
}

// Contains reports whether g geometrically contains other (closed-set
// containment — every point of other lies in g's interior or boundary).
//
// This intentionally maps to go-topology-suite's predicate.Covers rather
// than predicate.Contains. JTS-style Contains is strict (a polygon does
// NOT contain itself; the operand's boundary must not lie on the host's
// boundary), which surprises stac-proxy callers: geofencing asks "is the
// request inside the allowed area?", and "request equals allowed area"
// should be a yes. Covers matches that intuition AND preserves the
// behavior shift that motivated this migration — a concave polygon
// covers a point only if the point lies inside the polygon's body, not
// merely inside its bounding box.
//
// Returns false on nil receiver/argument or any library error (callers
// treat the predicate as a boolean filter, not an error channel).
func (g *Geometry) Contains(other *Geometry) bool {
	if g == nil || other == nil || g.g == nil || other.g == nil {
		return false
	}
	ok, err := predicate.Covers(g.g, other.g)
	if err != nil {
		return false
	}
	return ok
}

// Intersects reports true geometric intersection. Same nil/error semantics
// as Contains.
func (g *Geometry) Intersects(other *Geometry) bool {
	if g == nil || other == nil || g.g == nil || other.g == nil {
		return false
	}
	ok, err := predicate.Intersects(g.g, other.g)
	if err != nil {
		return false
	}
	return ok
}

// ToGeoJSON returns a map[string]interface{} suitable for embedding in a STAC
// response. We re-marshal through the library's writer (rather than reaching
// into the geometry's internals) so output stays canonical RFC 7946 — key
// order, layout handling, and ring orientation are the library's problem.
func (g *Geometry) ToGeoJSON() interface{} {
	if g == nil || g.g == nil {
		return nil
	}
	b, err := geojson.Marshal(g.g)
	if err != nil {
		return nil
	}
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil
	}
	return m
}
