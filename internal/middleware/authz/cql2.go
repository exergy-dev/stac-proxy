package authz

import (
	"encoding/json"
	"fmt"

	cql2 "github.com/exergy-dev/go-cql2"
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

// geofenceToCQL2 builds a CQL2 expression that enforces a geofence by
// requiring the item's geometry to intersect the geofence's allowed
// area. Returns nil if g is nil, has no allowed area, or has a denied
// area (denied-area push-down is not yet supported; callers should fall
// back to post-filtering in that case).
//
// The allowed area is expected to be a GeoJSON geometry (Point,
// Polygon, MultiPolygon, etc.) as a Go value that json-marshals to a
// valid GeoJSON object — typically a map[string]interface{}.
func geofenceToCQL2(g *GeofenceConstraint) (*cql2.Expr, error) {
	if g == nil || g.AllowedArea == nil {
		return nil, nil
	}
	// Denied-area push-down requires NOT(S_INTERSECTS(...)) and an
	// agreed-upon property name; defer to the post-filter for now.
	if g.DeniedArea != nil {
		return nil, nil
	}
	raw, err := json.Marshal(g.AllowedArea)
	if err != nil {
		return nil, fmt.Errorf("geofence: marshal allowed area: %w", err)
	}
	geom, err := geojson.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("geofence: parse allowed area as GeoJSON: %w", err)
	}
	expr := cql2.SIntersects("geometry", geom)
	return &expr, nil
}
