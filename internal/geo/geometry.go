// Package geo provides geometry operations.
package geo

import (
	"encoding/json"
	"fmt"
	"math"
)

// Point represents a 2D point.
type Point struct {
	X, Y float64
}

// Ring represents a linear ring (closed polygon boundary).
type Ring []Point

// Polygon represents a polygon with optional holes.
type Polygon struct {
	Exterior Ring
	Holes    []Ring
}

// ParsePolygonCoordinates parses polygon coordinates from GeoJSON.
func ParsePolygonCoordinates(coords json.RawMessage) (*Polygon, error) {
	var rings [][][]float64
	if err := json.Unmarshal(coords, &rings); err != nil {
		return nil, fmt.Errorf("failed to parse polygon coordinates: %w", err)
	}

	if len(rings) == 0 {
		return nil, fmt.Errorf("polygon must have at least one ring")
	}

	poly := &Polygon{
		Exterior: make(Ring, len(rings[0])),
	}

	for i, pt := range rings[0] {
		if len(pt) < 2 {
			return nil, fmt.Errorf("point must have at least 2 coordinates")
		}
		poly.Exterior[i] = Point{X: pt[0], Y: pt[1]}
	}

	for _, hole := range rings[1:] {
		ring := make(Ring, len(hole))
		for i, pt := range hole {
			if len(pt) < 2 {
				return nil, fmt.Errorf("point must have at least 2 coordinates")
			}
			ring[i] = Point{X: pt[0], Y: pt[1]}
		}
		poly.Holes = append(poly.Holes, ring)
	}

	return poly, nil
}

// Contains checks if a point is inside the polygon.
func (p *Polygon) Contains(pt Point) bool {
	if !pointInRing(pt, p.Exterior) {
		return false
	}
	for _, hole := range p.Holes {
		if pointInRing(pt, hole) {
			return false
		}
	}
	return true
}

// pointInRing uses the ray casting algorithm to check point-in-polygon.
func pointInRing(pt Point, ring Ring) bool {
	if len(ring) < 3 {
		return false
	}

	inside := false
	j := len(ring) - 1

	for i := 0; i < len(ring); i++ {
		xi, yi := ring[i].X, ring[i].Y
		xj, yj := ring[j].X, ring[j].Y

		if ((yi > pt.Y) != (yj > pt.Y)) &&
			(pt.X < (xj-xi)*(pt.Y-yi)/(yj-yi)+xi) {
			inside = !inside
		}
		j = i
	}

	return inside
}

// Bounds returns the bounding box of the polygon.
func (p *Polygon) Bounds() BBox {
	if len(p.Exterior) == 0 {
		return nil
	}

	minX, minY := math.MaxFloat64, math.MaxFloat64
	maxX, maxY := -math.MaxFloat64, -math.MaxFloat64

	for _, pt := range p.Exterior {
		minX = math.Min(minX, pt.X)
		minY = math.Min(minY, pt.Y)
		maxX = math.Max(maxX, pt.X)
		maxY = math.Max(maxY, pt.Y)
	}

	return BBox{minX, minY, maxX, maxY}
}

// BBoxIntersects checks if two bounding boxes intersect.
func BBoxIntersects(a, b BBox) bool {
	if len(a) < 4 || len(b) < 4 {
		return false
	}
	return a.MinX() <= b.MaxX() &&
		a.MaxX() >= b.MinX() &&
		a.MinY() <= b.MaxY() &&
		a.MaxY() >= b.MinY()
}

// BBoxContains checks if bbox a contains bbox b.
func BBoxContains(a, b BBox) bool {
	if len(a) < 4 || len(b) < 4 {
		return false
	}
	return a.MinX() <= b.MinX() &&
		a.MaxX() >= b.MaxX() &&
		a.MinY() <= b.MinY() &&
		a.MaxY() >= b.MaxY()
}

// BBoxFromGeometry extracts a bounding box from a geometry.
func BBoxFromGeometry(geom *Geometry) (BBox, error) {
	if geom == nil {
		return nil, fmt.Errorf("nil geometry")
	}

	switch geom.Type {
	case GeomTypePoint:
		var coords []float64
		if err := json.Unmarshal(geom.Coordinates, &coords); err != nil {
			return nil, err
		}
		if len(coords) < 2 {
			return nil, fmt.Errorf("point must have at least 2 coordinates")
		}
		return BBox{coords[0], coords[1], coords[0], coords[1]}, nil

	case GeomTypePolygon, GeomTypeMultiPolygon:
		// For polygons, we need to find the extent
		return bboxFromPolygonCoords(geom.Coordinates)

	case GeomTypeGeometryCollection:
		if len(geom.Geometries) == 0 {
			return nil, fmt.Errorf("empty geometry collection")
		}
		bbox, err := BBoxFromGeometry(&geom.Geometries[0])
		if err != nil {
			return nil, err
		}
		for _, g := range geom.Geometries[1:] {
			b, err := BBoxFromGeometry(&g)
			if err != nil {
				continue
			}
			bbox = MergeBBox(bbox, b)
		}
		return bbox, nil

	default:
		return nil, fmt.Errorf("unsupported geometry type: %s", geom.Type)
	}
}

// bboxFromPolygonCoords extracts bbox from polygon coordinates.
func bboxFromPolygonCoords(coords json.RawMessage) (BBox, error) {
	var rings [][][]float64
	if err := json.Unmarshal(coords, &rings); err != nil {
		// Try as MultiPolygon
		var multiRings [][][][]float64
		if err := json.Unmarshal(coords, &multiRings); err != nil {
			return nil, fmt.Errorf("failed to parse polygon coordinates")
		}
		if len(multiRings) == 0 || len(multiRings[0]) == 0 {
			return nil, fmt.Errorf("empty multi-polygon")
		}
		rings = multiRings[0]
	}

	if len(rings) == 0 || len(rings[0]) == 0 {
		return nil, fmt.Errorf("empty polygon")
	}

	minX, minY := math.MaxFloat64, math.MaxFloat64
	maxX, maxY := -math.MaxFloat64, -math.MaxFloat64

	for _, pt := range rings[0] {
		if len(pt) >= 2 {
			minX = math.Min(minX, pt[0])
			minY = math.Min(minY, pt[1])
			maxX = math.Max(maxX, pt[0])
			maxY = math.Max(maxY, pt[1])
		}
	}

	return BBox{minX, minY, maxX, maxY}, nil
}

// MergeBBox combines two bounding boxes.
func MergeBBox(a, b BBox) BBox {
	if len(a) < 4 {
		return b
	}
	if len(b) < 4 {
		return a
	}
	return BBox{
		math.Min(a.MinX(), b.MinX()),
		math.Min(a.MinY(), b.MinY()),
		math.Max(a.MaxX(), b.MaxX()),
		math.Max(a.MaxY(), b.MaxY()),
	}
}

// Intersects checks if two geometries intersect.
// This is a simplified implementation - for production use consider using
// a proper geometry library like simplefeatures.
func Intersects(a, b *Geometry) (bool, error) {
	if a == nil || b == nil {
		return false, nil
	}

	// Get bounding boxes and check for quick rejection
	bboxA, err := BBoxFromGeometry(a)
	if err != nil {
		return false, err
	}
	bboxB, err := BBoxFromGeometry(b)
	if err != nil {
		return false, err
	}

	return BBoxIntersects(bboxA, bboxB), nil
}

// Within checks if geometry a is within geometry b.
// This is a simplified bbox-based implementation.
func Within(a, b *Geometry) (bool, error) {
	if a == nil || b == nil {
		return false, nil
	}

	bboxA, err := BBoxFromGeometry(a)
	if err != nil {
		return false, err
	}
	bboxB, err := BBoxFromGeometry(b)
	if err != nil {
		return false, err
	}

	return BBoxContains(bboxB, bboxA), nil
}
