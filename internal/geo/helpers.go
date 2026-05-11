// Package geo provides geospatial operations.
package geo

import (
	"encoding/json"
	"fmt"
)

// ParseGeoJSON parses a GeoJSON object from an interface{}.
func ParseGeoJSON(data interface{}) (*Geometry, error) {
	if data == nil {
		return nil, fmt.Errorf("nil geojson data")
	}

	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal geojson: %w", err)
	}

	var geom Geometry
	if err := json.Unmarshal(jsonBytes, &geom); err != nil {
		return nil, fmt.Errorf("failed to parse geojson: %w", err)
	}

	return &geom, nil
}

// BboxToGeometry converts a bounding box to a Polygon geometry.
func BboxToGeometry(data interface{}) (*Geometry, error) {
	// Convert interface to bbox slice
	var bbox []float64
	switch v := data.(type) {
	case []float64:
		bbox = v
	case []interface{}:
		bbox = make([]float64, len(v))
		for i, val := range v {
			if f, ok := val.(float64); ok {
				bbox[i] = f
			} else {
				return nil, fmt.Errorf("invalid bbox value at index %d: %v", i, val)
			}
		}
	default:
		jsonBytes, err := json.Marshal(data)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal bbox: %w", err)
		}
		if err := json.Unmarshal(jsonBytes, &bbox); err != nil {
			return nil, fmt.Errorf("failed to unmarshal bbox: %w", err)
		}
	}

	if len(bbox) != 4 && len(bbox) != 6 {
		return nil, fmt.Errorf("bbox must have 4 or 6 values, got %d", len(bbox))
	}

	// Convert bbox to polygon
	b := BBox(bbox)
	return b.ToPolygon()
}

// ToGeoJSON converts a Geometry to a GeoJSON-compatible interface{}.
func (g *Geometry) ToGeoJSON() interface{} {
	if g == nil {
		return nil
	}

	result := map[string]interface{}{
		"type": g.Type,
	}

	if len(g.Coordinates) > 0 {
		var coords interface{}
		json.Unmarshal(g.Coordinates, &coords)
		result["coordinates"] = coords
	}

	if len(g.Geometries) > 0 {
		geoms := make([]interface{}, len(g.Geometries))
		for i, geom := range g.Geometries {
			geoms[i] = geom.ToGeoJSON()
		}
		result["geometries"] = geoms
	}

	return result
}

// Contains checks if geometry a contains geometry b.
// This is a simplified bbox-based implementation.
func (g *Geometry) Contains(other *Geometry) bool {
	if g == nil || other == nil {
		return false
	}

	bboxA, err := BBoxFromGeometry(g)
	if err != nil {
		return false
	}

	bboxB, err := BBoxFromGeometry(other)
	if err != nil {
		return false
	}

	return BBoxContains(bboxA, bboxB)
}

// Intersects checks if this geometry intersects with another.
// This is a simplified bbox-based implementation.
func (g *Geometry) Intersects(other *Geometry) bool {
	if g == nil || other == nil {
		return false
	}

	bboxA, err := BBoxFromGeometry(g)
	if err != nil {
		return false
	}

	bboxB, err := BBoxFromGeometry(other)
	if err != nil {
		return false
	}

	return BBoxIntersects(bboxA, bboxB)
}
