// Package geo provides geospatial operations and GeoJSON handling.
package geo

import (
	"encoding/json"
	"fmt"
)

// Geometry represents a GeoJSON geometry.
type Geometry struct {
	Type        string          `json:"type"`
	Coordinates json.RawMessage `json:"coordinates,omitempty"`
	Geometries  []Geometry      `json:"geometries,omitempty"` // For GeometryCollection
}

// Feature represents a GeoJSON Feature.
type Feature struct {
	Type       string                 `json:"type"` // Always "Feature"
	ID         interface{}            `json:"id,omitempty"`
	Geometry   *Geometry              `json:"geometry"`
	Properties map[string]interface{} `json:"properties"`
	BBox       []float64              `json:"bbox,omitempty"`
}

// FeatureCollection represents a GeoJSON FeatureCollection.
type FeatureCollection struct {
	Type     string    `json:"type"` // Always "FeatureCollection"
	Features []Feature `json:"features"`
	BBox     []float64 `json:"bbox,omitempty"`
}

// BBox represents a bounding box [minX, minY, maxX, maxY] or [minX, minY, minZ, maxX, maxY, maxZ].
type BBox []float64

// Valid checks if the bounding box is valid.
func (b BBox) Valid() bool {
	if len(b) != 4 && len(b) != 6 {
		return false
	}
	if len(b) == 4 {
		return b[0] <= b[2] && b[1] <= b[3]
	}
	return b[0] <= b[3] && b[1] <= b[4] && b[2] <= b[5]
}

// MinX returns the minimum X coordinate.
func (b BBox) MinX() float64 { return b[0] }

// MinY returns the minimum Y coordinate.
func (b BBox) MinY() float64 { return b[1] }

// MaxX returns the maximum X coordinate.
func (b BBox) MaxX() float64 {
	if len(b) == 6 {
		return b[3]
	}
	return b[2]
}

// MaxY returns the maximum Y coordinate.
func (b BBox) MaxY() float64 {
	if len(b) == 6 {
		return b[4]
	}
	return b[3]
}

// ToPolygon converts the bounding box to a Polygon geometry.
func (b BBox) ToPolygon() (*Geometry, error) {
	if !b.Valid() {
		return nil, fmt.Errorf("invalid bounding box")
	}

	minX, minY := b.MinX(), b.MinY()
	maxX, maxY := b.MaxX(), b.MaxY()

	coords := [][][]float64{
		{
			{minX, minY},
			{maxX, minY},
			{maxX, maxY},
			{minX, maxY},
			{minX, minY},
		},
	}

	coordsJSON, err := json.Marshal(coords)
	if err != nil {
		return nil, err
	}

	return &Geometry{
		Type:        "Polygon",
		Coordinates: coordsJSON,
	}, nil
}

// ParseGeometry parses a GeoJSON geometry from bytes.
func ParseGeometry(data []byte) (*Geometry, error) {
	var geom Geometry
	if err := json.Unmarshal(data, &geom); err != nil {
		return nil, fmt.Errorf("failed to parse geometry: %w", err)
	}
	return &geom, nil
}

// ParseFeatureCollection parses a GeoJSON FeatureCollection from bytes.
func ParseFeatureCollection(data []byte) (*FeatureCollection, error) {
	var fc FeatureCollection
	if err := json.Unmarshal(data, &fc); err != nil {
		return nil, fmt.Errorf("failed to parse feature collection: %w", err)
	}
	return &fc, nil
}

// GeometryType constants.
const (
	GeomTypePoint              = "Point"
	GeomTypeMultiPoint         = "MultiPoint"
	GeomTypeLineString         = "LineString"
	GeomTypeMultiLineString    = "MultiLineString"
	GeomTypePolygon            = "Polygon"
	GeomTypeMultiPolygon       = "MultiPolygon"
	GeomTypeGeometryCollection = "GeometryCollection"
)

// IsEmpty checks if the geometry is empty or nil.
func (g *Geometry) IsEmpty() bool {
	if g == nil {
		return true
	}
	if g.Type == GeomTypeGeometryCollection {
		return len(g.Geometries) == 0
	}
	return len(g.Coordinates) == 0 || string(g.Coordinates) == "null"
}

// Clone creates a deep copy of the geometry.
func (g *Geometry) Clone() *Geometry {
	if g == nil {
		return nil
	}
	clone := &Geometry{
		Type: g.Type,
	}
	if g.Coordinates != nil {
		clone.Coordinates = make(json.RawMessage, len(g.Coordinates))
		copy(clone.Coordinates, g.Coordinates)
	}
	if g.Geometries != nil {
		clone.Geometries = make([]Geometry, len(g.Geometries))
		for i, geom := range g.Geometries {
			if cloned := geom.Clone(); cloned != nil {
				clone.Geometries[i] = *cloned
			}
		}
	}
	return clone
}
