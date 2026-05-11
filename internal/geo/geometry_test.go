package geo

import (
	"encoding/json"
	"math"
	"testing"
)

// TestPointInRing tests the ray casting algorithm for point-in-polygon detection.
func TestPointInRing(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		point    Point
		ring     Ring
		expected bool
	}{
		{
			name:  "point clearly inside square",
			point: Point{X: 0, Y: 0},
			ring: Ring{
				{X: -10, Y: -10},
				{X: 10, Y: -10},
				{X: 10, Y: 10},
				{X: -10, Y: 10},
				{X: -10, Y: -10},
			},
			expected: true,
		},
		{
			name:  "point clearly outside square",
			point: Point{X: 20, Y: 20},
			ring: Ring{
				{X: -10, Y: -10},
				{X: 10, Y: -10},
				{X: 10, Y: 10},
				{X: -10, Y: 10},
				{X: -10, Y: -10},
			},
			expected: false,
		},
		{
			name:  "point on vertex",
			point: Point{X: 10, Y: 10},
			ring: Ring{
				{X: -10, Y: -10},
				{X: 10, Y: -10},
				{X: 10, Y: 10},
				{X: -10, Y: 10},
				{X: -10, Y: -10},
			},
			expected: false, // Ray casting doesn't include boundary points
		},
		{
			name:  "point on horizontal edge",
			point: Point{X: 0, Y: 10},
			ring: Ring{
				{X: -10, Y: -10},
				{X: 10, Y: -10},
				{X: 10, Y: 10},
				{X: -10, Y: 10},
				{X: -10, Y: -10},
			},
			expected: false, // Ray casting doesn't include boundary points
		},
		{
			name:  "point on vertical edge",
			point: Point{X: 10, Y: 0},
			ring: Ring{
				{X: -10, Y: -10},
				{X: 10, Y: -10},
				{X: 10, Y: 10},
				{X: -10, Y: 10},
				{X: -10, Y: -10},
			},
			expected: false, // Ray casting doesn't include boundary points
		},
		{
			name:  "point inside triangle",
			point: Point{X: 1, Y: 1},
			ring: Ring{
				{X: 0, Y: 0},
				{X: 10, Y: 0},
				{X: 5, Y: 10},
				{X: 0, Y: 0},
			},
			expected: true,
		},
		{
			name:  "point outside triangle",
			point: Point{X: -1, Y: 1},
			ring: Ring{
				{X: 0, Y: 0},
				{X: 10, Y: 0},
				{X: 5, Y: 10},
				{X: 0, Y: 0},
			},
			expected: false,
		},
		{
			name:  "ring with less than 3 points",
			point: Point{X: 0, Y: 0},
			ring: Ring{
				{X: 0, Y: 0},
				{X: 10, Y: 10},
			},
			expected: false,
		},
		{
			name:     "empty ring",
			point:    Point{X: 0, Y: 0},
			ring:     Ring{},
			expected: false,
		},
		{
			name:  "complex polygon - concave",
			point: Point{X: 0, Y: 0},
			ring: Ring{
				{X: -10, Y: -10},
				{X: 10, Y: -10},
				{X: 10, Y: 10},
				{X: 0, Y: 5},
				{X: -10, Y: 10},
				{X: -10, Y: -10},
			},
			expected: true,
		},
		{
			name:  "point with high precision",
			point: Point{X: 0.00001, Y: 0.00001},
			ring: Ring{
				{X: -1, Y: -1},
				{X: 1, Y: -1},
				{X: 1, Y: 1},
				{X: -1, Y: 1},
				{X: -1, Y: -1},
			},
			expected: true,
		},
		{
			name:  "point at exact boundary - edge case",
			point: Point{X: 10, Y: -10},
			ring: Ring{
				{X: -10, Y: -10},
				{X: 10, Y: -10},
				{X: 10, Y: 10},
				{X: -10, Y: 10},
				{X: -10, Y: -10},
			},
			expected: false, // Ray casting doesn't include boundary points
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := pointInRing(tt.point, tt.ring)
			if result != tt.expected {
				t.Errorf("pointInRing() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestPolygonContains tests polygon containment with holes.
func TestPolygonContains(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		polygon  *Polygon
		point    Point
		expected bool
	}{
		{
			name: "point inside polygon without holes",
			polygon: &Polygon{
				Exterior: Ring{
					{X: -10, Y: -10},
					{X: 10, Y: -10},
					{X: 10, Y: 10},
					{X: -10, Y: 10},
					{X: -10, Y: -10},
				},
			},
			point:    Point{X: 0, Y: 0},
			expected: true,
		},
		{
			name: "point outside polygon",
			polygon: &Polygon{
				Exterior: Ring{
					{X: -10, Y: -10},
					{X: 10, Y: -10},
					{X: 10, Y: 10},
					{X: -10, Y: 10},
					{X: -10, Y: -10},
				},
			},
			point:    Point{X: 20, Y: 20},
			expected: false,
		},
		{
			name: "point inside hole",
			polygon: &Polygon{
				Exterior: Ring{
					{X: -10, Y: -10},
					{X: 10, Y: -10},
					{X: 10, Y: 10},
					{X: -10, Y: 10},
					{X: -10, Y: -10},
				},
				Holes: []Ring{
					{
						{X: -5, Y: -5},
						{X: 5, Y: -5},
						{X: 5, Y: 5},
						{X: -5, Y: 5},
						{X: -5, Y: -5},
					},
				},
			},
			point:    Point{X: 0, Y: 0},
			expected: false,
		},
		{
			name: "point between exterior and hole",
			polygon: &Polygon{
				Exterior: Ring{
					{X: -10, Y: -10},
					{X: 10, Y: -10},
					{X: 10, Y: 10},
					{X: -10, Y: 10},
					{X: -10, Y: -10},
				},
				Holes: []Ring{
					{
						{X: -5, Y: -5},
						{X: 5, Y: -5},
						{X: 5, Y: 5},
						{X: -5, Y: 5},
						{X: -5, Y: -5},
					},
				},
			},
			point:    Point{X: 7, Y: 7},
			expected: true,
		},
		{
			name: "point inside polygon with multiple holes",
			polygon: &Polygon{
				Exterior: Ring{
					{X: -20, Y: -20},
					{X: 20, Y: -20},
					{X: 20, Y: 20},
					{X: -20, Y: 20},
					{X: -20, Y: -20},
				},
				Holes: []Ring{
					{
						{X: -10, Y: -10},
						{X: -5, Y: -10},
						{X: -5, Y: -5},
						{X: -10, Y: -5},
						{X: -10, Y: -10},
					},
					{
						{X: 5, Y: 5},
						{X: 10, Y: 5},
						{X: 10, Y: 10},
						{X: 5, Y: 10},
						{X: 5, Y: 5},
					},
				},
			},
			point:    Point{X: 0, Y: 0},
			expected: true,
		},
		{
			name: "point in first hole of multiple holes",
			polygon: &Polygon{
				Exterior: Ring{
					{X: -20, Y: -20},
					{X: 20, Y: -20},
					{X: 20, Y: 20},
					{X: -20, Y: 20},
					{X: -20, Y: -20},
				},
				Holes: []Ring{
					{
						{X: -10, Y: -10},
						{X: -5, Y: -10},
						{X: -5, Y: -5},
						{X: -10, Y: -5},
						{X: -10, Y: -10},
					},
					{
						{X: 5, Y: 5},
						{X: 10, Y: 5},
						{X: 10, Y: 10},
						{X: 5, Y: 10},
						{X: 5, Y: 5},
					},
				},
			},
			point:    Point{X: -7, Y: -7},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := tt.polygon.Contains(tt.point)
			if result != tt.expected {
				t.Errorf("Polygon.Contains() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestPolygonBounds tests polygon bounding box calculation.
func TestPolygonBounds(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		polygon  *Polygon
		expected BBox
	}{
		{
			name: "simple square",
			polygon: &Polygon{
				Exterior: Ring{
					{X: -10, Y: -10},
					{X: 10, Y: -10},
					{X: 10, Y: 10},
					{X: -10, Y: 10},
					{X: -10, Y: -10},
				},
			},
			expected: BBox{-10, -10, 10, 10},
		},
		{
			name: "triangle",
			polygon: &Polygon{
				Exterior: Ring{
					{X: 0, Y: 0},
					{X: 10, Y: 0},
					{X: 5, Y: 10},
					{X: 0, Y: 0},
				},
			},
			expected: BBox{0, 0, 10, 10},
		},
		{
			name: "empty polygon",
			polygon: &Polygon{
				Exterior: Ring{},
			},
			expected: nil,
		},
		{
			name: "polygon with negative coordinates",
			polygon: &Polygon{
				Exterior: Ring{
					{X: -100, Y: -50},
					{X: -20, Y: -50},
					{X: -20, Y: -10},
					{X: -100, Y: -10},
					{X: -100, Y: -50},
				},
			},
			expected: BBox{-100, -50, -20, -10},
		},
		{
			name: "polygon with high precision",
			polygon: &Polygon{
				Exterior: Ring{
					{X: -0.0001, Y: -0.0001},
					{X: 0.0001, Y: -0.0001},
					{X: 0.0001, Y: 0.0001},
					{X: -0.0001, Y: 0.0001},
					{X: -0.0001, Y: -0.0001},
				},
			},
			expected: BBox{-0.0001, -0.0001, 0.0001, 0.0001},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := tt.polygon.Bounds()
			if len(result) != len(tt.expected) {
				t.Fatalf("Bounds() returned bbox of length %d, want %d", len(result), len(tt.expected))
			}
			for i := range result {
				if math.Abs(result[i]-tt.expected[i]) > 1e-10 {
					t.Errorf("Bounds()[%d] = %v, want %v", i, result[i], tt.expected[i])
				}
			}
		})
	}
}

// TestBBoxValid tests bounding box validation.
func TestBBoxValid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		bbox     BBox
		expected bool
	}{
		{
			name:     "valid 2D bbox",
			bbox:     BBox{-10, -10, 10, 10},
			expected: true,
		},
		{
			name:     "valid 3D bbox",
			bbox:     BBox{-10, -10, 0, 10, 10, 100},
			expected: true,
		},
		{
			name:     "invalid - too few coordinates",
			bbox:     BBox{-10, -10, 10},
			expected: false,
		},
		{
			name:     "invalid - too many coordinates",
			bbox:     BBox{-10, -10, 10, 10, 0},
			expected: false,
		},
		{
			name:     "invalid - minX > maxX",
			bbox:     BBox{10, -10, -10, 10},
			expected: false,
		},
		{
			name:     "invalid - minY > maxY",
			bbox:     BBox{-10, 10, 10, -10},
			expected: false,
		},
		{
			name:     "invalid - 3D minX > maxX",
			bbox:     BBox{10, -10, 0, -10, 10, 100},
			expected: false,
		},
		{
			name:     "valid - point bbox (min == max)",
			bbox:     BBox{5, 5, 5, 5},
			expected: true,
		},
		{
			name:     "empty bbox",
			bbox:     BBox{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := tt.bbox.Valid()
			if result != tt.expected {
				t.Errorf("BBox.Valid() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestBBoxAccessors tests bounding box accessor methods.
func TestBBoxAccessors(t *testing.T) {
	t.Parallel()

	t.Run("2D bbox accessors", func(t *testing.T) {
		t.Parallel()
		bbox := BBox{-10.5, -20.3, 15.7, 25.9}
		if bbox.MinX() != -10.5 {
			t.Errorf("MinX() = %v, want -10.5", bbox.MinX())
		}
		if bbox.MinY() != -20.3 {
			t.Errorf("MinY() = %v, want -20.3", bbox.MinY())
		}
		if bbox.MaxX() != 15.7 {
			t.Errorf("MaxX() = %v, want 15.7", bbox.MaxX())
		}
		if bbox.MaxY() != 25.9 {
			t.Errorf("MaxY() = %v, want 25.9", bbox.MaxY())
		}
	})

	t.Run("3D bbox accessors", func(t *testing.T) {
		t.Parallel()
		bbox := BBox{-10.5, -20.3, 5.0, 15.7, 25.9, 100.0}
		if bbox.MinX() != -10.5 {
			t.Errorf("MinX() = %v, want -10.5", bbox.MinX())
		}
		if bbox.MinY() != -20.3 {
			t.Errorf("MinY() = %v, want -20.3", bbox.MinY())
		}
		if bbox.MaxX() != 15.7 {
			t.Errorf("MaxX() = %v, want 15.7", bbox.MaxX())
		}
		if bbox.MaxY() != 25.9 {
			t.Errorf("MaxY() = %v, want 25.9", bbox.MaxY())
		}
	})
}

// TestBBoxIntersects tests bounding box intersection detection.
func TestBBoxIntersects(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		a        BBox
		b        BBox
		expected bool
	}{
		{
			name:     "overlapping boxes",
			a:        BBox{-10, -10, 10, 10},
			b:        BBox{0, 0, 20, 20},
			expected: true,
		},
		{
			name:     "non-overlapping boxes",
			a:        BBox{-10, -10, -5, -5},
			b:        BBox{5, 5, 10, 10},
			expected: false,
		},
		{
			name:     "touching boxes - edge contact",
			a:        BBox{-10, -10, 0, 10},
			b:        BBox{0, -10, 10, 10},
			expected: true,
		},
		{
			name:     "one box contains the other",
			a:        BBox{-20, -20, 20, 20},
			b:        BBox{-10, -10, 10, 10},
			expected: true,
		},
		{
			name:     "identical boxes",
			a:        BBox{-10, -10, 10, 10},
			b:        BBox{-10, -10, 10, 10},
			expected: true,
		},
		{
			name:     "boxes separated horizontally",
			a:        BBox{-20, 0, -10, 10},
			b:        BBox{10, 0, 20, 10},
			expected: false,
		},
		{
			name:     "boxes separated vertically",
			a:        BBox{0, -20, 10, -10},
			b:        BBox{0, 10, 10, 20},
			expected: false,
		},
		{
			name:     "invalid bbox a - too few coordinates",
			a:        BBox{-10, -10},
			b:        BBox{0, 0, 10, 10},
			expected: false,
		},
		{
			name:     "invalid bbox b - too few coordinates",
			a:        BBox{-10, -10, 10, 10},
			b:        BBox{0, 0},
			expected: false,
		},
		{
			name:     "both invalid",
			a:        BBox{},
			b:        BBox{0},
			expected: false,
		},
		{
			name:     "corner overlap only",
			a:        BBox{0, 0, 10, 10},
			b:        BBox{10, 10, 20, 20},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := BBoxIntersects(tt.a, tt.b)
			if result != tt.expected {
				t.Errorf("BBoxIntersects() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestBBoxContains tests bounding box containment.
func TestBBoxContains(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		a        BBox
		b        BBox
		expected bool
	}{
		{
			name:     "a contains b",
			a:        BBox{-20, -20, 20, 20},
			b:        BBox{-10, -10, 10, 10},
			expected: true,
		},
		{
			name:     "b contains a",
			a:        BBox{-10, -10, 10, 10},
			b:        BBox{-20, -20, 20, 20},
			expected: false,
		},
		{
			name:     "identical boxes",
			a:        BBox{-10, -10, 10, 10},
			b:        BBox{-10, -10, 10, 10},
			expected: true,
		},
		{
			name:     "partially overlapping",
			a:        BBox{-10, -10, 10, 10},
			b:        BBox{0, 0, 20, 20},
			expected: false,
		},
		{
			name:     "completely separate",
			a:        BBox{-10, -10, -5, -5},
			b:        BBox{5, 5, 10, 10},
			expected: false,
		},
		{
			name:     "b touches edge of a",
			a:        BBox{-10, -10, 10, 10},
			b:        BBox{-10, -10, 0, 0},
			expected: true,
		},
		{
			name:     "invalid bbox a",
			a:        BBox{-10, -10},
			b:        BBox{-5, -5, 5, 5},
			expected: false,
		},
		{
			name:     "invalid bbox b",
			a:        BBox{-10, -10, 10, 10},
			b:        BBox{0},
			expected: false,
		},
		{
			name:     "both invalid",
			a:        BBox{},
			b:        BBox{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := BBoxContains(tt.a, tt.b)
			if result != tt.expected {
				t.Errorf("BBoxContains() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestBBoxToPolygon tests conversion of bbox to polygon geometry.
func TestBBoxToPolygon(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		bbox        BBox
		expectError bool
	}{
		{
			name:        "valid 2D bbox",
			bbox:        BBox{-10, -20, 30, 40},
			expectError: false,
		},
		{
			name:        "valid 3D bbox",
			bbox:        BBox{-10, -20, 0, 30, 40, 100},
			expectError: false,
		},
		{
			name:        "invalid bbox - too few coordinates",
			bbox:        BBox{-10, -20, 30},
			expectError: true,
		},
		{
			name:        "invalid bbox - minX > maxX",
			bbox:        BBox{10, -20, -10, 40},
			expectError: true,
		},
		{
			name:        "invalid bbox - minY > maxY",
			bbox:        BBox{-10, 40, 30, -20},
			expectError: true,
		},
		{
			name:        "empty bbox",
			bbox:        BBox{},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			geom, err := tt.bbox.ToPolygon()
			if tt.expectError {
				if err == nil {
					t.Error("ToPolygon() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("ToPolygon() unexpected error: %v", err)
			}
			if geom.Type != "Polygon" {
				t.Errorf("ToPolygon() type = %v, want Polygon", geom.Type)
			}

			// Parse coordinates to verify structure
			var coords [][][]float64
			if err := json.Unmarshal(geom.Coordinates, &coords); err != nil {
				t.Fatalf("Failed to parse polygon coordinates: %v", err)
			}
			if len(coords) != 1 {
				t.Errorf("Expected 1 ring, got %d", len(coords))
			}
			if len(coords[0]) != 5 {
				t.Errorf("Expected 5 points (closed ring), got %d", len(coords[0]))
			}
			// Verify first and last points are the same (closed ring)
			if coords[0][0][0] != coords[0][4][0] || coords[0][0][1] != coords[0][4][1] {
				t.Error("Ring is not closed")
			}
		})
	}
}

// TestMergeBBox tests merging of bounding boxes.
func TestMergeBBox(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		a        BBox
		b        BBox
		expected BBox
	}{
		{
			name:     "merge two valid bboxes",
			a:        BBox{-10, -10, 10, 10},
			b:        BBox{5, 5, 20, 20},
			expected: BBox{-10, -10, 20, 20},
		},
		{
			name:     "merge non-overlapping bboxes",
			a:        BBox{-20, -20, -10, -10},
			b:        BBox{10, 10, 20, 20},
			expected: BBox{-20, -20, 20, 20},
		},
		{
			name:     "first bbox invalid",
			a:        BBox{-10},
			b:        BBox{5, 5, 20, 20},
			expected: BBox{5, 5, 20, 20},
		},
		{
			name:     "second bbox invalid",
			a:        BBox{-10, -10, 10, 10},
			b:        BBox{},
			expected: BBox{-10, -10, 10, 10},
		},
		{
			name:     "both invalid",
			a:        BBox{},
			b:        BBox{1, 2},
			expected: BBox{1, 2},
		},
		{
			name:     "identical bboxes",
			a:        BBox{-10, -10, 10, 10},
			b:        BBox{-10, -10, 10, 10},
			expected: BBox{-10, -10, 10, 10},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := MergeBBox(tt.a, tt.b)
			if len(result) != len(tt.expected) {
				t.Fatalf("MergeBBox() returned bbox of length %d, want %d", len(result), len(tt.expected))
			}
			for i := range result {
				if result[i] != tt.expected[i] {
					t.Errorf("MergeBBox()[%d] = %v, want %v", i, result[i], tt.expected[i])
				}
			}
		})
	}
}

// TestParsePolygonCoordinates tests parsing of polygon coordinates from GeoJSON.
func TestParsePolygonCoordinates(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		coords      string
		expectError bool
		validate    func(*testing.T, *Polygon)
	}{
		{
			name:        "simple polygon without holes",
			coords:      `[[[-10,-10],[10,-10],[10,10],[-10,10],[-10,-10]]]`,
			expectError: false,
			validate: func(t *testing.T, p *Polygon) {
				if len(p.Exterior) != 5 {
					t.Errorf("Expected 5 exterior points, got %d", len(p.Exterior))
				}
				if len(p.Holes) != 0 {
					t.Errorf("Expected 0 holes, got %d", len(p.Holes))
				}
				if p.Exterior[0].X != -10 || p.Exterior[0].Y != -10 {
					t.Errorf("First point = (%v, %v), want (-10, -10)", p.Exterior[0].X, p.Exterior[0].Y)
				}
			},
		},
		{
			name:        "polygon with one hole",
			coords:      `[[[-10,-10],[10,-10],[10,10],[-10,10],[-10,-10]],[[-5,-5],[5,-5],[5,5],[-5,5],[-5,-5]]]`,
			expectError: false,
			validate: func(t *testing.T, p *Polygon) {
				if len(p.Exterior) != 5 {
					t.Errorf("Expected 5 exterior points, got %d", len(p.Exterior))
				}
				if len(p.Holes) != 1 {
					t.Errorf("Expected 1 hole, got %d", len(p.Holes))
				}
				if len(p.Holes[0]) != 5 {
					t.Errorf("Expected 5 points in hole, got %d", len(p.Holes[0]))
				}
			},
		},
		{
			name:        "polygon with multiple holes",
			coords:      `[[[-20,-20],[20,-20],[20,20],[-20,20],[-20,-20]],[[-10,-10],[-5,-10],[-5,-5],[-10,-5],[-10,-10]],[[5,5],[10,5],[10,10],[5,10],[5,5]]]`,
			expectError: false,
			validate: func(t *testing.T, p *Polygon) {
				if len(p.Holes) != 2 {
					t.Errorf("Expected 2 holes, got %d", len(p.Holes))
				}
			},
		},
		{
			name:        "invalid JSON",
			coords:      `invalid json`,
			expectError: true,
		},
		{
			name:        "empty rings array",
			coords:      `[]`,
			expectError: true,
		},
		{
			name:        "point with less than 2 coordinates in exterior",
			coords:      `[[[0]]]`,
			expectError: true,
		},
		{
			name:        "point with less than 2 coordinates in hole",
			coords:      `[[[-10,-10],[10,-10],[10,10],[-10,10],[-10,-10]],[[5]]]`,
			expectError: true,
		},
		{
			name:        "3D coordinates (should still work)",
			coords:      `[[[-10,-10,0],[10,-10,0],[10,10,0],[-10,10,0],[-10,-10,0]]]`,
			expectError: false,
			validate: func(t *testing.T, p *Polygon) {
				if len(p.Exterior) != 5 {
					t.Errorf("Expected 5 exterior points, got %d", len(p.Exterior))
				}
				// Z coordinate should be ignored
				if p.Exterior[0].X != -10 || p.Exterior[0].Y != -10 {
					t.Errorf("First point = (%v, %v), want (-10, -10)", p.Exterior[0].X, p.Exterior[0].Y)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			poly, err := ParsePolygonCoordinates(json.RawMessage(tt.coords))
			if tt.expectError {
				if err == nil {
					t.Error("ParsePolygonCoordinates() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("ParsePolygonCoordinates() unexpected error: %v", err)
			}
			if tt.validate != nil {
				tt.validate(t, poly)
			}
		})
	}
}

// TestBBoxFromGeometry tests extracting bounding box from various geometry types.
func TestBBoxFromGeometry(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		geometry    *Geometry
		expectError bool
		validate    func(*testing.T, BBox)
	}{
		{
			name: "point geometry",
			geometry: &Geometry{
				Type:        GeomTypePoint,
				Coordinates: json.RawMessage(`[10.5, 20.3]`),
			},
			expectError: false,
			validate: func(t *testing.T, bbox BBox) {
				expected := BBox{10.5, 20.3, 10.5, 20.3}
				for i := range expected {
					if math.Abs(bbox[i]-expected[i]) > 1e-10 {
						t.Errorf("BBox[%d] = %v, want %v", i, bbox[i], expected[i])
					}
				}
			},
		},
		{
			name: "polygon geometry",
			geometry: &Geometry{
				Type:        GeomTypePolygon,
				Coordinates: json.RawMessage(`[[[-10,-10],[10,-10],[10,10],[-10,10],[-10,-10]]]`),
			},
			expectError: false,
			validate: func(t *testing.T, bbox BBox) {
				expected := BBox{-10, -10, 10, 10}
				for i := range expected {
					if bbox[i] != expected[i] {
						t.Errorf("BBox[%d] = %v, want %v", i, bbox[i], expected[i])
					}
				}
			},
		},
		{
			name: "multi-polygon geometry",
			geometry: &Geometry{
				Type:        GeomTypeMultiPolygon,
				Coordinates: json.RawMessage(`[[[[-10,-10],[10,-10],[10,10],[-10,10],[-10,-10]]]]`),
			},
			expectError: false,
			validate: func(t *testing.T, bbox BBox) {
				expected := BBox{-10, -10, 10, 10}
				for i := range expected {
					if bbox[i] != expected[i] {
						t.Errorf("BBox[%d] = %v, want %v", i, bbox[i], expected[i])
					}
				}
			},
		},
		{
			name: "geometry collection",
			geometry: &Geometry{
				Type: GeomTypeGeometryCollection,
				Geometries: []Geometry{
					{
						Type:        GeomTypePoint,
						Coordinates: json.RawMessage(`[0, 0]`),
					},
					{
						Type:        GeomTypePoint,
						Coordinates: json.RawMessage(`[10, 10]`),
					},
				},
			},
			expectError: false,
			validate: func(t *testing.T, bbox BBox) {
				expected := BBox{0, 0, 10, 10}
				for i := range expected {
					if bbox[i] != expected[i] {
						t.Errorf("BBox[%d] = %v, want %v", i, bbox[i], expected[i])
					}
				}
			},
		},
		{
			name:        "nil geometry",
			geometry:    nil,
			expectError: true,
		},
		{
			name: "point with insufficient coordinates",
			geometry: &Geometry{
				Type:        GeomTypePoint,
				Coordinates: json.RawMessage(`[10]`),
			},
			expectError: true,
		},
		{
			name: "empty geometry collection",
			geometry: &Geometry{
				Type:       GeomTypeGeometryCollection,
				Geometries: []Geometry{},
			},
			expectError: true,
		},
		{
			name: "unsupported geometry type",
			geometry: &Geometry{
				Type:        "LineString",
				Coordinates: json.RawMessage(`[[0,0],[10,10]]`),
			},
			expectError: true,
		},
		{
			name: "invalid polygon coordinates",
			geometry: &Geometry{
				Type:        GeomTypePolygon,
				Coordinates: json.RawMessage(`invalid`),
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			bbox, err := BBoxFromGeometry(tt.geometry)
			if tt.expectError {
				if err == nil {
					t.Error("BBoxFromGeometry() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("BBoxFromGeometry() unexpected error: %v", err)
			}
			if tt.validate != nil {
				tt.validate(t, bbox)
			}
		})
	}
}

// TestIntersects tests geometry intersection detection.
func TestIntersects(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		a           *Geometry
		b           *Geometry
		expected    bool
		expectError bool
	}{
		{
			name: "intersecting polygons",
			a: &Geometry{
				Type:        GeomTypePolygon,
				Coordinates: json.RawMessage(`[[[-10,-10],[10,-10],[10,10],[-10,10],[-10,-10]]]`),
			},
			b: &Geometry{
				Type:        GeomTypePolygon,
				Coordinates: json.RawMessage(`[[[0,0],[20,0],[20,20],[0,20],[0,0]]]`),
			},
			expected:    true,
			expectError: false,
		},
		{
			name: "non-intersecting polygons",
			a: &Geometry{
				Type:        GeomTypePolygon,
				Coordinates: json.RawMessage(`[[[-20,-20],[-10,-20],[-10,-10],[-20,-10],[-20,-20]]]`),
			},
			b: &Geometry{
				Type:        GeomTypePolygon,
				Coordinates: json.RawMessage(`[[[10,10],[20,10],[20,20],[10,20],[10,10]]]`),
			},
			expected:    false,
			expectError: false,
		},
		{
			name: "point inside polygon",
			a: &Geometry{
				Type:        GeomTypePoint,
				Coordinates: json.RawMessage(`[0, 0]`),
			},
			b: &Geometry{
				Type:        GeomTypePolygon,
				Coordinates: json.RawMessage(`[[[-10,-10],[10,-10],[10,10],[-10,10],[-10,-10]]]`),
			},
			expected:    true,
			expectError: false,
		},
		{
			name: "point outside polygon",
			a: &Geometry{
				Type:        GeomTypePoint,
				Coordinates: json.RawMessage(`[50, 50]`),
			},
			b: &Geometry{
				Type:        GeomTypePolygon,
				Coordinates: json.RawMessage(`[[[-10,-10],[10,-10],[10,10],[-10,10],[-10,-10]]]`),
			},
			expected:    false,
			expectError: false,
		},
		{
			name:        "nil geometry a",
			a:           nil,
			b:           &Geometry{Type: GeomTypePoint, Coordinates: json.RawMessage(`[0,0]`)},
			expected:    false,
			expectError: false,
		},
		{
			name:        "nil geometry b",
			a:           &Geometry{Type: GeomTypePoint, Coordinates: json.RawMessage(`[0,0]`)},
			b:           nil,
			expected:    false,
			expectError: false,
		},
		{
			name:        "both nil",
			a:           nil,
			b:           nil,
			expected:    false,
			expectError: false,
		},
		{
			name: "invalid geometry a",
			a: &Geometry{
				Type:        GeomTypePolygon,
				Coordinates: json.RawMessage(`invalid`),
			},
			b: &Geometry{
				Type:        GeomTypePoint,
				Coordinates: json.RawMessage(`[0,0]`),
			},
			expected:    false,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result, err := Intersects(tt.a, tt.b)
			if tt.expectError {
				if err == nil {
					t.Error("Intersects() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("Intersects() unexpected error: %v", err)
			}
			if result != tt.expected {
				t.Errorf("Intersects() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestWithin tests geometry containment detection.
func TestWithin(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		a           *Geometry
		b           *Geometry
		expected    bool
		expectError bool
	}{
		{
			name: "polygon a within polygon b",
			a: &Geometry{
				Type:        GeomTypePolygon,
				Coordinates: json.RawMessage(`[[[-5,-5],[5,-5],[5,5],[-5,5],[-5,-5]]]`),
			},
			b: &Geometry{
				Type:        GeomTypePolygon,
				Coordinates: json.RawMessage(`[[[-10,-10],[10,-10],[10,10],[-10,10],[-10,-10]]]`),
			},
			expected:    true,
			expectError: false,
		},
		{
			name: "polygon a not within polygon b",
			a: &Geometry{
				Type:        GeomTypePolygon,
				Coordinates: json.RawMessage(`[[[-10,-10],[10,-10],[10,10],[-10,10],[-10,-10]]]`),
			},
			b: &Geometry{
				Type:        GeomTypePolygon,
				Coordinates: json.RawMessage(`[[[-5,-5],[5,-5],[5,5],[-5,5],[-5,-5]]]`),
			},
			expected:    false,
			expectError: false,
		},
		{
			name: "point within polygon",
			a: &Geometry{
				Type:        GeomTypePoint,
				Coordinates: json.RawMessage(`[0, 0]`),
			},
			b: &Geometry{
				Type:        GeomTypePolygon,
				Coordinates: json.RawMessage(`[[[-10,-10],[10,-10],[10,10],[-10,10],[-10,-10]]]`),
			},
			expected:    true,
			expectError: false,
		},
		{
			name: "point outside polygon",
			a: &Geometry{
				Type:        GeomTypePoint,
				Coordinates: json.RawMessage(`[50, 50]`),
			},
			b: &Geometry{
				Type:        GeomTypePolygon,
				Coordinates: json.RawMessage(`[[[-10,-10],[10,-10],[10,10],[-10,10],[-10,-10]]]`),
			},
			expected:    false,
			expectError: false,
		},
		{
			name:        "nil geometry a",
			a:           nil,
			b:           &Geometry{Type: GeomTypePoint, Coordinates: json.RawMessage(`[0,0]`)},
			expected:    false,
			expectError: false,
		},
		{
			name:        "nil geometry b",
			a:           &Geometry{Type: GeomTypePoint, Coordinates: json.RawMessage(`[0,0]`)},
			b:           nil,
			expected:    false,
			expectError: false,
		},
		{
			name: "invalid geometry b",
			a: &Geometry{
				Type:        GeomTypePoint,
				Coordinates: json.RawMessage(`[0,0]`),
			},
			b: &Geometry{
				Type:        GeomTypePolygon,
				Coordinates: json.RawMessage(`invalid`),
			},
			expected:    false,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result, err := Within(tt.a, tt.b)
			if tt.expectError {
				if err == nil {
					t.Error("Within() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("Within() unexpected error: %v", err)
			}
			if result != tt.expected {
				t.Errorf("Within() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestParseGeometry tests parsing GeoJSON geometry from bytes.
func TestParseGeometry(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		data        string
		expectError bool
		validate    func(*testing.T, *Geometry)
	}{
		{
			name:        "valid point",
			data:        `{"type":"Point","coordinates":[10.5,20.3]}`,
			expectError: false,
			validate: func(t *testing.T, g *Geometry) {
				if g.Type != GeomTypePoint {
					t.Errorf("Type = %v, want Point", g.Type)
				}
				var coords []float64
				if err := json.Unmarshal(g.Coordinates, &coords); err != nil {
					t.Fatalf("Failed to parse coordinates: %v", err)
				}
				if len(coords) != 2 || coords[0] != 10.5 || coords[1] != 20.3 {
					t.Errorf("Coordinates = %v, want [10.5, 20.3]", coords)
				}
			},
		},
		{
			name:        "valid polygon",
			data:        `{"type":"Polygon","coordinates":[[[-10,-10],[10,-10],[10,10],[-10,10],[-10,-10]]]}`,
			expectError: false,
			validate: func(t *testing.T, g *Geometry) {
				if g.Type != GeomTypePolygon {
					t.Errorf("Type = %v, want Polygon", g.Type)
				}
			},
		},
		{
			name:        "valid multi-polygon",
			data:        `{"type":"MultiPolygon","coordinates":[[[[-10,-10],[10,-10],[10,10],[-10,10],[-10,-10]]]]}`,
			expectError: false,
			validate: func(t *testing.T, g *Geometry) {
				if g.Type != GeomTypeMultiPolygon {
					t.Errorf("Type = %v, want MultiPolygon", g.Type)
				}
			},
		},
		{
			name:        "geometry collection",
			data:        `{"type":"GeometryCollection","geometries":[{"type":"Point","coordinates":[0,0]}]}`,
			expectError: false,
			validate: func(t *testing.T, g *Geometry) {
				if g.Type != GeomTypeGeometryCollection {
					t.Errorf("Type = %v, want GeometryCollection", g.Type)
				}
				if len(g.Geometries) != 1 {
					t.Errorf("Expected 1 geometry in collection, got %d", len(g.Geometries))
				}
			},
		},
		{
			name:        "invalid JSON",
			data:        `invalid json`,
			expectError: true,
		},
		{
			name:        "empty string",
			data:        ``,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			geom, err := ParseGeometry([]byte(tt.data))
			if tt.expectError {
				if err == nil {
					t.Error("ParseGeometry() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseGeometry() unexpected error: %v", err)
			}
			if tt.validate != nil {
				tt.validate(t, geom)
			}
		})
	}
}

// TestGeometryIsEmpty tests the IsEmpty method.
func TestGeometryIsEmpty(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		geometry *Geometry
		expected bool
	}{
		{
			name:     "nil geometry",
			geometry: nil,
			expected: true,
		},
		{
			name: "empty coordinates",
			geometry: &Geometry{
				Type:        GeomTypePoint,
				Coordinates: json.RawMessage(``),
			},
			expected: true,
		},
		{
			name: "null coordinates",
			geometry: &Geometry{
				Type:        GeomTypePoint,
				Coordinates: json.RawMessage(`null`),
			},
			expected: true,
		},
		{
			name: "valid point",
			geometry: &Geometry{
				Type:        GeomTypePoint,
				Coordinates: json.RawMessage(`[0,0]`),
			},
			expected: false,
		},
		{
			name: "empty geometry collection",
			geometry: &Geometry{
				Type:       GeomTypeGeometryCollection,
				Geometries: []Geometry{},
			},
			expected: true,
		},
		{
			name: "non-empty geometry collection",
			geometry: &Geometry{
				Type: GeomTypeGeometryCollection,
				Geometries: []Geometry{
					{Type: GeomTypePoint, Coordinates: json.RawMessage(`[0,0]`)},
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := tt.geometry.IsEmpty()
			if result != tt.expected {
				t.Errorf("IsEmpty() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestGeometryClone tests deep copying of geometries.
func TestGeometryClone(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		geometry *Geometry
	}{
		{
			name:     "nil geometry",
			geometry: nil,
		},
		{
			name: "simple point",
			geometry: &Geometry{
				Type:        GeomTypePoint,
				Coordinates: json.RawMessage(`[10.5,20.3]`),
			},
		},
		{
			name: "polygon",
			geometry: &Geometry{
				Type:        GeomTypePolygon,
				Coordinates: json.RawMessage(`[[[-10,-10],[10,-10],[10,10],[-10,10],[-10,-10]]]`),
			},
		},
		{
			name: "geometry collection",
			geometry: &Geometry{
				Type: GeomTypeGeometryCollection,
				Geometries: []Geometry{
					{Type: GeomTypePoint, Coordinates: json.RawMessage(`[0,0]`)},
					{Type: GeomTypePoint, Coordinates: json.RawMessage(`[10,10]`)},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			clone := tt.geometry.Clone()

			// Test nil case
			if tt.geometry == nil {
				if clone != nil {
					t.Error("Clone of nil should be nil")
				}
				return
			}

			// Verify clone is not same instance
			if tt.geometry == clone {
				t.Error("Clone should return a different instance")
			}

			// Verify type is the same
			if clone.Type != tt.geometry.Type {
				t.Errorf("Clone type = %v, want %v", clone.Type, tt.geometry.Type)
			}

			// Verify coordinates are copied (not same instance)
			if tt.geometry.Coordinates != nil {
				if len(clone.Coordinates) != len(tt.geometry.Coordinates) {
					t.Errorf("Clone coordinates length = %d, want %d", len(clone.Coordinates), len(tt.geometry.Coordinates))
				}
				if &clone.Coordinates[0] == &tt.geometry.Coordinates[0] {
					t.Error("Clone coordinates should be a different slice")
				}
			}

			// Verify geometries collection is copied
			if tt.geometry.Geometries != nil {
				if len(clone.Geometries) != len(tt.geometry.Geometries) {
					t.Errorf("Clone geometries length = %d, want %d", len(clone.Geometries), len(tt.geometry.Geometries))
				}
			}

			// Modify clone and verify original is unchanged
			if clone.Coordinates != nil && len(clone.Coordinates) > 0 {
				clone.Coordinates[0] = 'X'
				if len(tt.geometry.Coordinates) > 0 && tt.geometry.Coordinates[0] == 'X' {
					t.Error("Modifying clone should not affect original")
				}
			}
		})
	}
}

// TestCoordinatePrecision tests handling of high-precision coordinates.
func TestCoordinatePrecision(t *testing.T) {
	t.Parallel()

	t.Run("high precision point", func(t *testing.T) {
		t.Parallel()
		coords := json.RawMessage(`[123.456789012345, -45.678901234567]`)
		geom := &Geometry{
			Type:        GeomTypePoint,
			Coordinates: coords,
		}

		bbox, err := BBoxFromGeometry(geom)
		if err != nil {
			t.Fatalf("BBoxFromGeometry() error: %v", err)
		}

		var parsedCoords []float64
		if err := json.Unmarshal(coords, &parsedCoords); err != nil {
			t.Fatalf("Failed to parse coordinates: %v", err)
		}

		if bbox[0] != parsedCoords[0] || bbox[1] != parsedCoords[1] {
			t.Errorf("Precision lost: bbox = %v, want [%v, %v, %v, %v]",
				bbox, parsedCoords[0], parsedCoords[1], parsedCoords[0], parsedCoords[1])
		}
	})

	t.Run("high precision polygon", func(t *testing.T) {
		t.Parallel()
		poly := &Polygon{
			Exterior: Ring{
				{X: -0.123456789, Y: -0.987654321},
				{X: 0.123456789, Y: -0.987654321},
				{X: 0.123456789, Y: 0.987654321},
				{X: -0.123456789, Y: 0.987654321},
				{X: -0.123456789, Y: -0.987654321},
			},
		}

		bbox := poly.Bounds()
		if math.Abs(bbox.MinX()-(-0.123456789)) > 1e-15 {
			t.Errorf("Precision lost in MinX: %v", bbox.MinX())
		}
		if math.Abs(bbox.MinY()-(-0.987654321)) > 1e-15 {
			t.Errorf("Precision lost in MinY: %v", bbox.MinY())
		}
	})
}

// TestBboxFromPolygonCoords tests the internal bboxFromPolygonCoords function.
func TestBboxFromPolygonCoords(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		coords      string
		expectError bool
		validate    func(*testing.T, BBox)
	}{
		{
			name:        "simple polygon",
			coords:      `[[[-10,-10],[10,-10],[10,10],[-10,10],[-10,-10]]]`,
			expectError: false,
			validate: func(t *testing.T, bbox BBox) {
				expected := BBox{-10, -10, 10, 10}
				for i := range expected {
					if bbox[i] != expected[i] {
						t.Errorf("BBox[%d] = %v, want %v", i, bbox[i], expected[i])
					}
				}
			},
		},
		{
			name:        "multi-polygon",
			coords:      `[[[[-5,-5],[5,-5],[5,5],[-5,5],[-5,-5]]],[[[10,10],[20,10],[20,20],[10,20],[10,10]]]]`,
			expectError: false,
			validate: func(t *testing.T, bbox BBox) {
				// Should use only the first polygon
				expected := BBox{-5, -5, 5, 5}
				for i := range expected {
					if bbox[i] != expected[i] {
						t.Errorf("BBox[%d] = %v, want %v", i, bbox[i], expected[i])
					}
				}
			},
		},
		{
			name:        "invalid json",
			coords:      `invalid`,
			expectError: true,
		},
		{
			name:        "empty polygon",
			coords:      `[[]]`,
			expectError: true,
		},
		{
			name:        "empty multi-polygon",
			coords:      `[[[]]]`,
			expectError: false, // Function doesn't error on this edge case; returns degenerate bbox
			validate: func(t *testing.T, bbox BBox) {
				// With no valid points, returns initial min/max values
				if len(bbox) != 4 {
					t.Errorf("Expected bbox length 4, got %d", len(bbox))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			bbox, err := bboxFromPolygonCoords(json.RawMessage(tt.coords))
			if tt.expectError {
				if err == nil {
					t.Error("bboxFromPolygonCoords() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("bboxFromPolygonCoords() unexpected error: %v", err)
			}
			if tt.validate != nil {
				tt.validate(t, bbox)
			}
		})
	}
}

// BenchmarkPointInRing benchmarks the ray casting algorithm.
func BenchmarkPointInRing(b *testing.B) {
	ring := Ring{
		{X: -10, Y: -10},
		{X: 10, Y: -10},
		{X: 10, Y: 10},
		{X: -10, Y: 10},
		{X: -10, Y: -10},
	}
	point := Point{X: 0, Y: 0}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pointInRing(point, ring)
	}
}

// BenchmarkBBoxIntersects benchmarks bounding box intersection.
func BenchmarkBBoxIntersects(b *testing.B) {
	a := BBox{-10, -10, 10, 10}
	bb := BBox{0, 0, 20, 20}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		BBoxIntersects(a, bb)
	}
}

// BenchmarkPolygonContains benchmarks polygon containment with holes.
func BenchmarkPolygonContains(b *testing.B) {
	poly := &Polygon{
		Exterior: Ring{
			{X: -10, Y: -10},
			{X: 10, Y: -10},
			{X: 10, Y: 10},
			{X: -10, Y: 10},
			{X: -10, Y: -10},
		},
		Holes: []Ring{
			{
				{X: -5, Y: -5},
				{X: 5, Y: -5},
				{X: 5, Y: 5},
				{X: -5, Y: 5},
				{X: -5, Y: -5},
			},
		},
	}
	point := Point{X: 7, Y: 7}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		poly.Contains(point)
	}
}

// TestParseGeoJSON tests parsing GeoJSON from interface{}.
func TestParseGeoJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		data        interface{}
		expectError bool
		validate    func(*testing.T, *Geometry)
	}{
		{
			name: "point from map",
			data: map[string]interface{}{
				"type":        "Point",
				"coordinates": []interface{}{10.5, 20.3},
			},
			expectError: false,
			validate: func(t *testing.T, g *Geometry) {
				if g.Type != GeomTypePoint {
					t.Errorf("Type = %v, want Point", g.Type)
				}
			},
		},
		{
			name: "polygon from map",
			data: map[string]interface{}{
				"type": "Polygon",
				"coordinates": [][][]float64{
					{{-10, -10}, {10, -10}, {10, 10}, {-10, 10}, {-10, -10}},
				},
			},
			expectError: false,
			validate: func(t *testing.T, g *Geometry) {
				if g.Type != GeomTypePolygon {
					t.Errorf("Type = %v, want Polygon", g.Type)
				}
			},
		},
		{
			name:        "nil data",
			data:        nil,
			expectError: true,
		},
		{
			name: "invalid structure",
			data: map[string]interface{}{
				"invalid": "structure",
			},
			expectError: false, // Will parse but with empty type
			validate: func(t *testing.T, g *Geometry) {
				if g.Type != "" {
					t.Errorf("Expected empty type for invalid structure, got %v", g.Type)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			geom, err := ParseGeoJSON(tt.data)
			if tt.expectError {
				if err == nil {
					t.Error("ParseGeoJSON() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseGeoJSON() unexpected error: %v", err)
			}
			if tt.validate != nil {
				tt.validate(t, geom)
			}
		})
	}
}

// TestBboxToGeometry tests conversion of bbox to geometry.
func TestBboxToGeometry(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		data        interface{}
		expectError bool
		validate    func(*testing.T, *Geometry)
	}{
		{
			name:        "float64 slice",
			data:        []float64{-10, -20, 30, 40},
			expectError: false,
			validate: func(t *testing.T, g *Geometry) {
				if g.Type != GeomTypePolygon {
					t.Errorf("Type = %v, want Polygon", g.Type)
				}
			},
		},
		{
			name:        "interface slice",
			data:        []interface{}{-10.0, -20.0, 30.0, 40.0},
			expectError: false,
			validate: func(t *testing.T, g *Geometry) {
				if g.Type != GeomTypePolygon {
					t.Errorf("Type = %v, want Polygon", g.Type)
				}
			},
		},
		{
			name:        "3D bbox",
			data:        []float64{-10, -20, 0, 30, 40, 100},
			expectError: false,
			validate: func(t *testing.T, g *Geometry) {
				if g.Type != GeomTypePolygon {
					t.Errorf("Type = %v, want Polygon", g.Type)
				}
			},
		},
		{
			name:        "invalid interface slice - non-float value",
			data:        []interface{}{-10.0, "invalid", 30.0, 40.0},
			expectError: true,
		},
		{
			name:        "wrong number of values",
			data:        []float64{-10, -20, 30},
			expectError: true,
		},
		{
			name:        "invalid bbox - minX > maxX",
			data:        []float64{10, -20, -10, 40},
			expectError: true,
		},
		{
			name: "map with bbox array",
			data: map[string]interface{}{
				"bbox": []float64{-10, -20, 30, 40},
			},
			expectError: true, // Will fail because it tries to extract bbox from the map
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			geom, err := BboxToGeometry(tt.data)
			if tt.expectError {
				if err == nil {
					t.Error("BboxToGeometry() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("BboxToGeometry() unexpected error: %v", err)
			}
			if tt.validate != nil {
				tt.validate(t, geom)
			}
		})
	}
}

// TestGeometryToGeoJSON tests conversion of Geometry to GeoJSON interface.
func TestGeometryToGeoJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		geometry *Geometry
		validate func(*testing.T, interface{})
	}{
		{
			name:     "nil geometry",
			geometry: nil,
			validate: func(t *testing.T, result interface{}) {
				if result != nil {
					t.Errorf("ToGeoJSON() for nil = %v, want nil", result)
				}
			},
		},
		{
			name: "point geometry",
			geometry: &Geometry{
				Type:        GeomTypePoint,
				Coordinates: json.RawMessage(`[10.5, 20.3]`),
			},
			validate: func(t *testing.T, result interface{}) {
				m, ok := result.(map[string]interface{})
				if !ok {
					t.Fatal("Result is not a map")
				}
				if m["type"] != GeomTypePoint {
					t.Errorf("Type = %v, want Point", m["type"])
				}
				if m["coordinates"] == nil {
					t.Error("Coordinates should not be nil")
				}
			},
		},
		{
			name: "geometry collection",
			geometry: &Geometry{
				Type: GeomTypeGeometryCollection,
				Geometries: []Geometry{
					{Type: GeomTypePoint, Coordinates: json.RawMessage(`[0,0]`)},
					{Type: GeomTypePoint, Coordinates: json.RawMessage(`[10,10]`)},
				},
			},
			validate: func(t *testing.T, result interface{}) {
				m, ok := result.(map[string]interface{})
				if !ok {
					t.Fatal("Result is not a map")
				}
				if m["type"] != GeomTypeGeometryCollection {
					t.Errorf("Type = %v, want GeometryCollection", m["type"])
				}
				geoms, ok := m["geometries"].([]interface{})
				if !ok {
					t.Fatal("Geometries is not a slice")
				}
				if len(geoms) != 2 {
					t.Errorf("Expected 2 geometries, got %d", len(geoms))
				}
			},
		},
		{
			name: "empty geometry",
			geometry: &Geometry{
				Type: GeomTypePoint,
			},
			validate: func(t *testing.T, result interface{}) {
				m, ok := result.(map[string]interface{})
				if !ok {
					t.Fatal("Result is not a map")
				}
				if m["coordinates"] != nil {
					t.Error("Empty geometry should not have coordinates in output")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := tt.geometry.ToGeoJSON()
			if tt.validate != nil {
				tt.validate(t, result)
			}
		})
	}
}

// TestGeometryContainsMethod tests the Geometry.Contains method.
func TestGeometryContainsMethod(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		a        *Geometry
		b        *Geometry
		expected bool
	}{
		{
			name: "larger polygon contains smaller polygon",
			a: &Geometry{
				Type:        GeomTypePolygon,
				Coordinates: json.RawMessage(`[[[-20,-20],[20,-20],[20,20],[-20,20],[-20,-20]]]`),
			},
			b: &Geometry{
				Type:        GeomTypePolygon,
				Coordinates: json.RawMessage(`[[[-10,-10],[10,-10],[10,10],[-10,10],[-10,-10]]]`),
			},
			expected: true,
		},
		{
			name: "smaller polygon does not contain larger polygon",
			a: &Geometry{
				Type:        GeomTypePolygon,
				Coordinates: json.RawMessage(`[[[-10,-10],[10,-10],[10,10],[-10,10],[-10,-10]]]`),
			},
			b: &Geometry{
				Type:        GeomTypePolygon,
				Coordinates: json.RawMessage(`[[[-20,-20],[20,-20],[20,20],[-20,20],[-20,-20]]]`),
			},
			expected: false,
		},
		{
			name: "polygon contains point",
			a: &Geometry{
				Type:        GeomTypePolygon,
				Coordinates: json.RawMessage(`[[[-10,-10],[10,-10],[10,10],[-10,10],[-10,-10]]]`),
			},
			b: &Geometry{
				Type:        GeomTypePoint,
				Coordinates: json.RawMessage(`[0, 0]`),
			},
			expected: true,
		},
		{
			name:     "nil geometry a",
			a:        nil,
			b:        &Geometry{Type: GeomTypePoint, Coordinates: json.RawMessage(`[0,0]`)},
			expected: false,
		},
		{
			name:     "nil geometry b",
			a:        &Geometry{Type: GeomTypePoint, Coordinates: json.RawMessage(`[0,0]`)},
			b:        nil,
			expected: false,
		},
		{
			name: "invalid geometry a",
			a: &Geometry{
				Type:        GeomTypePolygon,
				Coordinates: json.RawMessage(`invalid`),
			},
			b: &Geometry{
				Type:        GeomTypePoint,
				Coordinates: json.RawMessage(`[0,0]`),
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := tt.a.Contains(tt.b)
			if result != tt.expected {
				t.Errorf("Contains() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestGeometryIntersectsMethod tests the Geometry.Intersects method.
func TestGeometryIntersectsMethod(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		a        *Geometry
		b        *Geometry
		expected bool
	}{
		{
			name: "intersecting polygons",
			a: &Geometry{
				Type:        GeomTypePolygon,
				Coordinates: json.RawMessage(`[[[-10,-10],[10,-10],[10,10],[-10,10],[-10,-10]]]`),
			},
			b: &Geometry{
				Type:        GeomTypePolygon,
				Coordinates: json.RawMessage(`[[[0,0],[20,0],[20,20],[0,20],[0,0]]]`),
			},
			expected: true,
		},
		{
			name: "non-intersecting polygons",
			a: &Geometry{
				Type:        GeomTypePolygon,
				Coordinates: json.RawMessage(`[[[-20,-20],[-10,-20],[-10,-10],[-20,-10],[-20,-20]]]`),
			},
			b: &Geometry{
				Type:        GeomTypePolygon,
				Coordinates: json.RawMessage(`[[[10,10],[20,10],[20,20],[10,20],[10,10]]]`),
			},
			expected: false,
		},
		{
			name: "point intersects polygon",
			a: &Geometry{
				Type:        GeomTypePoint,
				Coordinates: json.RawMessage(`[0, 0]`),
			},
			b: &Geometry{
				Type:        GeomTypePolygon,
				Coordinates: json.RawMessage(`[[[-10,-10],[10,-10],[10,10],[-10,10],[-10,-10]]]`),
			},
			expected: true,
		},
		{
			name:     "nil geometry a",
			a:        nil,
			b:        &Geometry{Type: GeomTypePoint, Coordinates: json.RawMessage(`[0,0]`)},
			expected: false,
		},
		{
			name:     "nil geometry b",
			a:        &Geometry{Type: GeomTypePoint, Coordinates: json.RawMessage(`[0,0]`)},
			b:        nil,
			expected: false,
		},
		{
			name: "invalid geometry b",
			a: &Geometry{
				Type:        GeomTypePoint,
				Coordinates: json.RawMessage(`[0,0]`),
			},
			b: &Geometry{
				Type:        GeomTypePolygon,
				Coordinates: json.RawMessage(`invalid`),
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := tt.a.Intersects(tt.b)
			if result != tt.expected {
				t.Errorf("Intersects() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestParseFeatureCollection tests parsing of GeoJSON feature collections.
func TestParseFeatureCollection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		data        string
		expectError bool
		validate    func(*testing.T, *FeatureCollection)
	}{
		{
			name: "valid feature collection",
			data: `{
				"type": "FeatureCollection",
				"features": [
					{
						"type": "Feature",
						"geometry": {"type": "Point", "coordinates": [0, 0]},
						"properties": {}
					}
				]
			}`,
			expectError: false,
			validate: func(t *testing.T, fc *FeatureCollection) {
				if fc.Type != "FeatureCollection" {
					t.Errorf("Type = %v, want FeatureCollection", fc.Type)
				}
				if len(fc.Features) != 1 {
					t.Errorf("Expected 1 feature, got %d", len(fc.Features))
				}
			},
		},
		{
			name: "empty feature collection",
			data: `{
				"type": "FeatureCollection",
				"features": []
			}`,
			expectError: false,
			validate: func(t *testing.T, fc *FeatureCollection) {
				if len(fc.Features) != 0 {
					t.Errorf("Expected 0 features, got %d", len(fc.Features))
				}
			},
		},
		{
			name:        "invalid JSON",
			data:        `invalid json`,
			expectError: true,
		},
		{
			name: "feature collection with bbox",
			data: `{
				"type": "FeatureCollection",
				"bbox": [-10, -10, 10, 10],
				"features": []
			}`,
			expectError: false,
			validate: func(t *testing.T, fc *FeatureCollection) {
				if len(fc.BBox) != 4 {
					t.Errorf("Expected bbox length 4, got %d", len(fc.BBox))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fc, err := ParseFeatureCollection([]byte(tt.data))
			if tt.expectError {
				if err == nil {
					t.Error("ParseFeatureCollection() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseFeatureCollection() unexpected error: %v", err)
			}
			if tt.validate != nil {
				tt.validate(t, fc)
			}
		})
	}
}

// TestEdgeCases tests additional edge cases for better coverage.
func TestEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("BBoxFromGeometry with geometry collection skipping invalid geometries", func(t *testing.T) {
		t.Parallel()
		// The first geometry is valid, so it should succeed
		geom := &Geometry{
			Type: GeomTypeGeometryCollection,
			Geometries: []Geometry{
				{
					Type:        GeomTypePoint,
					Coordinates: json.RawMessage(`[10, 20]`), // Valid - will be used
				},
				{
					Type:        GeomTypePoint,
					Coordinates: json.RawMessage(`invalid`), // Invalid - will be skipped
				},
			},
		}
		bbox, err := BBoxFromGeometry(geom)
		if err != nil {
			t.Fatalf("BBoxFromGeometry() unexpected error: %v", err)
		}
		if bbox == nil {
			t.Error("BBoxFromGeometry() should return a bbox")
		}
		// Verify bbox is correct for the valid geometry
		expected := BBox{10, 20, 10, 20}
		for i := range expected {
			if bbox[i] != expected[i] {
				t.Errorf("BBox[%d] = %v, want %v", i, bbox[i], expected[i])
			}
		}
	})

	t.Run("Intersects with error from BBoxFromGeometry for a", func(t *testing.T) {
		t.Parallel()
		a := &Geometry{
			Type:        GeomTypePoint,
			Coordinates: json.RawMessage(`[10]`), // Invalid - too few coords
		}
		b := &Geometry{
			Type:        GeomTypePoint,
			Coordinates: json.RawMessage(`[10, 20]`),
		}
		_, err := Intersects(a, b)
		if err == nil {
			t.Error("Intersects() should return error for invalid geometry a")
		}
	})

	t.Run("Intersects with error from BBoxFromGeometry for b", func(t *testing.T) {
		t.Parallel()
		a := &Geometry{
			Type:        GeomTypePoint,
			Coordinates: json.RawMessage(`[10, 20]`),
		}
		b := &Geometry{
			Type:        GeomTypePoint,
			Coordinates: json.RawMessage(`[10]`), // Invalid - too few coords
		}
		_, err := Intersects(a, b)
		if err == nil {
			t.Error("Intersects() should return error for invalid geometry b")
		}
	})

	t.Run("Within with error from BBoxFromGeometry for a", func(t *testing.T) {
		t.Parallel()
		a := &Geometry{
			Type:        GeomTypePoint,
			Coordinates: json.RawMessage(`[10]`), // Invalid - too few coords
		}
		b := &Geometry{
			Type:        GeomTypePoint,
			Coordinates: json.RawMessage(`[10, 20]`),
		}
		_, err := Within(a, b)
		if err == nil {
			t.Error("Within() should return error for invalid geometry a")
		}
	})

	t.Run("ParseGeoJSON with unmarshalable data", func(t *testing.T) {
		t.Parallel()
		// Create a channel which cannot be marshaled to JSON
		data := make(chan int)
		_, err := ParseGeoJSON(data)
		if err == nil {
			t.Error("ParseGeoJSON() should fail for unmarshalable data")
		}
	})

	t.Run("BboxToGeometry with JSON-marshalable non-slice", func(t *testing.T) {
		t.Parallel()
		// A string will marshal to JSON but won't unmarshal to a bbox
		data := "not a bbox"
		_, err := BboxToGeometry(data)
		if err == nil {
			t.Error("BboxToGeometry() should fail for non-bbox JSON")
		}
	})

	t.Run("BBox.ToPolygon with 6-element (3D) bbox", func(t *testing.T) {
		t.Parallel()
		bbox := BBox{-10, -20, 0, 30, 40, 100}
		geom, err := bbox.ToPolygon()
		if err != nil {
			t.Fatalf("ToPolygon() unexpected error: %v", err)
		}
		if geom.Type != GeomTypePolygon {
			t.Errorf("Type = %v, want Polygon", geom.Type)
		}
		// Verify it uses correct indices for 3D bbox
		var coords [][][]float64
		if err := json.Unmarshal(geom.Coordinates, &coords); err != nil {
			t.Fatalf("Failed to parse coordinates: %v", err)
		}
		// Check that coordinates use the correct min/max values
		// For 3D bbox, MaxX should be at index 3, MaxY at index 4
		if coords[0][1][0] != 30 { // Second point X should be maxX (index 3)
			t.Errorf("MaxX coordinate incorrect, got %v want 30", coords[0][1][0])
		}
		if coords[0][2][1] != 40 { // Third point Y should be maxY (index 4)
			t.Errorf("MaxY coordinate incorrect, got %v want 40", coords[0][2][1])
		}
	})
}
