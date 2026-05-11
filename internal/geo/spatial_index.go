// Package geo provides spatial indexing for regions.
package geo

import (
	"sync"
)

// SpatialIndex provides efficient spatial lookups for named regions.
type SpatialIndex struct {
	regions map[string]*IndexedRegion
	mu      sync.RWMutex
}

// IndexedRegion represents a named region with its geometry.
type IndexedRegion struct {
	Name     string
	Geometry *Geometry
	BBox     BBox
}

// NewSpatialIndex creates a new spatial index.
func NewSpatialIndex() *SpatialIndex {
	return &SpatialIndex{
		regions: make(map[string]*IndexedRegion),
	}
}

// Add adds a named region to the index.
func (idx *SpatialIndex) Add(name string, geom *Geometry) error {
	bbox, err := BBoxFromGeometry(geom)
	if err != nil {
		return err
	}

	idx.mu.Lock()
	defer idx.mu.Unlock()

	idx.regions[name] = &IndexedRegion{
		Name:     name,
		Geometry: geom,
		BBox:     bbox,
	}

	return nil
}

// Remove removes a region from the index.
func (idx *SpatialIndex) Remove(name string) {
	idx.mu.Lock()
	defer idx.mu.Unlock()
	delete(idx.regions, name)
}

// Get returns a region by name.
func (idx *SpatialIndex) Get(name string) *IndexedRegion {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	return idx.regions[name]
}

// Search finds all regions whose bounding boxes intersect the query bbox.
func (idx *SpatialIndex) Search(queryBBox BBox) []*IndexedRegion {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	var results []*IndexedRegion
	for _, region := range idx.regions {
		if BBoxIntersects(region.BBox, queryBBox) {
			results = append(results, region)
		}
	}
	return results
}

// SearchByGeometry finds all regions that intersect the query geometry.
func (idx *SpatialIndex) SearchByGeometry(queryGeom *Geometry) ([]*IndexedRegion, error) {
	queryBBox, err := BBoxFromGeometry(queryGeom)
	if err != nil {
		return nil, err
	}

	// First filter by bbox
	candidates := idx.Search(queryBBox)

	// Then do precise geometry check
	var results []*IndexedRegion
	for _, region := range candidates {
		intersects, err := Intersects(region.Geometry, queryGeom)
		if err != nil {
			continue
		}
		if intersects {
			results = append(results, region)
		}
	}

	return results, nil
}

// Contains checks if a point is within any indexed region.
func (idx *SpatialIndex) Contains(x, y float64) []*IndexedRegion {
	point := BBox{x, y, x, y}
	return idx.Search(point)
}

// All returns all indexed regions.
func (idx *SpatialIndex) All() []*IndexedRegion {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	results := make([]*IndexedRegion, 0, len(idx.regions))
	for _, region := range idx.regions {
		results = append(results, region)
	}
	return results
}

// Names returns all region names.
func (idx *SpatialIndex) Names() []string {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	names := make([]string, 0, len(idx.regions))
	for name := range idx.regions {
		names = append(names, name)
	}
	return names
}

// Count returns the number of indexed regions.
func (idx *SpatialIndex) Count() int {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	return len(idx.regions)
}

// Clear removes all regions from the index.
func (idx *SpatialIndex) Clear() {
	idx.mu.Lock()
	defer idx.mu.Unlock()
	idx.regions = make(map[string]*IndexedRegion)
}

// MergeRegions merges multiple regions into a single geometry.
// For simplicity, this returns the combined bounding box.
func (idx *SpatialIndex) MergeRegions(names []string) (BBox, error) {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	var merged BBox
	for _, name := range names {
		region, ok := idx.regions[name]
		if !ok {
			continue
		}
		merged = MergeBBox(merged, region.BBox)
	}

	if len(merged) == 0 {
		return nil, nil
	}

	return merged, nil
}
