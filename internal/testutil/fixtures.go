// Package testutil provides test fixtures, mocks, and helpers.
package testutil

import (
	"encoding/json"
	"time"

	"github.com/yourorg/stac-proxy/internal/stac"
)

// ItemOption configures a sample item.
type ItemOption func(*stac.Item)

// SampleItem creates a sample STAC item for testing.
func SampleItem(id string, opts ...ItemOption) *stac.Item {
	now := time.Now().UTC()
	item := &stac.Item{
		Type:       "Feature",
		ID:         id,
		Collection: "test-collection",
		Geometry: &stac.Geometry{
			Type:        "Polygon",
			Coordinates: json.RawMessage(`[[[-180,-90],[180,-90],[180,90],[-180,90],[-180,-90]]]`),
		},
		BBox: []float64{-180, -90, 180, 90},
		Properties: stac.Properties{
			DateTime: &now,
			Title:    "Test Item " + id,
			Extra: map[string]interface{}{
				"description": "A test item for unit testing",
			},
		},
		Links: []stac.Link{
			{Rel: "self", Href: "https://example.com/items/" + id, Type: "application/geo+json"},
			{Rel: "collection", Href: "https://example.com/collections/test-collection", Type: "application/json"},
		},
		Assets: map[string]stac.Asset{
			"data": {
				Href:  "https://example.com/assets/" + id + "/data.tif",
				Type:  "image/tiff; application=geotiff",
				Title: "Data",
				Roles: []string{"data"},
			},
		},
	}

	for _, opt := range opts {
		opt(item)
	}

	return item
}

// WithCollection sets the collection for a sample item.
func WithCollection(collection string) ItemOption {
	return func(i *stac.Item) {
		i.Collection = collection
	}
}

// WithDatetime sets the datetime property.
func WithDatetime(dt time.Time) ItemOption {
	return func(i *stac.Item) {
		utc := dt.UTC()
		i.Properties.DateTime = &utc
	}
}

// WithBbox sets the bounding box.
func WithBbox(bbox []float64) ItemOption {
	return func(i *stac.Item) {
		i.BBox = bbox
	}
}

// WithGeometry sets the geometry.
func WithGeometry(geom *stac.Geometry) ItemOption {
	return func(i *stac.Item) {
		i.Geometry = geom
	}
}

// WithProperty sets a property in the Extra map.
func WithProperty(key string, value interface{}) ItemOption {
	return func(i *stac.Item) {
		if i.Properties.Extra == nil {
			i.Properties.Extra = make(map[string]interface{})
		}
		i.Properties.Extra[key] = value
	}
}

// WithAsset adds an asset.
func WithAsset(key string, asset stac.Asset) ItemOption {
	return func(i *stac.Item) {
		i.Assets[key] = asset
	}
}

// SampleCollection creates a sample STAC collection.
func SampleCollection(id string) *stac.Collection {
	return &stac.Collection{
		Type:        "Collection",
		ID:          id,
		Title:       "Test Collection " + id,
		Description: "A test collection for unit testing",
		License:     "MIT",
		Extent: stac.Extent{
			Spatial: stac.SpatialExtent{
				BBox: [][]float64{{-180, -90, 180, 90}},
			},
			Temporal: stac.TemporalExtent{
				Interval: [][]interface{}{{"2020-01-01T00:00:00Z", "2023-12-31T23:59:59Z"}},
			},
		},
		Links: []stac.Link{
			{Rel: "self", Href: "https://example.com/collections/" + id, Type: "application/json"},
			{Rel: "items", Href: "https://example.com/collections/" + id + "/items", Type: "application/geo+json"},
		},
	}
}

// SearchOption configures a sample search request.
type SearchOption func(*stac.SearchRequest)

// SampleSearchRequest creates a sample search request.
func SampleSearchRequest(opts ...SearchOption) *stac.SearchRequest {
	req := &stac.SearchRequest{
		Limit: 10,
	}

	for _, opt := range opts {
		opt(req)
	}

	return req
}

// WithCollections sets the collections filter.
func WithCollections(collections ...string) SearchOption {
	return func(r *stac.SearchRequest) {
		r.Collections = collections
	}
}

// WithSearchBbox sets the bbox filter.
func WithSearchBbox(bbox []float64) SearchOption {
	return func(r *stac.SearchRequest) {
		r.BBox = bbox
	}
}

// WithSearchDatetime sets the datetime filter.
func WithSearchDatetime(datetime string) SearchOption {
	return func(r *stac.SearchRequest) {
		r.Datetime = datetime
	}
}

// WithLimit sets the limit.
func WithLimit(limit int) SearchOption {
	return func(r *stac.SearchRequest) {
		r.Limit = limit
	}
}

// WithIDs sets the item IDs filter.
func WithIDs(ids ...string) SearchOption {
	return func(r *stac.SearchRequest) {
		r.IDs = ids
	}
}

// WithIntersects sets the intersects geometry.
func WithIntersects(geom *stac.Geometry) SearchOption {
	return func(r *stac.SearchRequest) {
		r.Intersects = geom
	}
}

// SamplePolygonCoords returns sample polygon coordinates for testing.
func SamplePolygonCoords() [][][]float64 {
	return [][][]float64{
		{{-10, -10}, {10, -10}, {10, 10}, {-10, 10}, {-10, -10}},
	}
}

// SamplePolygon returns a sample GeoJSON polygon.
func SamplePolygon() map[string]interface{} {
	return map[string]interface{}{
		"type":        "Polygon",
		"coordinates": SamplePolygonCoords(),
	}
}

// SamplePoint returns a sample GeoJSON point.
func SamplePoint(lon, lat float64) map[string]interface{} {
	return map[string]interface{}{
		"type":        "Point",
		"coordinates": []float64{lon, lat},
	}
}

// SampleBbox returns a sample bounding box.
func SampleBbox() []float64 {
	return []float64{-10, -10, 10, 10}
}

// SampleFeatureCollection creates a sample feature collection.
func SampleFeatureCollection(items ...*stac.Item) *stac.FeatureCollection {
	// Convert pointers to values
	features := make([]stac.Item, len(items))
	for i, item := range items {
		if item != nil {
			features[i] = *item
		}
	}
	fc := &stac.FeatureCollection{
		Type:     "FeatureCollection",
		Features: features,
		Links: []stac.Link{
			{Rel: "self", Href: "https://example.com/search", Type: "application/geo+json"},
		},
		Context: &stac.SearchContext{
			Returned: len(items),
			Limit:    10,
		},
	}
	return fc
}

// SampleItemJSON returns a sample item as JSON bytes.
func SampleItemJSON(id string) []byte {
	item := SampleItem(id)
	data, _ := json.Marshal(item)
	return data
}

// SampleCollectionJSON returns a sample collection as JSON bytes.
func SampleCollectionJSON(id string) []byte {
	coll := SampleCollection(id)
	data, _ := json.Marshal(coll)
	return data
}

// USPolygon returns a polygon covering the continental US.
func USPolygon() map[string]interface{} {
	return map[string]interface{}{
		"type": "Polygon",
		"coordinates": [][][]float64{
			{{-125, 24}, {-66, 24}, {-66, 50}, {-125, 50}, {-125, 24}},
		},
	}
}

// EuropePolygon returns a polygon covering Europe.
func EuropePolygon() map[string]interface{} {
	return map[string]interface{}{
		"type": "Polygon",
		"coordinates": [][][]float64{
			{{-10, 35}, {40, 35}, {40, 70}, {-10, 70}, {-10, 35}},
		},
	}
}

// GlobalPolygon returns a polygon covering the entire world.
func GlobalPolygon() map[string]interface{} {
	return map[string]interface{}{
		"type": "Polygon",
		"coordinates": [][][]float64{
			{{-180, -90}, {180, -90}, {180, 90}, {-180, 90}, {-180, -90}},
		},
	}
}

// PolygonWithHole returns a polygon with a hole.
func PolygonWithHole() map[string]interface{} {
	return map[string]interface{}{
		"type": "Polygon",
		"coordinates": [][][]float64{
			// Outer ring
			{{-10, -10}, {10, -10}, {10, 10}, {-10, 10}, {-10, -10}},
			// Inner ring (hole)
			{{-5, -5}, {-5, 5}, {5, 5}, {5, -5}, {-5, -5}},
		},
	}
}
