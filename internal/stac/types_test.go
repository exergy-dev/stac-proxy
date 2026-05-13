package stac

import (
	"encoding/json"
	"testing"
	"time"
)

// TestItemMarshalJSON tests marshaling STAC Items to JSON.
func TestItemMarshalJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		item     *Item
		validate func(*testing.T, []byte)
	}{
		{
			name: "complete item with all fields",
			item: &Item{
				Type:        "Feature",
				StacVersion: "1.0.0",
				ID:          "test-item-1",
				Geometry: &Geometry{
					Type:        "Point",
					Coordinates: json.RawMessage(`[10.5, 20.3]`),
				},
				BBox: []float64{10.5, 20.3, 10.5, 20.3},
				Properties: Properties{
					DateTime: timePtr(time.Date(2023, 1, 15, 12, 0, 0, 0, time.UTC)),
					Title:    "Test Item",
				},
				Links: []Link{
					{Href: "https://example.com/item", Rel: "self"},
				},
				Assets: map[string]Asset{
					"data": {
						Href:  "https://example.com/data.tif",
						Type:  "image/tiff",
						Roles: []string{"data"},
					},
				},
				Collection: "test-collection",
			},
			validate: func(t *testing.T, data []byte) {
				var result map[string]interface{}
				if err := json.Unmarshal(data, &result); err != nil {
					t.Fatalf("Failed to unmarshal: %v", err)
				}
				if result["type"] != "Feature" {
					t.Errorf("type = %v, want Feature", result["type"])
				}
				if result["id"] != "test-item-1" {
					t.Errorf("id = %v, want test-item-1", result["id"])
				}
				if result["collection"] != "test-collection" {
					t.Errorf("collection = %v, want test-collection", result["collection"])
				}
			},
		},
		{
			name: "minimal item without optional fields",
			item: &Item{
				Type:        "Feature",
				StacVersion: "1.0.0",
				ID:          "minimal-item",
				Geometry: &Geometry{
					Type:        "Point",
					Coordinates: json.RawMessage(`[0, 0]`),
				},
				Properties: Properties{
					DateTime: timePtr(time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)),
				},
				Links:  []Link{},
				Assets: map[string]Asset{},
			},
			validate: func(t *testing.T, data []byte) {
				var result map[string]interface{}
				if err := json.Unmarshal(data, &result); err != nil {
					t.Fatalf("Failed to unmarshal: %v", err)
				}
				if _, exists := result["bbox"]; exists {
					t.Error("bbox should be omitted when empty")
				}
				if _, exists := result["collection"]; exists {
					t.Error("collection should be omitted when empty")
				}
			},
		},
		{
			name: "item with null geometry",
			item: &Item{
				Type:        "Feature",
				StacVersion: "1.0.0",
				ID:          "null-geom-item",
				Geometry:    nil,
				Properties: Properties{
					DateTime: timePtr(time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)),
				},
				Links:  []Link{},
				Assets: map[string]Asset{},
			},
			validate: func(t *testing.T, data []byte) {
				var result map[string]interface{}
				if err := json.Unmarshal(data, &result); err != nil {
					t.Fatalf("Failed to unmarshal: %v", err)
				}
				geom, exists := result["geometry"]
				if !exists {
					t.Error("geometry field should exist even if nil")
				}
				if geom != nil {
					t.Errorf("geometry should be null, got %v", geom)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			data, err := json.Marshal(tt.item)
			if err != nil {
				t.Fatalf("Marshal failed: %v", err)
			}
			if tt.validate != nil {
				tt.validate(t, data)
			}
		})
	}
}

// TestItemUnmarshalJSON tests unmarshaling JSON to STAC Items.
func TestItemUnmarshalJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		json        string
		expectError bool
		validate    func(*testing.T, *Item)
	}{
		{
			name: "complete valid item",
			json: `{
				"type": "Feature",
				"stac_version": "1.0.0",
				"id": "test-item",
				"geometry": {
					"type": "Point",
					"coordinates": [10.5, 20.3]
				},
				"bbox": [10.5, 20.3, 10.5, 20.3],
				"properties": {
					"datetime": "2023-01-15T12:00:00Z",
					"title": "Test Item"
				},
				"links": [
					{"href": "https://example.com", "rel": "self"}
				],
				"assets": {
					"data": {
						"href": "https://example.com/data.tif",
						"type": "image/tiff"
					}
				},
				"collection": "test-collection"
			}`,
			expectError: false,
			validate: func(t *testing.T, item *Item) {
				if item.Type != "Feature" {
					t.Errorf("Type = %v, want Feature", item.Type)
				}
				if item.ID != "test-item" {
					t.Errorf("ID = %v, want test-item", item.ID)
				}
				if item.Collection != "test-collection" {
					t.Errorf("Collection = %v, want test-collection", item.Collection)
				}
				if item.Geometry == nil {
					t.Fatal("Geometry should not be nil")
				}
				if item.Geometry.Type != "Point" {
					t.Errorf("Geometry type = %v, want Point", item.Geometry.Type)
				}
				if len(item.Links) != 1 {
					t.Errorf("Links count = %d, want 1", len(item.Links))
				}
				if len(item.Assets) != 1 {
					t.Errorf("Assets count = %d, want 1", len(item.Assets))
				}
			},
		},
		{
			name: "item with null geometry",
			json: `{
				"type": "Feature",
				"stac_version": "1.0.0",
				"id": "null-geom",
				"geometry": null,
				"properties": {
					"datetime": "2023-01-15T12:00:00Z"
				},
				"links": [],
				"assets": {}
			}`,
			expectError: false,
			validate: func(t *testing.T, item *Item) {
				if item.Geometry != nil {
					t.Error("Geometry should be nil")
				}
			},
		},
		{
			name:        "invalid json",
			json:        `{invalid json}`,
			expectError: true,
		},
		{
			name: "minimal item",
			json: `{
				"type": "Feature",
				"stac_version": "1.0.0",
				"id": "minimal",
				"geometry": {"type": "Point", "coordinates": [0, 0]},
				"properties": {"datetime": "2023-01-01T00:00:00Z"},
				"links": [],
				"assets": {}
			}`,
			expectError: false,
			validate: func(t *testing.T, item *Item) {
				if item.ID != "minimal" {
					t.Errorf("ID = %v, want minimal", item.ID)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var item Item
			err := json.Unmarshal([]byte(tt.json), &item)
			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("Unmarshal failed: %v", err)
			}
			if tt.validate != nil {
				tt.validate(t, &item)
			}
		})
	}
}

// TestItemRoundTrip tests marshaling and then unmarshaling Items.
func TestItemRoundTrip(t *testing.T) {
	t.Parallel()

	original := &Item{
		Type:        "Feature",
		StacVersion: "1.0.0",
		ID:          "round-trip-test",
		Geometry: &Geometry{
			Type:        "Polygon",
			Coordinates: json.RawMessage(`[[[-10,-10],[10,-10],[10,10],[-10,10],[-10,-10]]]`),
		},
		BBox: []float64{-10, -10, 10, 10},
		Properties: Properties{
			DateTime:      timePtr(time.Date(2023, 6, 15, 14, 30, 0, 0, time.UTC)),
			Created:       timePtr(time.Date(2023, 6, 1, 0, 0, 0, 0, time.UTC)),
			Updated:       timePtr(time.Date(2023, 6, 10, 0, 0, 0, 0, time.UTC)),
			StartDateTime: timePtr(time.Date(2023, 6, 15, 14, 0, 0, 0, time.UTC)),
			EndDateTime:   timePtr(time.Date(2023, 6, 15, 15, 0, 0, 0, time.UTC)),
			Title:         "Round Trip Test",
		},
		Links: []Link{
			{Href: "https://example.com/self", Rel: "self", Type: "application/json"},
			{Href: "https://example.com/parent", Rel: "parent"},
		},
		Assets: map[string]Asset{
			"thumbnail": {
				Href:  "https://example.com/thumb.jpg",
				Type:  "image/jpeg",
				Roles: []string{"thumbnail"},
				Title: "Thumbnail",
			},
			"data": {
				Href:        "https://example.com/data.tif",
				Type:        "image/tiff",
				Description: "Main data file",
			},
		},
		Collection: "test-collection",
	}

	// Marshal
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	// Unmarshal
	var decoded Item
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	// Verify fields match
	if decoded.Type != original.Type {
		t.Errorf("Type mismatch: got %v, want %v", decoded.Type, original.Type)
	}
	if decoded.ID != original.ID {
		t.Errorf("ID mismatch: got %v, want %v", decoded.ID, original.ID)
	}
	if decoded.Collection != original.Collection {
		t.Errorf("Collection mismatch: got %v, want %v", decoded.Collection, original.Collection)
	}
	if len(decoded.Links) != len(original.Links) {
		t.Errorf("Links count mismatch: got %d, want %d", len(decoded.Links), len(original.Links))
	}
	if len(decoded.Assets) != len(original.Assets) {
		t.Errorf("Assets count mismatch: got %d, want %d", len(decoded.Assets), len(original.Assets))
	}
	if decoded.Properties.Title != original.Properties.Title {
		t.Errorf("Properties.Title mismatch: got %v, want %v", decoded.Properties.Title, original.Properties.Title)
	}
}

// TestCollectionMarshalJSON tests marshaling STAC Collections to JSON.
func TestCollectionMarshalJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		collection *Collection
		validate   func(*testing.T, []byte)
	}{
		{
			name: "complete collection with all fields",
			collection: &Collection{
				Type:        "Collection",
				StacVersion: "1.0.0",
				ID:          "test-collection",
				Title:       "Test Collection",
				Description: "A test collection",
				Keywords:    []string{"test", "data"},
				License:     "MIT",
				Providers: []Provider{
					{
						Name:        "Test Provider",
						Description: "A test provider",
						Roles:       []string{"producer"},
						URL:         "https://example.com",
					},
				},
				Extent: Extent{
					Spatial: SpatialExtent{
						BBox: [][]float64{{-180, -90, 180, 90}},
					},
					Temporal: TemporalExtent{
						Interval: [][]interface{}{
							{"2020-01-01T00:00:00Z", "2023-12-31T23:59:59Z"},
						},
					},
				},
				Summaries: map[string]interface{}{
					"eo:bands": []string{"red", "green", "blue"},
				},
				Links: []Link{
					{Href: "https://example.com/collection", Rel: "self"},
				},
				Assets: map[string]Asset{
					"metadata": {
						Href: "https://example.com/metadata.xml",
						Type: "application/xml",
					},
				},
			},
			validate: func(t *testing.T, data []byte) {
				var result map[string]interface{}
				if err := json.Unmarshal(data, &result); err != nil {
					t.Fatalf("Failed to unmarshal: %v", err)
				}
				if result["type"] != "Collection" {
					t.Errorf("type = %v, want Collection", result["type"])
				}
				if result["id"] != "test-collection" {
					t.Errorf("id = %v, want test-collection", result["id"])
				}
				if result["license"] != "MIT" {
					t.Errorf("license = %v, want MIT", result["license"])
				}
			},
		},
		{
			name: "minimal collection",
			collection: &Collection{
				Type:        "Collection",
				StacVersion: "1.0.0",
				ID:          "minimal",
				Description: "Minimal collection",
				License:     "proprietary",
				Extent: Extent{
					Spatial: SpatialExtent{
						BBox: [][]float64{{0, 0, 1, 1}},
					},
					Temporal: TemporalExtent{
						Interval: [][]interface{}{{nil, nil}},
					},
				},
				Links: []Link{},
			},
			validate: func(t *testing.T, data []byte) {
				var result map[string]interface{}
				if err := json.Unmarshal(data, &result); err != nil {
					t.Fatalf("Failed to unmarshal: %v", err)
				}
				if _, exists := result["title"]; exists {
					t.Error("title should be omitted when empty")
				}
				if _, exists := result["keywords"]; exists {
					t.Error("keywords should be omitted when empty")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			data, err := json.Marshal(tt.collection)
			if err != nil {
				t.Fatalf("Marshal failed: %v", err)
			}
			if tt.validate != nil {
				tt.validate(t, data)
			}
		})
	}
}

// TestCollectionUnmarshalJSON tests unmarshaling JSON to STAC Collections.
func TestCollectionUnmarshalJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		json        string
		expectError bool
		validate    func(*testing.T, *Collection)
	}{
		{
			name: "complete valid collection",
			json: `{
				"type": "Collection",
				"stac_version": "1.0.0",
				"id": "test-collection",
				"title": "Test Collection",
				"description": "A test collection",
				"keywords": ["test", "data"],
				"license": "MIT",
				"providers": [
					{
						"name": "Test Provider",
						"roles": ["producer"]
					}
				],
				"extent": {
					"spatial": {
						"bbox": [[-180, -90, 180, 90]]
					},
					"temporal": {
						"interval": [["2020-01-01T00:00:00Z", "2023-12-31T23:59:59Z"]]
					}
				},
				"links": [
					{"href": "https://example.com", "rel": "self"}
				]
			}`,
			expectError: false,
			validate: func(t *testing.T, coll *Collection) {
				if coll.Type != "Collection" {
					t.Errorf("Type = %v, want Collection", coll.Type)
				}
				if coll.ID != "test-collection" {
					t.Errorf("ID = %v, want test-collection", coll.ID)
				}
				if coll.License != "MIT" {
					t.Errorf("License = %v, want MIT", coll.License)
				}
				if len(coll.Keywords) != 2 {
					t.Errorf("Keywords count = %d, want 2", len(coll.Keywords))
				}
				if len(coll.Providers) != 1 {
					t.Errorf("Providers count = %d, want 1", len(coll.Providers))
				}
			},
		},
		{
			name:        "invalid json",
			json:        `{invalid}`,
			expectError: true,
		},
		{
			name: "collection with null temporal interval",
			json: `{
				"type": "Collection",
				"stac_version": "1.0.0",
				"id": "open-ended",
				"description": "Open-ended collection",
				"license": "MIT",
				"extent": {
					"spatial": {
						"bbox": [[0, 0, 1, 1]]
					},
					"temporal": {
						"interval": [[null, null]]
					}
				},
				"links": []
			}`,
			expectError: false,
			validate: func(t *testing.T, coll *Collection) {
				if len(coll.Extent.Temporal.Interval) != 1 {
					t.Errorf("Interval count = %d, want 1", len(coll.Extent.Temporal.Interval))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var coll Collection
			err := json.Unmarshal([]byte(tt.json), &coll)
			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("Unmarshal failed: %v", err)
			}
			if tt.validate != nil {
				tt.validate(t, &coll)
			}
		})
	}
}

// TestCollectionRoundTrip tests marshaling and unmarshaling Collections.
func TestCollectionRoundTrip(t *testing.T) {
	t.Parallel()

	original := &Collection{
		Type:        "Collection",
		StacVersion: "1.0.0",
		ID:          "round-trip-collection",
		Title:       "Round Trip Collection",
		Description: "Testing round-trip serialization",
		Keywords:    []string{"test", "round-trip"},
		License:     "Apache-2.0",
		Providers: []Provider{
			{
				Name:        "Test Org",
				Description: "Test organization",
				Roles:       []string{"producer", "licensor"},
				URL:         "https://test.org",
			},
		},
		Extent: Extent{
			Spatial: SpatialExtent{
				BBox: [][]float64{
					{-180, -90, 180, 90},
					{-10, -10, 10, 10},
				},
			},
			Temporal: TemporalExtent{
				Interval: [][]interface{}{
					{"2020-01-01T00:00:00Z", "2023-12-31T23:59:59Z"},
				},
			},
		},
		Summaries: map[string]interface{}{
			"constellation": []string{"sentinel-2"},
			"platform":      []string{"sentinel-2a", "sentinel-2b"},
		},
		Links: []Link{
			{Href: "https://example.com/collection", Rel: "self", Type: "application/json"},
		},
		Assets: map[string]Asset{
			"thumbnail": {
				Href:  "https://example.com/thumb.png",
				Type:  "image/png",
				Title: "Collection thumbnail",
			},
		},
	}

	// Marshal
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	// Unmarshal
	var decoded Collection
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	// Verify fields
	if decoded.ID != original.ID {
		t.Errorf("ID mismatch: got %v, want %v", decoded.ID, original.ID)
	}
	if decoded.Title != original.Title {
		t.Errorf("Title mismatch: got %v, want %v", decoded.Title, original.Title)
	}
	if decoded.License != original.License {
		t.Errorf("License mismatch: got %v, want %v", decoded.License, original.License)
	}
	if len(decoded.Keywords) != len(original.Keywords) {
		t.Errorf("Keywords count mismatch: got %d, want %d", len(decoded.Keywords), len(original.Keywords))
	}
	if len(decoded.Providers) != len(original.Providers) {
		t.Errorf("Providers count mismatch: got %d, want %d", len(decoded.Providers), len(original.Providers))
	}
}

// TestSearchRequestMarshalJSON tests marshaling SearchRequests to JSON.
func TestSearchRequestMarshalJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		request  *SearchRequest
		validate func(*testing.T, []byte)
	}{
		{
			name: "complete search request",
			request: &SearchRequest{
				Collections: []string{"collection1", "collection2"},
				IDs:         []string{"item1", "item2"},
				BBox:        []float64{-10, -10, 10, 10},
				Intersects: &Geometry{
					Type:        "Point",
					Coordinates: json.RawMessage(`[0, 0]`),
				},
				Datetime: "2023-01-01T00:00:00Z/2023-12-31T23:59:59Z",
				Limit:    100,
				Cursor:   "next-page-token",
				Sortby: []SortSpec{
					{Field: "properties.datetime", Direction: "desc"},
				},
				Filter:     map[string]interface{}{"eo:cloud_cover": map[string]interface{}{"lt": 10}},
				FilterLang: "cql2-json",
			},
			validate: func(t *testing.T, data []byte) {
				var result map[string]interface{}
				if err := json.Unmarshal(data, &result); err != nil {
					t.Fatalf("Failed to unmarshal: %v", err)
				}
				if result["limit"] != float64(100) {
					t.Errorf("limit = %v, want 100", result["limit"])
				}
				collections, ok := result["collections"].([]interface{})
				if !ok || len(collections) != 2 {
					t.Errorf("collections count = %v, want 2", len(collections))
				}
			},
		},
		{
			name: "minimal search request",
			request: &SearchRequest{
				Limit: 10,
			},
			validate: func(t *testing.T, data []byte) {
				var result map[string]interface{}
				if err := json.Unmarshal(data, &result); err != nil {
					t.Fatalf("Failed to unmarshal: %v", err)
				}
				if _, exists := result["collections"]; exists {
					t.Error("collections should be omitted when empty")
				}
				if _, exists := result["bbox"]; exists {
					t.Error("bbox should be omitted when empty")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			data, err := json.Marshal(tt.request)
			if err != nil {
				t.Fatalf("Marshal failed: %v", err)
			}
			if tt.validate != nil {
				tt.validate(t, data)
			}
		})
	}
}

// TestSearchRequestUnmarshalJSON tests unmarshaling JSON to SearchRequests.
func TestSearchRequestUnmarshalJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		json        string
		expectError bool
		validate    func(*testing.T, *SearchRequest)
	}{
		{
			name: "complete search request",
			json: `{
				"collections": ["collection1", "collection2"],
				"ids": ["item1", "item2"],
				"bbox": [-10, -10, 10, 10],
				"intersects": {
					"type": "Point",
					"coordinates": [0, 0]
				},
				"datetime": "2023-01-01T00:00:00Z/2023-12-31T23:59:59Z",
				"limit": 50,
				"cursor": "abc123",
				"sortby": [
					{"field": "properties.datetime", "direction": "desc"}
				],
				"filter-lang": "cql2-json"
			}`,
			expectError: false,
			validate: func(t *testing.T, req *SearchRequest) {
				if len(req.Collections) != 2 {
					t.Errorf("Collections count = %d, want 2", len(req.Collections))
				}
				if len(req.IDs) != 2 {
					t.Errorf("IDs count = %d, want 2", len(req.IDs))
				}
				if req.Limit != 50 {
					t.Errorf("Limit = %d, want 50", req.Limit)
				}
				if req.Cursor != "abc123" {
					t.Errorf("Cursor = %v, want abc123", req.Cursor)
				}
				if len(req.Sortby) != 1 {
					t.Errorf("Sortby count = %d, want 1", len(req.Sortby))
				}
			},
		},
		{
			name:        "invalid json",
			json:        `{invalid}`,
			expectError: true,
		},
		{
			name: "empty search request",
			json: `{}`,
			validate: func(t *testing.T, req *SearchRequest) {
				if req.Limit != 0 {
					t.Errorf("Limit = %d, want 0", req.Limit)
				}
				if len(req.Collections) != 0 {
					t.Errorf("Collections should be empty")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var req SearchRequest
			err := json.Unmarshal([]byte(tt.json), &req)
			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("Unmarshal failed: %v", err)
			}
			if tt.validate != nil {
				tt.validate(t, &req)
			}
		})
	}
}

// TestSearchRequestRoundTrip tests marshaling and unmarshaling SearchRequests.
func TestSearchRequestRoundTrip(t *testing.T) {
	t.Parallel()

	original := &SearchRequest{
		Collections: []string{"sentinel-2", "landsat-8"},
		IDs:         []string{"S2A_MSIL2A_001", "S2A_MSIL2A_002"},
		BBox:        []float64{-122.5, 37.5, -122.0, 38.0},
		Intersects: &Geometry{
			Type:        "Polygon",
			Coordinates: json.RawMessage(`[[[-122.5,37.5],[-122.0,37.5],[-122.0,38.0],[-122.5,38.0],[-122.5,37.5]]]`),
		},
		Datetime:   "2023-06-01T00:00:00Z/2023-06-30T23:59:59Z",
		Limit:      25,
		Cursor:     "eyJwYWdlIjoyfQ==",
		Token:      "legacy-token",
		Sortby:     []SortSpec{{Field: "properties.datetime", Direction: "desc"}},
		Filter:     map[string]interface{}{"platform": "sentinel-2a"},
		FilterLang: "cql2-json",
		FilterCRS:  "http://www.opengis.net/def/crs/OGC/1.3/CRS84",
		Query:      map[string]interface{}{"eo:cloud_cover": map[string]interface{}{"lt": 20}},
	}

	// Marshal
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	// Unmarshal
	var decoded SearchRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	// Verify fields
	if len(decoded.Collections) != len(original.Collections) {
		t.Errorf("Collections count mismatch: got %d, want %d", len(decoded.Collections), len(original.Collections))
	}
	if decoded.Limit != original.Limit {
		t.Errorf("Limit mismatch: got %d, want %d", decoded.Limit, original.Limit)
	}
	if decoded.Cursor != original.Cursor {
		t.Errorf("Cursor mismatch: got %v, want %v", decoded.Cursor, original.Cursor)
	}
	if len(decoded.Sortby) != len(original.Sortby) {
		t.Errorf("Sortby count mismatch: got %d, want %d", len(decoded.Sortby), len(original.Sortby))
	}
}

// TestFeatureCollectionMarshalJSON tests marshaling FeatureCollections to JSON.
func TestFeatureCollectionMarshalJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		fc       *FeatureCollection
		validate func(*testing.T, []byte)
	}{
		{
			name: "complete feature collection",
			fc: &FeatureCollection{
				Type: "FeatureCollection",
				Features: []Item{
					{
						Type:        "Feature",
						StacVersion: "1.0.0",
						ID:          "item1",
						Geometry: &Geometry{
							Type:        "Point",
							Coordinates: json.RawMessage(`[0, 0]`),
						},
						Properties: Properties{
							DateTime: timePtr(time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)),
						},
						Links:  []Link{},
						Assets: map[string]Asset{},
					},
				},
				Links: []Link{
					{Href: "https://example.com/next", Rel: "next"},
				},
				Context: &SearchContext{
					Returned: 1,
					Limit:    10,
					Matched:  100,
				},
				NumberMatched:  intPtr(100),
				NumberReturned: 1,
			},
			validate: func(t *testing.T, data []byte) {
				var result map[string]interface{}
				if err := json.Unmarshal(data, &result); err != nil {
					t.Fatalf("Failed to unmarshal: %v", err)
				}
				if result["type"] != "FeatureCollection" {
					t.Errorf("type = %v, want FeatureCollection", result["type"])
				}
				features, ok := result["features"].([]interface{})
				if !ok || len(features) != 1 {
					t.Errorf("features count = %v, want 1", len(features))
				}
			},
		},
		{
			name: "empty feature collection",
			fc: &FeatureCollection{
				Type:     "FeatureCollection",
				Features: []Item{},
			},
			validate: func(t *testing.T, data []byte) {
				var result map[string]interface{}
				if err := json.Unmarshal(data, &result); err != nil {
					t.Fatalf("Failed to unmarshal: %v", err)
				}
				features, ok := result["features"].([]interface{})
				if !ok || len(features) != 0 {
					t.Error("features should be empty array")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			data, err := json.Marshal(tt.fc)
			if err != nil {
				t.Fatalf("Marshal failed: %v", err)
			}
			if tt.validate != nil {
				tt.validate(t, data)
			}
		})
	}
}

// TestFeatureCollectionUnmarshalJSON tests unmarshaling JSON to FeatureCollections.
func TestFeatureCollectionUnmarshalJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		json        string
		expectError bool
		validate    func(*testing.T, *FeatureCollection)
	}{
		{
			name: "complete feature collection",
			json: `{
				"type": "FeatureCollection",
				"features": [
					{
						"type": "Feature",
						"stac_version": "1.0.0",
						"id": "item1",
						"geometry": {"type": "Point", "coordinates": [0, 0]},
						"properties": {"datetime": "2023-01-01T00:00:00Z"},
						"links": [],
						"assets": {}
					}
				],
				"links": [
					{"href": "https://example.com/next", "rel": "next"}
				],
				"context": {
					"returned": 1,
					"limit": 10,
					"matched": 100
				},
				"numberMatched": 100,
				"numberReturned": 1
			}`,
			expectError: false,
			validate: func(t *testing.T, fc *FeatureCollection) {
				if fc.Type != "FeatureCollection" {
					t.Errorf("Type = %v, want FeatureCollection", fc.Type)
				}
				if len(fc.Features) != 1 {
					t.Errorf("Features count = %d, want 1", len(fc.Features))
				}
				if fc.Context == nil {
					t.Fatal("Context should not be nil")
				}
				if fc.Context.Returned != 1 {
					t.Errorf("Context.Returned = %d, want 1", fc.Context.Returned)
				}
				if fc.NumberReturned != 1 {
					t.Errorf("NumberReturned = %d, want 1", fc.NumberReturned)
				}
			},
		},
		{
			name:        "invalid json",
			json:        `{invalid}`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var fc FeatureCollection
			err := json.Unmarshal([]byte(tt.json), &fc)
			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("Unmarshal failed: %v", err)
			}
			if tt.validate != nil {
				tt.validate(t, &fc)
			}
		})
	}
}

// TestCatalogMarshalJSON tests marshaling Catalogs to JSON.
func TestCatalogMarshalJSON(t *testing.T) {
	t.Parallel()

	catalog := &Catalog{
		Type:        "Catalog",
		StacVersion: "1.0.0",
		ID:          "test-catalog",
		Title:       "Test Catalog",
		Description: "A test catalog",
		Links: []Link{
			{Href: "https://example.com/catalog", Rel: "self"},
		},
		ConformsTo: []string{
			"https://api.stacspec.org/v1.0.0/core",
		},
	}

	data, err := json.Marshal(catalog)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if result["type"] != "Catalog" {
		t.Errorf("type = %v, want Catalog", result["type"])
	}
	if result["id"] != "test-catalog" {
		t.Errorf("id = %v, want test-catalog", result["id"])
	}
}

// TestCatalogUnmarshalJSON tests unmarshaling JSON to Catalogs.
func TestCatalogUnmarshalJSON(t *testing.T) {
	t.Parallel()

	jsonData := `{
		"type": "Catalog",
		"stac_version": "1.0.0",
		"id": "test-catalog",
		"title": "Test Catalog",
		"description": "A test catalog",
		"links": [
			{"href": "https://example.com/catalog", "rel": "self"}
		],
		"conformsTo": [
			"https://api.stacspec.org/v1.0.0/core"
		]
	}`

	var catalog Catalog
	if err := json.Unmarshal([]byte(jsonData), &catalog); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if catalog.Type != "Catalog" {
		t.Errorf("Type = %v, want Catalog", catalog.Type)
	}
	if catalog.ID != "test-catalog" {
		t.Errorf("ID = %v, want test-catalog", catalog.ID)
	}
	if len(catalog.ConformsTo) != 1 {
		t.Errorf("ConformsTo count = %d, want 1", len(catalog.ConformsTo))
	}
}

// TestLinkMarshalJSON tests marshaling Links to JSON.
func TestLinkMarshalJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		link     *Link
		validate func(*testing.T, []byte)
	}{
		{
			name: "complete link with all fields",
			link: &Link{
				Href:   "https://example.com/resource",
				Rel:    "related",
				Type:   "application/json",
				Title:  "Related Resource",
				Method: "POST",
				Body: map[string]interface{}{
					"filter": "value",
				},
			},
			validate: func(t *testing.T, data []byte) {
				var result map[string]interface{}
				if err := json.Unmarshal(data, &result); err != nil {
					t.Fatalf("Failed to unmarshal: %v", err)
				}
				if result["href"] != "https://example.com/resource" {
					t.Errorf("href = %v", result["href"])
				}
				if result["rel"] != "related" {
					t.Errorf("rel = %v", result["rel"])
				}
				if result["method"] != "POST" {
					t.Errorf("method = %v", result["method"])
				}
			},
		},
		{
			name: "minimal link",
			link: &Link{
				Href: "https://example.com",
				Rel:  "self",
			},
			validate: func(t *testing.T, data []byte) {
				var result map[string]interface{}
				if err := json.Unmarshal(data, &result); err != nil {
					t.Fatalf("Failed to unmarshal: %v", err)
				}
				if _, exists := result["type"]; exists {
					t.Error("type should be omitted when empty")
				}
				if _, exists := result["method"]; exists {
					t.Error("method should be omitted when empty")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			data, err := json.Marshal(tt.link)
			if err != nil {
				t.Fatalf("Marshal failed: %v", err)
			}
			if tt.validate != nil {
				tt.validate(t, data)
			}
		})
	}
}

// TestLinkUnmarshalJSON tests unmarshaling JSON to Links.
func TestLinkUnmarshalJSON(t *testing.T) {
	t.Parallel()

	jsonData := `{
		"href": "https://example.com/search",
		"rel": "search",
		"type": "application/json",
		"title": "Search Endpoint",
		"method": "POST",
		"body": {"limit": 10}
	}`

	var link Link
	if err := json.Unmarshal([]byte(jsonData), &link); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if link.Href != "https://example.com/search" {
		t.Errorf("Href = %v", link.Href)
	}
	if link.Method != "POST" {
		t.Errorf("Method = %v", link.Method)
	}
	if link.Body == nil {
		t.Error("Body should not be nil")
	}
}

// TestAssetMarshalJSON tests marshaling Assets to JSON.
func TestAssetMarshalJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		asset    *Asset
		validate func(*testing.T, []byte)
	}{
		{
			name: "complete asset",
			asset: &Asset{
				Href:        "https://example.com/data.tif",
				Title:       "Data File",
				Description: "Main data file",
				Type:        "image/tiff; application=geotiff",
				Roles:       []string{"data", "visual"},
			},
			validate: func(t *testing.T, data []byte) {
				var result map[string]interface{}
				if err := json.Unmarshal(data, &result); err != nil {
					t.Fatalf("Failed to unmarshal: %v", err)
				}
				if result["href"] != "https://example.com/data.tif" {
					t.Errorf("href = %v", result["href"])
				}
				roles, ok := result["roles"].([]interface{})
				if !ok || len(roles) != 2 {
					t.Errorf("roles count = %v, want 2", len(roles))
				}
			},
		},
		{
			name: "minimal asset",
			asset: &Asset{
				Href: "https://example.com/thumbnail.jpg",
			},
			validate: func(t *testing.T, data []byte) {
				var result map[string]interface{}
				if err := json.Unmarshal(data, &result); err != nil {
					t.Fatalf("Failed to unmarshal: %v", err)
				}
				if _, exists := result["title"]; exists {
					t.Error("title should be omitted when empty")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			data, err := json.Marshal(tt.asset)
			if err != nil {
				t.Fatalf("Marshal failed: %v", err)
			}
			if tt.validate != nil {
				tt.validate(t, data)
			}
		})
	}
}

// TestAssetUnmarshalJSON tests unmarshaling JSON to Assets.
func TestAssetUnmarshalJSON(t *testing.T) {
	t.Parallel()

	jsonData := `{
		"href": "https://example.com/data.tif",
		"title": "Data File",
		"description": "Main data file",
		"type": "image/tiff",
		"roles": ["data"]
	}`

	var asset Asset
	if err := json.Unmarshal([]byte(jsonData), &asset); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if asset.Href != "https://example.com/data.tif" {
		t.Errorf("Href = %v", asset.Href)
	}
	if asset.Title != "Data File" {
		t.Errorf("Title = %v", asset.Title)
	}
	if len(asset.Roles) != 1 {
		t.Errorf("Roles count = %d, want 1", len(asset.Roles))
	}
}

// TestPropertiesMarshalJSON tests marshaling Properties to JSON.
func TestPropertiesMarshalJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		props    *Properties
		validate func(*testing.T, []byte)
	}{
		{
			name: "complete properties",
			props: &Properties{
				DateTime:      timePtr(time.Date(2023, 6, 15, 12, 0, 0, 0, time.UTC)),
				Created:       timePtr(time.Date(2023, 6, 1, 0, 0, 0, 0, time.UTC)),
				Updated:       timePtr(time.Date(2023, 6, 10, 0, 0, 0, 0, time.UTC)),
				StartDateTime: timePtr(time.Date(2023, 6, 15, 11, 0, 0, 0, time.UTC)),
				EndDateTime:   timePtr(time.Date(2023, 6, 15, 13, 0, 0, 0, time.UTC)),
				Title:         "Test Properties",
			},
			validate: func(t *testing.T, data []byte) {
				var result map[string]interface{}
				if err := json.Unmarshal(data, &result); err != nil {
					t.Fatalf("Failed to unmarshal: %v", err)
				}
				if result["datetime"] == nil {
					t.Error("datetime should not be nil")
				}
				if result["title"] != "Test Properties" {
					t.Errorf("title = %v", result["title"])
				}
			},
		},
		{
			name: "minimal properties with null datetime",
			props: &Properties{
				DateTime:      nil,
				StartDateTime: timePtr(time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)),
				EndDateTime:   timePtr(time.Date(2023, 12, 31, 23, 59, 59, 0, time.UTC)),
			},
			validate: func(t *testing.T, data []byte) {
				var result map[string]interface{}
				if err := json.Unmarshal(data, &result); err != nil {
					t.Fatalf("Failed to unmarshal: %v", err)
				}
				// datetime field should exist but be null
				if _, exists := result["datetime"]; !exists {
					t.Error("datetime field should exist")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			data, err := json.Marshal(tt.props)
			if err != nil {
				t.Fatalf("Marshal failed: %v", err)
			}
			if tt.validate != nil {
				tt.validate(t, data)
			}
		})
	}
}

// TestPropertiesUnmarshalJSON tests unmarshaling JSON to Properties.
func TestPropertiesUnmarshalJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		json        string
		expectError bool
		validate    func(*testing.T, *Properties)
	}{
		{
			name: "complete properties",
			json: `{
				"datetime": "2023-06-15T12:00:00Z",
				"created": "2023-06-01T00:00:00Z",
				"updated": "2023-06-10T00:00:00Z",
				"start_datetime": "2023-06-15T11:00:00Z",
				"end_datetime": "2023-06-15T13:00:00Z",
				"title": "Test Properties"
			}`,
			validate: func(t *testing.T, props *Properties) {
				if props.DateTime == nil {
					t.Error("DateTime should not be nil")
				}
				if props.Title != "Test Properties" {
					t.Errorf("Title = %v", props.Title)
				}
				if props.Created == nil {
					t.Error("Created should not be nil")
				}
			},
		},
		{
			name: "null datetime with range",
			json: `{
				"datetime": null,
				"start_datetime": "2023-01-01T00:00:00Z",
				"end_datetime": "2023-12-31T23:59:59Z"
			}`,
			validate: func(t *testing.T, props *Properties) {
				if props.DateTime != nil {
					t.Error("DateTime should be nil")
				}
				if props.StartDateTime == nil {
					t.Error("StartDateTime should not be nil")
				}
				if props.EndDateTime == nil {
					t.Error("EndDateTime should not be nil")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var props Properties
			err := json.Unmarshal([]byte(tt.json), &props)
			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("Unmarshal failed: %v", err)
			}
			if tt.validate != nil {
				tt.validate(t, &props)
			}
		})
	}
}

// TestExtentMarshalJSON tests marshaling Extents to JSON.
func TestExtentMarshalJSON(t *testing.T) {
	t.Parallel()

	extent := &Extent{
		Spatial: SpatialExtent{
			BBox: [][]float64{
				{-180, -90, 180, 90},
				{-10, -10, 10, 10},
			},
		},
		Temporal: TemporalExtent{
			Interval: [][]interface{}{
				{"2020-01-01T00:00:00Z", "2023-12-31T23:59:59Z"},
				{nil, nil},
			},
		},
	}

	data, err := json.Marshal(extent)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	spatial, ok := result["spatial"].(map[string]interface{})
	if !ok {
		t.Fatal("spatial should be an object")
	}
	bbox, ok := spatial["bbox"].([]interface{})
	if !ok || len(bbox) != 2 {
		t.Errorf("bbox count = %v, want 2", len(bbox))
	}
}

// TestExtentUnmarshalJSON tests unmarshaling JSON to Extents.
func TestExtentUnmarshalJSON(t *testing.T) {
	t.Parallel()

	jsonData := `{
		"spatial": {
			"bbox": [[-180, -90, 180, 90]]
		},
		"temporal": {
			"interval": [["2020-01-01T00:00:00Z", "2023-12-31T23:59:59Z"]]
		}
	}`

	var extent Extent
	if err := json.Unmarshal([]byte(jsonData), &extent); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if len(extent.Spatial.BBox) != 1 {
		t.Errorf("Spatial.BBox count = %d, want 1", len(extent.Spatial.BBox))
	}
	if len(extent.Temporal.Interval) != 1 {
		t.Errorf("Temporal.Interval count = %d, want 1", len(extent.Temporal.Interval))
	}
}

// TestSearchContextMarshalJSON tests marshaling SearchContext to JSON.
func TestSearchContextMarshalJSON(t *testing.T) {
	t.Parallel()

	ctx := &SearchContext{
		Returned: 10,
		Limit:    100,
		Matched:  1000,
		Next:     true, // This field should not be marshaled
	}

	data, err := json.Marshal(ctx)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if result["returned"] != float64(10) {
		t.Errorf("returned = %v, want 10", result["returned"])
	}
	if _, exists := result["next"]; exists {
		t.Error("next field should not be marshaled (has json:\"-\" tag)")
	}
}

// TestSearchContextUnmarshalJSON tests unmarshaling JSON to SearchContext.
func TestSearchContextUnmarshalJSON(t *testing.T) {
	t.Parallel()

	jsonData := `{
		"returned": 10,
		"limit": 100,
		"matched": 1000
	}`

	var ctx SearchContext
	if err := json.Unmarshal([]byte(jsonData), &ctx); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if ctx.Returned != 10 {
		t.Errorf("Returned = %d, want 10", ctx.Returned)
	}
	if ctx.Limit != 100 {
		t.Errorf("Limit = %d, want 100", ctx.Limit)
	}
	if ctx.Matched != 1000 {
		t.Errorf("Matched = %d, want 1000", ctx.Matched)
	}
}

// TestSortSpecMarshalJSON tests marshaling SortSpec to JSON.
func TestSortSpecMarshalJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		sortSpec *SortSpec
		validate func(*testing.T, []byte)
	}{
		{
			name: "ascending sort",
			sortSpec: &SortSpec{
				Field:     "properties.datetime",
				Direction: "asc",
			},
			validate: func(t *testing.T, data []byte) {
				var result map[string]interface{}
				if err := json.Unmarshal(data, &result); err != nil {
					t.Fatalf("Failed to unmarshal: %v", err)
				}
				if result["field"] != "properties.datetime" {
					t.Errorf("field = %v", result["field"])
				}
				if result["direction"] != "asc" {
					t.Errorf("direction = %v", result["direction"])
				}
			},
		},
		{
			name: "descending sort",
			sortSpec: &SortSpec{
				Field:     "id",
				Direction: "desc",
			},
			validate: func(t *testing.T, data []byte) {
				var result map[string]interface{}
				if err := json.Unmarshal(data, &result); err != nil {
					t.Fatalf("Failed to unmarshal: %v", err)
				}
				if result["direction"] != "desc" {
					t.Errorf("direction = %v", result["direction"])
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			data, err := json.Marshal(tt.sortSpec)
			if err != nil {
				t.Fatalf("Marshal failed: %v", err)
			}
			if tt.validate != nil {
				tt.validate(t, data)
			}
		})
	}
}

// TestSortSpecUnmarshalJSON tests unmarshaling JSON to SortSpec.
func TestSortSpecUnmarshalJSON(t *testing.T) {
	t.Parallel()

	jsonData := `{
		"field": "properties.datetime",
		"direction": "desc"
	}`

	var sortSpec SortSpec
	if err := json.Unmarshal([]byte(jsonData), &sortSpec); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if sortSpec.Field != "properties.datetime" {
		t.Errorf("Field = %v", sortSpec.Field)
	}
	if sortSpec.Direction != "desc" {
		t.Errorf("Direction = %v", sortSpec.Direction)
	}
}

// TestGeometryMarshalJSON tests marshaling Geometry to JSON.
func TestGeometryMarshalJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		geometry *Geometry
		validate func(*testing.T, []byte)
	}{
		{
			name: "point geometry",
			geometry: &Geometry{
				Type:        "Point",
				Coordinates: json.RawMessage(`[10.5, 20.3]`),
			},
			validate: func(t *testing.T, data []byte) {
				var result map[string]interface{}
				if err := json.Unmarshal(data, &result); err != nil {
					t.Fatalf("Failed to unmarshal: %v", err)
				}
				if result["type"] != "Point" {
					t.Errorf("type = %v", result["type"])
				}
			},
		},
		{
			name: "polygon geometry",
			geometry: &Geometry{
				Type:        "Polygon",
				Coordinates: json.RawMessage(`[[[-10,-10],[10,-10],[10,10],[-10,10],[-10,-10]]]`),
			},
			validate: func(t *testing.T, data []byte) {
				var result map[string]interface{}
				if err := json.Unmarshal(data, &result); err != nil {
					t.Fatalf("Failed to unmarshal: %v", err)
				}
				if result["type"] != "Polygon" {
					t.Errorf("type = %v", result["type"])
				}
			},
		},
		{
			name: "geometry collection",
			geometry: &Geometry{
				Type: "GeometryCollection",
				Geometries: []Geometry{
					{Type: "Point", Coordinates: json.RawMessage(`[0, 0]`)},
					{Type: "Point", Coordinates: json.RawMessage(`[10, 10]`)},
				},
			},
			validate: func(t *testing.T, data []byte) {
				var result map[string]interface{}
				if err := json.Unmarshal(data, &result); err != nil {
					t.Fatalf("Failed to unmarshal: %v", err)
				}
				geoms, ok := result["geometries"].([]interface{})
				if !ok || len(geoms) != 2 {
					t.Errorf("geometries count = %v, want 2", len(geoms))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			data, err := json.Marshal(tt.geometry)
			if err != nil {
				t.Fatalf("Marshal failed: %v", err)
			}
			if tt.validate != nil {
				tt.validate(t, data)
			}
		})
	}
}

// TestGeometryUnmarshalJSON tests unmarshaling JSON to Geometry.
func TestGeometryUnmarshalJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		json        string
		expectError bool
		validate    func(*testing.T, *Geometry)
	}{
		{
			name: "point geometry",
			json: `{
				"type": "Point",
				"coordinates": [10.5, 20.3]
			}`,
			validate: func(t *testing.T, geom *Geometry) {
				if geom.Type != "Point" {
					t.Errorf("Type = %v, want Point", geom.Type)
				}
				if len(geom.Coordinates) == 0 {
					t.Error("Coordinates should not be empty")
				}
			},
		},
		{
			name: "geometry collection",
			json: `{
				"type": "GeometryCollection",
				"geometries": [
					{"type": "Point", "coordinates": [0, 0]},
					{"type": "Point", "coordinates": [10, 10]}
				]
			}`,
			validate: func(t *testing.T, geom *Geometry) {
				if geom.Type != "GeometryCollection" {
					t.Errorf("Type = %v, want GeometryCollection", geom.Type)
				}
				if len(geom.Geometries) != 2 {
					t.Errorf("Geometries count = %d, want 2", len(geom.Geometries))
				}
			},
		},
		{
			name:        "invalid json",
			json:        `{invalid}`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var geom Geometry
			err := json.Unmarshal([]byte(tt.json), &geom)
			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("Unmarshal failed: %v", err)
			}
			if tt.validate != nil {
				tt.validate(t, &geom)
			}
		})
	}
}

// TestProviderMarshalJSON tests marshaling Provider to JSON.
func TestProviderMarshalJSON(t *testing.T) {
	t.Parallel()

	provider := &Provider{
		Name:        "Test Provider",
		Description: "A test data provider",
		Roles:       []string{"producer", "licensor"},
		URL:         "https://test-provider.com",
	}

	data, err := json.Marshal(provider)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if result["name"] != "Test Provider" {
		t.Errorf("name = %v", result["name"])
	}
}

// TestProviderUnmarshalJSON tests unmarshaling JSON to Provider.
func TestProviderUnmarshalJSON(t *testing.T) {
	t.Parallel()

	jsonData := `{
		"name": "Test Provider",
		"description": "A test data provider",
		"roles": ["producer", "licensor"],
		"url": "https://test-provider.com"
	}`

	var provider Provider
	if err := json.Unmarshal([]byte(jsonData), &provider); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if provider.Name != "Test Provider" {
		t.Errorf("Name = %v", provider.Name)
	}
	if len(provider.Roles) != 2 {
		t.Errorf("Roles count = %d, want 2", len(provider.Roles))
	}
}

// TestCollectionsResponseMarshalJSON tests marshaling CollectionsResponse.
func TestCollectionsResponseMarshalJSON(t *testing.T) {
	t.Parallel()

	response := &CollectionsResponse{
		Collections: []Collection{
			{
				Type:        "Collection",
				StacVersion: "1.0.0",
				ID:          "col1",
				Description: "Collection 1",
				License:     "MIT",
				Extent: Extent{
					Spatial:  SpatialExtent{BBox: [][]float64{{0, 0, 1, 1}}},
					Temporal: TemporalExtent{Interval: [][]interface{}{{nil, nil}}},
				},
				Links: []Link{},
			},
		},
		Links: []Link{
			{Href: "https://example.com/collections", Rel: "self"},
		},
	}

	data, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	collections, ok := result["collections"].([]interface{})
	if !ok || len(collections) != 1 {
		t.Errorf("collections count = %v, want 1", len(collections))
	}
}


// Helper function to create time pointers.
func timePtr(t time.Time) *time.Time {
	return &t
}

// Helper function to create int pointers.
func intPtr(i int) *int {
	return &i
}
