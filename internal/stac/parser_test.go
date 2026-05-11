package stac

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewParser(t *testing.T) {
	t.Parallel()

	parser := NewParser()
	if parser == nil {
		t.Fatal("NewParser() returned nil")
	}
}

func TestParseItem(t *testing.T) {
	t.Parallel()

	parser := NewParser()
	now := time.Now().UTC()

	tests := []struct {
		name    string
		input   string
		wantErr bool
		errMsg  string
		validate func(*testing.T, *Item)
	}{
		{
			name: "valid item",
			input: `{
				"type": "Feature",
				"stac_version": "1.0.0",
				"id": "test-item-1",
				"geometry": {
					"type": "Point",
					"coordinates": [100.0, 0.0]
				},
				"bbox": [100.0, 0.0, 100.0, 0.0],
				"properties": {
					"datetime": "` + now.Format(time.RFC3339) + `",
					"title": "Test Item"
				},
				"links": [
					{"rel": "self", "href": "https://example.com/items/test-item-1"}
				],
				"assets": {
					"data": {
						"href": "https://example.com/data.tif",
						"type": "image/tiff"
					}
				}
			}`,
			wantErr: false,
			validate: func(t *testing.T, item *Item) {
				if item.Type != "Feature" {
					t.Errorf("Type = %q, want %q", item.Type, "Feature")
				}
				if item.ID != "test-item-1" {
					t.Errorf("ID = %q, want %q", item.ID, "test-item-1")
				}
				if item.StacVersion != "1.0.0" {
					t.Errorf("StacVersion = %q, want %q", item.StacVersion, "1.0.0")
				}
				if item.Geometry == nil {
					t.Error("Geometry is nil")
				}
				if len(item.BBox) != 4 {
					t.Errorf("BBox length = %d, want 4", len(item.BBox))
				}
				if len(item.Links) != 1 {
					t.Errorf("Links length = %d, want 1", len(item.Links))
				}
				if len(item.Assets) != 1 {
					t.Errorf("Assets length = %d, want 1", len(item.Assets))
				}
			},
		},
		{
			name: "minimal valid item",
			input: `{
				"type": "Feature",
				"id": "minimal",
				"geometry": null,
				"properties": {}
			}`,
			wantErr: false,
			validate: func(t *testing.T, item *Item) {
				if item.ID != "minimal" {
					t.Errorf("ID = %q, want %q", item.ID, "minimal")
				}
			},
		},
		{
			name:    "invalid JSON",
			input:   `{invalid json}`,
			wantErr: true,
			errMsg:  "failed to parse item",
		},
		{
			name: "wrong type - Collection instead of Feature",
			input: `{
				"type": "Collection",
				"id": "not-a-feature"
			}`,
			wantErr: true,
			errMsg:  "type must be 'Feature'",
		},
		{
			name: "missing type field",
			input: `{
				"id": "no-type",
				"geometry": null,
				"properties": {}
			}`,
			wantErr: true,
			errMsg:  "type must be 'Feature'",
		},
		{
			name:    "empty JSON",
			input:   `{}`,
			wantErr: true,
			errMsg:  "type must be 'Feature'",
		},
		{
			name:    "null JSON",
			input:   `null`,
			wantErr: true,
			errMsg:  "type must be 'Feature'",
		},
		{
			name: "item with collection",
			input: `{
				"type": "Feature",
				"id": "item-with-collection",
				"collection": "test-collection",
				"geometry": null,
				"properties": {}
			}`,
			wantErr: false,
			validate: func(t *testing.T, item *Item) {
				if item.Collection != "test-collection" {
					t.Errorf("Collection = %q, want %q", item.Collection, "test-collection")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			item, err := parser.ParseItem([]byte(tt.input))

			if tt.wantErr {
				if err == nil {
					t.Fatal("ParseItem() expected error, got nil")
				}
				if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("ParseItem() error = %q, want substring %q", err.Error(), tt.errMsg)
				}
				return
			}

			if err != nil {
				t.Fatalf("ParseItem() unexpected error: %v", err)
			}

			if item == nil {
				t.Fatal("ParseItem() returned nil item")
			}

			if tt.validate != nil {
				tt.validate(t, item)
			}
		})
	}
}

func TestParseCollection(t *testing.T) {
	t.Parallel()

	parser := NewParser()

	tests := []struct {
		name    string
		input   string
		wantErr bool
		errMsg  string
		validate func(*testing.T, *Collection)
	}{
		{
			name: "valid collection",
			input: `{
				"type": "Collection",
				"stac_version": "1.0.0",
				"id": "test-collection",
				"title": "Test Collection",
				"description": "A test collection",
				"license": "MIT",
				"extent": {
					"spatial": {
						"bbox": [[-180, -90, 180, 90]]
					},
					"temporal": {
						"interval": [["2020-01-01T00:00:00Z", "2023-12-31T23:59:59Z"]]
					}
				},
				"links": [
					{"rel": "self", "href": "https://example.com/collections/test"}
				]
			}`,
			wantErr: false,
			validate: func(t *testing.T, coll *Collection) {
				if coll.Type != "Collection" {
					t.Errorf("Type = %q, want %q", coll.Type, "Collection")
				}
				if coll.ID != "test-collection" {
					t.Errorf("ID = %q, want %q", coll.ID, "test-collection")
				}
				if coll.Description != "A test collection" {
					t.Errorf("Description = %q, want %q", coll.Description, "A test collection")
				}
				if coll.License != "MIT" {
					t.Errorf("License = %q, want %q", coll.License, "MIT")
				}
			},
		},
		{
			name: "collection with providers",
			input: `{
				"type": "Collection",
				"id": "provider-test",
				"description": "Test",
				"license": "Apache-2.0",
				"extent": {
					"spatial": {"bbox": [[0, 0, 1, 1]]},
					"temporal": {"interval": [[null, null]]}
				},
				"providers": [
					{
						"name": "Test Provider",
						"roles": ["producer", "licensor"],
						"url": "https://example.com"
					}
				]
			}`,
			wantErr: false,
			validate: func(t *testing.T, coll *Collection) {
				if len(coll.Providers) != 1 {
					t.Errorf("Providers length = %d, want 1", len(coll.Providers))
				}
				if coll.Providers[0].Name != "Test Provider" {
					t.Errorf("Provider name = %q, want %q", coll.Providers[0].Name, "Test Provider")
				}
			},
		},
		{
			name:    "invalid JSON",
			input:   `{invalid}`,
			wantErr: true,
			errMsg:  "failed to parse collection",
		},
		{
			name: "wrong type - Feature instead of Collection",
			input: `{
				"type": "Feature",
				"id": "not-a-collection"
			}`,
			wantErr: true,
			errMsg:  "type must be 'Collection'",
		},
		{
			name:    "empty JSON",
			input:   `{}`,
			wantErr: true,
			errMsg:  "type must be 'Collection'",
		},
		{
			name: "collection with summaries",
			input: `{
				"type": "Collection",
				"id": "summary-test",
				"description": "Test",
				"license": "CC-BY-4.0",
				"extent": {
					"spatial": {"bbox": [[0, 0, 1, 1]]},
					"temporal": {"interval": [[null, null]]}
				},
				"summaries": {
					"platform": ["sentinel-2a", "sentinel-2b"],
					"gsd": [10, 20, 60]
				}
			}`,
			wantErr: false,
			validate: func(t *testing.T, coll *Collection) {
				if coll.Summaries == nil {
					t.Error("Summaries is nil")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			coll, err := parser.ParseCollection([]byte(tt.input))

			if tt.wantErr {
				if err == nil {
					t.Fatal("ParseCollection() expected error, got nil")
				}
				if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("ParseCollection() error = %q, want substring %q", err.Error(), tt.errMsg)
				}
				return
			}

			if err != nil {
				t.Fatalf("ParseCollection() unexpected error: %v", err)
			}

			if coll == nil {
				t.Fatal("ParseCollection() returned nil collection")
			}

			if tt.validate != nil {
				tt.validate(t, coll)
			}
		})
	}
}

func TestParseFeatureCollection(t *testing.T) {
	t.Parallel()

	parser := NewParser()

	tests := []struct {
		name    string
		input   string
		wantErr bool
		errMsg  string
		validate func(*testing.T, *FeatureCollection)
	}{
		{
			name: "valid feature collection with items",
			input: `{
				"type": "FeatureCollection",
				"features": [
					{
						"type": "Feature",
						"id": "item-1",
						"geometry": null,
						"properties": {}
					},
					{
						"type": "Feature",
						"id": "item-2",
						"geometry": null,
						"properties": {}
					}
				],
				"links": [
					{"rel": "self", "href": "https://example.com/search"}
				],
				"context": {
					"returned": 2,
					"limit": 10,
					"matched": 100
				}
			}`,
			wantErr: false,
			validate: func(t *testing.T, fc *FeatureCollection) {
				if fc.Type != "FeatureCollection" {
					t.Errorf("Type = %q, want %q", fc.Type, "FeatureCollection")
				}
				if len(fc.Features) != 2 {
					t.Errorf("Features length = %d, want 2", len(fc.Features))
				}
				if fc.Context == nil {
					t.Error("Context is nil")
				} else if fc.Context.Returned != 2 {
					t.Errorf("Context.Returned = %d, want 2", fc.Context.Returned)
				}
			},
		},
		{
			name: "empty feature collection",
			input: `{
				"type": "FeatureCollection",
				"features": []
			}`,
			wantErr: false,
			validate: func(t *testing.T, fc *FeatureCollection) {
				if len(fc.Features) != 0 {
					t.Errorf("Features length = %d, want 0", len(fc.Features))
				}
			},
		},
		{
			name: "feature collection with numberMatched",
			input: `{
				"type": "FeatureCollection",
				"features": [],
				"numberMatched": 500,
				"numberReturned": 0
			}`,
			wantErr: false,
			validate: func(t *testing.T, fc *FeatureCollection) {
				if fc.NumberMatched == nil {
					t.Error("NumberMatched is nil")
				} else if *fc.NumberMatched != 500 {
					t.Errorf("NumberMatched = %d, want 500", *fc.NumberMatched)
				}
				if fc.NumberReturned != 0 {
					t.Errorf("NumberReturned = %d, want 0", fc.NumberReturned)
				}
			},
		},
		{
			name:    "invalid JSON",
			input:   `{not valid json`,
			wantErr: true,
			errMsg:  "failed to parse feature collection",
		},
		{
			name: "wrong type - Collection instead of FeatureCollection",
			input: `{
				"type": "Collection",
				"features": []
			}`,
			wantErr: true,
			errMsg:  "type must be 'FeatureCollection'",
		},
		{
			name:    "empty JSON",
			input:   `{}`,
			wantErr: true,
			errMsg:  "type must be 'FeatureCollection'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			fc, err := parser.ParseFeatureCollection([]byte(tt.input))

			if tt.wantErr {
				if err == nil {
					t.Fatal("ParseFeatureCollection() expected error, got nil")
				}
				if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("ParseFeatureCollection() error = %q, want substring %q", err.Error(), tt.errMsg)
				}
				return
			}

			if err != nil {
				t.Fatalf("ParseFeatureCollection() unexpected error: %v", err)
			}

			if fc == nil {
				t.Fatal("ParseFeatureCollection() returned nil")
			}

			if tt.validate != nil {
				tt.validate(t, fc)
			}
		})
	}
}

func TestParseCollections(t *testing.T) {
	t.Parallel()

	parser := NewParser()

	tests := []struct {
		name    string
		input   string
		wantErr bool
		errMsg  string
		validate func(*testing.T, *CollectionsResponse)
	}{
		{
			name: "valid collections response",
			input: `{
				"collections": [
					{
						"type": "Collection",
						"id": "coll-1",
						"description": "First collection",
						"license": "MIT",
						"extent": {
							"spatial": {"bbox": [[0, 0, 1, 1]]},
							"temporal": {"interval": [[null, null]]}
						}
					},
					{
						"type": "Collection",
						"id": "coll-2",
						"description": "Second collection",
						"license": "Apache-2.0",
						"extent": {
							"spatial": {"bbox": [[0, 0, 1, 1]]},
							"temporal": {"interval": [[null, null]]}
						}
					}
				],
				"links": [
					{"rel": "self", "href": "https://example.com/collections"}
				]
			}`,
			wantErr: false,
			validate: func(t *testing.T, resp *CollectionsResponse) {
				if len(resp.Collections) != 2 {
					t.Errorf("Collections length = %d, want 2", len(resp.Collections))
				}
				if resp.Collections[0].ID != "coll-1" {
					t.Errorf("First collection ID = %q, want %q", resp.Collections[0].ID, "coll-1")
				}
			},
		},
		{
			name: "empty collections response",
			input: `{
				"collections": []
			}`,
			wantErr: false,
			validate: func(t *testing.T, resp *CollectionsResponse) {
				if len(resp.Collections) != 0 {
					t.Errorf("Collections length = %d, want 0", len(resp.Collections))
				}
			},
		},
		{
			name:    "invalid JSON",
			input:   `{bad json`,
			wantErr: true,
			errMsg:  "failed to parse collections",
		},
		{
			name: "collections with links",
			input: `{
				"collections": [],
				"links": [
					{"rel": "self", "href": "https://example.com/collections"},
					{"rel": "next", "href": "https://example.com/collections?page=2"}
				]
			}`,
			wantErr: false,
			validate: func(t *testing.T, resp *CollectionsResponse) {
				if len(resp.Links) != 2 {
					t.Errorf("Links length = %d, want 2", len(resp.Links))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			resp, err := parser.ParseCollections([]byte(tt.input))

			if tt.wantErr {
				if err == nil {
					t.Fatal("ParseCollections() expected error, got nil")
				}
				if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("ParseCollections() error = %q, want substring %q", err.Error(), tt.errMsg)
				}
				return
			}

			if err != nil {
				t.Fatalf("ParseCollections() unexpected error: %v", err)
			}

			if resp == nil {
				t.Fatal("ParseCollections() returned nil")
			}

			if tt.validate != nil {
				tt.validate(t, resp)
			}
		})
	}
}

func TestParseCatalog(t *testing.T) {
	t.Parallel()

	parser := NewParser()

	tests := []struct {
		name    string
		input   string
		wantErr bool
		errMsg  string
		validate func(*testing.T, *Catalog)
	}{
		{
			name: "valid catalog",
			input: `{
				"type": "Catalog",
				"stac_version": "1.0.0",
				"id": "test-catalog",
				"title": "Test Catalog",
				"description": "A test STAC catalog",
				"links": [
					{"rel": "self", "href": "https://example.com/"},
					{"rel": "child", "href": "https://example.com/collections"}
				],
				"conformsTo": [
					"https://api.stacspec.org/v1.0.0/core"
				]
			}`,
			wantErr: false,
			validate: func(t *testing.T, cat *Catalog) {
				if cat.Type != "Catalog" {
					t.Errorf("Type = %q, want %q", cat.Type, "Catalog")
				}
				if cat.ID != "test-catalog" {
					t.Errorf("ID = %q, want %q", cat.ID, "test-catalog")
				}
				if cat.Title != "Test Catalog" {
					t.Errorf("Title = %q, want %q", cat.Title, "Test Catalog")
				}
				if len(cat.Links) != 2 {
					t.Errorf("Links length = %d, want 2", len(cat.Links))
				}
			},
		},
		{
			name: "minimal catalog",
			input: `{
				"type": "Catalog",
				"id": "minimal",
				"description": "Minimal catalog",
				"links": []
			}`,
			wantErr: false,
			validate: func(t *testing.T, cat *Catalog) {
				if cat.ID != "minimal" {
					t.Errorf("ID = %q, want %q", cat.ID, "minimal")
				}
			},
		},
		{
			name:    "invalid JSON",
			input:   `{invalid`,
			wantErr: true,
			errMsg:  "failed to parse catalog",
		},
		{
			name: "wrong type - Collection instead of Catalog",
			input: `{
				"type": "Collection",
				"id": "not-a-catalog"
			}`,
			wantErr: true,
			errMsg:  "type must be 'Catalog'",
		},
		{
			name:    "empty JSON",
			input:   `{}`,
			wantErr: true,
			errMsg:  "type must be 'Catalog'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cat, err := parser.ParseCatalog([]byte(tt.input))

			if tt.wantErr {
				if err == nil {
					t.Fatal("ParseCatalog() expected error, got nil")
				}
				if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("ParseCatalog() error = %q, want substring %q", err.Error(), tt.errMsg)
				}
				return
			}

			if err != nil {
				t.Fatalf("ParseCatalog() unexpected error: %v", err)
			}

			if cat == nil {
				t.Fatal("ParseCatalog() returned nil")
			}

			if tt.validate != nil {
				tt.validate(t, cat)
			}
		})
	}
}

func TestParseSearchRequest(t *testing.T) {
	t.Parallel()

	parser := NewParser()

	tests := []struct {
		name    string
		input   string
		wantErr bool
		validate func(*testing.T, *SearchRequest)
	}{
		{
			name: "basic search request",
			input: `{
				"collections": ["sentinel-2", "landsat-8"],
				"limit": 10
			}`,
			wantErr: false,
			validate: func(t *testing.T, req *SearchRequest) {
				if len(req.Collections) != 2 {
					t.Errorf("Collections length = %d, want 2", len(req.Collections))
				}
				if req.Limit != 10 {
					t.Errorf("Limit = %d, want 10", req.Limit)
				}
			},
		},
		{
			name: "search request with bbox",
			input: `{
				"bbox": [-10, -10, 10, 10],
				"limit": 50
			}`,
			wantErr: false,
			validate: func(t *testing.T, req *SearchRequest) {
				if len(req.BBox) != 4 {
					t.Errorf("BBox length = %d, want 4", len(req.BBox))
				}
				if req.BBox[0] != -10 {
					t.Errorf("BBox[0] = %f, want -10", req.BBox[0])
				}
			},
		},
		{
			name: "search request with datetime",
			input: `{
				"datetime": "2023-01-01T00:00:00Z/2023-12-31T23:59:59Z",
				"limit": 100
			}`,
			wantErr: false,
			validate: func(t *testing.T, req *SearchRequest) {
				if req.Datetime == "" {
					t.Error("Datetime is empty")
				}
			},
		},
		{
			name: "search request with ids",
			input: `{
				"ids": ["item-1", "item-2", "item-3"]
			}`,
			wantErr: false,
			validate: func(t *testing.T, req *SearchRequest) {
				if len(req.IDs) != 3 {
					t.Errorf("IDs length = %d, want 3", len(req.IDs))
				}
			},
		},
		{
			name: "search request with intersects",
			input: `{
				"intersects": {
					"type": "Point",
					"coordinates": [100.0, 0.0]
				}
			}`,
			wantErr: false,
			validate: func(t *testing.T, req *SearchRequest) {
				if req.Intersects == nil {
					t.Error("Intersects is nil")
				}
			},
		},
		{
			name: "search request with sortby",
			input: `{
				"sortby": [
					{"field": "properties.datetime", "direction": "desc"},
					{"field": "id", "direction": "asc"}
				]
			}`,
			wantErr: false,
			validate: func(t *testing.T, req *SearchRequest) {
				if len(req.Sortby) != 2 {
					t.Errorf("Sortby length = %d, want 2", len(req.Sortby))
				}
				if req.Sortby[0].Direction != "desc" {
					t.Errorf("Sortby[0].Direction = %q, want %q", req.Sortby[0].Direction, "desc")
				}
			},
		},
		{
			name: "search request with filter",
			input: `{
				"filter": "property1 > 100 AND property2 < 200",
				"filter-lang": "cql2-text"
			}`,
			wantErr: false,
			validate: func(t *testing.T, req *SearchRequest) {
				if req.FilterLang != "cql2-text" {
					t.Errorf("FilterLang = %q, want %q", req.FilterLang, "cql2-text")
				}
			},
		},
		{
			name: "search request with token",
			input: `{
				"token": "next-page-token-123"
			}`,
			wantErr: false,
			validate: func(t *testing.T, req *SearchRequest) {
				if req.Token != "next-page-token-123" {
					t.Errorf("Token = %q, want %q", req.Token, "next-page-token-123")
				}
			},
		},
		{
			name:    "invalid JSON",
			input:   `{invalid}`,
			wantErr: true,
		},
		{
			name:    "empty JSON",
			input:   `{}`,
			wantErr: false,
			validate: func(t *testing.T, req *SearchRequest) {
				// Empty request is valid
				if req == nil {
					t.Error("Request is nil")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req, err := parser.ParseSearchRequest([]byte(tt.input))

			if tt.wantErr {
				if err == nil {
					t.Fatal("ParseSearchRequest() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("ParseSearchRequest() unexpected error: %v", err)
			}

			if req == nil {
				t.Fatal("ParseSearchRequest() returned nil")
			}

			if tt.validate != nil {
				tt.validate(t, req)
			}
		})
	}
}

func TestParseSearchRequestFromHTTP(t *testing.T) {
	t.Parallel()

	parser := NewParser()

	t.Run("GET request with query parameters", func(t *testing.T) {
		t.Parallel()

		req := httptest.NewRequest(http.MethodGet, "/search?collections=sentinel-2&limit=20", nil)

		searchReq, err := parser.ParseSearchRequestFromHTTP(req)
		if err != nil {
			t.Fatalf("ParseSearchRequestFromHTTP() error = %v", err)
		}

		if len(searchReq.Collections) != 1 {
			t.Errorf("Collections length = %d, want 1", len(searchReq.Collections))
		}
		if searchReq.Collections[0] != "sentinel-2" {
			t.Errorf("Collections[0] = %q, want %q", searchReq.Collections[0], "sentinel-2")
		}
		if searchReq.Limit != 20 {
			t.Errorf("Limit = %d, want 20", searchReq.Limit)
		}
	})

	t.Run("GET request without query parameters", func(t *testing.T) {
		t.Parallel()

		req := httptest.NewRequest(http.MethodGet, "/search", nil)

		searchReq, err := parser.ParseSearchRequestFromHTTP(req)
		if err != nil {
			t.Fatalf("ParseSearchRequestFromHTTP() error = %v", err)
		}

		if searchReq == nil {
			t.Fatal("ParseSearchRequestFromHTTP() returned nil")
		}
	})

	t.Run("POST request with JSON body", func(t *testing.T) {
		t.Parallel()

		body := `{"collections": ["landsat-8"], "limit": 30}`
		req := httptest.NewRequest(http.MethodPost, "/search", bytes.NewBufferString(body))

		searchReq, err := parser.ParseSearchRequestFromHTTP(req)
		if err != nil {
			t.Fatalf("ParseSearchRequestFromHTTP() error = %v", err)
		}

		if len(searchReq.Collections) != 1 {
			t.Errorf("Collections length = %d, want 1", len(searchReq.Collections))
		}
		if searchReq.Limit != 30 {
			t.Errorf("Limit = %d, want 30", searchReq.Limit)
		}
	})

	t.Run("POST request with empty body", func(t *testing.T) {
		t.Parallel()

		req := httptest.NewRequest(http.MethodPost, "/search", bytes.NewBufferString(""))

		searchReq, err := parser.ParseSearchRequestFromHTTP(req)
		if err != nil {
			t.Fatalf("ParseSearchRequestFromHTTP() error = %v", err)
		}

		if searchReq == nil {
			t.Fatal("ParseSearchRequestFromHTTP() returned nil")
		}
	})

	t.Run("POST request with invalid JSON", func(t *testing.T) {
		t.Parallel()

		body := `{invalid json}`
		req := httptest.NewRequest(http.MethodPost, "/search", bytes.NewBufferString(body))

		_, err := parser.ParseSearchRequestFromHTTP(req)
		if err == nil {
			t.Fatal("ParseSearchRequestFromHTTP() expected error for invalid JSON, got nil")
		}
	})

	t.Run("POST request with read error", func(t *testing.T) {
		t.Parallel()

		// Use an error reader to simulate read failure
		req := httptest.NewRequest(http.MethodPost, "/search", &errorReader{})

		_, err := parser.ParseSearchRequestFromHTTP(req)
		if err == nil {
			t.Fatal("ParseSearchRequestFromHTTP() expected error for read failure, got nil")
		}
	})
}

// errorReader always returns an error when read
type errorReader struct{}

func (e *errorReader) Read(p []byte) (n int, err error) {
	return 0, io.ErrUnexpectedEOF
}

func TestParseSearchFromQuery(t *testing.T) {
	t.Parallel()

	parser := NewParser()

	tests := []struct {
		name     string
		url      string
		validate func(*testing.T, *SearchRequest)
	}{
		{
			name: "collections parameter",
			url:  "/search?collections=sentinel-2,landsat-8",
			validate: func(t *testing.T, req *SearchRequest) {
				if len(req.Collections) != 2 {
					t.Errorf("Collections length = %d, want 2", len(req.Collections))
				}
				if req.Collections[0] != "sentinel-2" {
					t.Errorf("Collections[0] = %q, want %q", req.Collections[0], "sentinel-2")
				}
			},
		},
		{
			name: "single collection",
			url:  "/search?collections=sentinel-2",
			validate: func(t *testing.T, req *SearchRequest) {
				if len(req.Collections) != 1 {
					t.Errorf("Collections length = %d, want 1", len(req.Collections))
				}
			},
		},
		{
			name: "ids parameter",
			url:  "/search?ids=item-1,item-2,item-3",
			validate: func(t *testing.T, req *SearchRequest) {
				if len(req.IDs) != 3 {
					t.Errorf("IDs length = %d, want 3", len(req.IDs))
				}
			},
		},
		{
			name: "bbox with 4 coordinates",
			url:  "/search?bbox=-10,-5,10,5",
			validate: func(t *testing.T, req *SearchRequest) {
				if len(req.BBox) != 4 {
					t.Errorf("BBox length = %d, want 4", len(req.BBox))
				}
				if req.BBox[0] != -10 {
					t.Errorf("BBox[0] = %f, want -10", req.BBox[0])
				}
			},
		},
		{
			name: "bbox with 6 coordinates (3D)",
			url:  "/search?bbox=-10,-5,0,10,5,100",
			validate: func(t *testing.T, req *SearchRequest) {
				if len(req.BBox) != 6 {
					t.Errorf("BBox length = %d, want 6", len(req.BBox))
				}
			},
		},
		{
			name: "bbox with invalid count ignored",
			url:  "/search?bbox=-10,-5,10",
			validate: func(t *testing.T, req *SearchRequest) {
				if req.BBox != nil {
					t.Errorf("BBox should be nil for invalid coordinate count, got %v", req.BBox)
				}
			},
		},
		{
			name: "datetime parameter",
			url:  "/search?datetime=2023-01-01T00:00:00Z/2023-12-31T23:59:59Z",
			validate: func(t *testing.T, req *SearchRequest) {
				expected := "2023-01-01T00:00:00Z/2023-12-31T23:59:59Z"
				if req.Datetime != expected {
					t.Errorf("Datetime = %q, want %q", req.Datetime, expected)
				}
			},
		},
		{
			name: "limit parameter",
			url:  "/search?limit=100",
			validate: func(t *testing.T, req *SearchRequest) {
				if req.Limit != 100 {
					t.Errorf("Limit = %d, want 100", req.Limit)
				}
			},
		},
		{
			name: "limit with invalid value",
			url:  "/search?limit=abc",
			validate: func(t *testing.T, req *SearchRequest) {
				if req.Limit != 0 {
					t.Errorf("Limit = %d, want 0 for invalid value", req.Limit)
				}
			},
		},
		{
			name: "token parameter",
			url:  "/search?token=abc123",
			validate: func(t *testing.T, req *SearchRequest) {
				if req.Token != "abc123" {
					t.Errorf("Token = %q, want %q", req.Token, "abc123")
				}
			},
		},
		{
			name: "intersects with valid GeoJSON",
			url:  `/search?intersects={"type":"Point","coordinates":[100.0,0.0]}`,
			validate: func(t *testing.T, req *SearchRequest) {
				if req.Intersects == nil {
					t.Error("Intersects is nil")
				} else if req.Intersects.Type != "Point" {
					t.Errorf("Intersects.Type = %q, want %q", req.Intersects.Type, "Point")
				}
			},
		},
		{
			name: "intersects with invalid JSON",
			url:  "/search?intersects={invalid}",
			validate: func(t *testing.T, req *SearchRequest) {
				if req.Intersects != nil {
					t.Error("Intersects should be nil for invalid JSON")
				}
			},
		},
		{
			name: "filter with default filter-lang",
			url:  "/search?filter=property1>100",
			validate: func(t *testing.T, req *SearchRequest) {
				if req.Filter == "" {
					t.Error("Filter is empty")
				}
				if req.FilterLang != "cql2-text" {
					t.Errorf("FilterLang = %q, want %q", req.FilterLang, "cql2-text")
				}
			},
		},
		{
			name: "filter with explicit filter-lang",
			url:  "/search?filter=property1>100&filter-lang=cql2-json",
			validate: func(t *testing.T, req *SearchRequest) {
				if req.FilterLang != "cql2-json" {
					t.Errorf("FilterLang = %q, want %q", req.FilterLang, "cql2-json")
				}
			},
		},
		{
			name: "sortby with ascending fields",
			url:  "/search?sortby=properties.datetime,id",
			validate: func(t *testing.T, req *SearchRequest) {
				if len(req.Sortby) != 2 {
					t.Errorf("Sortby length = %d, want 2", len(req.Sortby))
				}
				if req.Sortby[0].Field != "properties.datetime" {
					t.Errorf("Sortby[0].Field = %q, want %q", req.Sortby[0].Field, "properties.datetime")
				}
				if req.Sortby[0].Direction != "asc" {
					t.Errorf("Sortby[0].Direction = %q, want %q", req.Sortby[0].Direction, "asc")
				}
			},
		},
		{
			name: "sortby with descending fields (minus prefix)",
			url:  "/search?sortby=-properties.datetime,-id",
			validate: func(t *testing.T, req *SearchRequest) {
				if len(req.Sortby) != 2 {
					t.Errorf("Sortby length = %d, want 2", len(req.Sortby))
				}
				if req.Sortby[0].Direction != "desc" {
					t.Errorf("Sortby[0].Direction = %q, want %q", req.Sortby[0].Direction, "desc")
				}
				if req.Sortby[0].Field != "properties.datetime" {
					t.Errorf("Sortby[0].Field = %q, want %q (minus prefix should be removed)", req.Sortby[0].Field, "properties.datetime")
				}
			},
		},
		{
			name: "sortby with plus prefix (explicit ascending)",
			url:  "/search?sortby=%2Bproperties.datetime",
			validate: func(t *testing.T, req *SearchRequest) {
				if len(req.Sortby) != 1 {
					t.Errorf("Sortby length = %d, want 1", len(req.Sortby))
				}
				if req.Sortby[0].Direction != "asc" {
					t.Errorf("Sortby[0].Direction = %q, want %q", req.Sortby[0].Direction, "asc")
				}
				if req.Sortby[0].Field != "properties.datetime" {
					t.Errorf("Sortby[0].Field = %q, want %q (plus prefix should be removed)", req.Sortby[0].Field, "properties.datetime")
				}
			},
		},
		{
			name: "sortby with mixed directions",
			url:  "/search?sortby=-properties.datetime,%2Bid,collection",
			validate: func(t *testing.T, req *SearchRequest) {
				if len(req.Sortby) != 3 {
					t.Errorf("Sortby length = %d, want 3", len(req.Sortby))
				}
				if req.Sortby[0].Direction != "desc" {
					t.Errorf("Sortby[0].Direction = %q, want %q", req.Sortby[0].Direction, "desc")
				}
				if req.Sortby[1].Direction != "asc" {
					t.Errorf("Sortby[1].Direction = %q, want %q", req.Sortby[1].Direction, "asc")
				}
				if req.Sortby[2].Direction != "asc" {
					t.Errorf("Sortby[2].Direction = %q, want %q", req.Sortby[2].Direction, "asc")
				}
			},
		},
		{
			name: "multiple parameters combined",
			url:  "/search?collections=sentinel-2&bbox=-10,-5,10,5&limit=50&datetime=2023-01-01T00:00:00Z",
			validate: func(t *testing.T, req *SearchRequest) {
				if len(req.Collections) != 1 {
					t.Errorf("Collections length = %d, want 1", len(req.Collections))
				}
				if len(req.BBox) != 4 {
					t.Errorf("BBox length = %d, want 4", len(req.BBox))
				}
				if req.Limit != 50 {
					t.Errorf("Limit = %d, want 50", req.Limit)
				}
				if req.Datetime == "" {
					t.Error("Datetime is empty")
				}
			},
		},
		{
			name: "empty query string",
			url:  "/search",
			validate: func(t *testing.T, req *SearchRequest) {
				// Should return empty request
				if req == nil {
					t.Error("Request is nil")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodGet, tt.url, nil)

			searchReq, err := parser.parseSearchFromQuery(req)
			if err != nil {
				t.Fatalf("parseSearchFromQuery() error = %v", err)
			}

			if searchReq == nil {
				t.Fatal("parseSearchFromQuery() returned nil")
			}

			if tt.validate != nil {
				tt.validate(t, searchReq)
			}
		})
	}
}

func TestExtractNextLink(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		links    []Link
		expected *Link
	}{
		{
			name: "next link present",
			links: []Link{
				{Rel: "self", Href: "https://example.com/search"},
				{Rel: "next", Href: "https://example.com/search?token=abc123"},
			},
			expected: &Link{
				Rel:  "next",
				Href: "https://example.com/search?token=abc123",
			},
		},
		{
			name: "no next link",
			links: []Link{
				{Rel: "self", Href: "https://example.com/search"},
				{Rel: "prev", Href: "https://example.com/search?token=prev123"},
			},
			expected: nil,
		},
		{
			name:     "empty links",
			links:    []Link{},
			expected: nil,
		},
		{
			name:     "nil links",
			links:    nil,
			expected: nil,
		},
		{
			name: "multiple next links (returns first)",
			links: []Link{
				{Rel: "next", Href: "https://example.com/first"},
				{Rel: "next", Href: "https://example.com/second"},
			},
			expected: &Link{
				Rel:  "next",
				Href: "https://example.com/first",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := ExtractNextLink(tt.links)

			if tt.expected == nil {
				if result != nil {
					t.Errorf("ExtractNextLink() = %+v, want nil", result)
				}
				return
			}

			if result == nil {
				t.Fatal("ExtractNextLink() returned nil, want non-nil")
			}

			if result.Rel != tt.expected.Rel {
				t.Errorf("Rel = %q, want %q", result.Rel, tt.expected.Rel)
			}
			if result.Href != tt.expected.Href {
				t.Errorf("Href = %q, want %q", result.Href, tt.expected.Href)
			}
		})
	}
}

func TestExtractNextToken(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		links    []Link
		expected string
	}{
		{
			name: "token in URL",
			links: []Link{
				{Rel: "next", Href: "https://example.com/search?token=abc123"},
			},
			expected: "abc123",
		},
		{
			name: "token with other parameters before",
			links: []Link{
				{Rel: "next", Href: "https://example.com/search?limit=10&token=xyz789"},
			},
			expected: "xyz789",
		},
		{
			name: "token with other parameters after",
			links: []Link{
				{Rel: "next", Href: "https://example.com/search?token=abc123&limit=10"},
			},
			expected: "abc123",
		},
		{
			name: "no token parameter",
			links: []Link{
				{Rel: "next", Href: "https://example.com/search?limit=10"},
			},
			expected: "",
		},
		{
			name: "no next link",
			links: []Link{
				{Rel: "self", Href: "https://example.com/search"},
			},
			expected: "",
		},
		{
			name:     "empty links",
			links:    []Link{},
			expected: "",
		},
		{
			name: "next link with empty href",
			links: []Link{
				{Rel: "next", Href: ""},
			},
			expected: "",
		},
		{
			name: "token with special characters",
			links: []Link{
				{Rel: "next", Href: "https://example.com/search?token=abc-123_xyz.token"},
			},
			expected: "abc-123_xyz.token",
		},
		{
			name: "URL encoded token",
			links: []Link{
				{Rel: "next", Href: "https://example.com/search?token=abc%20123"},
			},
			expected: "abc%20123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := ExtractNextToken(tt.links)

			if result != tt.expected {
				t.Errorf("ExtractNextToken() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestValidateItem(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		item    *Item
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid item",
			item: &Item{
				Type:     "Feature",
				ID:       "test-item",
				Geometry: &Geometry{Type: "Point", Coordinates: json.RawMessage(`[100.0, 0.0]`)},
				Properties: Properties{},
			},
			wantErr: false,
		},
		{
			name: "missing ID",
			item: &Item{
				Type:       "Feature",
				Geometry:   &Geometry{Type: "Point"},
				Properties: Properties{},
			},
			wantErr: true,
			errMsg:  "item missing ID",
		},
		{
			name: "wrong type",
			item: &Item{
				Type:       "Collection",
				ID:         "test",
				Geometry:   &Geometry{Type: "Point"},
				Properties: Properties{},
			},
			wantErr: true,
			errMsg:  "item type must be 'Feature'",
		},
		{
			name: "missing geometry",
			item: &Item{
				Type:       "Feature",
				ID:         "test",
				Geometry:   nil,
				Properties: Properties{},
			},
			wantErr: true,
			errMsg:  "item missing geometry",
		},
		{
			name: "valid item with null geometry",
			item: &Item{
				Type:       "Feature",
				ID:         "test-null-geom",
				Geometry:   &Geometry{},
				Properties: Properties{},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := ValidateItem(tt.item)

			if tt.wantErr {
				if err == nil {
					t.Fatal("ValidateItem() expected error, got nil")
				}
				if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("ValidateItem() error = %q, want substring %q", err.Error(), tt.errMsg)
				}
				return
			}

			if err != nil {
				t.Fatalf("ValidateItem() unexpected error: %v", err)
			}
		})
	}
}

func TestValidateCollection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		coll    *Collection
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid collection",
			coll: &Collection{
				Type:        "Collection",
				ID:          "test-coll",
				Description: "A test collection",
				License:     "MIT",
			},
			wantErr: false,
		},
		{
			name: "missing ID",
			coll: &Collection{
				Type:        "Collection",
				Description: "A test collection",
				License:     "MIT",
			},
			wantErr: true,
			errMsg:  "collection missing ID",
		},
		{
			name: "wrong type",
			coll: &Collection{
				Type:        "Feature",
				ID:          "test",
				Description: "A test collection",
				License:     "MIT",
			},
			wantErr: true,
			errMsg:  "collection type must be 'Collection'",
		},
		{
			name: "missing description",
			coll: &Collection{
				Type:    "Collection",
				ID:      "test",
				License: "MIT",
			},
			wantErr: true,
			errMsg:  "collection missing description",
		},
		{
			name: "missing license",
			coll: &Collection{
				Type:        "Collection",
				ID:          "test",
				Description: "A test collection",
			},
			wantErr: true,
			errMsg:  "collection missing license",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := ValidateCollection(tt.coll)

			if tt.wantErr {
				if err == nil {
					t.Fatal("ValidateCollection() expected error, got nil")
				}
				if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("ValidateCollection() error = %q, want substring %q", err.Error(), tt.errMsg)
				}
				return
			}

			if err != nil {
				t.Fatalf("ValidateCollection() unexpected error: %v", err)
			}
		})
	}
}

func TestValidateSearchRequest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		req     *SearchRequest
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid request with bbox",
			req: &SearchRequest{
				BBox:  []float64{-10, -5, 10, 5},
				Limit: 10,
			},
			wantErr: false,
		},
		{
			name: "valid request with 6-coordinate bbox",
			req: &SearchRequest{
				BBox:  []float64{-10, -5, 0, 10, 5, 100},
				Limit: 10,
			},
			wantErr: false,
		},
		{
			name: "bbox with invalid count (3 coordinates)",
			req: &SearchRequest{
				BBox: []float64{-10, -5, 10},
			},
			wantErr: true,
			errMsg:  "bbox must have 4 or 6 coordinates",
		},
		{
			name: "bbox with invalid count (5 coordinates)",
			req: &SearchRequest{
				BBox: []float64{-10, -5, 10, 5, 100},
			},
			wantErr: true,
			errMsg:  "bbox must have 4 or 6 coordinates",
		},
		{
			name: "bbox with west > east",
			req: &SearchRequest{
				BBox: []float64{10, -5, -10, 5},
			},
			wantErr: true,
			errMsg:  "bbox west must be less than east",
		},
		{
			name: "bbox with south > north",
			req: &SearchRequest{
				BBox: []float64{-10, 5, 10, -5},
			},
			wantErr: true,
			errMsg:  "bbox south must be less than north",
		},
		{
			name: "negative limit",
			req: &SearchRequest{
				Limit: -1,
			},
			wantErr: true,
			errMsg:  "limit must be non-negative",
		},
		{
			name: "zero limit is valid",
			req: &SearchRequest{
				Limit: 0,
			},
			wantErr: false,
		},
		{
			name:    "empty request is valid",
			req:     &SearchRequest{},
			wantErr: false,
		},
		{
			name: "valid request with collections",
			req: &SearchRequest{
				Collections: []string{"sentinel-2", "landsat-8"},
				Limit:       10,
			},
			wantErr: false,
		},
		{
			name: "valid bbox with same west and east (point)",
			req: &SearchRequest{
				BBox: []float64{100, 0, 100, 0},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := ValidateSearchRequest(tt.req)

			if tt.wantErr {
				if err == nil {
					t.Fatal("ValidateSearchRequest() expected error, got nil")
				}
				if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("ValidateSearchRequest() error = %q, want substring %q", err.Error(), tt.errMsg)
				}
				return
			}

			if err != nil {
				t.Fatalf("ValidateSearchRequest() unexpected error: %v", err)
			}
		})
	}
}

// Benchmark tests

func BenchmarkParseItem(b *testing.B) {
	parser := NewParser()
	data := []byte(`{
		"type": "Feature",
		"stac_version": "1.0.0",
		"id": "test-item",
		"geometry": {
			"type": "Point",
			"coordinates": [100.0, 0.0]
		},
		"properties": {
			"datetime": "2023-01-01T00:00:00Z"
		},
		"links": [],
		"assets": {}
	}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = parser.ParseItem(data)
	}
}

func BenchmarkParseCollection(b *testing.B) {
	parser := NewParser()
	data := []byte(`{
		"type": "Collection",
		"id": "test",
		"description": "Test",
		"license": "MIT",
		"extent": {
			"spatial": {"bbox": [[0, 0, 1, 1]]},
			"temporal": {"interval": [[null, null]]}
		},
		"links": []
	}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = parser.ParseCollection(data)
	}
}

func BenchmarkParseSearchRequest(b *testing.B) {
	parser := NewParser()
	data := []byte(`{
		"collections": ["sentinel-2", "landsat-8"],
		"bbox": [-10, -10, 10, 10],
		"datetime": "2023-01-01T00:00:00Z/2023-12-31T23:59:59Z",
		"limit": 10
	}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = parser.ParseSearchRequest(data)
	}
}

func BenchmarkParseSearchFromQuery(b *testing.B) {
	parser := NewParser()
	req := httptest.NewRequest(
		http.MethodGet,
		"/search?collections=sentinel-2,landsat-8&bbox=-10,-10,10,10&limit=10&datetime=2023-01-01T00:00:00Z",
		nil,
	)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = parser.parseSearchFromQuery(req)
	}
}

func BenchmarkExtractNextToken(b *testing.B) {
	links := []Link{
		{Rel: "self", Href: "https://example.com/search"},
		{Rel: "next", Href: "https://example.com/search?token=abc123&limit=10"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ExtractNextToken(links)
	}
}

func BenchmarkValidateSearchRequest(b *testing.B) {
	req := &SearchRequest{
		Collections: []string{"sentinel-2"},
		BBox:        []float64{-10, -10, 10, 10},
		Limit:       10,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ValidateSearchRequest(req)
	}
}
