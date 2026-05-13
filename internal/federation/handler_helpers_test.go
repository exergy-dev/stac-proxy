package federation

// Test fixtures previously in internal/testutil. Moved here when the
// testutil package was deleted as part of the Part 4 simplification
// sweep (only this file and ratelimit/middleware_test.go consumed it,
// and 99% of consumption was here).

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/yourorg/stac-proxy/internal/middleware"
	"github.com/yourorg/stac-proxy/internal/stac"
)

// --- Item fixtures ---------------------------------------------------------

type ItemOption func(*stac.Item)

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

func WithCollection(collection string) ItemOption {
	return func(i *stac.Item) { i.Collection = collection }
}

// --- Collection / FeatureCollection fixtures -------------------------------

func SampleCollection(id string) *stac.Collection {
	return &stac.Collection{
		Type:        "Collection",
		ID:          id,
		Title:       "Test Collection " + id,
		Description: "A test collection for unit testing",
		License:     "MIT",
		Extent: stac.Extent{
			Spatial:  stac.SpatialExtent{BBox: [][]float64{{-180, -90, 180, 90}}},
			Temporal: stac.TemporalExtent{Interval: [][]interface{}{{"2020-01-01T00:00:00Z", "2023-12-31T23:59:59Z"}}},
		},
		Links: []stac.Link{
			{Rel: "self", Href: "https://example.com/collections/" + id, Type: "application/json"},
			{Rel: "items", Href: "https://example.com/collections/" + id + "/items", Type: "application/geo+json"},
		},
	}
}

func SampleFeatureCollection(items ...*stac.Item) *stac.FeatureCollection {
	features := make([]stac.Item, len(items))
	for i, item := range items {
		if item != nil {
			features[i] = *item
		}
	}
	return &stac.FeatureCollection{
		Type:     "FeatureCollection",
		Features: features,
		Links: []stac.Link{
			{Rel: "self", Href: "https://example.com/search", Type: "application/geo+json"},
		},
		Context: &stac.SearchContext{Returned: len(items), Limit: 10},
	}
}

func SampleBbox() []float64 { return []float64{-10, -10, 10, 10} }

// --- Search-request fixtures -----------------------------------------------

type SearchOption func(*stac.SearchRequest)

func SampleSearchRequest(opts ...SearchOption) *stac.SearchRequest {
	req := &stac.SearchRequest{Limit: 10}
	for _, opt := range opts {
		opt(req)
	}
	return req
}

func WithCollections(collections ...string) SearchOption {
	return func(r *stac.SearchRequest) { r.Collections = collections }
}

func WithSearchBbox(bbox []float64) SearchOption {
	return func(r *stac.SearchRequest) { r.BBox = bbox }
}

func WithSearchDatetime(datetime string) SearchOption {
	return func(r *stac.SearchRequest) { r.Datetime = datetime }
}

func WithLimit(limit int) SearchOption {
	return func(r *stac.SearchRequest) { r.Limit = limit }
}

// --- Test-server helpers ---------------------------------------------------

func newTestServerWithResponse(statusCode int, body interface{}) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		if body != nil {
			_ = json.NewEncoder(w).Encode(body)
		}
	}))
}

func NewTestServerWithJSONResponse(body interface{}) *httptest.Server {
	return newTestServerWithResponse(http.StatusOK, body)
}

func NewTestServerWithError(statusCode int, message string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
	}))
}

func NewTestServerWithDelay(delay time.Duration, body interface{}) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(delay)
		w.Header().Set("Content-Type", "application/json")
		if body != nil {
			_ = json.NewEncoder(w).Encode(body)
		}
	}))
}

// NewSTACRequest builds a STACRequest with a sensible default Search shape.
// Used by older test fixtures; the canonical request type tag is overridable.
func NewSTACRequest(method, path string, body interface{}) *middleware.STACRequest {
	var bodyReader io.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		bodyReader = bytes.NewReader(data)
	}
	req := httptest.NewRequest(method, path, bodyReader)
	req.Header.Set("Content-Type", "application/json")
	return &middleware.STACRequest{
		Request:     req,
		Context:     context.Background(),
		RequestType: middleware.RequestTypeSearch,
		Params:      make(map[string]interface{}),
	}
}
