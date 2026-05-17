package federation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/stac-proxy/internal/middleware"
	"github.com/yourorg/stac-proxy/internal/stac"
)

// TestNewHandler tests handler initialization
func TestNewHandler(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		config      HandlerConfig
		wantOrigins int
		wantErr     bool
	}{
		{
			name: "valid configuration",
			config: HandlerConfig{
				Origins: []*Origin{
					{
						ID:         "origin1",
						BaseURL:    "http://origin1.example.com",
						Enabled:    true,
						Searchable: true,
					},
					{
						ID:         "origin2",
						BaseURL:    "http://origin2.example.com",
						Enabled:    true,
						Searchable: true,
					},
				},
				ConflictStrategy: ConflictPriorityWins,
				MaxConcurrent:    5,
				AggregateTimeout: 30 * time.Second,
				ProxyBaseURL:     "http://proxy.example.com",
				DefaultPageSize:  50,
				MaxPageSize:      500,
			},
			wantOrigins: 2,
			wantErr:     false,
		},
		{
			name: "disabled origins excluded",
			config: HandlerConfig{
				Origins: []*Origin{
					{
						ID:         "origin1",
						BaseURL:    "http://origin1.example.com",
						Enabled:    true,
						Searchable: true,
					},
					{
						ID:         "origin2",
						BaseURL:    "http://origin2.example.com",
						Enabled:    false,
						Searchable: true,
					},
				},
				ConflictStrategy: ConflictPriorityWins,
			},
			wantOrigins: 1,
			wantErr:     false,
		},
		{
			name: "default values applied",
			config: HandlerConfig{
				Origins: []*Origin{
					{
						ID:         "origin1",
						BaseURL:    "http://origin1.example.com",
						Enabled:    true,
						Searchable: true,
					},
				},
				ConflictStrategy: ConflictPriorityWins,
			},
			wantOrigins: 1,
			wantErr:     false,
		},
		{
			name: "empty origins list",
			config: HandlerConfig{
				Origins:          []*Origin{},
				ConflictStrategy: ConflictPriorityWins,
			},
			wantOrigins: 0,
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			handler, err := NewHandler(tt.config)

			if tt.wantErr {
				require.Error(t, err, "expected error but got nil")
				return
			}

			require.NoError(t, err)
			require.NotNil(t, handler, "handler is nil")

			assert.Equal(t, tt.wantOrigins, handler.OriginCount(), "OriginCount()")

			// Check default values
			assert.Greater(t, handler.maxConcurrent, 0, "maxConcurrent not set to default")
			assert.Greater(t, handler.aggregateTimeout, time.Duration(0), "aggregateTimeout not set to default")
			assert.Greater(t, handler.defaultPageSize, 0, "defaultPageSize not set to default")
			assert.Greater(t, handler.maxPageSize, 0, "maxPageSize not set to default")
		})
	}
}

// TestHandlerOriginIDs tests the OriginIDs method
func TestHandlerOriginIDs(t *testing.T) {
	t.Parallel()

	handler, err := NewHandler(HandlerConfig{
		Origins: []*Origin{
			{
				ID:         "origin1",
				BaseURL:    "http://origin1.example.com",
				Enabled:    true,
				Searchable: true,
			},
			{
				ID:         "origin2",
				BaseURL:    "http://origin2.example.com",
				Enabled:    true,
				Searchable: true,
			},
		},
		ConflictStrategy: ConflictPriorityWins,
	})
	require.NoError(t, err, "failed to create handler")

	ids := handler.OriginIDs()
	require.Len(t, ids, 2, "expected 2 origin IDs")
	assert.ElementsMatch(t, []string{"origin1", "origin2"}, ids)
}

// TestHandleSearch tests the search request handling
func TestHandleSearch(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		searchReq      *stac.SearchRequest
		mockResponses  map[string]*stac.FeatureCollection
		expectedItems  int
		expectedStatus int
	}{
		{
			name: "successful search from multiple origins",
			searchReq: SampleSearchRequest(
				WithCollections("collection1"),
				WithLimit(10),
			),
			mockResponses: map[string]*stac.FeatureCollection{
				"origin1": SampleFeatureCollection(
					SampleItem("item1", WithCollection("collection1")),
					SampleItem("item2", WithCollection("collection1")),
				),
				"origin2": SampleFeatureCollection(
					SampleItem("item3", WithCollection("collection1")),
				),
			},
			expectedItems:  3,
			expectedStatus: http.StatusOK,
		},
		{
			name: "search with no results",
			searchReq: SampleSearchRequest(
				WithCollections("nonexistent"),
				WithLimit(10),
			),
			mockResponses:  map[string]*stac.FeatureCollection{},
			expectedItems:  0,
			expectedStatus: http.StatusOK,
		},
		{
			name: "search with limit applied (single origin pass-through)",
			searchReq: SampleSearchRequest(
				WithCollections("collection1"),
				WithLimit(2),
			),
			mockResponses: map[string]*stac.FeatureCollection{
				"origin1": SampleFeatureCollection(
					SampleItem("item1", WithCollection("collection1")),
					SampleItem("item2", WithCollection("collection1")),
					SampleItem("item3", WithCollection("collection1")),
				),
			},
			// In single-origin mode the proxy is a transparent
			// ReverseProxy pass-through; limit enforcement is the
			// upstream's responsibility (the test mock ignores it
			// and returns all 3 items).
			expectedItems:  3,
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Create test servers for each origin
			origins := make([]*Origin, 0)
			for originID, fc := range tt.mockResponses {
				server := NewTestServerWithJSONResponse(fc)
				defer server.Close()

				origins = append(origins, &Origin{
					ID:          originID,
					BaseURL:     server.URL,
					Enabled:     true,
					Searchable:  true,
					Collections: []string{"collection1"},
					Timeout:     5 * time.Second,
					Priority:    1,
				})
			}

			handler, err := NewHandler(HandlerConfig{
				Origins:          origins,
				ConflictStrategy: ConflictPriorityWins,
				MaxConcurrent:    10,
				AggregateTimeout: 10 * time.Second,
			})
			require.NoError(t, err, "failed to create handler")

			// Create request
			req := &request{
				Request:     httptest.NewRequest(http.MethodPost, "/search", nil),
				Context:     context.Background(),
				RequestType: middleware.RequestTypeSearch,
				SearchReq:   tt.searchReq,
			}

			// Execute
			resp, err := handler.Handle(req.Context, req)
			require.NoError(t, err, "Handle()")

			assert.Equal(t, tt.expectedStatus, resp.StatusCode, "StatusCode")

			// Parse response
			var fc stac.FeatureCollection
			require.NoError(t, json.Unmarshal(resp.Body, &fc), "failed to parse response")

			assert.Len(t, fc.Features, tt.expectedItems, "items count")
		})
	}
}

// TestHandleSearchWithErrors tests error handling during search
func TestHandleSearchWithErrors(t *testing.T) {
	t.Parallel()

	// Create one failing and one successful origin
	successFC := SampleFeatureCollection(
		SampleItem("item1", WithCollection("collection1")),
	)
	successServer := NewTestServerWithJSONResponse(successFC)
	defer successServer.Close()

	failServer := NewTestServerWithError(http.StatusInternalServerError, "origin error")
	defer failServer.Close()

	handler, err := NewHandler(HandlerConfig{
		Origins: []*Origin{
			{
				ID:          "success",
				BaseURL:     successServer.URL,
				Enabled:     true,
				Searchable:  true,
				Collections: []string{"collection1"},
				Timeout:     5 * time.Second,
				Priority:    1,
			},
			{
				ID:          "fail",
				BaseURL:     failServer.URL,
				Enabled:     true,
				Searchable:  true,
				Collections: []string{"collection1"},
				Timeout:     5 * time.Second,
				Priority:    2,
			},
		},
		ConflictStrategy: ConflictPriorityWins,
		MaxConcurrent:    10,
		AggregateTimeout: 10 * time.Second,
	})
	require.NoError(t, err, "failed to create handler")

	req := &request{
		Request:     httptest.NewRequest(http.MethodPost, "/search", nil),
		Context:     context.Background(),
		RequestType: middleware.RequestTypeSearch,
		SearchReq: SampleSearchRequest(
			WithCollections("collection1"),
			WithLimit(10),
		),
	}

	resp, err := handler.Handle(req.Context, req)
	require.NoError(t, err, "Handle()")

	// Should still succeed with results from successful origin
	var fc stac.FeatureCollection
	require.NoError(t, json.Unmarshal(resp.Body, &fc), "failed to parse response")

	assert.Len(t, fc.Features, 1, "expected 1 item from successful origin")
}

// TestHandleSearchTimeout tests timeout handling
func TestHandleSearchTimeout(t *testing.T) {
	// Create a slow server
	slowServer := NewTestServerWithDelay(2*time.Second, SampleFeatureCollection(
		SampleItem("item1"),
	))
	defer slowServer.Close()

	slowServer2 := NewTestServerWithDelay(2*time.Second, SampleFeatureCollection(
		SampleItem("item2"),
	))
	defer slowServer2.Close()

	// Two-origin handler so aggregate-timeout / fan-out semantics apply
	// (the single-origin path is a transparent ReverseProxy pass-through
	// and does NOT honor aggregateTimeout — that's tied to fan-out).
	handler, err := NewHandler(HandlerConfig{
		Origins: []*Origin{
			{
				ID:          "slow",
				BaseURL:     slowServer.URL,
				Enabled:     true,
				Searchable:  true,
				Collections: []string{"collection1"},
				Timeout:     5 * time.Second,
			},
			{
				ID:          "slow2",
				BaseURL:     slowServer2.URL,
				Enabled:     true,
				Searchable:  true,
				Collections: []string{"collection1"},
				Timeout:     5 * time.Second,
			},
		},
		ConflictStrategy: ConflictPriorityWins,
		MaxConcurrent:    10,
		AggregateTimeout: 100 * time.Millisecond, // Very short timeout
	})
	require.NoError(t, err, "failed to create handler")

	req := &request{
		Request:     httptest.NewRequest(http.MethodPost, "/search", nil),
		Context:     context.Background(),
		RequestType: middleware.RequestTypeSearch,
		SearchReq: SampleSearchRequest(
			WithCollections("collection1"),
		),
	}

	resp, err := handler.Handle(req.Context, req)
	require.NoError(t, err, "Handle()")

	// Should return empty results due to timeout
	var fc stac.FeatureCollection
	require.NoError(t, json.Unmarshal(resp.Body, &fc), "failed to parse response")

	assert.Empty(t, fc.Features, "expected 0 items due to timeout")
}

// TestHandleSearchContextCancellation tests context cancellation
func TestHandleSearchContextCancellation(t *testing.T) {
	// Create a slow server
	slowServer := NewTestServerWithDelay(2*time.Second, SampleFeatureCollection(
		SampleItem("item1"),
	))
	defer slowServer.Close()

	slowServer2 := NewTestServerWithDelay(2*time.Second, SampleFeatureCollection(
		SampleItem("item2"),
	))
	defer slowServer2.Close()

	handler, err := NewHandler(HandlerConfig{
		Origins: []*Origin{
			{
				ID:          "slow",
				BaseURL:     slowServer.URL,
				Enabled:     true,
				Searchable:  true,
				Collections: []string{"collection1"},
				Timeout:     5 * time.Second,
			},
			{
				ID:          "slow2",
				BaseURL:     slowServer2.URL,
				Enabled:     true,
				Searchable:  true,
				Collections: []string{"collection1"},
				Timeout:     5 * time.Second,
			},
		},
		ConflictStrategy: ConflictPriorityWins,
		MaxConcurrent:    10,
		AggregateTimeout: 10 * time.Second,
	})
	require.NoError(t, err, "failed to create handler")

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	req := &request{
		Request:     httptest.NewRequest(http.MethodPost, "/search", nil),
		Context:     ctx,
		RequestType: middleware.RequestTypeSearch,
		SearchReq: SampleSearchRequest(
			WithCollections("collection1"),
		),
	}

	resp, err := handler.Handle(req.Context, req)
	require.NoError(t, err, "Handle()")

	// Should return empty results
	var fc stac.FeatureCollection
	require.NoError(t, json.Unmarshal(resp.Body, &fc), "failed to parse response")

	assert.Empty(t, fc.Features, "expected 0 items due to cancellation")
}

// TestHandleGetCollections tests collection listing
func TestHandleGetCollections(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		mockResponses     map[string][]*stac.Collection
		expectedCollCount int
		expectedStatus    int
	}{
		{
			name: "collections from multiple origins",
			mockResponses: map[string][]*stac.Collection{
				"origin1": {
					SampleCollection("coll1"),
					SampleCollection("coll2"),
				},
				"origin2": {
					SampleCollection("coll3"),
				},
			},
			expectedCollCount: 3,
			expectedStatus:    http.StatusOK,
		},
		{
			name: "duplicate collections deduplicated",
			mockResponses: map[string][]*stac.Collection{
				"origin1": {
					SampleCollection("coll1"),
				},
				"origin2": {
					SampleCollection("coll1"), // Same ID
				},
			},
			expectedCollCount: 1,
			expectedStatus:    http.StatusOK,
		},
		{
			name:              "no collections",
			mockResponses:     map[string][]*stac.Collection{},
			expectedCollCount: 0,
			expectedStatus:    http.StatusOK,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			origins := make([]*Origin, 0)
			for originID, collections := range tt.mockResponses {
				resp := &stac.CollectionsResponse{Collections: collections}
				server := NewTestServerWithJSONResponse(resp)
				defer server.Close()

				origins = append(origins, &Origin{
					ID:         originID,
					BaseURL:    server.URL,
					Enabled:    true,
					Searchable: true,
					Timeout:    5 * time.Second,
					Priority:   1,
				})
			}

			handler, err := NewHandler(HandlerConfig{
				Origins:          origins,
				ConflictStrategy: ConflictPriorityWins,
			})
			require.NoError(t, err, "failed to create handler")

			req := &request{
				Request:     httptest.NewRequest(http.MethodGet, "/collections", nil),
				Context:     context.Background(),
				RequestType: middleware.RequestTypeCollections,
			}

			resp, err := handler.Handle(req.Context, req)
			require.NoError(t, err, "Handle()")

			assert.Equal(t, tt.expectedStatus, resp.StatusCode, "StatusCode")

			var collResp stac.CollectionsResponse
			require.NoError(t, json.Unmarshal(resp.Body, &collResp), "failed to parse response")

			assert.Len(t, collResp.Collections, tt.expectedCollCount, "collections count")

			// Verify origin metadata is added (as a stac_proxy:origin link).
			for _, coll := range collResp.Collections {
				if !assert.NotNil(t, coll, "nil collection in response") {
					continue
				}
				assert.NotEmpty(t, stac.CollectionOriginID(coll), "missing stac_proxy:origin link")
			}
		})
	}
}

// TestHandleGetCollection tests single collection retrieval
func TestHandleGetCollection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		collectionID   string
		mockCollection *stac.Collection
		mockStatus     int
		expectedStatus int
	}{
		{
			name:           "collection found",
			collectionID:   "test-collection",
			mockCollection: SampleCollection("test-collection"),
			mockStatus:     http.StatusOK,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "collection not found",
			collectionID:   "nonexistent",
			mockCollection: nil,
			mockStatus:     http.StatusNotFound,
			expectedStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var server *httptest.Server
			if tt.mockCollection != nil {
				server = NewTestServerWithJSONResponse(tt.mockCollection)
			} else {
				server = NewTestServerWithError(tt.mockStatus, "not found")
			}
			defer server.Close()

			handler, err := NewHandler(HandlerConfig{
				Origins: []*Origin{
					{
						ID:          "origin1",
						BaseURL:     server.URL,
						Enabled:     true,
						Searchable:  true,
						Collections: []string{tt.collectionID},
						Timeout:     5 * time.Second,
					},
				},
				ConflictStrategy: ConflictPriorityWins,
			})
			require.NoError(t, err, "failed to create handler")

			req := &request{
				Request:     httptest.NewRequest(http.MethodGet, "/collections/"+tt.collectionID, nil),
				Context:     context.Background(),
				RequestType: middleware.RequestTypeCollection,
				Collection:  tt.collectionID,
			}

			resp, err := handler.Handle(req.Context, req)
			require.NoError(t, err, "Handle()")

			assert.Equal(t, tt.expectedStatus, resp.StatusCode, "StatusCode")

			if tt.expectedStatus == http.StatusOK {
				var coll stac.Collection
				require.NoError(t, json.Unmarshal(resp.Body, &coll), "failed to parse response")

				assert.Equal(t, tt.collectionID, coll.ID, "collection ID")

				// stac_proxy:origin is only injected when there is
				// more than one registered origin (true federation
				// mode). This test uses a single origin so the
				// proxied payload passes through unannotated.
				assert.Empty(t, stac.CollectionOriginID(&coll), "unexpected stac_proxy:origin link in single-origin response")
			}
		})
	}
}

// TestHandleGetCollectionWithPrefix tests collection retrieval with prefix
func TestHandleGetCollectionWithPrefix(t *testing.T) {
	t.Parallel()

	coll := SampleCollection("my-collection")
	server := NewTestServerWithJSONResponse(coll)
	defer server.Close()

	handler, err := NewHandler(HandlerConfig{
		Origins: []*Origin{
			{
				ID:               "origin1",
				BaseURL:          server.URL,
				Enabled:          true,
				Searchable:       true,
				Collections:      []string{"my-collection"},
				CollectionPrefix: "prefix_",
				Timeout:          5 * time.Second,
			},
		},
		ConflictStrategy: ConflictPriorityWins,
	})
	require.NoError(t, err, "failed to create handler")

	// Request with prefix
	req := &request{
		Request:     httptest.NewRequest(http.MethodGet, "/collections/prefix_my-collection", nil),
		Context:     context.Background(),
		RequestType: middleware.RequestTypeCollection,
		Collection:  "prefix_my-collection",
	}

	resp, err := handler.Handle(req.Context, req)
	require.NoError(t, err, "Handle()")

	assert.Equal(t, http.StatusOK, resp.StatusCode, "StatusCode")
}

// TestHandleGetItem tests single item retrieval
func TestHandleGetItem(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		collectionID   string
		itemID         string
		mockItem       *stac.Item
		mockStatus     int
		expectedStatus int
	}{
		{
			name:           "item found",
			collectionID:   "test-collection",
			itemID:         "test-item",
			mockItem:       SampleItem("test-item", WithCollection("test-collection")),
			mockStatus:     http.StatusOK,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "item not found",
			collectionID:   "test-collection",
			itemID:         "nonexistent",
			mockItem:       nil,
			mockStatus:     http.StatusNotFound,
			expectedStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var server *httptest.Server
			if tt.mockItem != nil {
				server = NewTestServerWithJSONResponse(tt.mockItem)
			} else {
				server = NewTestServerWithError(tt.mockStatus, "not found")
			}
			defer server.Close()

			handler, err := NewHandler(HandlerConfig{
				Origins: []*Origin{
					{
						ID:          "origin1",
						BaseURL:     server.URL,
						Enabled:     true,
						Searchable:  true,
						Collections: []string{tt.collectionID},
						Timeout:     5 * time.Second,
					},
				},
				ConflictStrategy: ConflictPriorityWins,
			})
			require.NoError(t, err, "failed to create handler")

			req := &request{
				Request:     httptest.NewRequest(http.MethodGet, "/collections/"+tt.collectionID+"/items/"+tt.itemID, nil),
				Context:     context.Background(),
				RequestType: middleware.RequestTypeItem,
				Collection:  tt.collectionID,
				ItemID:      tt.itemID,
			}

			resp, err := handler.Handle(req.Context, req)
			require.NoError(t, err, "Handle()")

			assert.Equal(t, tt.expectedStatus, resp.StatusCode, "StatusCode")

			if tt.expectedStatus == http.StatusOK {
				var item stac.Item
				require.NoError(t, json.Unmarshal(resp.Body, &item), "failed to parse response")

				assert.Equal(t, tt.itemID, item.ID, "item ID")

				// stac_proxy:origin is only injected when there is
				// more than one registered origin (true federation
				// mode). This test uses a single origin so the
				// proxied payload passes through unannotated.
				assert.Empty(t, stac.ItemOriginID(&item), "unexpected stac_proxy:origin link in single-origin response")
			}
		})
	}
}

// TestHandleGetItemWithPrefix tests item retrieval with collection prefix
func TestHandleGetItemWithPrefix(t *testing.T) {
	t.Parallel()

	item := SampleItem("test-item", WithCollection("my-collection"))
	server := NewTestServerWithJSONResponse(item)
	defer server.Close()

	handler, err := NewHandler(HandlerConfig{
		Origins: []*Origin{
			{
				ID:               "origin1",
				BaseURL:          server.URL,
				Enabled:          true,
				Searchable:       true,
				Collections:      []string{"my-collection"},
				CollectionPrefix: "prefix_",
				Timeout:          5 * time.Second,
			},
		},
		ConflictStrategy: ConflictPriorityWins,
	})
	require.NoError(t, err, "failed to create handler")

	// Request with prefix
	req := &request{
		Request:     httptest.NewRequest(http.MethodGet, "/collections/prefix_my-collection/items/test-item", nil),
		Context:     context.Background(),
		RequestType: middleware.RequestTypeItem,
		Collection:  "prefix_my-collection",
		ItemID:      "test-item",
	}

	resp, err := handler.Handle(req.Context, req)
	require.NoError(t, err, "Handle()")

	assert.Equal(t, http.StatusOK, resp.StatusCode, "StatusCode")
}

// TestHandleGenericProxy tests generic request proxying
func TestHandleGenericProxy(t *testing.T) {
	t.Parallel()

	mockResp := map[string]interface{}{
		"message": "generic response",
	}
	server := NewTestServerWithJSONResponse(mockResp)
	defer server.Close()

	handler, err := NewHandler(HandlerConfig{
		Origins: []*Origin{
			{
				ID:         "origin1",
				BaseURL:    server.URL,
				Enabled:    true,
				Searchable: true,
				Priority:   1,
				Timeout:    5 * time.Second,
			},
		},
		ConflictStrategy: ConflictPriorityWins,
	})
	require.NoError(t, err, "failed to create handler")

	req := &request{
		Request:     httptest.NewRequest(http.MethodGet, "/conformance", nil),
		Context:     context.Background(),
		RequestType: middleware.RequestTypeConformance,
	}

	resp, err := handler.Handle(req.Context, req)
	require.NoError(t, err, "Handle()")

	assert.Equal(t, http.StatusOK, resp.StatusCode, "StatusCode")
}

// TestHandleGenericProxyNoOrigins tests the generic-proxy fallback
// returns 503 when no origins are configured. /conformance is no
// longer handled by handleGenericProxy (it now synthesizes a
// proxy-owned response from ConformanceCaps), so this test routes
// through /queryables — a passthrough endpoint that still falls back
// to the primary origin and returns 503 when there isn't one.
func TestHandleGenericProxyNoOrigins(t *testing.T) {
	t.Parallel()

	handler, err := NewHandler(HandlerConfig{
		Origins:          []*Origin{},
		ConflictStrategy: ConflictPriorityWins,
	})
	require.NoError(t, err, "failed to create handler")

	req := &request{
		Request:     httptest.NewRequest(http.MethodGet, "/queryables", nil),
		Context:     context.Background(),
		RequestType: middleware.RequestTypeQueryables,
	}

	resp, err := handler.Handle(req.Context, req)
	require.NoError(t, err, "Handle()")

	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode, "StatusCode")
}

// TestParseSearchRequest tests search request parsing
func TestParseSearchRequest(t *testing.T) {
	t.Parallel()

	handler := &Handler{
		defaultPageSize: 100,
		maxPageSize:     1000,
	}

	tests := []struct {
		name      string
		method    string
		body      interface{}
		queryVars map[string]string
		wantErr   bool
	}{
		{
			name:   "POST with JSON body",
			method: http.MethodPost,
			body: &stac.SearchRequest{
				Collections: []string{"test"},
				Limit:       10,
			},
			wantErr: false,
		},
		{
			name:    "GET with query params",
			method:  http.MethodGet,
			wantErr: false,
		},
		{
			name:    "POST with invalid JSON",
			method:  http.MethodPost,
			body:    "invalid json",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var bodyReader io.Reader
			if tt.body != nil {
				if str, ok := tt.body.(string); ok {
					bodyReader = bytes.NewReader([]byte(str))
				} else {
					data, _ := json.Marshal(tt.body)
					bodyReader = bytes.NewReader(data)
				}
			}

			httpReq := httptest.NewRequest(tt.method, "/search", bodyReader)
			if bodyReader != nil {
				httpReq.Header.Set("Content-Type", "application/json")
			}

			req := &request{
				Request:     httpReq,
				Context:     httpReq.Context(),
				RequestType: middleware.RequestTypeSearch,
			}

			searchReq, err := handler.parseSearchRequest(req)

			if tt.wantErr {
				assert.Error(t, err, "expected error but got nil")
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, searchReq, "searchReq is nil")
		})
	}
}

// TestParseSearchRequest_GET_ParsesAllParams is a regression test for
// H-federation-2: the hand-rolled GET parser dropped most query
// parameters (collections wasn't comma-split, bbox/limit/filter/ids
// were ignored). After delegating to stac.Parser, every documented
// search parameter round-trips through the federation parser.
func TestParseSearchRequest_GET_ParsesAllParams(t *testing.T) {
	t.Parallel()

	h := &Handler{}
	httpReq := httptest.NewRequest(http.MethodGet,
		"/search?collections=a,b&bbox=0,0,10,10&limit=5&filter=foo", nil)
	req := &request{
		Request:     httpReq,
		Context:     httpReq.Context(),
		RequestType: middleware.RequestTypeSearch,
	}

	got, err := h.parseSearchRequest(req)
	require.NoError(t, err, "parseSearchRequest")

	assert.Equal(t, []string{"a", "b"}, got.Collections, "Collections")
	assert.Equal(t, []float64{0, 0, 10, 10}, got.BBox, "BBox")
	assert.Equal(t, 5, got.Limit, "Limit")
	assert.Equal(t, "foo", got.Filter, "Filter")
}

// TestEmptySearchResponse tests empty search response generation
func TestEmptySearchResponse(t *testing.T) {
	t.Parallel()

	handler := &Handler{}

	req := &stac.SearchRequest{
		Collections: []string{"test"},
		Limit:       10,
	}

	resp, err := handler.emptySearchResponse(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode, "StatusCode")

	var fc stac.FeatureCollection
	require.NoError(t, json.Unmarshal(resp.Body, &fc), "failed to parse response")

	assert.Equal(t, "FeatureCollection", fc.Type, "Type")
	assert.Empty(t, fc.Features, "expected 0 features")

	sc := stac.SearchContextOf(&fc)
	require.NotNil(t, sc, "Context missing from FeatureCollection")
	assert.Equal(t, 0, sc.Returned, "Context.Returned")
	assert.Equal(t, 0, sc.Matched, "Context.Matched")
}

// TestBuildSearchResponse tests search response building
func TestBuildSearchResponse(t *testing.T) {
	t.Parallel()

	handler := &Handler{}

	fc := &stac.FeatureCollection{
		Type: "FeatureCollection",
		Features: []*stac.Item{
			SampleItem("item1"),
			SampleItem("item2"),
		},
		Context: &stac.SearchContext{
			Returned: 2,
			Matched:  10,
		},
	}

	req := &request{
		Request: httptest.NewRequest(http.MethodPost, "/search", nil),
	}

	resp, err := handler.buildSearchResponse(fc, req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode, "StatusCode")

	var parsedFC stac.FeatureCollection
	require.NoError(t, json.Unmarshal(resp.Body, &parsedFC), "failed to parse response")

	assert.Len(t, parsedFC.Features, 2, "expected 2 features")
}

// TestAdaptRequestForOrigin tests request adaptation for specific origins
func TestAdaptRequestForOrigin(t *testing.T) {
	t.Parallel()

	handler := &Handler{}

	tests := []struct {
		name                string
		req                 *stac.SearchRequest
		origin              *Origin
		expectedCollections []string
	}{
		{
			name: "no adaptation needed",
			req: &stac.SearchRequest{
				Collections: []string{"coll1", "coll2"},
			},
			origin: &Origin{
				ID: "origin1",
			},
			expectedCollections: []string{"coll1", "coll2"},
		},
		{
			name: "collection mapping applied",
			req: &stac.SearchRequest{
				Collections: []string{"coll1", "coll2"},
			},
			origin: &Origin{
				ID: "origin1",
				CollectionMapping: map[string]string{
					"coll1": "mapped_coll1",
				},
			},
			expectedCollections: []string{"mapped_coll1", "coll2"},
		},
		{
			name: "collection prefix stripped",
			req: &stac.SearchRequest{
				Collections: []string{"prefix_coll1", "prefix_coll2"},
			},
			origin: &Origin{
				ID:               "origin1",
				CollectionPrefix: "prefix_",
			},
			expectedCollections: []string{"coll1", "coll2"},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			adapted := handler.adaptRequestForOrigin(tt.req, tt.origin)

			assert.Equal(t, tt.expectedCollections, adapted.Collections, "collections")
		})
	}
}

// TestFanOutSearch tests parallel search execution
func TestFanOutSearch(t *testing.T) {
	// Create multiple test servers
	origins := make([]*Origin, 3)
	for i := 0; i < 3; i++ {
		fc := SampleFeatureCollection(
			SampleItem("item" + string(rune('1'+i))),
		)
		server := NewTestServerWithJSONResponse(fc)
		defer server.Close()

		origins[i] = &Origin{
			ID:          "origin" + string(rune('1'+i)),
			BaseURL:     server.URL,
			Enabled:     true,
			Searchable:  true,
			Collections: []string{"collection1"},
			Timeout:     5 * time.Second,
			Priority:    i + 1,
		}
	}

	handler, err := NewHandler(HandlerConfig{
		Origins:          origins,
		ConflictStrategy: ConflictPriorityWins,
		MaxConcurrent:    2, // Test concurrency limit
	})
	require.NoError(t, err, "failed to create handler")

	searchReq := SampleSearchRequest(
		WithCollections("collection1"),
		WithLimit(10),
	)

	ctx := context.Background()
	results := handler.fanOutSearch(ctx, origins, searchReq)

	assert.Len(t, results, 3, "expected 3 results")

	// All results should be successful
	for _, result := range results {
		assert.NoError(t, result.Error, "unexpected error in result")
		assert.Len(t, result.Items, 1, "expected 1 item")
	}
}

// TestSearchOrigin tests single origin search
func TestSearchOrigin(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		mockFC    *stac.FeatureCollection
		mockError error
		wantError bool
	}{
		{
			name: "successful search",
			mockFC: SampleFeatureCollection(
				SampleItem("item1"),
				SampleItem("item2"),
			),
			wantError: false,
		},
		{
			name:      "search error",
			mockFC:    nil,
			mockError: errors.New("search failed"),
			wantError: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var server *httptest.Server
			if tt.mockFC != nil {
				server = NewTestServerWithJSONResponse(tt.mockFC)
			} else {
				server = NewTestServerWithError(http.StatusInternalServerError, "error")
			}
			defer server.Close()

			origin := &Origin{
				ID:          "origin1",
				BaseURL:     server.URL,
				Enabled:     true,
				Searchable:  true,
				Collections: []string{"collection1"},
				Timeout:     5 * time.Second,
				Priority:    1,
			}

			handler, err := NewHandler(HandlerConfig{
				Origins:          []*Origin{origin},
				ConflictStrategy: ConflictPriorityWins,
			})
			require.NoError(t, err, "failed to create handler")

			searchReq := SampleSearchRequest(
				WithCollections("collection1"),
			)

			result := handler.searchOrigin(context.Background(), origin, searchReq)

			if tt.wantError {
				assert.Error(t, result.Error, "expected error but got nil")
			} else {
				assert.NoError(t, result.Error, "unexpected error")
				assert.Lenf(t, result.Items, len(tt.mockFC.Features), "expected %d items", len(tt.mockFC.Features))
			}
		})
	}
}

// TestHandlerPaginationLimits tests pagination limit enforcement
func TestHandlerPaginationLimits(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		requestLimit  int
		defaultLimit  int
		maxLimit      int
		expectedLimit int
	}{
		{
			name:          "use request limit when valid",
			requestLimit:  50,
			defaultLimit:  100,
			maxLimit:      1000,
			expectedLimit: 50,
		},
		{
			name:          "use default when request limit is 0",
			requestLimit:  0,
			defaultLimit:  100,
			maxLimit:      1000,
			expectedLimit: 100,
		},
		{
			name:          "cap at max limit",
			requestLimit:  5000,
			defaultLimit:  100,
			maxLimit:      1000,
			expectedLimit: 1000,
		},
		{
			name:          "negative limit uses default",
			requestLimit:  -10,
			defaultLimit:  100,
			maxLimit:      1000,
			expectedLimit: 100,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			fc := SampleFeatureCollection(
				SampleItem("item1"),
			)
			server := NewTestServerWithJSONResponse(fc)
			defer server.Close()

			handler, err := NewHandler(HandlerConfig{
				Origins: []*Origin{
					{
						ID:          "origin1",
						BaseURL:     server.URL,
						Enabled:     true,
						Searchable:  true,
						Collections: []string{"collection1"},
						Timeout:     5 * time.Second,
					},
				},
				ConflictStrategy: ConflictPriorityWins,
				DefaultPageSize:  tt.defaultLimit,
				MaxPageSize:      tt.maxLimit,
			})
			require.NoError(t, err, "failed to create handler")

			searchReq := SampleSearchRequest(
				WithCollections("collection1"),
				WithLimit(tt.requestLimit),
			)

			req := &request{
				Request:     httptest.NewRequest(http.MethodPost, "/search", nil),
				Context:     context.Background(),
				RequestType: middleware.RequestTypeSearch,
				SearchReq:   searchReq,
			}

			resp, err := handler.Handle(req.Context, req)
			require.NoError(t, err, "Handle()")

			var fc2 stac.FeatureCollection
			require.NoError(t, json.Unmarshal(resp.Body, &fc2), "failed to parse response")

			// The limit should be applied (Context.Limit may be set)
			// We can't directly verify the limit sent to origin, but we can verify
			// that the handler processed it correctly
			assert.Equal(t, tt.expectedLimit, searchReq.Limit, "searchReq.Limit")
		})
	}
}

// TestHandleWithNoMatchingOrigins tests handling when no origins match
func TestHandleWithNoMatchingOrigins(t *testing.T) {
	t.Parallel()

	handler, err := NewHandler(HandlerConfig{
		Origins: []*Origin{
			{
				ID:          "origin1",
				BaseURL:     "http://example.com",
				Enabled:     true,
				Searchable:  true,
				Collections: []string{"other-collection"},
				Timeout:     5 * time.Second,
			},
		},
		ConflictStrategy: ConflictPriorityWins,
	})
	require.NoError(t, err, "failed to create handler")

	// Search for a collection not served by any origin
	req := &request{
		Request:     httptest.NewRequest(http.MethodPost, "/search", nil),
		Context:     context.Background(),
		RequestType: middleware.RequestTypeSearch,
		SearchReq: SampleSearchRequest(
			WithCollections("nonexistent-collection"),
		),
	}

	resp, err := handler.Handle(req.Context, req)
	require.NoError(t, err, "Handle()")

	assert.Equal(t, http.StatusOK, resp.StatusCode, "StatusCode")

	var fc stac.FeatureCollection
	require.NoError(t, json.Unmarshal(resp.Body, &fc), "failed to parse response")

	assert.Empty(t, fc.Features, "expected 0 features")
}

// TestHandleCollectionPriority tests that higher priority origins are tried first
func TestHandleCollectionPriority(t *testing.T) {
	t.Parallel()

	// Create two servers, one that will fail and one that will succeed
	failServer := NewTestServerWithError(http.StatusNotFound, "not found")
	defer failServer.Close()

	coll := SampleCollection("test-collection")
	successServer := NewTestServerWithJSONResponse(coll)
	defer successServer.Close()

	handler, err := NewHandler(HandlerConfig{
		Origins: []*Origin{
			{
				ID:          "high-priority",
				BaseURL:     failServer.URL,
				Enabled:     true,
				Searchable:  true,
				Collections: []string{"test-collection"},
				Priority:    1, // Higher priority (lower number)
				Timeout:     5 * time.Second,
			},
			{
				ID:          "low-priority",
				BaseURL:     successServer.URL,
				Enabled:     true,
				Searchable:  true,
				Collections: []string{"test-collection"},
				Priority:    2, // Lower priority
				Timeout:     5 * time.Second,
			},
		},
		ConflictStrategy: ConflictPriorityWins,
	})
	require.NoError(t, err, "failed to create handler")

	req := &request{
		Request:     httptest.NewRequest(http.MethodGet, "/collections/test-collection", nil),
		Context:     context.Background(),
		RequestType: middleware.RequestTypeCollection,
		Collection:  "test-collection",
	}

	resp, err := handler.Handle(req.Context, req)
	require.NoError(t, err, "Handle()")

	// Should succeed with lower priority origin after higher priority fails
	assert.Equal(t, http.StatusOK, resp.StatusCode, "StatusCode")
}

// TestHandleSearchWithBbox tests search with bounding box
func TestHandleSearchWithBbox(t *testing.T) {
	t.Parallel()

	fc := SampleFeatureCollection(
		SampleItem("item1"),
	)
	server := NewTestServerWithJSONResponse(fc)
	defer server.Close()

	handler, err := NewHandler(HandlerConfig{
		Origins: []*Origin{
			{
				ID:         "origin1",
				BaseURL:    server.URL,
				Enabled:    true,
				Searchable: true,
				Timeout:    5 * time.Second,
			},
		},
		ConflictStrategy: ConflictPriorityWins,
	})
	require.NoError(t, err, "failed to create handler")

	req := &request{
		Request:     httptest.NewRequest(http.MethodPost, "/search", nil),
		Context:     context.Background(),
		RequestType: middleware.RequestTypeSearch,
		SearchReq: SampleSearchRequest(
			WithSearchBbox(SampleBbox()),
		),
	}

	resp, err := handler.Handle(req.Context, req)
	require.NoError(t, err, "Handle()")

	assert.Equal(t, http.StatusOK, resp.StatusCode, "StatusCode")
}

// TestHandleSearchWithDatetime tests search with datetime filter
func TestHandleSearchWithDatetime(t *testing.T) {
	t.Parallel()

	fc := SampleFeatureCollection(
		SampleItem("item1"),
	)
	server := NewTestServerWithJSONResponse(fc)
	defer server.Close()

	handler, err := NewHandler(HandlerConfig{
		Origins: []*Origin{
			{
				ID:         "origin1",
				BaseURL:    server.URL,
				Enabled:    true,
				Searchable: true,
				Timeout:    5 * time.Second,
			},
		},
		ConflictStrategy: ConflictPriorityWins,
	})
	require.NoError(t, err, "failed to create handler")

	req := &request{
		Request:     httptest.NewRequest(http.MethodPost, "/search", nil),
		Context:     context.Background(),
		RequestType: middleware.RequestTypeSearch,
		SearchReq: SampleSearchRequest(
			WithSearchDatetime("2023-01-01T00:00:00Z/2023-12-31T23:59:59Z"),
		),
	}

	resp, err := handler.Handle(req.Context, req)
	require.NoError(t, err, "Handle()")

	assert.Equal(t, http.StatusOK, resp.StatusCode, "StatusCode")
}

// paginatingTestServer is a minimal STAC search backend used to drive
// multi-page federation tests. It owns an ordered list of items and
// honors `?token=off-<N>` for cursor-style pagination.
type paginatingTestServer struct {
	id     string
	items  []*stac.Item
	server *httptest.Server
	mu     sync.Mutex
	calls  int
}

func newPaginatingTestServer(t *testing.T, id string, items []*stac.Item) *paginatingTestServer {
	t.Helper()
	p := &paginatingTestServer{id: id, items: items}
	p.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		p.calls++
		p.mu.Unlock()

		var body struct {
			Token string `json:"token"`
			Limit int    `json:"limit"`
		}
		if r.Body != nil {
			defer r.Body.Close()
			_ = json.NewDecoder(r.Body).Decode(&body)
		}

		offset := 0
		if body.Token != "" {
			_, _ = fmt.Sscanf(body.Token, "off-%d", &offset)
		}
		limit := body.Limit
		if limit <= 0 {
			limit = len(items)
		}

		end := offset + limit
		if end > len(items) {
			end = len(items)
		}
		page := items[offset:end]

		fc := &stac.FeatureCollection{
			Type:     "FeatureCollection",
			Features: page,
			Context:  &stac.SearchContext{Returned: len(page), Limit: limit},
		}
		if end < len(items) {
			nextHref := fmt.Sprintf("%s/search?token=off-%d", p.server.URL, end)
			fc.Links = append(fc.Links, &stac.Link{Rel: "next", Href: nextHref, Type: "application/geo+json"})
		}

		w.Header().Set("Content-Type", "application/geo+json")
		_ = json.NewEncoder(w).Encode(fc)
	}))
	t.Cleanup(p.server.Close)
	return p
}

// TestHandleSearch_MultiPageFederation drives B1 end-to-end: two
// paginating origins walked across multiple pages via the proxy's
// signed cursor. Asserts every item appears exactly once, cursor
// signatures survive a round-trip, and tampered cursors are rejected.
func TestHandleSearch_MultiPageFederation(t *testing.T) {
	t.Parallel()

	makeItem := func(id string, day int) *stac.Item {
		return SampleItem(id, func(i *stac.Item) {
			i.Properties["datetime"] = time.Date(2024, 1, day, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
		})
	}

	originA := newPaginatingTestServer(t, "origin-a", []*stac.Item{
		makeItem("a-1", 30), makeItem("a-2", 28), makeItem("a-3", 26),
		makeItem("a-4", 24), makeItem("a-5", 22), makeItem("a-6", 20),
		makeItem("a-7", 18), makeItem("a-8", 16), makeItem("a-9", 14),
		makeItem("a-10", 12),
	})
	originB := newPaginatingTestServer(t, "origin-b", []*stac.Item{
		makeItem("b-1", 29), makeItem("b-2", 27), makeItem("b-3", 25),
		makeItem("b-4", 23), makeItem("b-5", 21), makeItem("b-6", 19),
		makeItem("b-7", 17), makeItem("b-8", 15),
	})

	origins := []*Origin{
		{ID: "origin-a", BaseURL: originA.server.URL, Enabled: true, Searchable: true, Collections: []string{"test-collection"}, Timeout: 5 * time.Second, Priority: 1},
		{ID: "origin-b", BaseURL: originB.server.URL, Enabled: true, Searchable: true, Collections: []string{"test-collection"}, Timeout: 5 * time.Second, Priority: 1},
	}

	handler, err := NewHandler(HandlerConfig{
		Origins:          origins,
		ConflictStrategy: ConflictPriorityWins,
		MaxConcurrent:    4,
		AggregateTimeout: 10 * time.Second,
		DefaultPageSize:  3,
		MaxPageSize:      100,
		CursorSecret:     []byte("test-secret-for-handler-pagination"),
		ProxyBaseURL:     "https://proxy.example.test",
	})
	require.NoError(t, err, "NewHandler")
	require.NotNil(t, handler.searcher, "expected paginated searcher to be initialized")

	seen := map[string]int{}
	var pageSizes []int
	cursor := ""
	for page := 0; page < 10; page++ {
		searchReq := &stac.SearchRequest{
			Collections: []string{"test-collection"},
			Limit:       3,
			Token:       cursor,
		}
		r := httptest.NewRequest(http.MethodGet, "/search?limit=3", nil)
		req := &request{
			Request:     r,
			Context:     context.Background(),
			RequestType: middleware.RequestTypeSearch,
			SearchReq:   searchReq,
		}
		resp, err := handler.Handle(req.Context, req)
		require.NoErrorf(t, err, "page %d: Handle", page)
		var fc stac.FeatureCollection
		require.NoErrorf(t, json.Unmarshal(resp.Body, &fc), "page %d: unmarshal", page)
		pageSizes = append(pageSizes, len(fc.Features))
		for _, it := range fc.Features {
			seen[it.ID]++
		}
		next := stac.ExtractNextLink(fc.Links)
		if next == nil {
			break
		}
		u, err := url.Parse(next.Href)
		require.NoErrorf(t, err, "page %d: parse next href %q", page, next.Href)
		assert.Truef(t, strings.HasPrefix(next.Href, "https://proxy.example.test/search"), "page %d: next.Href should be proxy-rooted, got %q", page, next.Href)
		tok := u.Query().Get("token")
		require.NotEmptyf(t, tok, "page %d: next link missing token", page)
		cursor = tok
	}

	// Wiring assertions for B1 (paginated searcher integration):
	// 1. Multiple pages are produced when datasets exceed limit.
	// 2. Items returned to the client are unique across pages
	//    (cross-page dedup via the searcher's deduplicator).
	// Total item coverage is governed by H5 (keyset resume) and is
	// intentionally out of scope here.
	assert.GreaterOrEqualf(t, len(pageSizes), 2, "expected at least 2 pages, got %d (sizes=%v)", len(pageSizes), pageSizes)
	for id, n := range seen {
		assert.Equalf(t, 1, n, "item %q returned %d times across pages, want 1", id, n)
	}
	assert.GreaterOrEqualf(t, len(seen), 4, "expected at least 4 unique items across pages, got %d", len(seen))

	// Tampered cursor: a malformed token must be rejected.
	r := httptest.NewRequest(http.MethodGet, "/search?limit=3", nil)
	tampered := &stac.SearchRequest{
		Collections: []string{"test-collection"},
		Limit:       3,
		Token:       "AAAA.BBBB",
	}
	req := &request{
		Request:     r,
		Context:     context.Background(),
		RequestType: middleware.RequestTypeSearch,
		SearchReq:   tampered,
	}
	_, err = handler.Handle(req.Context, req)
	assert.Error(t, err, "expected error on tampered cursor")
}

// TestHandleItems_FederatedAcrossOrigins drives B3: a federated
// /collections/{id}/items request must walk multiple origins and
// return items from each, scoped to the URL's collection.
func TestHandleItems_FederatedAcrossOrigins(t *testing.T) {
	t.Parallel()

	makeItem := func(id string, day int) *stac.Item {
		return SampleItem(id, func(i *stac.Item) {
			i.Collection = "shared"
			i.Properties["datetime"] = time.Date(2024, 1, day, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
		})
	}
	originA := newPaginatingTestServer(t, "origin-a", []*stac.Item{
		makeItem("a-1", 10), makeItem("a-2", 8),
	})
	originB := newPaginatingTestServer(t, "origin-b", []*stac.Item{
		makeItem("b-1", 9), makeItem("b-2", 7),
	})
	origins := []*Origin{
		{ID: "origin-a", BaseURL: originA.server.URL, Enabled: true, Searchable: true, Collections: []string{"shared"}, Timeout: 5 * time.Second, Priority: 1},
		{ID: "origin-b", BaseURL: originB.server.URL, Enabled: true, Searchable: true, Collections: []string{"shared"}, Timeout: 5 * time.Second, Priority: 1},
	}

	handler, err := NewHandler(HandlerConfig{
		Origins:          origins,
		ConflictStrategy: ConflictPriorityWins,
		MaxConcurrent:    4,
		AggregateTimeout: 10 * time.Second,
		DefaultPageSize:  10,
		MaxPageSize:      100,
		CursorSecret:     []byte("test-secret-for-items"),
	})
	require.NoError(t, err, "NewHandler")

	r := httptest.NewRequest(http.MethodGet, "/collections/shared/items", nil)
	req := &request{
		Request:     r,
		Context:     context.Background(),
		RequestType: middleware.RequestTypeItems,
		Collection:  "shared",
	}
	resp, err := handler.Handle(req.Context, req)
	require.NoError(t, err, "Handle")
	assert.Equal(t, http.StatusOK, resp.StatusCode, "StatusCode")

	var fc stac.FeatureCollection
	require.NoError(t, json.Unmarshal(resp.Body, &fc), "unmarshal")
	// Both origins contribute — at minimum we want items from each.
	gotA, gotB := false, false
	for _, it := range fc.Features {
		if strings.HasPrefix(it.ID, "a-") {
			gotA = true
		}
		if strings.HasPrefix(it.ID, "b-") {
			gotB = true
		}
	}
	assert.Truef(t, gotA && gotB, "federated items missing an origin: gotA=%v gotB=%v ids=%v", gotA, gotB, featureIDs(&fc))
}

// TestHandleQueryables_IntersectsAcrossOrigins drives B4: the merged
// queryables schema includes only properties that every origin agrees
// on; properties unique to one origin are dropped.
func TestHandleQueryables_IntersectsAcrossOrigins(t *testing.T) {
	t.Parallel()

	makeServer := func(schema map[string]any) *httptest.Server {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/schema+json")
			_ = json.NewEncoder(w).Encode(schema)
		}))
		t.Cleanup(s.Close)
		return s
	}

	schemaA := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"datetime":        map[string]any{"type": "string"},
			"eo:cloud_cover":  map[string]any{"type": "number"},
			"a_only_property": map[string]any{"type": "string"},
		},
	}
	schemaB := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"datetime":        map[string]any{"type": "string"},
			"eo:cloud_cover":  map[string]any{"type": "number"},
			"b_only_property": map[string]any{"type": "boolean"},
		},
	}
	srvA := makeServer(schemaA)
	srvB := makeServer(schemaB)

	origins := []*Origin{
		{ID: "a", BaseURL: srvA.URL, Enabled: true, Searchable: true, Timeout: 5 * time.Second, Priority: 1},
		{ID: "b", BaseURL: srvB.URL, Enabled: true, Searchable: true, Timeout: 5 * time.Second, Priority: 1},
	}
	handler, err := NewHandler(HandlerConfig{
		Origins:          origins,
		ConflictStrategy: ConflictPriorityWins,
		MaxConcurrent:    4,
		AggregateTimeout: 5 * time.Second,
	})
	require.NoError(t, err, "NewHandler")

	r := httptest.NewRequest(http.MethodGet, "/queryables", nil)
	req := &request{
		Request:     r,
		Context:     context.Background(),
		RequestType: middleware.RequestTypeQueryables,
	}
	resp, err := handler.Handle(req.Context, req)
	require.NoError(t, err, "Handle")
	require.Equal(t, http.StatusOK, resp.StatusCode, "StatusCode")

	var merged map[string]any
	require.NoError(t, json.Unmarshal(resp.Body, &merged), "unmarshal")
	props, _ := merged["properties"].(map[string]any)
	assert.Contains(t, props, "datetime", "expected 'datetime' in intersected properties")
	assert.Contains(t, props, "eo:cloud_cover", "expected 'eo:cloud_cover' in intersected properties")
	assert.NotContains(t, props, "a_only_property", "a_only_property should have been dropped (origin-B lacks it)")
	assert.NotContains(t, props, "b_only_property", "b_only_property should have been dropped (origin-A lacks it)")
}

func featureIDs(fc *stac.FeatureCollection) []string {
	out := make([]string, 0, len(fc.Features))
	for _, it := range fc.Features {
		out = append(out, it.ID)
	}
	return out
}

// blockingSigner blocks in Sign until ctx is done, then returns the
// underlying ctx error formatted as a string. Used to verify that the
// rewrite path threads the inbound request context (not a fresh
// context.Background()) through to the signer.
type blockingSigner struct{}

func (blockingSigner) Sign(ctx context.Context, _ string, _ time.Duration) string {
	<-ctx.Done()
	return "cancelled:" + ctx.Err().Error()
}

// TestRewriteAssetHref_RespectsRequestCancellation is a regression
// test for H-federation-1: the rewrite path used to call
// assetSigner.Sign(context.Background(), ...), which detached the
// signer from the inbound request. With the fix, ctx flows from the
// HTTP layer through transformResponse → rewriteLinks →
// rewriteAssetHref → AssetSigner.Sign, so cancelling the request
// promptly unblocks the signer.
func TestRewriteAssetHref_RespectsRequestCancellation(t *testing.T) {
	t.Parallel()

	client, err := NewOriginClient(&Origin{
		ID:            "a",
		BaseURL:       "https://upstream.example",
		Enabled:       true,
		Timeout:       time.Second,
		RewriteAssets: "sign",
	})
	require.NoError(t, err, "client")

	h := &Handler{
		proxyBaseURL: "https://proxy.example",
		assetSigner:  blockingSigner{},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	done := make(chan string, 1)
	start := time.Now()
	go func() {
		done <- h.rewriteAssetHref(ctx, client, "https://upstream.example/items/x/asset.tif")
	}()

	select {
	case got := <-done:
		elapsed := time.Since(start)
		assert.LessOrEqualf(t, elapsed, 200*time.Millisecond, "rewrite returned after %s, want < 200ms", elapsed)
		assert.Truef(t, strings.HasPrefix(got, "cancelled:"), "got %q, want cancellation sentinel", got)
	case <-time.After(2 * time.Second):
		t.Fatal("rewriteAssetHref did not return after request cancellation")
	}
}

// TestTransformResponse_SkipsDecodeWhenNoRewriteNeeded is the
// M-federation-1 regression: a JSON body with no "links" or "assets"
// keys must not be unmarshaled+remarshaled. We assert the body bytes
// pass through *unchanged*, which proves the JSON round-trip was
// avoided (any round-trip would re-key in unspecified order and lose
// formatting whitespace).
func TestTransformResponse_SkipsDecodeWhenNoRewriteNeeded(t *testing.T) {
	t.Parallel()

	client, err := NewOriginClient(&Origin{
		ID:      "a",
		BaseURL: "https://upstream.example",
		Enabled: true,
		Timeout: time.Second,
	})
	require.NoError(t, err, "client")

	h := &Handler{proxyBaseURL: "https://proxy.example"}

	// A "large" body with no top-level links/assets — pretend it's a
	// JSON shape we don't recognize. Whitespace formatting is
	// preserved so we can detect any re-marshal.
	body := []byte(`{
    "type":  "SomeOtherShape",
    "data":  ["a", "b", "c"],
    "stats": {"count": 3, "bytes": 12345}
}`)
	original := append([]byte(nil), body...)

	resp := &response{
		StatusCode: 200,
		Headers:    http.Header{"Content-Type": []string{"application/json"}},
		Body:       body,
	}

	out := h.transformResponse(context.Background(), client, resp)

	require.Truef(t, bytes.Equal(out.Body, original), "body was mutated; expected pass-through.\n got: %s\nwant: %s", out.Body, original)
}

// TestRewriteLinks_DoesNotRecurseIntoProperties is the M-federation-2
// regression: STAC items carry arbitrary user data under "properties"
// and the rewriter must not descend into that subtree. We construct a
// feature whose properties map contains a key literally named "links"
// — an attacker-crafted shape that previously would have triggered
// URL rewriting on user-supplied data. Only top-level links should be
// rewritten.
func TestRewriteLinks_DoesNotRecurseIntoProperties(t *testing.T) {
	t.Parallel()

	client, err := NewOriginClient(&Origin{
		ID:      "a",
		BaseURL: "https://upstream.example",
		Enabled: true,
		Timeout: time.Second,
	})
	require.NoError(t, err, "client")

	h := &Handler{proxyBaseURL: "https://proxy.example"}

	feature := map[string]interface{}{
		"type": "Feature",
		"id":   "x",
		"links": []interface{}{
			map[string]interface{}{
				"rel":  "self",
				"href": "https://upstream.example/items/x",
			},
		},
		// User-supplied properties — must NOT be touched.
		"properties": map[string]interface{}{
			"datetime": "2025-01-01T00:00:00Z",
			"links": []interface{}{
				map[string]interface{}{
					"rel":  "evil",
					"href": "https://upstream.example/should/not/be/rewritten",
				},
			},
			"nested": map[string]interface{}{
				"href": "https://upstream.example/also/should/stay",
			},
		},
	}

	h.rewriteLinks(context.Background(), client, feature)

	// Top-level link IS rewritten.
	topLinks := feature["links"].([]interface{})
	topHref := topLinks[0].(map[string]interface{})["href"].(string)
	assert.Equal(t, "https://proxy.example/items/x", topHref, "top-level link not rewritten")

	// Properties subtree is untouched.
	props := feature["properties"].(map[string]interface{})
	propLinks := props["links"].([]interface{})
	propHref := propLinks[0].(map[string]interface{})["href"].(string)
	assert.Equal(t, "https://upstream.example/should/not/be/rewritten", propHref, "properties.links was rewritten")
	nestedHref := props["nested"].(map[string]interface{})["href"].(string)
	assert.Equal(t, "https://upstream.example/also/should/stay", nestedHref, "properties.nested was rewritten")
}

// TestRewriteLinks_RecursesIntoFeatures verifies that the allowlist
// still descends into the spec-described nesting keys — features in a
// FeatureCollection must have their links rewritten.
func TestRewriteLinks_RecursesIntoFeatures(t *testing.T) {
	t.Parallel()

	client, err := NewOriginClient(&Origin{
		ID:      "a",
		BaseURL: "https://upstream.example",
		Enabled: true,
		Timeout: time.Second,
	})
	require.NoError(t, err, "client")
	h := &Handler{proxyBaseURL: "https://proxy.example"}

	fc := map[string]interface{}{
		"type": "FeatureCollection",
		"features": []interface{}{
			map[string]interface{}{
				"type": "Feature",
				"id":   "x",
				"links": []interface{}{
					map[string]interface{}{"rel": "self", "href": "https://upstream.example/items/x"},
				},
			},
		},
	}
	h.rewriteLinks(context.Background(), client, fc)

	feature := fc["features"].([]interface{})[0].(map[string]interface{})
	href := feature["links"].([]interface{})[0].(map[string]interface{})["href"].(string)
	assert.Equal(t, "https://proxy.example/items/x", href, "feature link not rewritten")
}
