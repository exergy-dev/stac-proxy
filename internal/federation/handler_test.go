package federation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yourorg/stac-proxy/internal/middleware"
	"github.com/yourorg/stac-proxy/internal/stac"
	"github.com/yourorg/stac-proxy/internal/testutil"
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
				if err == nil {
					t.Error("expected error but got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if handler == nil {
				t.Fatal("handler is nil")
			}

			if got := handler.OriginCount(); got != tt.wantOrigins {
				t.Errorf("OriginCount() = %d, want %d", got, tt.wantOrigins)
			}

			// Check default values
			if handler.maxConcurrent <= 0 {
				t.Error("maxConcurrent not set to default")
			}
			if handler.aggregateTimeout <= 0 {
				t.Error("aggregateTimeout not set to default")
			}
			if handler.defaultPageSize <= 0 {
				t.Error("defaultPageSize not set to default")
			}
			if handler.maxPageSize <= 0 {
				t.Error("maxPageSize not set to default")
			}
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
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	ids := handler.OriginIDs()
	if len(ids) != 2 {
		t.Errorf("expected 2 origin IDs, got %d", len(ids))
	}

	// Check both IDs are present (order may vary)
	idMap := make(map[string]bool)
	for _, id := range ids {
		idMap[id] = true
	}

	if !idMap["origin1"] || !idMap["origin2"] {
		t.Errorf("expected origin1 and origin2, got %v", ids)
	}
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
			searchReq: testutil.SampleSearchRequest(
				testutil.WithCollections("collection1"),
				testutil.WithLimit(10),
			),
			mockResponses: map[string]*stac.FeatureCollection{
				"origin1": testutil.SampleFeatureCollection(
					testutil.SampleItem("item1", testutil.WithCollection("collection1")),
					testutil.SampleItem("item2", testutil.WithCollection("collection1")),
				),
				"origin2": testutil.SampleFeatureCollection(
					testutil.SampleItem("item3", testutil.WithCollection("collection1")),
				),
			},
			expectedItems:  3,
			expectedStatus: http.StatusOK,
		},
		{
			name: "search with no results",
			searchReq: testutil.SampleSearchRequest(
				testutil.WithCollections("nonexistent"),
				testutil.WithLimit(10),
			),
			mockResponses:  map[string]*stac.FeatureCollection{},
			expectedItems:  0,
			expectedStatus: http.StatusOK,
		},
		{
			name: "search with limit applied",
			searchReq: testutil.SampleSearchRequest(
				testutil.WithCollections("collection1"),
				testutil.WithLimit(2),
			),
			mockResponses: map[string]*stac.FeatureCollection{
				"origin1": testutil.SampleFeatureCollection(
					testutil.SampleItem("item1", testutil.WithCollection("collection1")),
					testutil.SampleItem("item2", testutil.WithCollection("collection1")),
					testutil.SampleItem("item3", testutil.WithCollection("collection1")),
				),
			},
			expectedItems:  2,
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
				server := testutil.NewTestServerWithJSONResponse(fc)
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
			if err != nil {
				t.Fatalf("failed to create handler: %v", err)
			}

			// Create request
			req := &middleware.STACRequest{
				Request:     httptest.NewRequest(http.MethodPost, "/search", nil),
				Context:     context.Background(),
				RequestType: middleware.RequestTypeSearch,
				SearchReq:   tt.searchReq,
			}

			// Execute
			resp, err := handler.Handle(req.Context, req)
			if err != nil {
				t.Fatalf("Handle() error = %v", err)
			}

			if resp.StatusCode != tt.expectedStatus {
				t.Errorf("StatusCode = %d, want %d", resp.StatusCode, tt.expectedStatus)
			}

			// Parse response
			var fc stac.FeatureCollection
			if err := json.Unmarshal(resp.Body, &fc); err != nil {
				t.Fatalf("failed to parse response: %v", err)
			}

			if len(fc.Features) != tt.expectedItems {
				t.Errorf("got %d items, want %d", len(fc.Features), tt.expectedItems)
			}
		})
	}
}

// TestHandleSearchWithErrors tests error handling during search
func TestHandleSearchWithErrors(t *testing.T) {
	t.Parallel()

	// Create one failing and one successful origin
	successFC := testutil.SampleFeatureCollection(
		testutil.SampleItem("item1", testutil.WithCollection("collection1")),
	)
	successServer := testutil.NewTestServerWithJSONResponse(successFC)
	defer successServer.Close()

	failServer := testutil.NewTestServerWithError(http.StatusInternalServerError, "origin error")
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
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	req := &middleware.STACRequest{
		Request:     httptest.NewRequest(http.MethodPost, "/search", nil),
		Context:     context.Background(),
		RequestType: middleware.RequestTypeSearch,
		SearchReq: testutil.SampleSearchRequest(
			testutil.WithCollections("collection1"),
			testutil.WithLimit(10),
		),
	}

	resp, err := handler.Handle(req.Context, req)
	if err != nil {
		t.Fatalf("Handle() error = %v", err)
	}

	// Should still succeed with results from successful origin
	var fc stac.FeatureCollection
	if err := json.Unmarshal(resp.Body, &fc); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if len(fc.Features) != 1 {
		t.Errorf("expected 1 item from successful origin, got %d", len(fc.Features))
	}
}

// TestHandleSearchTimeout tests timeout handling
func TestHandleSearchTimeout(t *testing.T) {
	// Create a slow server
	slowServer := testutil.NewTestServerWithDelay(2*time.Second, testutil.SampleFeatureCollection(
		testutil.SampleItem("item1"),
	))
	defer slowServer.Close()

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
		},
		ConflictStrategy: ConflictPriorityWins,
		MaxConcurrent:    10,
		AggregateTimeout: 100 * time.Millisecond, // Very short timeout
	})
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	req := &middleware.STACRequest{
		Request:     httptest.NewRequest(http.MethodPost, "/search", nil),
		Context:     context.Background(),
		RequestType: middleware.RequestTypeSearch,
		SearchReq: testutil.SampleSearchRequest(
			testutil.WithCollections("collection1"),
		),
	}

	resp, err := handler.Handle(req.Context, req)
	if err != nil {
		t.Fatalf("Handle() error = %v", err)
	}

	// Should return empty results due to timeout
	var fc stac.FeatureCollection
	if err := json.Unmarshal(resp.Body, &fc); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if len(fc.Features) != 0 {
		t.Errorf("expected 0 items due to timeout, got %d", len(fc.Features))
	}
}

// TestHandleSearchContextCancellation tests context cancellation
func TestHandleSearchContextCancellation(t *testing.T) {
	// Create a slow server
	slowServer := testutil.NewTestServerWithDelay(2*time.Second, testutil.SampleFeatureCollection(
		testutil.SampleItem("item1"),
	))
	defer slowServer.Close()

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
		},
		ConflictStrategy: ConflictPriorityWins,
		MaxConcurrent:    10,
		AggregateTimeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	req := &middleware.STACRequest{
		Request:     httptest.NewRequest(http.MethodPost, "/search", nil),
		Context:     ctx,
		RequestType: middleware.RequestTypeSearch,
		SearchReq: testutil.SampleSearchRequest(
			testutil.WithCollections("collection1"),
		),
	}

	resp, err := handler.Handle(req.Context, req)
	if err != nil {
		t.Fatalf("Handle() error = %v", err)
	}

	// Should return empty results
	var fc stac.FeatureCollection
	if err := json.Unmarshal(resp.Body, &fc); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if len(fc.Features) != 0 {
		t.Errorf("expected 0 items due to cancellation, got %d", len(fc.Features))
	}
}

// TestHandleGetCollections tests collection listing
func TestHandleGetCollections(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		mockResponses     map[string][]stac.Collection
		expectedCollCount int
		expectedStatus    int
	}{
		{
			name: "collections from multiple origins",
			mockResponses: map[string][]stac.Collection{
				"origin1": {
					*testutil.SampleCollection("coll1"),
					*testutil.SampleCollection("coll2"),
				},
				"origin2": {
					*testutil.SampleCollection("coll3"),
				},
			},
			expectedCollCount: 3,
			expectedStatus:    http.StatusOK,
		},
		{
			name: "duplicate collections deduplicated",
			mockResponses: map[string][]stac.Collection{
				"origin1": {
					*testutil.SampleCollection("coll1"),
				},
				"origin2": {
					*testutil.SampleCollection("coll1"), // Same ID
				},
			},
			expectedCollCount: 1,
			expectedStatus:    http.StatusOK,
		},
		{
			name:              "no collections",
			mockResponses:     map[string][]stac.Collection{},
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
				server := testutil.NewTestServerWithJSONResponse(resp)
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
			if err != nil {
				t.Fatalf("failed to create handler: %v", err)
			}

			req := &middleware.STACRequest{
				Request:     httptest.NewRequest(http.MethodGet, "/collections", nil),
				Context:     context.Background(),
				RequestType: middleware.RequestTypeCollections,
			}

			resp, err := handler.Handle(req.Context, req)
			if err != nil {
				t.Fatalf("Handle() error = %v", err)
			}

			if resp.StatusCode != tt.expectedStatus {
				t.Errorf("StatusCode = %d, want %d", resp.StatusCode, tt.expectedStatus)
			}

			var collResp stac.CollectionsResponse
			if err := json.Unmarshal(resp.Body, &collResp); err != nil {
				t.Fatalf("failed to parse response: %v", err)
			}

			if len(collResp.Collections) != tt.expectedCollCount {
				t.Errorf("got %d collections, want %d", len(collResp.Collections), tt.expectedCollCount)
			}

			// Verify origin metadata is added
			for _, coll := range collResp.Collections {
				if coll.Properties == nil {
					t.Error("collection properties is nil")
					continue
				}
				if _, ok := coll.Properties["stac_proxy:origin"]; !ok {
					t.Error("missing stac_proxy:origin metadata")
				}
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
			mockCollection: testutil.SampleCollection("test-collection"),
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
				server = testutil.NewTestServerWithJSONResponse(tt.mockCollection)
			} else {
				server = testutil.NewTestServerWithError(tt.mockStatus, "not found")
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
			if err != nil {
				t.Fatalf("failed to create handler: %v", err)
			}

			req := &middleware.STACRequest{
				Request:     httptest.NewRequest(http.MethodGet, "/collections/"+tt.collectionID, nil),
				Context:     context.Background(),
				RequestType: middleware.RequestTypeCollection,
				Collection:  tt.collectionID,
			}

			resp, err := handler.Handle(req.Context, req)
			if err != nil {
				t.Fatalf("Handle() error = %v", err)
			}

			if resp.StatusCode != tt.expectedStatus {
				t.Errorf("StatusCode = %d, want %d", resp.StatusCode, tt.expectedStatus)
			}

			if tt.expectedStatus == http.StatusOK {
				var coll stac.Collection
				if err := json.Unmarshal(resp.Body, &coll); err != nil {
					t.Fatalf("failed to parse response: %v", err)
				}

				if coll.ID != tt.collectionID {
					t.Errorf("collection ID = %s, want %s", coll.ID, tt.collectionID)
				}

				// Verify origin metadata
				if coll.Properties == nil {
					t.Error("collection properties is nil")
				} else if _, ok := coll.Properties["stac_proxy:origin"]; !ok {
					t.Error("missing stac_proxy:origin metadata")
				}
			}
		})
	}
}

// TestHandleGetCollectionWithPrefix tests collection retrieval with prefix
func TestHandleGetCollectionWithPrefix(t *testing.T) {
	t.Parallel()

	coll := testutil.SampleCollection("my-collection")
	server := testutil.NewTestServerWithJSONResponse(coll)
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
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	// Request with prefix
	req := &middleware.STACRequest{
		Request:     httptest.NewRequest(http.MethodGet, "/collections/prefix_my-collection", nil),
		Context:     context.Background(),
		RequestType: middleware.RequestTypeCollection,
		Collection:  "prefix_my-collection",
	}

	resp, err := handler.Handle(req.Context, req)
	if err != nil {
		t.Fatalf("Handle() error = %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusOK)
	}
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
			mockItem:       testutil.SampleItem("test-item", testutil.WithCollection("test-collection")),
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
				server = testutil.NewTestServerWithJSONResponse(tt.mockItem)
			} else {
				server = testutil.NewTestServerWithError(tt.mockStatus, "not found")
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
			if err != nil {
				t.Fatalf("failed to create handler: %v", err)
			}

			req := &middleware.STACRequest{
				Request:     httptest.NewRequest(http.MethodGet, "/collections/"+tt.collectionID+"/items/"+tt.itemID, nil),
				Context:     context.Background(),
				RequestType: middleware.RequestTypeItem,
				Collection:  tt.collectionID,
				ItemID:      tt.itemID,
			}

			resp, err := handler.Handle(req.Context, req)
			if err != nil {
				t.Fatalf("Handle() error = %v", err)
			}

			if resp.StatusCode != tt.expectedStatus {
				t.Errorf("StatusCode = %d, want %d", resp.StatusCode, tt.expectedStatus)
			}

			if tt.expectedStatus == http.StatusOK {
				var item stac.Item
				if err := json.Unmarshal(resp.Body, &item); err != nil {
					t.Fatalf("failed to parse response: %v", err)
				}

				if item.ID != tt.itemID {
					t.Errorf("item ID = %s, want %s", item.ID, tt.itemID)
				}

				// Verify origin metadata
				if item.Properties.Extra == nil {
					t.Error("item properties.Extra is nil")
				} else if _, ok := item.Properties.Extra["stac_proxy:origin"]; !ok {
					t.Error("missing stac_proxy:origin metadata")
				}
			}
		})
	}
}

// TestHandleGetItemWithPrefix tests item retrieval with collection prefix
func TestHandleGetItemWithPrefix(t *testing.T) {
	t.Parallel()

	item := testutil.SampleItem("test-item", testutil.WithCollection("my-collection"))
	server := testutil.NewTestServerWithJSONResponse(item)
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
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	// Request with prefix
	req := &middleware.STACRequest{
		Request:     httptest.NewRequest(http.MethodGet, "/collections/prefix_my-collection/items/test-item", nil),
		Context:     context.Background(),
		RequestType: middleware.RequestTypeItem,
		Collection:  "prefix_my-collection",
		ItemID:      "test-item",
	}

	resp, err := handler.Handle(req.Context, req)
	if err != nil {
		t.Fatalf("Handle() error = %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

// TestHandleGenericProxy tests generic request proxying
func TestHandleGenericProxy(t *testing.T) {
	t.Parallel()

	mockResp := map[string]interface{}{
		"message": "generic response",
	}
	server := testutil.NewTestServerWithJSONResponse(mockResp)
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
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	req := &middleware.STACRequest{
		Request:     httptest.NewRequest(http.MethodGet, "/conformance", nil),
		Context:     context.Background(),
		RequestType: middleware.RequestTypeConformance,
	}

	resp, err := handler.Handle(req.Context, req)
	if err != nil {
		t.Fatalf("Handle() error = %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

// TestHandleGenericProxyNoOrigins tests generic proxy with no origins
func TestHandleGenericProxyNoOrigins(t *testing.T) {
	t.Parallel()

	handler, err := NewHandler(HandlerConfig{
		Origins:          []*Origin{},
		ConflictStrategy: ConflictPriorityWins,
	})
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	req := &middleware.STACRequest{
		Request:     httptest.NewRequest(http.MethodGet, "/conformance", nil),
		Context:     context.Background(),
		RequestType: middleware.RequestTypeConformance,
	}

	resp, err := handler.Handle(req.Context, req)
	if err != nil {
		t.Fatalf("Handle() error = %v", err)
	}

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusServiceUnavailable)
	}
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

			var bodyReader *bytes.Reader
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

			req := &middleware.STACRequest{
				Request:     httpReq,
				Context:     httpReq.Context(),
				RequestType: middleware.RequestTypeSearch,
			}

			searchReq, err := handler.parseSearchRequest(req)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			if searchReq == nil {
				t.Error("searchReq is nil")
			}
		})
	}
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
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var fc stac.FeatureCollection
	if err := json.Unmarshal(resp.Body, &fc); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if fc.Type != "FeatureCollection" {
		t.Errorf("Type = %s, want FeatureCollection", fc.Type)
	}

	if len(fc.Features) != 0 {
		t.Errorf("expected 0 features, got %d", len(fc.Features))
	}

	if fc.Context.Returned != 0 {
		t.Errorf("Context.Returned = %d, want 0", fc.Context.Returned)
	}

	if fc.Context.Matched != 0 {
		t.Errorf("Context.Matched = %d, want 0", fc.Context.Matched)
	}
}

// TestBuildSearchResponse tests search response building
func TestBuildSearchResponse(t *testing.T) {
	t.Parallel()

	handler := &Handler{}

	fc := &stac.FeatureCollection{
		Type: "FeatureCollection",
		Features: []stac.Item{
			*testutil.SampleItem("item1"),
			*testutil.SampleItem("item2"),
		},
		Context: &stac.SearchContext{
			Returned: 2,
			Matched:  10,
		},
	}

	req := &middleware.STACRequest{
		Request: httptest.NewRequest(http.MethodPost, "/search", nil),
	}

	resp, err := handler.buildSearchResponse(fc, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var parsedFC stac.FeatureCollection
	if err := json.Unmarshal(resp.Body, &parsedFC); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if len(parsedFC.Features) != 2 {
		t.Errorf("expected 2 features, got %d", len(parsedFC.Features))
	}
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

			if len(adapted.Collections) != len(tt.expectedCollections) {
				t.Errorf("expected %d collections, got %d", len(tt.expectedCollections), len(adapted.Collections))
				return
			}

			for i, expected := range tt.expectedCollections {
				if adapted.Collections[i] != expected {
					t.Errorf("collection[%d] = %s, want %s", i, adapted.Collections[i], expected)
				}
			}
		})
	}
}

// TestFanOutSearch tests parallel search execution
func TestFanOutSearch(t *testing.T) {
	// Create multiple test servers
	origins := make([]*Origin, 3)
	for i := 0; i < 3; i++ {
		fc := testutil.SampleFeatureCollection(
			testutil.SampleItem("item" + string(rune('1'+i))),
		)
		server := testutil.NewTestServerWithJSONResponse(fc)
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
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	searchReq := testutil.SampleSearchRequest(
		testutil.WithCollections("collection1"),
		testutil.WithLimit(10),
	)

	ctx := context.Background()
	results := handler.fanOutSearch(ctx, origins, searchReq)

	if len(results) != 3 {
		t.Errorf("expected 3 results, got %d", len(results))
	}

	// All results should be successful
	for _, result := range results {
		if result.Error != nil {
			t.Errorf("unexpected error in result: %v", result.Error)
		}
		if len(result.Items) != 1 {
			t.Errorf("expected 1 item, got %d", len(result.Items))
		}
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
			mockFC: testutil.SampleFeatureCollection(
				testutil.SampleItem("item1"),
				testutil.SampleItem("item2"),
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
				server = testutil.NewTestServerWithJSONResponse(tt.mockFC)
			} else {
				server = testutil.NewTestServerWithError(http.StatusInternalServerError, "error")
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
			if err != nil {
				t.Fatalf("failed to create handler: %v", err)
			}

			searchReq := testutil.SampleSearchRequest(
				testutil.WithCollections("collection1"),
			)

			result := handler.searchOrigin(context.Background(), origin, searchReq)

			if tt.wantError {
				if result.Error == nil {
					t.Error("expected error but got nil")
				}
			} else {
				if result.Error != nil {
					t.Errorf("unexpected error: %v", result.Error)
				}
				if len(result.Items) != len(tt.mockFC.Features) {
					t.Errorf("expected %d items, got %d", len(tt.mockFC.Features), len(result.Items))
				}
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

			fc := testutil.SampleFeatureCollection(
				testutil.SampleItem("item1"),
			)
			server := testutil.NewTestServerWithJSONResponse(fc)
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
			if err != nil {
				t.Fatalf("failed to create handler: %v", err)
			}

			searchReq := testutil.SampleSearchRequest(
				testutil.WithCollections("collection1"),
				testutil.WithLimit(tt.requestLimit),
			)

			req := &middleware.STACRequest{
				Request:     httptest.NewRequest(http.MethodPost, "/search", nil),
				Context:     context.Background(),
				RequestType: middleware.RequestTypeSearch,
				SearchReq:   searchReq,
			}

			resp, err := handler.Handle(req.Context, req)
			if err != nil {
				t.Fatalf("Handle() error = %v", err)
			}

			var fc2 stac.FeatureCollection
			if err := json.Unmarshal(resp.Body, &fc2); err != nil {
				t.Fatalf("failed to parse response: %v", err)
			}

			// The limit should be applied (Context.Limit may be set)
			// We can't directly verify the limit sent to origin, but we can verify
			// that the handler processed it correctly
			if searchReq.Limit != tt.expectedLimit {
				t.Errorf("searchReq.Limit = %d, want %d", searchReq.Limit, tt.expectedLimit)
			}
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
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	// Search for a collection not served by any origin
	req := &middleware.STACRequest{
		Request:     httptest.NewRequest(http.MethodPost, "/search", nil),
		Context:     context.Background(),
		RequestType: middleware.RequestTypeSearch,
		SearchReq: testutil.SampleSearchRequest(
			testutil.WithCollections("nonexistent-collection"),
		),
	}

	resp, err := handler.Handle(req.Context, req)
	if err != nil {
		t.Fatalf("Handle() error = %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var fc stac.FeatureCollection
	if err := json.Unmarshal(resp.Body, &fc); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if len(fc.Features) != 0 {
		t.Errorf("expected 0 features, got %d", len(fc.Features))
	}
}

// TestHandleCollectionPriority tests that higher priority origins are tried first
func TestHandleCollectionPriority(t *testing.T) {
	t.Parallel()

	// Create two servers, one that will fail and one that will succeed
	failServer := testutil.NewTestServerWithError(http.StatusNotFound, "not found")
	defer failServer.Close()

	coll := testutil.SampleCollection("test-collection")
	successServer := testutil.NewTestServerWithJSONResponse(coll)
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
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	req := &middleware.STACRequest{
		Request:     httptest.NewRequest(http.MethodGet, "/collections/test-collection", nil),
		Context:     context.Background(),
		RequestType: middleware.RequestTypeCollection,
		Collection:  "test-collection",
	}

	resp, err := handler.Handle(req.Context, req)
	if err != nil {
		t.Fatalf("Handle() error = %v", err)
	}

	// Should succeed with lower priority origin after higher priority fails
	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

// TestHandleSearchWithBbox tests search with bounding box
func TestHandleSearchWithBbox(t *testing.T) {
	t.Parallel()

	fc := testutil.SampleFeatureCollection(
		testutil.SampleItem("item1"),
	)
	server := testutil.NewTestServerWithJSONResponse(fc)
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
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	req := &middleware.STACRequest{
		Request:     httptest.NewRequest(http.MethodPost, "/search", nil),
		Context:     context.Background(),
		RequestType: middleware.RequestTypeSearch,
		SearchReq: testutil.SampleSearchRequest(
			testutil.WithSearchBbox(testutil.SampleBbox()),
		),
	}

	resp, err := handler.Handle(req.Context, req)
	if err != nil {
		t.Fatalf("Handle() error = %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

// TestHandleSearchWithDatetime tests search with datetime filter
func TestHandleSearchWithDatetime(t *testing.T) {
	t.Parallel()

	fc := testutil.SampleFeatureCollection(
		testutil.SampleItem("item1"),
	)
	server := testutil.NewTestServerWithJSONResponse(fc)
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
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	req := &middleware.STACRequest{
		Request:     httptest.NewRequest(http.MethodPost, "/search", nil),
		Context:     context.Background(),
		RequestType: middleware.RequestTypeSearch,
		SearchReq: testutil.SampleSearchRequest(
			testutil.WithSearchDatetime("2023-01-01T00:00:00Z/2023-12-31T23:59:59Z"),
		),
	}

	resp, err := handler.Handle(req.Context, req)
	if err != nil {
		t.Fatalf("Handle() error = %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}
