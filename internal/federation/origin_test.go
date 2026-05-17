// Package federation provides tests for origin client functionality.
package federation

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/stac-proxy/internal/stac"
)

func TestNewOriginClient(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		origin      *Origin
		wantErr     bool
		errContains string
	}{
		{
			name: "valid origin with no auth",
			origin: &Origin{
				ID:      "test-origin",
				BaseURL: "https://api.example.com",
				Enabled: true,
				Timeout: 30 * time.Second,
			},
			wantErr: false,
		},
		{
			name: "valid origin with basic auth",
			origin: &Origin{
				ID:      "test-origin",
				BaseURL: "https://api.example.com",
				Enabled: true,
				Timeout: 30 * time.Second,
				Auth: AuthConfig{
					Type:     "basic",
					Username: "user",
					Password: "pass",
				},
			},
			wantErr: false,
		},
		{
			name: "valid origin with bearer token",
			origin: &Origin{
				ID:      "test-origin",
				BaseURL: "https://api.example.com",
				Enabled: true,
				Timeout: 30 * time.Second,
				Auth: AuthConfig{
					Type:  "bearer",
					Token: "test-token",
				},
			},
			wantErr: false,
		},
		{
			name: "valid origin with api key",
			origin: &Origin{
				ID:      "test-origin",
				BaseURL: "https://api.example.com",
				Enabled: true,
				Timeout: 30 * time.Second,
				Auth: AuthConfig{
					Type:         "api_key",
					APIKeyHeader: "X-API-Key",
					APIKeyValue:  "test-key",
				},
			},
			wantErr: false,
		},
		{
			name: "valid origin with custom headers",
			origin: &Origin{
				ID:      "test-origin",
				BaseURL: "https://api.example.com",
				Enabled: true,
				Timeout: 30 * time.Second,
				Auth: AuthConfig{
					Type: "custom",
					CustomHeaders: map[string]string{
						"X-Custom-Header": "value",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid base URL",
			origin: &Origin{
				ID:      "test-origin",
				BaseURL: "://invalid-url",
				Enabled: true,
				Timeout: 30 * time.Second,
			},
			wantErr:     true,
			errContains: "invalid base URL",
		},
		{
			name: "empty base URL",
			origin: &Origin{
				ID:      "test-origin",
				BaseURL: "",
				Enabled: true,
				Timeout: 30 * time.Second,
			},
			wantErr: false, // Empty URL is technically valid (relative)
		},
		{
			name: "origin with retry policy",
			origin: &Origin{
				ID:      "test-origin",
				BaseURL: "https://api.example.com",
				Enabled: true,
				Timeout: 30 * time.Second,
				Retry: &RetryPolicy{
					MaxRetries:     3,
					InitialBackoff: 100 * time.Millisecond,
					MaxBackoff:     5 * time.Second,
					RetryOn:        []int{502, 503, 504},
				},
			},
			wantErr: false,
		},
		{
			name: "origin with collections filter",
			origin: &Origin{
				ID:          "test-origin",
				BaseURL:     "https://api.example.com",
				Enabled:     true,
				Timeout:     30 * time.Second,
				Collections: []string{"col1", "col2"},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			client, err := NewOriginClient(tt.origin)

			if tt.wantErr {
				require.Error(t, err, "expected error but got nil")
				if tt.errContains != "" {
					assert.ErrorContainsf(t, err, tt.errContains, "error should contain")
				}
				return
			}

			require.NoError(t, err)

			require.NotNil(t, client, "expected client to be non-nil")
			assert.Same(t, tt.origin, client.origin, "client origin does not match input origin")
			assert.NotNil(t, client.httpClient, "expected httpClient to be non-nil")
			assert.NotNil(t, client.baseURL, "expected baseURL to be non-nil")
			assert.NotNil(t, client.collections, "expected collections map to be initialized")
		})
	}
}

func TestNewOriginClient_AutoDiscover(t *testing.T) {
	// Set up a test server
	collections := []*stac.Collection{
		sampleCollection("test-col-1"),
		sampleCollection("test-col-2"),
	}
	resp := stac.CollectionsResponse{Collections: collections}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/collections" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		}
	}))
	defer server.Close()

	origin := &Origin{
		ID:           "test-origin",
		BaseURL:      server.URL,
		Enabled:      true,
		Timeout:      30 * time.Second,
		AutoDiscover: true,
	}

	client, err := NewOriginClient(origin)
	require.NoError(t, err)

	// Wait a bit for autodiscovery goroutine to complete
	time.Sleep(100 * time.Millisecond)

	// Check that collections were discovered
	cached := client.CachedCollections()
	assert.Len(t, cached, 2, "expected 2 cached collections")
}

func TestOriginClient_DoRequest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		method         string
		path           string
		body           io.Reader
		serverResponse func(w http.ResponseWriter, r *http.Request)
		authConfig     AuthConfig
		checkRequest   func(t *testing.T, r *http.Request)
		wantErr        bool
	}{
		{
			name:   "GET request without auth",
			method: "GET",
			path:   "/collections",
			body:   nil,
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(map[string]string{"test": "data"})
			},
			checkRequest: func(t *testing.T, r *http.Request) {
				assert.Equal(t, "GET", r.Method, "method")
				assert.Equal(t, "/collections", r.URL.Path, "path")
				accept := r.Header.Get("Accept")
				assert.Containsf(t, accept, "application/geo+json", "expected Accept header to contain application/geo+json")
			},
			wantErr: false,
		},
		{
			name:   "POST request with body",
			method: "POST",
			path:   "/search",
			body:   strings.NewReader(`{"collections":["test"]}`),
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(map[string]string{"test": "data"})
			},
			checkRequest: func(t *testing.T, r *http.Request) {
				assert.Equal(t, "POST", r.Method, "method")
				assert.Equal(t, "application/json", r.Header.Get("Content-Type"), "Content-Type")
			},
			wantErr: false,
		},
		{
			name:   "request with basic auth",
			method: "GET",
			path:   "/collections",
			body:   nil,
			authConfig: AuthConfig{
				Type:     "basic",
				Username: "testuser",
				Password: "testpass",
			},
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			},
			checkRequest: func(t *testing.T, r *http.Request) {
				username, password, ok := r.BasicAuth()
				assert.True(t, ok, "expected basic auth to be present")
				assert.Equal(t, "testuser", username, "username")
				assert.Equal(t, "testpass", password, "password")
			},
			wantErr: false,
		},
		{
			name:   "request with bearer token",
			method: "GET",
			path:   "/collections",
			body:   nil,
			authConfig: AuthConfig{
				Type:  "bearer",
				Token: "test-bearer-token",
			},
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			},
			checkRequest: func(t *testing.T, r *http.Request) {
				assert.Equal(t, "Bearer test-bearer-token", r.Header.Get("Authorization"), "Authorization")
			},
			wantErr: false,
		},
		{
			name:   "request with api key in header",
			method: "GET",
			path:   "/collections",
			body:   nil,
			authConfig: AuthConfig{
				Type:          "api_key",
				APIKeyHeader:  "X-API-Key",
				APIKeyValue:   "test-key-123",
				APIKeyInQuery: false,
			},
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			},
			checkRequest: func(t *testing.T, r *http.Request) {
				assert.Equal(t, "test-key-123", r.Header.Get("X-API-Key"), "X-API-Key")
			},
			wantErr: false,
		},
		{
			name:   "request with api key in query",
			method: "GET",
			path:   "/collections",
			body:   nil,
			authConfig: AuthConfig{
				Type:          "api_key",
				APIKeyHeader:  "api_key",
				APIKeyValue:   "test-key-456",
				APIKeyInQuery: true,
			},
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			},
			checkRequest: func(t *testing.T, r *http.Request) {
				assert.Equal(t, "test-key-456", r.URL.Query().Get("api_key"), "api_key")
			},
			wantErr: false,
		},
		{
			name:   "request with custom headers",
			method: "GET",
			path:   "/collections",
			body:   nil,
			authConfig: AuthConfig{
				Type: "custom",
				CustomHeaders: map[string]string{
					"X-Custom-1": "value1",
					"X-Custom-2": "value2",
				},
			},
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			},
			checkRequest: func(t *testing.T, r *http.Request) {
				assert.Equal(t, "value1", r.Header.Get("X-Custom-1"))
				assert.Equal(t, "value2", r.Header.Get("X-Custom-2"))
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Create test server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.checkRequest != nil {
					tt.checkRequest(t, r)
				}
				if tt.serverResponse != nil {
					tt.serverResponse(w, r)
				}
			}))
			defer server.Close()

			// Create origin client
			origin := &Origin{
				ID:      "test-origin",
				BaseURL: server.URL,
				Enabled: true,
				Timeout: 5 * time.Second,
				Auth:    tt.authConfig,
			}

			client, err := NewOriginClient(origin)
			require.NoError(t, err, "failed to create client")

			// Execute request
			ctx := context.Background()
			resp, err := client.DoRequest(ctx, tt.method, tt.path, tt.body)

			if tt.wantErr {
				require.Error(t, err, "expected error but got nil")
				return
			}

			require.NoError(t, err)
			require.NotNil(t, resp, "expected response to be non-nil")
			defer resp.Body.Close()
		})
	}
}

func TestOriginClient_DoRequest_Timeout(t *testing.T) {
	t.Parallel()

	// Create server that delays response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	origin := &Origin{
		ID:      "test-origin",
		BaseURL: server.URL,
		Enabled: true,
		Timeout: 50 * time.Millisecond,
	}

	client, err := NewOriginClient(origin)
	require.NoError(t, err, "failed to create client")

	ctx := context.Background()
	_, err = client.DoRequest(ctx, "GET", "/collections", nil)

	assert.Error(t, err, "expected timeout error but got nil")
}

func TestOriginClient_DoRequest_ContextCancellation(t *testing.T) {
	t.Parallel()

	// Create server that delays response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	origin := &Origin{
		ID:      "test-origin",
		BaseURL: server.URL,
		Enabled: true,
		Timeout: 5 * time.Second,
	}

	client, err := NewOriginClient(origin)
	require.NoError(t, err, "failed to create client")

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err = client.DoRequest(ctx, "GET", "/collections", nil)

	assert.Error(t, err, "expected context cancellation error but got nil")
}

func TestOriginClient_Search(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		request        *stac.SearchRequest
		serverResponse *stac.FeatureCollection
		serverStatus   int
		wantErr        bool
		errContains    string
		checkResult    func(t *testing.T, fc *stac.FeatureCollection)
	}{
		{
			name: "successful search with items",
			request: buildSearchRequest(
				withCollections("test-collection"),
				withLimit(10),
			),
			serverResponse: sampleFeatureCollection(
				sampleItem("item-1"),
				sampleItem("item-2"),
			),
			serverStatus: http.StatusOK,
			wantErr:      false,
			checkResult: func(t *testing.T, fc *stac.FeatureCollection) {
				require.Len(t, fc.Features, 2, "features")
				assert.Equal(t, "item-1", fc.Features[0].ID, "first item ID")
			},
		},
		{
			name: "successful search with no items",
			request: buildSearchRequest(
				withCollections("empty-collection"),
			),
			serverResponse: sampleFeatureCollection(),
			serverStatus:   http.StatusOK,
			wantErr:        false,
			checkResult: func(t *testing.T, fc *stac.FeatureCollection) {
				assert.Empty(t, fc.Features, "expected 0 features")
			},
		},
		{
			name: "search with bbox",
			request: buildSearchRequest(
				withBbox([]float64{-10, -10, 10, 10}),
			),
			serverResponse: sampleFeatureCollection(
				sampleItem("item-1"),
			),
			serverStatus: http.StatusOK,
			wantErr:      false,
			checkResult: func(t *testing.T, fc *stac.FeatureCollection) {
				assert.Len(t, fc.Features, 1, "features")
			},
		},
		{
			name: "search with datetime",
			request: buildSearchRequest(
				withDatetime("2023-01-01T00:00:00Z/2023-12-31T23:59:59Z"),
			),
			serverResponse: sampleFeatureCollection(
				sampleItem("item-1"),
			),
			serverStatus: http.StatusOK,
			wantErr:      false,
			checkResult: func(t *testing.T, fc *stac.FeatureCollection) {
				assert.Len(t, fc.Features, 1, "features")
			},
		},
		{
			name:         "search returns 404",
			request:      buildSearchRequest(),
			serverStatus: http.StatusNotFound,
			wantErr:      true,
			errContains:  "404",
		},
		{
			name:         "search returns 500",
			request:      buildSearchRequest(),
			serverStatus: http.StatusInternalServerError,
			wantErr:      true,
			errContains:  "500",
		},
		{
			name:         "search returns 401",
			request:      buildSearchRequest(),
			serverStatus: http.StatusUnauthorized,
			wantErr:      true,
			errContains:  "401",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Create test server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/search", r.URL.Path, "path")
				assert.Equal(t, "POST", r.Method, "method")

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.serverStatus)

				if tt.serverResponse != nil {
					json.NewEncoder(w).Encode(tt.serverResponse)
				}
			}))
			defer server.Close()

			// Create origin client
			origin := &Origin{
				ID:      "test-origin",
				BaseURL: server.URL,
				Enabled: true,
				Timeout: 5 * time.Second,
			}

			client, err := NewOriginClient(origin)
			require.NoError(t, err, "failed to create client")

			// Execute search
			ctx := context.Background()
			fc, _, err := client.Search(ctx, tt.request)

			if tt.wantErr {
				require.Error(t, err, "expected error but got nil")
				if tt.errContains != "" {
					assert.ErrorContainsf(t, err, tt.errContains, "error message")
				}
				return
			}

			require.NoError(t, err)
			require.NotNil(t, fc, "expected feature collection to be non-nil")

			if tt.checkResult != nil {
				tt.checkResult(t, fc)
			}
		})
	}
}

func TestOriginClient_GetCollections(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		serverResponse *stac.CollectionsResponse
		serverStatus   int
		wantErr        bool
		errContains    string
		checkResult    func(t *testing.T, collections []*stac.Collection)
	}{
		{
			name: "successful get collections",
			serverResponse: &stac.CollectionsResponse{
				Collections: []*stac.Collection{
					sampleCollection("col-1"),
					sampleCollection("col-2"),
					sampleCollection("col-3"),
				},
			},
			serverStatus: http.StatusOK,
			wantErr:      false,
			checkResult: func(t *testing.T, collections []*stac.Collection) {
				require.Len(t, collections, 3)
				assert.Equal(t, "col-1", collections[0].ID, "first collection ID")
			},
		},
		{
			name: "get collections returns empty list",
			serverResponse: &stac.CollectionsResponse{
				Collections: []*stac.Collection{},
			},
			serverStatus: http.StatusOK,
			wantErr:      false,
			checkResult: func(t *testing.T, collections []*stac.Collection) {
				assert.Empty(t, collections, "expected 0 collections")
			},
		},
		{
			name:         "get collections returns 500",
			serverStatus: http.StatusInternalServerError,
			wantErr:      true,
			errContains:  "500",
		},
		{
			name:         "get collections returns 404",
			serverStatus: http.StatusNotFound,
			wantErr:      true,
			errContains:  "404",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Create test server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/collections", r.URL.Path)
				assert.Equal(t, "GET", r.Method)

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.serverStatus)

				if tt.serverResponse != nil {
					json.NewEncoder(w).Encode(tt.serverResponse)
				}
			}))
			defer server.Close()

			// Create origin client
			origin := &Origin{
				ID:      "test-origin",
				BaseURL: server.URL,
				Enabled: true,
				Timeout: 5 * time.Second,
			}

			client, err := NewOriginClient(origin)
			require.NoError(t, err, "failed to create client")

			// Execute get collections
			ctx := context.Background()
			collections, err := client.GetCollections(ctx)

			if tt.wantErr {
				require.Error(t, err, "expected error but got nil")
				if tt.errContains != "" {
					assert.ErrorContainsf(t, err, tt.errContains, "error message")
				}
				return
			}

			require.NoError(t, err)

			if tt.checkResult != nil {
				tt.checkResult(t, collections)
			}
		})
	}
}

func TestOriginClient_GetCollection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		collectionID   string
		serverResponse *stac.Collection
		serverStatus   int
		wantErr        bool
		wantNil        bool
		errContains    string
		checkResult    func(t *testing.T, collection *stac.Collection)
	}{
		{
			name:           "successful get collection",
			collectionID:   "test-collection",
			serverResponse: sampleCollection("test-collection"),
			serverStatus:   http.StatusOK,
			wantErr:        false,
			wantNil:        false,
			checkResult: func(t *testing.T, collection *stac.Collection) {
				assert.Equal(t, "test-collection", collection.ID, "collection ID")
			},
		},
		{
			name:         "get collection returns 404 - returns nil",
			collectionID: "nonexistent",
			serverStatus: http.StatusNotFound,
			wantErr:      false,
			wantNil:      true,
		},
		{
			name:         "get collection returns 500",
			collectionID: "test-collection",
			serverStatus: http.StatusInternalServerError,
			wantErr:      true,
			errContains:  "500",
		},
		{
			name:         "get collection returns 401",
			collectionID: "test-collection",
			serverStatus: http.StatusUnauthorized,
			wantErr:      true,
			errContains:  "401",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Create test server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				expectedPath := fmt.Sprintf("/collections/%s", tt.collectionID)
				assert.Equal(t, expectedPath, r.URL.Path)
				assert.Equal(t, "GET", r.Method)

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.serverStatus)

				if tt.serverResponse != nil {
					json.NewEncoder(w).Encode(tt.serverResponse)
				}
			}))
			defer server.Close()

			// Create origin client
			origin := &Origin{
				ID:      "test-origin",
				BaseURL: server.URL,
				Enabled: true,
				Timeout: 5 * time.Second,
			}

			client, err := NewOriginClient(origin)
			require.NoError(t, err, "failed to create client")

			// Execute get collection
			ctx := context.Background()
			collection, err := client.GetCollection(ctx, tt.collectionID)

			if tt.wantErr {
				require.Error(t, err, "expected error but got nil")
				if tt.errContains != "" {
					assert.ErrorContainsf(t, err, tt.errContains, "error message")
				}
				return
			}

			require.NoError(t, err)

			if tt.wantNil {
				assert.Nil(t, collection, "expected collection to be nil for 404")
				return
			}

			require.NotNil(t, collection, "expected collection to be non-nil")

			if tt.checkResult != nil {
				tt.checkResult(t, collection)
			}
		})
	}
}

func TestOriginClient_GetItem(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		collectionID   string
		itemID         string
		serverResponse *stac.Item
		serverStatus   int
		wantErr        bool
		wantNil        bool
		errContains    string
		checkResult    func(t *testing.T, item *stac.Item)
	}{
		{
			name:           "successful get item",
			collectionID:   "test-collection",
			itemID:         "test-item",
			serverResponse: sampleItem("test-item"),
			serverStatus:   http.StatusOK,
			wantErr:        false,
			wantNil:        false,
			checkResult: func(t *testing.T, item *stac.Item) {
				assert.Equal(t, "test-item", item.ID, "item ID")
			},
		},
		{
			name:         "get item returns 404 - returns nil",
			collectionID: "test-collection",
			itemID:       "nonexistent",
			serverStatus: http.StatusNotFound,
			wantErr:      false,
			wantNil:      true,
		},
		{
			name:         "get item returns 500",
			collectionID: "test-collection",
			itemID:       "test-item",
			serverStatus: http.StatusInternalServerError,
			wantErr:      true,
			errContains:  "500",
		},
		{
			name:         "get item returns 403",
			collectionID: "test-collection",
			itemID:       "test-item",
			serverStatus: http.StatusForbidden,
			wantErr:      true,
			errContains:  "403",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Create test server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				expectedPath := fmt.Sprintf("/collections/%s/items/%s", tt.collectionID, tt.itemID)
				assert.Equal(t, expectedPath, r.URL.Path)
				assert.Equal(t, "GET", r.Method)

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.serverStatus)

				if tt.serverResponse != nil {
					json.NewEncoder(w).Encode(tt.serverResponse)
				}
			}))
			defer server.Close()

			// Create origin client
			origin := &Origin{
				ID:      "test-origin",
				BaseURL: server.URL,
				Enabled: true,
				Timeout: 5 * time.Second,
			}

			client, err := NewOriginClient(origin)
			require.NoError(t, err, "failed to create client")

			// Execute get item
			ctx := context.Background()
			item, err := client.GetItem(ctx, tt.collectionID, tt.itemID)

			if tt.wantErr {
				require.Error(t, err, "expected error but got nil")
				if tt.errContains != "" {
					assert.ErrorContainsf(t, err, tt.errContains, "error message")
				}
				return
			}

			require.NoError(t, err)

			if tt.wantNil {
				assert.Nil(t, item, "expected item to be nil for 404")
				return
			}

			require.NotNil(t, item, "expected item to be non-nil")

			if tt.checkResult != nil {
				tt.checkResult(t, item)
			}
		})
	}
}

func TestOriginClient_Retry(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		retryPolicy    *RetryPolicy
		serverBehavior func(attempt *int) (int, interface{})
		wantErr        bool
		wantAttempts   int
	}{
		{
			name: "retry on 503 until success",
			retryPolicy: &RetryPolicy{
				MaxRetries:     3,
				InitialBackoff: 10 * time.Millisecond,
				MaxBackoff:     100 * time.Millisecond,
				RetryOn:        []int{503},
			},
			serverBehavior: func(attempt *int) (int, interface{}) {
				*attempt++
				if *attempt < 3 {
					return http.StatusServiceUnavailable, nil
				}
				return http.StatusOK, sampleCollection("test")
			},
			wantErr:      false,
			wantAttempts: 3,
		},
		{
			// Retries exhausted: caller sees the final upstream response
			// (502 here) rather than a synthetic error.
			name: "retry on 502 but always fails",
			retryPolicy: &RetryPolicy{
				MaxRetries:     2,
				InitialBackoff: 10 * time.Millisecond,
				MaxBackoff:     100 * time.Millisecond,
				RetryOn:        []int{502},
			},
			serverBehavior: func(attempt *int) (int, interface{}) {
				*attempt++
				return http.StatusBadGateway, nil
			},
			wantErr:      false,
			wantAttempts: 3, // initial + 2 retries
		},
		{
			name: "no retry on 404",
			retryPolicy: &RetryPolicy{
				MaxRetries:     3,
				InitialBackoff: 10 * time.Millisecond,
				MaxBackoff:     100 * time.Millisecond,
				RetryOn:        []int{500, 502, 503},
			},
			serverBehavior: func(attempt *int) (int, interface{}) {
				*attempt++
				return http.StatusNotFound, nil
			},
			wantErr:      false, // DoRequest returns the response, not an error
			wantAttempts: 1,     // no retries
		},
		{
			name: "default retry behavior on 5xx",
			retryPolicy: &RetryPolicy{
				MaxRetries:     2,
				InitialBackoff: 10 * time.Millisecond,
				MaxBackoff:     100 * time.Millisecond,
				RetryOn:        []int{}, // empty means default to 5xx
			},
			serverBehavior: func(attempt *int) (int, interface{}) {
				*attempt++
				if *attempt < 2 {
					return http.StatusInternalServerError, nil
				}
				return http.StatusOK, sampleCollection("test")
			},
			wantErr:      false,
			wantAttempts: 2,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			attempt := 0

			// Create test server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				status, response := tt.serverBehavior(&attempt)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(status)
				if response != nil {
					json.NewEncoder(w).Encode(response)
				}
			}))
			defer server.Close()

			// Create origin client with retry policy
			origin := &Origin{
				ID:      "test-origin",
				BaseURL: server.URL,
				Enabled: true,
				Timeout: 5 * time.Second,
				Retry:   tt.retryPolicy,
			}

			client, err := NewOriginClient(origin)
			require.NoError(t, err, "failed to create client")

			// Execute request
			ctx := context.Background()
			resp, err := client.DoRequest(ctx, "GET", "/collections/test", nil)

			if tt.wantErr {
				assert.Error(t, err, "expected error but got nil")
			} else {
				assert.NoError(t, err)
				if resp != nil {
					resp.Body.Close()
				}
			}

			assert.Equalf(t, tt.wantAttempts, attempt, "expected %d attempts", tt.wantAttempts)
		})
	}
}

func TestOriginClient_DiscoverCollections(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		serverResponse *stac.CollectionsResponse
		serverStatus   int
		wantErr        bool
		checkCache     func(t *testing.T, client *OriginClient)
	}{
		{
			name: "successful discovery",
			serverResponse: &stac.CollectionsResponse{
				Collections: []*stac.Collection{
					sampleCollection("col-1"),
					sampleCollection("col-2"),
				},
			},
			serverStatus: http.StatusOK,
			wantErr:      false,
			checkCache: func(t *testing.T, client *OriginClient) {
				cached := client.CachedCollections()
				require.Len(t, cached, 2, "cached collections")
				assert.Contains(t, cached, "col-1", "expected col-1 in cache")
				assert.Contains(t, cached, "col-2", "expected col-2 in cache")
			},
		},
		{
			name: "discovery with no collections",
			serverResponse: &stac.CollectionsResponse{
				Collections: []*stac.Collection{},
			},
			serverStatus: http.StatusOK,
			wantErr:      false,
			checkCache: func(t *testing.T, client *OriginClient) {
				assert.Empty(t, client.CachedCollections(), "expected 0 cached collections")
			},
		},
		{
			name:         "discovery fails",
			serverStatus: http.StatusInternalServerError,
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Create test server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.serverStatus)
				if tt.serverResponse != nil {
					json.NewEncoder(w).Encode(tt.serverResponse)
				}
			}))
			defer server.Close()

			// Create origin client
			origin := &Origin{
				ID:      "test-origin",
				BaseURL: server.URL,
				Enabled: true,
				Timeout: 5 * time.Second,
			}

			client, err := NewOriginClient(origin)
			require.NoError(t, err, "failed to create client")

			// Execute discovery
			ctx := context.Background()
			err = client.DiscoverCollections(ctx)

			if tt.wantErr {
				require.Error(t, err, "expected error but got nil")
				return
			}

			require.NoError(t, err)

			if tt.checkCache != nil {
				tt.checkCache(t, client)
			}
		})
	}
}

func TestOriginClient_HasCollection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		origin       *Origin
		setupCache   func(*OriginClient)
		collectionID string
		want         bool
	}{
		{
			name: "explicit collections - has collection",
			origin: &Origin{
				ID:          "test-origin",
				BaseURL:     "https://api.example.com",
				Collections: []string{"col-1", "col-2"},
			},
			collectionID: "col-1",
			want:         true,
		},
		{
			name: "explicit collections - does not have collection",
			origin: &Origin{
				ID:          "test-origin",
				BaseURL:     "https://api.example.com",
				Collections: []string{"col-1", "col-2"},
			},
			collectionID: "col-3",
			want:         false,
		},
		{
			name: "exclude collections - excluded",
			origin: &Origin{
				ID:                 "test-origin",
				BaseURL:            "https://api.example.com",
				ExcludeCollections: []string{"excluded-1", "excluded-2"},
			},
			setupCache: func(c *OriginClient) {
				c.collectionsLock.Lock()
				c.collections["excluded-1"] = sampleCollection("excluded-1")
				c.collections["other"] = sampleCollection("other")
				c.collectionsLock.Unlock()
			},
			collectionID: "excluded-1",
			want:         false,
		},
		{
			name: "exclude collections - not excluded",
			origin: &Origin{
				ID:                 "test-origin",
				BaseURL:            "https://api.example.com",
				ExcludeCollections: []string{"excluded-1"},
			},
			setupCache: func(c *OriginClient) {
				c.collectionsLock.Lock()
				c.collections["other"] = sampleCollection("other")
				c.collectionsLock.Unlock()
			},
			collectionID: "other",
			want:         true,
		},
		{
			name: "cache only - has collection",
			origin: &Origin{
				ID:      "test-origin",
				BaseURL: "https://api.example.com",
			},
			setupCache: func(c *OriginClient) {
				c.collectionsLock.Lock()
				c.collections["cached-1"] = sampleCollection("cached-1")
				c.collectionsLock.Unlock()
			},
			collectionID: "cached-1",
			want:         true,
		},
		{
			name: "cache only - does not have collection",
			origin: &Origin{
				ID:      "test-origin",
				BaseURL: "https://api.example.com",
			},
			setupCache: func(c *OriginClient) {
				c.collectionsLock.Lock()
				c.collections["cached-1"] = sampleCollection("cached-1")
				c.collectionsLock.Unlock()
			},
			collectionID: "not-cached",
			want:         false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			client, err := NewOriginClient(tt.origin)
			require.NoError(t, err, "failed to create client")

			if tt.setupCache != nil {
				tt.setupCache(client)
			}

			assert.Equalf(t, tt.want, client.HasCollection(tt.collectionID), "HasCollection(%q)", tt.collectionID)
		})
	}
}

func TestOriginClient_CachedCollections(t *testing.T) {
	t.Parallel()

	origin := &Origin{
		ID:      "test-origin",
		BaseURL: "https://api.example.com",
	}

	client, err := NewOriginClient(origin)
	require.NoError(t, err, "failed to create client")

	// Initially empty
	cached := client.CachedCollections()
	assert.Empty(t, cached, "expected 0 cached collections initially")

	// Add some collections
	client.collectionsLock.Lock()
	client.collections["col-1"] = sampleCollection("col-1")
	client.collections["col-2"] = sampleCollection("col-2")
	client.collections["col-3"] = sampleCollection("col-3")
	client.collectionsLock.Unlock()

	// Check cached
	cached = client.CachedCollections()
	require.Len(t, cached, 3, "cached collections")

	// Verify all collections are present
	for _, expectedID := range []string{"col-1", "col-2", "col-3"} {
		assert.Containsf(t, cached, expectedID, "expected %s in cached collections", expectedID)
	}
}

func TestOriginClient_Origin(t *testing.T) {
	t.Parallel()

	origin := &Origin{
		ID:      "test-origin",
		BaseURL: "https://api.example.com",
		Name:    "Test Origin",
	}

	client, err := NewOriginClient(origin)
	require.NoError(t, err, "failed to create client")

	assert.Same(t, origin, client.Origin(), "Origin() did not return the same origin instance")
}

func TestOriginClient_BaseURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		baseURL     string
		wantBaseURL string
	}{
		{
			name:        "simple URL",
			baseURL:     "https://api.example.com",
			wantBaseURL: "https://api.example.com",
		},
		{
			name:        "URL with path",
			baseURL:     "https://api.example.com/stac/v1",
			wantBaseURL: "https://api.example.com/stac/v1",
		},
		{
			name:        "URL with trailing slash",
			baseURL:     "https://api.example.com/",
			wantBaseURL: "https://api.example.com/",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			origin := &Origin{
				ID:      "test-origin",
				BaseURL: tt.baseURL,
			}

			client, err := NewOriginClient(origin)
			require.NoError(t, err, "failed to create client")

			assert.Equal(t, tt.wantBaseURL, client.BaseURL(), "BaseURL()")
		})
	}
}

// TestShouldRetry was removed: retry policy logic now lives in
// internal/httpx (worktree A) and is tested there. The federation
// origin client wires httpx.NewRetryTransport via NewOriginClient.

// TestMinDuration removed: minDuration helper is now in internal/httpx
// (worktree A) and tested there.

func TestOriginClient_URLConstruction(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		baseURL     string
		path        string
		expectedURL string
	}{
		{
			name:        "simple path",
			baseURL:     "https://api.example.com",
			path:        "/collections",
			expectedURL: "https://api.example.com/collections",
		},
		{
			name:        "base with trailing slash",
			baseURL:     "https://api.example.com/",
			path:        "/collections",
			expectedURL: "https://api.example.com/collections",
		},
		{
			name:        "base with path",
			baseURL:     "https://api.example.com/stac/v1",
			path:        "/collections",
			expectedURL: "https://api.example.com/stac/v1/collections",
		},
		{
			name:        "complex path",
			baseURL:     "https://api.example.com",
			path:        "/collections/test-col/items/test-item",
			expectedURL: "https://api.example.com/collections/test-col/items/test-item",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Create test server that captures the URL
			var capturedURL string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				capturedURL = r.URL.String()
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			// Use server URL as base, but we'll verify path construction
			origin := &Origin{
				ID:      "test-origin",
				BaseURL: server.URL,
				Enabled: true,
				Timeout: 5 * time.Second,
			}

			client, err := NewOriginClient(origin)
			require.NoError(t, err, "failed to create client")

			ctx := context.Background()
			resp, err := client.DoRequest(ctx, "GET", tt.path, nil)
			require.NoError(t, err)
			defer resp.Body.Close()

			assert.Equal(t, tt.path, capturedURL, "URL path")
		})
	}
}

// Test helper functions to avoid import cycle with testutil

func sampleItem(id string) *stac.Item {
	now := time.Now()
	return &stac.Item{
		Version:    "1.0.0",
		ID:         id,
		Collection: "test-collection",
		Geometry:   json.RawMessage(`{"type":"Polygon","coordinates":[[[-180,-90],[180,-90],[180,90],[-180,90],[-180,-90]]]}`),
		Bbox:       []float64{-180, -90, 180, 90},
		Properties: map[string]any{
			"datetime": now.Format(time.RFC3339),
			"title":    "Test Item " + id,
		},
		Links: []*stac.Link{
			{Rel: "self", Href: "https://example.com/items/" + id, Type: "application/geo+json"},
		},
		Assets: map[string]*stac.Asset{
			"data": {
				Href:  "https://example.com/assets/" + id + "/data.tif",
				Type:  "image/tiff",
				Title: "Data",
				Roles: []string{"data"},
			},
		},
	}
}

func sampleCollection(id string) *stac.Collection {
	return &stac.Collection{
		Version:     "1.0.0",
		ID:          id,
		Title:       "Test Collection " + id,
		Description: "A test collection for unit testing",
		License:     "MIT",
		Extent: &stac.Extent{
			Spatial:  &stac.SpatialExtent{Bbox: [][]float64{{-180, -90, 180, 90}}},
			Temporal: &stac.TemporalExtent{Interval: [][]*string{{strPtr("2020-01-01T00:00:00Z"), strPtr("2023-12-31T23:59:59Z")}}},
		},
		Links: []*stac.Link{
			{Rel: "self", Href: "https://example.com/collections/" + id, Type: "application/json"},
		},
	}
}

func sampleFeatureCollection(items ...*stac.Item) *stac.FeatureCollection {
	return &stac.FeatureCollection{
		Type:     "FeatureCollection",
		Features: append([]*stac.Item(nil), items...),
		Links: []*stac.Link{
			{Rel: "self", Href: "https://example.com/search", Type: "application/geo+json"},
		},
		Context: &stac.SearchContext{
			Returned: len(items),
			Limit:    10,
		},
	}
}

func sampleSearchRequest() *stac.SearchRequest {
	return &stac.SearchRequest{
		Limit: 10,
	}
}

func withCollections(collections ...string) func(*stac.SearchRequest) {
	return func(r *stac.SearchRequest) {
		r.Collections = collections
	}
}

func withLimit(limit int) func(*stac.SearchRequest) {
	return func(r *stac.SearchRequest) {
		r.Limit = limit
	}
}

func withBbox(bbox []float64) func(*stac.SearchRequest) {
	return func(r *stac.SearchRequest) {
		r.BBox = bbox
	}
}

func withDatetime(datetime string) func(*stac.SearchRequest) {
	return func(r *stac.SearchRequest) {
		r.Datetime = datetime
	}
}

func buildSearchRequest(opts ...func(*stac.SearchRequest)) *stac.SearchRequest {
	req := sampleSearchRequest()
	for _, opt := range opts {
		opt(req)
	}
	return req
}

func TestOriginClient_Search_InvalidJSON(t *testing.T) {
	t.Parallel()

	// Test server that returns invalid JSON
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{invalid json`))
	}))
	defer server.Close()

	origin := &Origin{
		ID:      "test-origin",
		BaseURL: server.URL,
		Timeout: 5 * time.Second,
	}

	client, err := NewOriginClient(origin)
	require.NoError(t, err, "failed to create client")

	ctx := context.Background()
	_, _, err = client.Search(ctx, sampleSearchRequest())

	require.Error(t, err, "expected error for invalid JSON")
	assert.ErrorContainsf(t, err, "parse", "expected parse error")
}

func TestOriginClient_GetCollections_InvalidJSON(t *testing.T) {
	t.Parallel()

	// Test server that returns invalid JSON
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{invalid`))
	}))
	defer server.Close()

	origin := &Origin{
		ID:      "test-origin",
		BaseURL: server.URL,
		Timeout: 5 * time.Second,
	}

	client, err := NewOriginClient(origin)
	require.NoError(t, err, "failed to create client")

	ctx := context.Background()
	_, err = client.GetCollections(ctx)

	assert.Error(t, err, "expected error for invalid JSON")
}

func TestOriginClient_GetCollection_InvalidJSON(t *testing.T) {
	t.Parallel()

	// Test server that returns invalid JSON
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`not valid`))
	}))
	defer server.Close()

	origin := &Origin{
		ID:      "test-origin",
		BaseURL: server.URL,
		Timeout: 5 * time.Second,
	}

	client, err := NewOriginClient(origin)
	require.NoError(t, err, "failed to create client")

	ctx := context.Background()
	_, err = client.GetCollection(ctx, "test-collection")

	assert.Error(t, err, "expected error for invalid JSON")
}

func TestOriginClient_GetItem_InvalidJSON(t *testing.T) {
	t.Parallel()

	// Test server that returns invalid JSON
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{{`))
	}))
	defer server.Close()

	origin := &Origin{
		ID:      "test-origin",
		BaseURL: server.URL,
		Timeout: 5 * time.Second,
	}

	client, err := NewOriginClient(origin)
	require.NoError(t, err, "failed to create client")

	ctx := context.Background()
	_, err = client.GetItem(ctx, "test-collection", "test-item")

	assert.Error(t, err, "expected error for invalid JSON")
}

func TestOriginClient_Retry_ContextCancellation(t *testing.T) {
	t.Parallel()

	attempt := 0

	// Server that always returns 503
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempt++
		time.Sleep(50 * time.Millisecond)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	origin := &Origin{
		ID:      "test-origin",
		BaseURL: server.URL,
		Timeout: 10 * time.Second,
		Retry: &RetryPolicy{
			MaxRetries:     5,
			InitialBackoff: 100 * time.Millisecond,
			MaxBackoff:     1 * time.Second,
			RetryOn:        []int{503},
		},
	}

	client, err := NewOriginClient(origin)
	require.NoError(t, err, "failed to create client")

	// Create context that will be cancelled during retry
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	_, err = client.DoRequest(ctx, "GET", "/test", nil)

	assert.Error(t, err, "expected context cancellation error but got nil")

	// Should have attempted at least once but not all retries
	assert.NotZero(t, attempt, "expected at least one attempt")
	assert.Lessf(t, attempt, 5, "expected fewer than 5 attempts due to context cancellation")
}

func TestOriginClient_DoRequest_InvalidMethod(t *testing.T) {
	t.Parallel()

	origin := &Origin{
		ID:      "test-origin",
		BaseURL: "https://api.example.com",
		Timeout: 5 * time.Second,
	}

	client, err := NewOriginClient(origin)
	require.NoError(t, err, "failed to create client")

	ctx := context.Background()
	// Invalid method with control characters
	_, err = client.DoRequest(ctx, "GET\n", "/collections", nil)

	assert.Error(t, err, "expected error for invalid method but got nil")
}

func TestOriginClient_DiscoverCollections_UpdateCache(t *testing.T) {
	t.Parallel()

	// Test that discovery updates an existing cache
	collections1 := []*stac.Collection{
		sampleCollection("col-1"),
	}
	collections2 := []*stac.Collection{
		sampleCollection("col-2"),
		sampleCollection("col-3"),
	}

	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		callCount++
		if callCount == 1 {
			json.NewEncoder(w).Encode(stac.CollectionsResponse{Collections: collections1})
		} else {
			json.NewEncoder(w).Encode(stac.CollectionsResponse{Collections: collections2})
		}
	}))
	defer server.Close()

	origin := &Origin{
		ID:      "test-origin",
		BaseURL: server.URL,
		Timeout: 5 * time.Second,
	}

	client, err := NewOriginClient(origin)
	require.NoError(t, err, "failed to create client")

	ctx := context.Background()

	// First discovery
	require.NoError(t, client.DiscoverCollections(ctx))

	cached := client.CachedCollections()
	assert.Len(t, cached, 1, "expected 1 cached collection after first discovery")

	// Second discovery should replace the cache
	require.NoError(t, client.DiscoverCollections(ctx))

	cached = client.CachedCollections()
	assert.Len(t, cached, 2, "expected 2 cached collections after second discovery")
}

func TestOriginClient_Search_MarshalError(t *testing.T) {
	t.Parallel()

	origin := &Origin{
		ID:      "test-origin",
		BaseURL: "https://api.example.com",
		Timeout: 5 * time.Second,
	}

	client, err := NewOriginClient(origin)
	require.NoError(t, err, "failed to create client")

	ctx := context.Background()

	// Create an unmarshalable search request (channel can't be marshaled)
	req := &stac.SearchRequest{
		Filter: make(chan int),
	}

	_, _, err = client.Search(ctx, req)

	require.Error(t, err, "expected marshal error but got nil")
	assert.ErrorContainsf(t, err, "marshal", "expected marshal error")
}

func TestOriginClient_Retry_BackoffProgression(t *testing.T) {
	t.Parallel()

	var requestTimes []time.Time
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestTimes = append(requestTimes, time.Now())
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer server.Close()

	origin := &Origin{
		ID:      "test-origin",
		BaseURL: server.URL,
		Timeout: 5 * time.Second,
		Retry: &RetryPolicy{
			MaxRetries:     3,
			InitialBackoff: 50 * time.Millisecond,
			MaxBackoff:     200 * time.Millisecond,
			RetryOn:        []int{502},
		},
	}

	client, err := NewOriginClient(origin)
	require.NoError(t, err, "failed to create client")

	ctx := context.Background()
	resp, err := client.DoRequest(ctx, "GET", "/test", nil)
	require.NoError(t, err, "DoRequest")
	resp.Body.Close()
	assert.Equalf(t, http.StatusBadGateway, resp.StatusCode, "final status; want 502 after retry exhaustion")

	// Verify exponential backoff
	require.Len(t, requestTimes, 4, "expected 4 attempts (initial + 3 retries)")

	if len(requestTimes) >= 2 {
		delay1 := requestTimes[1].Sub(requestTimes[0])
		assert.GreaterOrEqualf(t, delay1, 40*time.Millisecond, "first retry delay too short: %v", delay1)
	}

	if len(requestTimes) >= 3 {
		delay2 := requestTimes[2].Sub(requestTimes[1])
		// Second delay should be roughly 2x first (100ms), but allow for timing variance
		assert.GreaterOrEqualf(t, delay2, 80*time.Millisecond, "second retry delay too short: %v", delay2)
	}
}

func TestOriginClient_HasCollection_EmptyCache(t *testing.T) {
	t.Parallel()

	origin := &Origin{
		ID:      "test-origin",
		BaseURL: "https://api.example.com",
	}

	client, err := NewOriginClient(origin)
	require.NoError(t, err, "failed to create client")

	// With empty cache and no explicit collections, should return false
	assert.False(t, client.HasCollection("any-collection"), "expected false for empty cache with no explicit collections")
}

// TestOriginClient_DoRequest_PathPrefixedBaseURL is a regression test
// for a real-world bug discovered by the live tests: STAC APIs in
// the wild host their endpoints under version-prefixed paths like
// https://earth-search.aws.element84.com/v1 and
// https://planetarycomputer.microsoft.com/api/stac/v1. The previous
// implementation used url.ResolveReference("/search"), which per
// RFC 3986 treats `/search` as an absolute-path reference that
// REPLACES the base's path — so the request went out to /search
// instead of /v1/search and the upstream returned 403/405. The fix
// is to treat the path argument as a suffix to be appended to the
// base path.
func TestOriginClient_DoRequest_PathPrefixedBaseURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		basePath   string
		callerPath string
		wantPath   string
	}{
		{"no base path, leading slash", "", "/search", "/search"},
		{"no base path, no leading slash", "", "search", "/search"},
		{"single-segment base, leading slash", "/v1", "/search", "/v1/search"},
		{"single-segment base, no leading slash", "/v1", "search", "/v1/search"},
		{"single-segment base with trailing slash", "/v1/", "/search", "/v1/search"},
		{"multi-segment base", "/api/stac/v1", "/collections", "/api/stac/v1/collections"},
		{"multi-segment base, no leading slash", "/api/stac/v1", "collections", "/api/stac/v1/collections"},
		{"nested suffix path", "/v1", "/collections/landsat/items", "/v1/collections/landsat/items"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var gotPath string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotPath = r.URL.Path
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{}`))
			}))
			defer srv.Close()

			client, err := NewOriginClient(&Origin{
				ID:      "t",
				BaseURL: srv.URL + tt.basePath,
				Enabled: true,
				Timeout: 5 * time.Second,
			})
			require.NoError(t, err, "NewOriginClient")

			resp, err := client.DoRequest(context.Background(), http.MethodGet, tt.callerPath, nil)
			require.NoError(t, err, "DoRequest")
			resp.Body.Close()

			assert.Equalf(t, tt.wantPath, gotPath, "path (base=%q, caller=%q)", tt.basePath, tt.callerPath)
		})
	}
}

// --- H1 regression tests (Worktree B) -----------------------------------

// TestOriginClient_RejectsOversizedResponse: when the upstream returns
// a body larger than Origin.MaxResponseBytes, the origin client must
// error rather than buffer the whole thing into memory.
func TestOriginClient_RejectsOversizedResponse(t *testing.T) {
	t.Parallel()

	// Build a FeatureCollection with a single Item carrying a giant
	// title in Properties. JSON-marshaling produces well over 1 KiB.
	pad := strings.Repeat("A", 2048)
	item := sampleItem("big-item")
	item.Properties["title"] = pad
	fc := sampleFeatureCollection(item)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(fc)
	}))
	defer server.Close()

	origin := &Origin{
		ID:               "test-origin",
		BaseURL:          server.URL,
		Enabled:          true,
		Timeout:          5 * time.Second,
		MaxResponseBytes: 1024,
	}

	client, err := NewOriginClient(origin)
	require.NoError(t, err, "failed to create client")

	_, _, err = client.Search(context.Background(), sampleSearchRequest())
	require.Error(t, err, "expected error for oversized response")
	assert.ErrorContains(t, err, "exceeded", "error should contain 'exceeded'")
}

func TestOriginClient_AcceptsUnderLimit(t *testing.T) {
	t.Parallel()

	fc := sampleFeatureCollection(sampleItem("item-1"))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(fc)
	}))
	defer server.Close()

	origin := &Origin{
		ID:               "test-origin",
		BaseURL:          server.URL,
		Enabled:          true,
		Timeout:          5 * time.Second,
		MaxResponseBytes: 1 << 20,
	}

	client, err := NewOriginClient(origin)
	require.NoError(t, err, "failed to create client")

	got, _, err := client.Search(context.Background(), sampleSearchRequest())
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Len(t, got.Features, 1, "expected 1 feature")
}

func TestOriginClient_DefaultMaxResponseBytes(t *testing.T) {
	t.Parallel()

	origin := &Origin{
		ID:      "test-origin",
		BaseURL: "https://api.example.com",
	}
	client, err := NewOriginClient(origin)
	require.NoError(t, err, "failed to create client")
	assert.Equal(t, int64(32<<20), client.MaxResponseBytes(), "default MaxResponseBytes")
}
