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
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			client, err := NewOriginClient(tt.origin)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got nil")
				} else if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.errContains)
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if client == nil {
				t.Fatal("expected client to be non-nil")
			}

			if client.origin != tt.origin {
				t.Error("client origin does not match input origin")
			}

			if client.httpClient == nil {
				t.Error("expected httpClient to be non-nil")
			}

			if client.baseURL == nil {
				t.Error("expected baseURL to be non-nil")
			}

			if client.collections == nil {
				t.Error("expected collections map to be initialized")
			}
		})
	}
}

func TestNewOriginClient_AutoDiscover(t *testing.T) {
	// Set up a test server
	collections := []stac.Collection{
		*sampleCollection("test-col-1"),
		*sampleCollection("test-col-2"),
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
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Wait a bit for autodiscovery goroutine to complete
	time.Sleep(100 * time.Millisecond)

	// Check that collections were discovered
	cached := client.CachedCollections()
	if len(cached) != 2 {
		t.Errorf("expected 2 cached collections, got %d", len(cached))
	}
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
				if r.Method != "GET" {
					t.Errorf("expected method GET, got %s", r.Method)
				}
				if r.URL.Path != "/collections" {
					t.Errorf("expected path /collections, got %s", r.URL.Path)
				}
				accept := r.Header.Get("Accept")
				if !strings.Contains(accept, "application/geo+json") {
					t.Errorf("expected Accept header to contain application/geo+json, got %s", accept)
				}
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
				if r.Method != "POST" {
					t.Errorf("expected method POST, got %s", r.Method)
				}
				contentType := r.Header.Get("Content-Type")
				if contentType != "application/json" {
					t.Errorf("expected Content-Type application/json, got %s", contentType)
				}
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
				if !ok {
					t.Error("expected basic auth to be present")
				}
				if username != "testuser" {
					t.Errorf("expected username testuser, got %s", username)
				}
				if password != "testpass" {
					t.Errorf("expected password testpass, got %s", password)
				}
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
				auth := r.Header.Get("Authorization")
				expected := "Bearer test-bearer-token"
				if auth != expected {
					t.Errorf("expected Authorization %q, got %q", expected, auth)
				}
			},
			wantErr: false,
		},
		{
			name:   "request with api key in header",
			method: "GET",
			path:   "/collections",
			body:   nil,
			authConfig: AuthConfig{
				Type:         "api_key",
				APIKeyHeader: "X-API-Key",
				APIKeyValue:  "test-key-123",
				APIKeyInQuery: false,
			},
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			},
			checkRequest: func(t *testing.T, r *http.Request) {
				apiKey := r.Header.Get("X-API-Key")
				if apiKey != "test-key-123" {
					t.Errorf("expected X-API-Key test-key-123, got %s", apiKey)
				}
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
				apiKey := r.URL.Query().Get("api_key")
				if apiKey != "test-key-456" {
					t.Errorf("expected api_key test-key-456, got %s", apiKey)
				}
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
				if r.Header.Get("X-Custom-1") != "value1" {
					t.Errorf("expected X-Custom-1 value1, got %s", r.Header.Get("X-Custom-1"))
				}
				if r.Header.Get("X-Custom-2") != "value2" {
					t.Errorf("expected X-Custom-2 value2, got %s", r.Header.Get("X-Custom-2"))
				}
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
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
			if err != nil {
				t.Fatalf("failed to create client: %v", err)
			}

			// Execute request
			ctx := context.Background()
			resp, err := client.DoRequest(ctx, tt.method, tt.path, tt.body)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if resp == nil {
				t.Fatal("expected response to be non-nil")
			}
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
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	ctx := context.Background()
	_, err = client.DoRequest(ctx, "GET", "/collections", nil)

	if err == nil {
		t.Error("expected timeout error but got nil")
	}
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
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err = client.DoRequest(ctx, "GET", "/collections", nil)

	if err == nil {
		t.Error("expected context cancellation error but got nil")
	}
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
				if len(fc.Features) != 2 {
					t.Errorf("expected 2 features, got %d", len(fc.Features))
				}
				if fc.Features[0].ID != "item-1" {
					t.Errorf("expected first item ID item-1, got %s", fc.Features[0].ID)
				}
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
				if len(fc.Features) != 0 {
					t.Errorf("expected 0 features, got %d", len(fc.Features))
				}
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
				if len(fc.Features) != 1 {
					t.Errorf("expected 1 feature, got %d", len(fc.Features))
				}
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
				if len(fc.Features) != 1 {
					t.Errorf("expected 1 feature, got %d", len(fc.Features))
				}
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
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Create test server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/search" {
					t.Errorf("expected path /search, got %s", r.URL.Path)
				}
				if r.Method != "POST" {
					t.Errorf("expected method POST, got %s", r.Method)
				}

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
			if err != nil {
				t.Fatalf("failed to create client: %v", err)
			}

			// Execute search
			ctx := context.Background()
			fc, err := client.Search(ctx, tt.request)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got nil")
				} else if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.errContains)
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if fc == nil {
				t.Fatal("expected feature collection to be non-nil")
			}

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
		checkResult    func(t *testing.T, collections []stac.Collection)
	}{
		{
			name: "successful get collections",
			serverResponse: &stac.CollectionsResponse{
				Collections: []stac.Collection{
					*sampleCollection("col-1"),
					*sampleCollection("col-2"),
					*sampleCollection("col-3"),
				},
			},
			serverStatus: http.StatusOK,
			wantErr:      false,
			checkResult: func(t *testing.T, collections []stac.Collection) {
				if len(collections) != 3 {
					t.Errorf("expected 3 collections, got %d", len(collections))
				}
				if collections[0].ID != "col-1" {
					t.Errorf("expected first collection ID col-1, got %s", collections[0].ID)
				}
			},
		},
		{
			name: "get collections returns empty list",
			serverResponse: &stac.CollectionsResponse{
				Collections: []stac.Collection{},
			},
			serverStatus: http.StatusOK,
			wantErr:      false,
			checkResult: func(t *testing.T, collections []stac.Collection) {
				if len(collections) != 0 {
					t.Errorf("expected 0 collections, got %d", len(collections))
				}
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
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Create test server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/collections" {
					t.Errorf("expected path /collections, got %s", r.URL.Path)
				}
				if r.Method != "GET" {
					t.Errorf("expected method GET, got %s", r.Method)
				}

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
			if err != nil {
				t.Fatalf("failed to create client: %v", err)
			}

			// Execute get collections
			ctx := context.Background()
			collections, err := client.GetCollections(ctx)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got nil")
				} else if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.errContains)
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

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
				if collection.ID != "test-collection" {
					t.Errorf("expected collection ID test-collection, got %s", collection.ID)
				}
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
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Create test server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				expectedPath := fmt.Sprintf("/collections/%s", tt.collectionID)
				if r.URL.Path != expectedPath {
					t.Errorf("expected path %s, got %s", expectedPath, r.URL.Path)
				}
				if r.Method != "GET" {
					t.Errorf("expected method GET, got %s", r.Method)
				}

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
			if err != nil {
				t.Fatalf("failed to create client: %v", err)
			}

			// Execute get collection
			ctx := context.Background()
			collection, err := client.GetCollection(ctx, tt.collectionID)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got nil")
				} else if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.errContains)
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if tt.wantNil {
				if collection != nil {
					t.Error("expected collection to be nil for 404")
				}
				return
			}

			if collection == nil {
				t.Fatal("expected collection to be non-nil")
			}

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
				if item.ID != "test-item" {
					t.Errorf("expected item ID test-item, got %s", item.ID)
				}
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
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Create test server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				expectedPath := fmt.Sprintf("/collections/%s/items/%s", tt.collectionID, tt.itemID)
				if r.URL.Path != expectedPath {
					t.Errorf("expected path %s, got %s", expectedPath, r.URL.Path)
				}
				if r.Method != "GET" {
					t.Errorf("expected method GET, got %s", r.Method)
				}

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
			if err != nil {
				t.Fatalf("failed to create client: %v", err)
			}

			// Execute get item
			ctx := context.Background()
			item, err := client.GetItem(ctx, tt.collectionID, tt.itemID)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got nil")
				} else if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.errContains)
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if tt.wantNil {
				if item != nil {
					t.Error("expected item to be nil for 404")
				}
				return
			}

			if item == nil {
				t.Fatal("expected item to be non-nil")
			}

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
			if err != nil {
				t.Fatalf("failed to create client: %v", err)
			}

			// Execute request
			ctx := context.Background()
			resp, err := client.DoRequest(ctx, "GET", "/collections/test", nil)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if resp != nil {
					resp.Body.Close()
				}
			}

			if attempt != tt.wantAttempts {
				t.Errorf("expected %d attempts, got %d", tt.wantAttempts, attempt)
			}
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
				Collections: []stac.Collection{
					*sampleCollection("col-1"),
					*sampleCollection("col-2"),
				},
			},
			serverStatus: http.StatusOK,
			wantErr:      false,
			checkCache: func(t *testing.T, client *OriginClient) {
				cached := client.CachedCollections()
				if len(cached) != 2 {
					t.Errorf("expected 2 cached collections, got %d", len(cached))
				}

				hasCol1 := false
				hasCol2 := false
				for _, id := range cached {
					if id == "col-1" {
						hasCol1 = true
					}
					if id == "col-2" {
						hasCol2 = true
					}
				}

				if !hasCol1 {
					t.Error("expected col-1 in cache")
				}
				if !hasCol2 {
					t.Error("expected col-2 in cache")
				}
			},
		},
		{
			name: "discovery with no collections",
			serverResponse: &stac.CollectionsResponse{
				Collections: []stac.Collection{},
			},
			serverStatus: http.StatusOK,
			wantErr:      false,
			checkCache: func(t *testing.T, client *OriginClient) {
				cached := client.CachedCollections()
				if len(cached) != 0 {
					t.Errorf("expected 0 cached collections, got %d", len(cached))
				}
			},
		},
		{
			name:         "discovery fails",
			serverStatus: http.StatusInternalServerError,
			wantErr:      true,
		},
	}

	for _, tt := range tests {
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
			if err != nil {
				t.Fatalf("failed to create client: %v", err)
			}

			// Execute discovery
			ctx := context.Background()
			err = client.DiscoverCollections(ctx)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

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
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			client, err := NewOriginClient(tt.origin)
			if err != nil {
				t.Fatalf("failed to create client: %v", err)
			}

			if tt.setupCache != nil {
				tt.setupCache(client)
			}

			got := client.HasCollection(tt.collectionID)
			if got != tt.want {
				t.Errorf("HasCollection(%q) = %v, want %v", tt.collectionID, got, tt.want)
			}
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
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	// Initially empty
	cached := client.CachedCollections()
	if len(cached) != 0 {
		t.Errorf("expected 0 cached collections initially, got %d", len(cached))
	}

	// Add some collections
	client.collectionsLock.Lock()
	client.collections["col-1"] = sampleCollection("col-1")
	client.collections["col-2"] = sampleCollection("col-2")
	client.collections["col-3"] = sampleCollection("col-3")
	client.collectionsLock.Unlock()

	// Check cached
	cached = client.CachedCollections()
	if len(cached) != 3 {
		t.Errorf("expected 3 cached collections, got %d", len(cached))
	}

	// Verify all collections are present
	found := make(map[string]bool)
	for _, id := range cached {
		found[id] = true
	}

	for _, expectedID := range []string{"col-1", "col-2", "col-3"} {
		if !found[expectedID] {
			t.Errorf("expected %s in cached collections", expectedID)
		}
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
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	got := client.Origin()
	if got != origin {
		t.Error("Origin() did not return the same origin instance")
	}
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
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			origin := &Origin{
				ID:      "test-origin",
				BaseURL: tt.baseURL,
			}

			client, err := NewOriginClient(origin)
			if err != nil {
				t.Fatalf("failed to create client: %v", err)
			}

			got := client.BaseURL()
			if got != tt.wantBaseURL {
				t.Errorf("BaseURL() = %q, want %q", got, tt.wantBaseURL)
			}
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
			if err != nil {
				t.Fatalf("failed to create client: %v", err)
			}

			ctx := context.Background()
			resp, err := client.DoRequest(ctx, "GET", tt.path, nil)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			defer resp.Body.Close()

			if capturedURL != tt.path {
				t.Errorf("expected URL path %q, got %q", tt.path, capturedURL)
			}
		})
	}
}

// Test helper functions to avoid import cycle with testutil

func sampleItem(id string) *stac.Item {
	now := time.Now()
	return &stac.Item{
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
		},
		Links: []stac.Link{
			{Rel: "self", Href: "https://example.com/items/" + id, Type: "application/geo+json"},
		},
		Assets: map[string]stac.Asset{
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
		},
	}
}

func sampleFeatureCollection(items ...*stac.Item) *stac.FeatureCollection {
	stacItems := make([]stac.Item, len(items))
	for i, item := range items {
		stacItems[i] = *item
	}

	fc := &stac.FeatureCollection{
		Type:     "FeatureCollection",
		Features: stacItems,
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
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	ctx := context.Background()
	_, err = client.Search(ctx, sampleSearchRequest())

	if err == nil {
		t.Error("expected error for invalid JSON but got nil")
	}
	if !strings.Contains(err.Error(), "parse") {
		t.Errorf("expected parse error, got: %v", err)
	}
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
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	ctx := context.Background()
	_, err = client.GetCollections(ctx)

	if err == nil {
		t.Error("expected error for invalid JSON but got nil")
	}
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
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	ctx := context.Background()
	_, err = client.GetCollection(ctx, "test-collection")

	if err == nil {
		t.Error("expected error for invalid JSON but got nil")
	}
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
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	ctx := context.Background()
	_, err = client.GetItem(ctx, "test-collection", "test-item")

	if err == nil {
		t.Error("expected error for invalid JSON but got nil")
	}
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
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	// Create context that will be cancelled during retry
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	_, err = client.DoRequest(ctx, "GET", "/test", nil)

	if err == nil {
		t.Error("expected context cancellation error but got nil")
	}

	// Should have attempted at least once but not all retries
	if attempt == 0 {
		t.Error("expected at least one attempt")
	}
	if attempt >= 5 {
		t.Errorf("expected fewer than 5 attempts due to context cancellation, got %d", attempt)
	}
}

func TestOriginClient_DoRequest_InvalidMethod(t *testing.T) {
	t.Parallel()

	origin := &Origin{
		ID:      "test-origin",
		BaseURL: "https://api.example.com",
		Timeout: 5 * time.Second,
	}

	client, err := NewOriginClient(origin)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	ctx := context.Background()
	// Invalid method with control characters
	_, err = client.DoRequest(ctx, "GET\n", "/collections", nil)

	if err == nil {
		t.Error("expected error for invalid method but got nil")
	}
}

func TestOriginClient_DiscoverCollections_UpdateCache(t *testing.T) {
	t.Parallel()

	// Test that discovery updates an existing cache
	collections1 := []stac.Collection{
		*sampleCollection("col-1"),
	}
	collections2 := []stac.Collection{
		*sampleCollection("col-2"),
		*sampleCollection("col-3"),
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
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	ctx := context.Background()

	// First discovery
	err = client.DiscoverCollections(ctx)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	cached := client.CachedCollections()
	if len(cached) != 1 {
		t.Errorf("expected 1 cached collection after first discovery, got %d", len(cached))
	}

	// Second discovery should replace the cache
	err = client.DiscoverCollections(ctx)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	cached = client.CachedCollections()
	if len(cached) != 2 {
		t.Errorf("expected 2 cached collections after second discovery, got %d", len(cached))
	}
}

func TestOriginClient_Search_MarshalError(t *testing.T) {
	t.Parallel()

	origin := &Origin{
		ID:      "test-origin",
		BaseURL: "https://api.example.com",
		Timeout: 5 * time.Second,
	}

	client, err := NewOriginClient(origin)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	ctx := context.Background()

	// Create an unmarshalable search request (channel can't be marshaled)
	req := &stac.SearchRequest{
		Filter: make(chan int),
	}

	_, err = client.Search(ctx, req)

	if err == nil {
		t.Error("expected marshal error but got nil")
	}
	if !strings.Contains(err.Error(), "marshal") {
		t.Errorf("expected marshal error, got: %v", err)
	}
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
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	ctx := context.Background()
	resp, err := client.DoRequest(ctx, "GET", "/test", nil)
	if err != nil {
		t.Fatalf("DoRequest: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("final status = %d, want 502 after retry exhaustion", resp.StatusCode)
	}

	// Verify exponential backoff
	if len(requestTimes) != 4 { // initial + 3 retries
		t.Errorf("expected 4 attempts, got %d", len(requestTimes))
	}

	if len(requestTimes) >= 2 {
		delay1 := requestTimes[1].Sub(requestTimes[0])
		if delay1 < 40*time.Millisecond {
			t.Errorf("first retry delay too short: %v", delay1)
		}
	}

	if len(requestTimes) >= 3 {
		delay2 := requestTimes[2].Sub(requestTimes[1])
		// Second delay should be roughly 2x first (100ms), but allow for timing variance
		if delay2 < 80*time.Millisecond {
			t.Errorf("second retry delay too short: %v", delay2)
		}
	}
}

func TestOriginClient_HasCollection_EmptyCache(t *testing.T) {
	t.Parallel()

	origin := &Origin{
		ID:      "test-origin",
		BaseURL: "https://api.example.com",
	}

	client, err := NewOriginClient(origin)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	// With empty cache and no explicit collections, should return false
	has := client.HasCollection("any-collection")
	if has {
		t.Error("expected false for empty cache with no explicit collections")
	}
}
