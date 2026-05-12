package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yourorg/stac-proxy/internal/middleware"
	"github.com/yourorg/stac-proxy/internal/stac"
	"github.com/yourorg/stac-proxy/internal/testutil"
)

// TestNewHandler tests handler initialization with various configurations.
func TestNewHandler(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		config    Config
		wantErr   bool
		errString string
	}{
		{
			name: "valid config",
			config: Config{
				UpstreamURL:  "https://example.com",
				ProxyBaseURL: "https://proxy.example.com",
				Timeout:      30,
			},
			wantErr: false,
		},
		{
			name: "valid config with retry",
			config: Config{
				UpstreamURL:  "https://example.com",
				ProxyBaseURL: "https://proxy.example.com",
				Timeout:      60,
				Retry: &RetryConfig{
					MaxRetries:     3,
					InitialBackoff: time.Second,
					MaxBackoff:     10 * time.Second,
					RetryOn:        []int{500, 502, 503},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid upstream URL",
			config: Config{
				UpstreamURL:  "://invalid-url",
				ProxyBaseURL: "https://proxy.example.com",
			},
			wantErr:   true,
			errString: "failed to create client",
		},
		{
			name: "empty upstream URL",
			config: Config{
				UpstreamURL:  "",
				ProxyBaseURL: "https://proxy.example.com",
			},
			wantErr:   true,
			errString: "failed to create client",
		},
		{
			name: "zero timeout",
			config: Config{
				UpstreamURL:  "https://example.com",
				ProxyBaseURL: "https://proxy.example.com",
				Timeout:      0,
			},
			wantErr: false,
		},
		{
			name: "empty proxy base URL (allowed)",
			config: Config{
				UpstreamURL:  "https://example.com",
				ProxyBaseURL: "",
			},
			wantErr: false,
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
				} else if tt.errString != "" && !strings.Contains(err.Error(), tt.errString) {
					t.Errorf("expected error to contain %q, got %q", tt.errString, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if handler == nil {
				t.Error("handler is nil")
				return
			}

			if handler.client == nil {
				t.Error("handler client is nil")
			}

			if handler.proxyBaseURL != tt.config.ProxyBaseURL {
				t.Errorf("proxyBaseURL = %q, want %q", handler.proxyBaseURL, tt.config.ProxyBaseURL)
			}
		})
	}
}

// TestHandle tests the main Handle method with various request types.
func TestHandle(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		method         string
		path           string
		requestBody    interface{}
		requestType    middleware.RequestType
		upstreamStatus int
		upstreamBody   interface{}
		proxyBaseURL   string
		wantStatus     int
		wantErr        bool
		errString      string
		checkBody      func(t *testing.T, body []byte)
	}{
		{
			name:           "successful GET request",
			method:         http.MethodGet,
			path:           "/collections",
			requestType:    middleware.RequestTypeCollections,
			upstreamStatus: http.StatusOK,
			upstreamBody: map[string]interface{}{
				"collections": []interface{}{},
				"links":       []interface{}{},
			},
			wantStatus: http.StatusOK,
			wantErr:    false,
		},
		{
			name:           "successful POST request",
			method:         http.MethodPost,
			path:           "/search",
			requestBody:    map[string]interface{}{"limit": 10},
			requestType:    middleware.RequestTypeSearch,
			upstreamStatus: http.StatusOK,
			upstreamBody: map[string]interface{}{
				"type":     "FeatureCollection",
				"features": []interface{}{},
			},
			wantStatus: http.StatusOK,
			wantErr:    false,
		},
		{
			name:           "upstream returns 404",
			method:         http.MethodGet,
			path:           "/collections/nonexistent",
			requestType:    middleware.RequestTypeCollection,
			upstreamStatus: http.StatusNotFound,
			upstreamBody:   map[string]interface{}{"error": "not found"},
			wantStatus:     http.StatusNotFound,
			wantErr:        false,
		},
		{
			name:           "upstream returns 500",
			method:         http.MethodGet,
			path:           "/collections",
			requestType:    middleware.RequestTypeCollections,
			upstreamStatus: http.StatusInternalServerError,
			upstreamBody:   map[string]interface{}{"error": "internal error"},
			wantStatus:     http.StatusInternalServerError,
			wantErr:        false,
		},
		{
			name:           "link rewriting with proxy base URL",
			method:         http.MethodGet,
			path:           "/collections/test-coll",
			requestType:    middleware.RequestTypeCollection,
			upstreamStatus: http.StatusOK,
			upstreamBody: map[string]interface{}{
				"id":   "test-coll",
				"type": "Collection",
				"links": []interface{}{
					map[string]interface{}{
						"rel":  "self",
						"href": "https://upstream.example.com/collections/test-coll",
					},
				},
			},
			proxyBaseURL: "https://proxy.example.com",
			wantStatus:   http.StatusOK,
			wantErr:      false,
			checkBody: func(t *testing.T, body []byte) {
				var result map[string]interface{}
				if err := json.Unmarshal(body, &result); err != nil {
					t.Fatalf("failed to parse response: %v", err)
				}

				links, ok := result["links"].([]interface{})
				if !ok || len(links) == 0 {
					t.Fatal("links not found in response")
				}

				link := links[0].(map[string]interface{})
				href := link["href"].(string)
				if !strings.HasPrefix(href, "https://proxy.example.com") {
					t.Errorf("link not rewritten: got %q", href)
				}
			},
		},
		{
			name:           "no link rewriting without proxy base URL",
			method:         http.MethodGet,
			path:           "/collections/test-coll",
			requestType:    middleware.RequestTypeCollection,
			upstreamStatus: http.StatusOK,
			upstreamBody: map[string]interface{}{
				"id":   "test-coll",
				"type": "Collection",
				"links": []interface{}{
					map[string]interface{}{
						"rel":  "self",
						"href": "https://upstream.example.com/collections/test-coll",
					},
				},
			},
			proxyBaseURL: "",
			wantStatus:   http.StatusOK,
			wantErr:      false,
			checkBody: func(t *testing.T, body []byte) {
				var result map[string]interface{}
				if err := json.Unmarshal(body, &result); err != nil {
					t.Fatalf("failed to parse response: %v", err)
				}

				links, ok := result["links"].([]interface{})
				if !ok || len(links) == 0 {
					t.Fatal("links not found in response")
				}

				link := links[0].(map[string]interface{})
				href := link["href"].(string)
				if href != "https://upstream.example.com/collections/test-coll" {
					t.Errorf("link was modified unexpectedly: got %q", href)
				}
			},
		},
		{
			name:           "non-JSON content-type skips link rewriting",
			method:         http.MethodGet,
			path:           "/data.tif",
			requestType:    middleware.RequestTypeUnknown,
			upstreamStatus: http.StatusOK,
			upstreamBody:   []byte("binary data"),
			proxyBaseURL:   "https://proxy.example.com",
			wantStatus:     http.StatusOK,
			wantErr:        false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Create test server. The handler also rewrites any
			// hardcoded "https://upstream.example.com" placeholder in
			// JSON response bodies so the link rewriter can recognise
			// the real upstream URL (httptest assigns it dynamically).
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Verify request method and path
				if r.Method != tt.method {
					t.Errorf("method = %q, want %q", r.Method, tt.method)
				}
				if r.URL.Path != tt.path {
					t.Errorf("path = %q, want %q", r.URL.Path, tt.path)
				}

				// Set content type based on body type
				if _, ok := tt.upstreamBody.([]byte); ok {
					w.Header().Set("Content-Type", "application/octet-stream")
				} else {
					w.Header().Set("Content-Type", "application/json")
				}

				w.WriteHeader(tt.upstreamStatus)

				if tt.upstreamBody != nil {
					if bodyBytes, ok := tt.upstreamBody.([]byte); ok {
						w.Write(bodyBytes)
					} else {
						raw, _ := json.Marshal(tt.upstreamBody)
						// When the test expects the link rewriter to
						// fire, substitute the placeholder URL with the
						// real upstream URL so the rewriter recognises
						// it. Otherwise leave the body verbatim.
						if tt.proxyBaseURL != "" {
							raw = bytes.ReplaceAll(raw,
								[]byte("https://upstream.example.com"),
								[]byte("http://"+r.Host))
						}
						w.Write(raw)
					}
				}
			}))
			defer server.Close()

			// Create handler
			handler, err := NewHandler(Config{
				UpstreamURL:  server.URL,
				ProxyBaseURL: tt.proxyBaseURL,
				Timeout:      5,
			})
			if err != nil {
				t.Fatalf("failed to create handler: %v", err)
			}

			// Create request
			var bodyReader io.Reader
			if tt.requestBody != nil {
				bodyBytes, _ := json.Marshal(tt.requestBody)
				bodyReader = bytes.NewReader(bodyBytes)
			}

			httpReq := httptest.NewRequest(tt.method, tt.path, bodyReader)
			stacReq := &middleware.STACRequest{
				Request:     httpReq,
				Context:     context.Background(),
				RequestType: tt.requestType,
			}

			// Execute
			resp, err := handler.Handle(context.Background(), stacReq)

			// Check error
			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got nil")
				} else if tt.errString != "" && !strings.Contains(err.Error(), tt.errString) {
					t.Errorf("error = %q, want substring %q", err.Error(), tt.errString)
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			// Check status code
			if resp.StatusCode != tt.wantStatus {
				t.Errorf("status code = %d, want %d", resp.StatusCode, tt.wantStatus)
			}

			// Run custom body checks
			if tt.checkBody != nil {
				tt.checkBody(t, resp.Body)
			}
		})
	}
}

// TestHandleWithUpstreamErrors tests handling of upstream errors.
func TestHandleWithUpstreamErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		serverFn  func(w http.ResponseWriter, r *http.Request)
		wantErr   bool
		errString string
	}{
		{
			name: "upstream connection refused",
			serverFn: func(w http.ResponseWriter, r *http.Request) {
				// Server closed before handler executes
			},
			wantErr:   true,
			errString: "upstream request failed",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Create and immediately close server to simulate connection error
			server := httptest.NewServer(http.HandlerFunc(tt.serverFn))
			server.Close()

			handler, err := NewHandler(Config{
				UpstreamURL: server.URL,
				Timeout:     1,
			})
			if err != nil {
				t.Fatalf("failed to create handler: %v", err)
			}

			httpReq := httptest.NewRequest(http.MethodGet, "/test", nil)
			stacReq := &middleware.STACRequest{
				Request:     httpReq,
				Context:     context.Background(),
				RequestType: middleware.RequestTypeUnknown,
			}

			_, err = handler.Handle(context.Background(), stacReq)

			if tt.wantErr && err == nil {
				t.Error("expected error but got nil")
			} else if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			} else if tt.wantErr && tt.errString != "" && !strings.Contains(err.Error(), tt.errString) {
				t.Errorf("error = %q, want substring %q", err.Error(), tt.errString)
			}
		})
	}
}

// TestTransformResponse tests the response transformation logic.
func TestTransformResponse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		proxyBaseURL string
		contentType  string
		inputBody    map[string]interface{}
		wantBody     map[string]interface{}
		expectChange bool
	}{
		{
			name:         "no proxy base URL - no transformation",
			proxyBaseURL: "",
			contentType:  "application/json",
			inputBody: map[string]interface{}{
				"links": []interface{}{
					map[string]interface{}{
						"rel":  "self",
						"href": "https://upstream.example.com/test",
					},
				},
			},
			wantBody: map[string]interface{}{
				"links": []interface{}{
					map[string]interface{}{
						"rel":  "self",
						"href": "https://upstream.example.com/test",
					},
				},
			},
			expectChange: false,
		},
		{
			name:         "non-JSON content type - no transformation",
			proxyBaseURL: "https://proxy.example.com",
			contentType:  "text/plain",
			inputBody: map[string]interface{}{
				"links": []interface{}{
					map[string]interface{}{
						"rel":  "self",
						"href": "https://upstream.example.com/test",
					},
				},
			},
			wantBody: map[string]interface{}{
				"links": []interface{}{
					map[string]interface{}{
						"rel":  "self",
						"href": "https://upstream.example.com/test",
					},
				},
			},
			expectChange: false,
		},
		{
			name:         "simple link rewriting",
			proxyBaseURL: "https://proxy.example.com",
			contentType:  "application/json",
			inputBody: map[string]interface{}{
				"links": []interface{}{
					map[string]interface{}{
						"rel":  "self",
						"href": "https://upstream.example.com/test",
					},
				},
			},
			wantBody: map[string]interface{}{
				"links": []interface{}{
					map[string]interface{}{
						"rel":  "self",
						"href": "https://proxy.example.com/test",
					},
				},
			},
			expectChange: true,
		},
		{
			name:         "nested links rewriting",
			proxyBaseURL: "https://proxy.example.com",
			contentType:  "application/json",
			inputBody: map[string]interface{}{
				"collections": []interface{}{
					map[string]interface{}{
						"id": "test",
						"links": []interface{}{
							map[string]interface{}{
								"rel":  "items",
								"href": "https://upstream.example.com/collections/test/items",
							},
						},
					},
				},
			},
			wantBody: map[string]interface{}{
				"collections": []interface{}{
					map[string]interface{}{
						"id": "test",
						"links": []interface{}{
							map[string]interface{}{
								"rel":  "items",
								"href": "https://proxy.example.com/collections/test/items",
							},
						},
					},
				},
			},
			expectChange: true,
		},
		{
			name:         "links not matching upstream base URL - no change",
			proxyBaseURL: "https://proxy.example.com",
			contentType:  "application/json",
			inputBody: map[string]interface{}{
				"links": []interface{}{
					map[string]interface{}{
						"rel":  "external",
						"href": "https://other.example.com/test",
					},
				},
			},
			wantBody: map[string]interface{}{
				"links": []interface{}{
					map[string]interface{}{
						"rel":  "external",
						"href": "https://other.example.com/test",
					},
				},
			},
			expectChange: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// We don't dial the upstream in this test — only the URL
			// is used by the link rewriter — so a fixed upstream URL
			// that matches the test bodies is what we want.
			handler, err := NewHandler(Config{
				UpstreamURL:  "https://upstream.example.com",
				ProxyBaseURL: tt.proxyBaseURL,
			})
			if err != nil {
				t.Fatalf("failed to create handler: %v", err)
			}

			// Create response
			bodyBytes, _ := json.Marshal(tt.inputBody)
			headers := http.Header{}
			headers.Set("Content-Type", tt.contentType)

			resp := &middleware.STACResponse{
				StatusCode: http.StatusOK,
				Headers:    headers,
				Body:       bodyBytes,
			}

			// Transform
			req := &middleware.STACRequest{
				Request: httptest.NewRequest(http.MethodGet, "/test", nil),
			}
			result := handler.transformResponse(req, resp)

			// Parse result
			var resultBody map[string]interface{}
			if err := json.Unmarshal(result.Body, &resultBody); err != nil {
				t.Fatalf("failed to parse result: %v", err)
			}

			// Compare
			resultJSON, _ := json.Marshal(resultBody)
			wantJSON, _ := json.Marshal(tt.wantBody)

			if string(resultJSON) != string(wantJSON) {
				t.Errorf("body mismatch:\ngot:  %s\nwant: %s", resultJSON, wantJSON)
			}
		})
	}
}

// TestRewriteLinks tests the link rewriting recursion.
func TestRewriteLinks(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server.Close()

	handler, err := NewHandler(Config{
		UpstreamURL:  server.URL,
		ProxyBaseURL: "https://proxy.example.com",
	})
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	tests := []struct {
		name  string
		input map[string]interface{}
		want  map[string]interface{}
	}{
		{
			name: "top level links",
			input: map[string]interface{}{
				"links": []interface{}{
					map[string]interface{}{
						"href": server.URL + "/test",
					},
				},
			},
			want: map[string]interface{}{
				"links": []interface{}{
					map[string]interface{}{
						"href": "https://proxy.example.com/test",
					},
				},
			},
		},
		{
			name: "deeply nested links",
			input: map[string]interface{}{
				"level1": map[string]interface{}{
					"level2": map[string]interface{}{
						"links": []interface{}{
							map[string]interface{}{
								"href": server.URL + "/deep",
							},
						},
					},
				},
			},
			want: map[string]interface{}{
				"level1": map[string]interface{}{
					"level2": map[string]interface{}{
						"links": []interface{}{
							map[string]interface{}{
								"href": "https://proxy.example.com/deep",
							},
						},
					},
				},
			},
		},
		{
			name: "multiple links in array",
			input: map[string]interface{}{
				"links": []interface{}{
					map[string]interface{}{"href": server.URL + "/link1"},
					map[string]interface{}{"href": server.URL + "/link2"},
					map[string]interface{}{"href": server.URL + "/link3"},
				},
			},
			want: map[string]interface{}{
				"links": []interface{}{
					map[string]interface{}{"href": "https://proxy.example.com/link1"},
					map[string]interface{}{"href": "https://proxy.example.com/link2"},
					map[string]interface{}{"href": "https://proxy.example.com/link3"},
				},
			},
		},
		{
			name: "no links array",
			input: map[string]interface{}{
				"data": "test",
			},
			want: map[string]interface{}{
				"data": "test",
			},
		},
		{
			name: "empty links array",
			input: map[string]interface{}{
				"links": []interface{}{},
			},
			want: map[string]interface{}{
				"links": []interface{}{},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Make a deep copy of input
			inputCopy := copyMap(tt.input)

			// Rewrite
			handler.rewriteLinks(inputCopy)

			// Compare
			inputJSON, _ := json.Marshal(inputCopy)
			wantJSON, _ := json.Marshal(tt.want)

			if string(inputJSON) != string(wantJSON) {
				t.Errorf("result mismatch:\ngot:  %s\nwant: %s", inputJSON, wantJSON)
			}
		})
	}
}

// TestRewriteURL tests the URL rewriting logic.
func TestRewriteURL(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server.Close()

	handler, err := NewHandler(Config{
		UpstreamURL:  server.URL,
		ProxyBaseURL: "https://proxy.example.com",
	})
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	tests := []struct {
		name string
		href string
		want string
	}{
		{
			name: "matching upstream URL",
			href: server.URL + "/collections",
			want: "https://proxy.example.com/collections",
		},
		{
			name: "non-matching URL",
			href: "https://other.example.com/test",
			want: "https://other.example.com/test",
		},
		{
			name: "relative URL (no prefix match)",
			href: "/collections",
			want: "/collections",
		},
		{
			name: "empty URL",
			href: "",
			want: "",
		},
		{
			name: "URL with query params",
			href: server.URL + "/search?limit=10",
			want: "https://proxy.example.com/search?limit=10",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := handler.rewriteURL(tt.href)
			if got != tt.want {
				t.Errorf("rewriteURL(%q) = %q, want %q", tt.href, got, tt.want)
			}
		})
	}
}

// TestHandleSearch tests the HandleSearch method.
func TestHandleSearch(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		searchReq      *stac.SearchRequest
		upstreamStatus int
		upstreamBody   interface{}
		wantErr        bool
		errString      string
		checkResult    func(t *testing.T, fc *stac.FeatureCollection)
	}{
		{
			name: "successful search",
			searchReq: &stac.SearchRequest{
				Limit: 10,
			},
			upstreamStatus: http.StatusOK,
			upstreamBody: map[string]interface{}{
				"type":     "FeatureCollection",
				"features": []interface{}{},
			},
			wantErr: false,
			checkResult: func(t *testing.T, fc *stac.FeatureCollection) {
				if fc == nil {
					t.Error("result is nil")
				}
				if fc.Type != "FeatureCollection" {
					t.Errorf("type = %q, want %q", fc.Type, "FeatureCollection")
				}
			},
		},
		{
			name: "search with filters",
			searchReq: &stac.SearchRequest{
				Collections: []string{"test-coll"},
				Limit:       50,
				BBox:        []float64{-10, -10, 10, 10},
			},
			upstreamStatus: http.StatusOK,
			upstreamBody: stac.FeatureCollection{
				Type:     "FeatureCollection",
				Features: []stac.Item{},
				Context: &stac.SearchContext{
					Returned: 0,
					Limit:    50,
				},
			},
			wantErr: false,
		},
		{
			name: "upstream error",
			searchReq: &stac.SearchRequest{
				Limit: 10,
			},
			upstreamStatus: http.StatusBadRequest,
			upstreamBody:   map[string]interface{}{"error": "bad request"},
			wantErr:        true,
			errString:      "search failed with status 400",
		},
		{
			name: "upstream 500 error",
			searchReq: &stac.SearchRequest{
				Limit: 10,
			},
			upstreamStatus: http.StatusInternalServerError,
			upstreamBody:   map[string]interface{}{"error": "internal error"},
			wantErr:        true,
			errString:      "search failed with status 500",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Create test server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Verify it's a POST to /search
				if r.Method != http.MethodPost {
					t.Errorf("method = %q, want POST", r.Method)
				}
				if r.URL.Path != "/search" {
					t.Errorf("path = %q, want /search", r.URL.Path)
				}

				// Verify request body
				var reqBody stac.SearchRequest
				if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
					t.Errorf("failed to decode request: %v", err)
				}

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.upstreamStatus)
				json.NewEncoder(w).Encode(tt.upstreamBody)
			}))
			defer server.Close()

			// Create handler
			handler, err := NewHandler(Config{
				UpstreamURL: server.URL,
			})
			if err != nil {
				t.Fatalf("failed to create handler: %v", err)
			}

			// Execute
			result, err := handler.HandleSearch(context.Background(), tt.searchReq)

			// Check error
			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got nil")
				} else if tt.errString != "" && !strings.Contains(err.Error(), tt.errString) {
					t.Errorf("error = %q, want substring %q", err.Error(), tt.errString)
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			// Run custom checks
			if tt.checkResult != nil {
				tt.checkResult(t, result)
			}
		})
	}
}

// TestHandleGetCollections tests the HandleGetCollections method.
func TestHandleGetCollections(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		upstreamStatus int
		upstreamBody   interface{}
		wantErr        bool
		errString      string
		checkResult    func(t *testing.T, colls *stac.CollectionsResponse)
	}{
		{
			name:           "successful get collections",
			upstreamStatus: http.StatusOK,
			upstreamBody: stac.CollectionsResponse{
				Collections: []stac.Collection{
					{ID: "coll1", Type: "Collection", Description: "Test collection 1", License: "MIT"},
					{ID: "coll2", Type: "Collection", Description: "Test collection 2", License: "MIT"},
				},
			},
			wantErr: false,
			checkResult: func(t *testing.T, colls *stac.CollectionsResponse) {
				if len(colls.Collections) != 2 {
					t.Errorf("got %d collections, want 2", len(colls.Collections))
				}
			},
		},
		{
			name:           "empty collections",
			upstreamStatus: http.StatusOK,
			upstreamBody: stac.CollectionsResponse{
				Collections: []stac.Collection{},
			},
			wantErr: false,
			checkResult: func(t *testing.T, colls *stac.CollectionsResponse) {
				if len(colls.Collections) != 0 {
					t.Errorf("got %d collections, want 0", len(colls.Collections))
				}
			},
		},
		{
			name:           "upstream error",
			upstreamStatus: http.StatusInternalServerError,
			upstreamBody:   map[string]interface{}{"error": "internal error"},
			wantErr:        true,
			errString:      "get collections failed with status 500",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Errorf("method = %q, want GET", r.Method)
				}
				if r.URL.Path != "/collections" {
					t.Errorf("path = %q, want /collections", r.URL.Path)
				}

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.upstreamStatus)
				json.NewEncoder(w).Encode(tt.upstreamBody)
			}))
			defer server.Close()

			handler, err := NewHandler(Config{
				UpstreamURL: server.URL,
			})
			if err != nil {
				t.Fatalf("failed to create handler: %v", err)
			}

			result, err := handler.HandleGetCollections(context.Background())

			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got nil")
				} else if tt.errString != "" && !strings.Contains(err.Error(), tt.errString) {
					t.Errorf("error = %q, want substring %q", err.Error(), tt.errString)
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if tt.checkResult != nil {
				tt.checkResult(t, result)
			}
		})
	}
}

// TestHandleGetCollection tests the HandleGetCollection method.
func TestHandleGetCollection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		collectionID   string
		upstreamStatus int
		upstreamBody   interface{}
		wantErr        bool
		errString      string
		wantNil        bool
		checkResult    func(t *testing.T, coll *stac.Collection)
	}{
		{
			name:           "successful get collection",
			collectionID:   "test-coll",
			upstreamStatus: http.StatusOK,
			upstreamBody: stac.Collection{
				ID:          "test-coll",
				Type:        "Collection",
				Description: "Test collection",
				License:     "MIT",
			},
			wantErr: false,
			checkResult: func(t *testing.T, coll *stac.Collection) {
				if coll.ID != "test-coll" {
					t.Errorf("ID = %q, want %q", coll.ID, "test-coll")
				}
			},
		},
		{
			name:           "collection not found returns nil",
			collectionID:   "nonexistent",
			upstreamStatus: http.StatusNotFound,
			upstreamBody:   map[string]interface{}{"error": "not found"},
			wantErr:        false,
			wantNil:        true,
		},
		{
			name:           "upstream error",
			collectionID:   "test-coll",
			upstreamStatus: http.StatusInternalServerError,
			upstreamBody:   map[string]interface{}{"error": "internal error"},
			wantErr:        true,
			errString:      "get collection failed with status 500",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				expectedPath := "/collections/" + tt.collectionID
				if r.URL.Path != expectedPath {
					t.Errorf("path = %q, want %q", r.URL.Path, expectedPath)
				}

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.upstreamStatus)
				json.NewEncoder(w).Encode(tt.upstreamBody)
			}))
			defer server.Close()

			handler, err := NewHandler(Config{
				UpstreamURL: server.URL,
			})
			if err != nil {
				t.Fatalf("failed to create handler: %v", err)
			}

			result, err := handler.HandleGetCollection(context.Background(), tt.collectionID)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got nil")
				} else if tt.errString != "" && !strings.Contains(err.Error(), tt.errString) {
					t.Errorf("error = %q, want substring %q", err.Error(), tt.errString)
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if tt.wantNil {
				if result != nil {
					t.Error("expected nil result but got non-nil")
				}
				return
			}

			if result == nil {
				t.Error("unexpected nil result")
				return
			}

			if tt.checkResult != nil {
				tt.checkResult(t, result)
			}
		})
	}
}

// TestHandleGetItem tests the HandleGetItem method.
func TestHandleGetItem(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		collectionID   string
		itemID         string
		upstreamStatus int
		upstreamBody   interface{}
		wantErr        bool
		errString      string
		wantNil        bool
		checkResult    func(t *testing.T, item *stac.Item)
	}{
		{
			name:           "successful get item",
			collectionID:   "test-coll",
			itemID:         "item1",
			upstreamStatus: http.StatusOK,
			upstreamBody:   testutil.SampleItem("item1"),
			wantErr:        false,
			checkResult: func(t *testing.T, item *stac.Item) {
				if item.ID != "item1" {
					t.Errorf("ID = %q, want %q", item.ID, "item1")
				}
			},
		},
		{
			name:           "item not found returns nil",
			collectionID:   "test-coll",
			itemID:         "nonexistent",
			upstreamStatus: http.StatusNotFound,
			upstreamBody:   map[string]interface{}{"error": "not found"},
			wantErr:        false,
			wantNil:        true,
		},
		{
			name:           "upstream error",
			collectionID:   "test-coll",
			itemID:         "item1",
			upstreamStatus: http.StatusInternalServerError,
			upstreamBody:   map[string]interface{}{"error": "internal error"},
			wantErr:        true,
			errString:      "get item failed with status 500",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				expectedPath := "/collections/" + tt.collectionID + "/items/" + tt.itemID
				if r.URL.Path != expectedPath {
					t.Errorf("path = %q, want %q", r.URL.Path, expectedPath)
				}

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.upstreamStatus)
				json.NewEncoder(w).Encode(tt.upstreamBody)
			}))
			defer server.Close()

			handler, err := NewHandler(Config{
				UpstreamURL: server.URL,
			})
			if err != nil {
				t.Fatalf("failed to create handler: %v", err)
			}

			result, err := handler.HandleGetItem(context.Background(), tt.collectionID, tt.itemID)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got nil")
				} else if tt.errString != "" && !strings.Contains(err.Error(), tt.errString) {
					t.Errorf("error = %q, want substring %q", err.Error(), tt.errString)
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if tt.wantNil {
				if result != nil {
					t.Error("expected nil result but got non-nil")
				}
				return
			}

			if result == nil {
				t.Error("unexpected nil result")
				return
			}

			if tt.checkResult != nil {
				tt.checkResult(t, result)
			}
		})
	}
}

// TestHandleWithContext tests context handling.
func TestHandleWithContext(t *testing.T) {
	t.Parallel()

	t.Run("context cancellation", func(t *testing.T) {
		t.Parallel()

		// Create server that delays
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(100 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		handler, err := NewHandler(Config{
			UpstreamURL: server.URL,
		})
		if err != nil {
			t.Fatalf("failed to create handler: %v", err)
		}

		// Create context that will be cancelled
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()

		httpReq := httptest.NewRequest(http.MethodGet, "/test", nil)
		stacReq := &middleware.STACRequest{
			Request: httpReq,
			Context: ctx,
		}

		_, err = handler.Handle(ctx, stacReq)
		if err == nil {
			t.Error("expected error due to context cancellation")
		}
	})

	t.Run("context with values", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{}`))
		}))
		defer server.Close()

		handler, err := NewHandler(Config{
			UpstreamURL: server.URL,
		})
		if err != nil {
			t.Fatalf("failed to create handler: %v", err)
		}

		// Create context with value
		ctx := context.WithValue(context.Background(), "test-key", "test-value")

		httpReq := httptest.NewRequest(http.MethodGet, "/test", nil)
		stacReq := &middleware.STACRequest{
			Request: httpReq,
			Context: ctx,
		}

		_, err = handler.Handle(ctx, stacReq)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

// TestHandleWithDifferentMethods tests all HTTP methods.
func TestHandleWithDifferentMethods(t *testing.T) {
	t.Parallel()

	methods := []string{
		http.MethodGet,
		http.MethodPost,
		http.MethodPut,
		http.MethodPatch,
		http.MethodDelete,
	}

	for _, method := range methods {
		method := method
		t.Run(method, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != method {
					t.Errorf("method = %q, want %q", r.Method, method)
				}
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{}`))
			}))
			defer server.Close()

			handler, err := NewHandler(Config{
				UpstreamURL: server.URL,
			})
			if err != nil {
				t.Fatalf("failed to create handler: %v", err)
			}

			httpReq := httptest.NewRequest(method, "/test", nil)
			stacReq := &middleware.STACRequest{
				Request: httpReq,
			}

			_, err = handler.Handle(context.Background(), stacReq)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// TestHandleInvalidJSON tests handling of invalid JSON in response.
func TestHandleInvalidJSON(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{invalid json`))
	}))
	defer server.Close()

	handler, err := NewHandler(Config{
		UpstreamURL:  server.URL,
		ProxyBaseURL: "https://proxy.example.com",
	})
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	httpReq := httptest.NewRequest(http.MethodGet, "/test", nil)
	stacReq := &middleware.STACRequest{
		Request: httpReq,
	}

	// Should not error, just return response as-is
	resp, err := handler.Handle(context.Background(), stacReq)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status code = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	// Body should be unchanged invalid JSON
	if string(resp.Body) != `{invalid json` {
		t.Errorf("body was modified: %s", string(resp.Body))
	}
}

// TestHandleWithRequestBody tests handling requests with body.
func TestHandleWithRequestBody(t *testing.T) {
	t.Parallel()

	t.Run("POST with JSON body", func(t *testing.T) {
		t.Parallel()

		requestBody := map[string]interface{}{
			"limit":       10,
			"collections": []string{"test"},
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Verify body was sent
			var body map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("failed to decode body: %v", err)
			}

			if body["limit"].(float64) != 10 {
				t.Errorf("limit = %v, want 10", body["limit"])
			}

			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"type":     "FeatureCollection",
				"features": []interface{}{},
			})
		}))
		defer server.Close()

		handler, err := NewHandler(Config{
			UpstreamURL: server.URL,
		})
		if err != nil {
			t.Fatalf("failed to create handler: %v", err)
		}

		bodyBytes, _ := json.Marshal(requestBody)
		httpReq := httptest.NewRequest(http.MethodPost, "/search", bytes.NewReader(bodyBytes))
		httpReq.Header.Set("Content-Type", "application/json")

		stacReq := &middleware.STACRequest{
			Request: httpReq,
		}

		_, err = handler.Handle(context.Background(), stacReq)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

// TestHandleResponseHeaders tests that response headers are preserved.
func TestHandleResponseHeaders(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Custom-Header", "test-value")
		w.Header().Set("Cache-Control", "max-age=3600")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{}`))
	}))
	defer server.Close()

	handler, err := NewHandler(Config{
		UpstreamURL: server.URL,
	})
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	httpReq := httptest.NewRequest(http.MethodGet, "/test", nil)
	stacReq := &middleware.STACRequest{
		Request: httpReq,
	}

	resp, err := handler.Handle(context.Background(), stacReq)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if ct := resp.Headers.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/json")
	}

	if custom := resp.Headers.Get("X-Custom-Header"); custom != "test-value" {
		t.Errorf("X-Custom-Header = %q, want %q", custom, "test-value")
	}

	if cc := resp.Headers.Get("Cache-Control"); cc != "max-age=3600" {
		t.Errorf("Cache-Control = %q, want %q", cc, "max-age=3600")
	}
}

// Helper function to create a deep copy of a map
func copyMap(m map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	for k, v := range m {
		switch val := v.(type) {
		case map[string]interface{}:
			result[k] = copyMap(val)
		case []interface{}:
			result[k] = copySlice(val)
		default:
			result[k] = v
		}
	}
	return result
}

func copySlice(s []interface{}) []interface{} {
	result := make([]interface{}, len(s))
	for i, v := range s {
		switch val := v.(type) {
		case map[string]interface{}:
			result[i] = copyMap(val)
		case []interface{}:
			result[i] = copySlice(val)
		default:
			result[i] = v
		}
	}
	return result
}

// captureUpstream stands up an httptest server that records the
// inbound request method, path, raw query, and body so tests can
// assert on what the proxy actually forwarded.
type captured struct {
	method string
	path   string
	query  string
	body   []byte
}

func captureUpstream(t *testing.T) (*httptest.Server, *captured) {
	t.Helper()
	c := &captured{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.method = r.Method
		c.path = r.URL.Path
		c.query = r.URL.RawQuery
		b, _ := io.ReadAll(r.Body)
		c.body = b
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(`{"type":"FeatureCollection","features":[]}`))
	}))
	t.Cleanup(srv.Close)
	return srv, c
}

func TestHandle_SearchReqReserialized(t *testing.T) {
	srv, cap := captureUpstream(t)

	handler, err := NewHandler(Config{UpstreamURL: srv.URL, Timeout: 5})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	httpReq := httptest.NewRequest("GET", "/search?limit=10", nil)
	req := &middleware.STACRequest{
		Request:     httpReq,
		Context:     httpReq.Context(),
		RequestType: middleware.RequestTypeSearch,
		SearchReq: &stac.SearchRequest{
			Filter:     "eo:cloud_cover < 20 AND datetime > '2025-01-01'",
			FilterLang: "cql2-text",
			Limit:      10,
		},
	}

	if _, err := handler.Handle(context.Background(), req); err != nil {
		t.Fatalf("Handle: %v", err)
	}

	if cap.method != http.MethodPost {
		t.Errorf("method = %q, want POST", cap.method)
	}
	if cap.path != "/search" {
		t.Errorf("path = %q, want /search", cap.path)
	}
	if !strings.Contains(string(cap.body), "eo:cloud_cover") {
		t.Errorf("body missing injected filter: %s", cap.body)
	}
	if !strings.Contains(string(cap.body), "filter-lang") {
		t.Errorf("body missing filter-lang: %s", cap.body)
	}
}

func TestHandle_SearchReqReserialized_ItemsPath(t *testing.T) {
	srv, cap := captureUpstream(t)

	handler, err := NewHandler(Config{UpstreamURL: srv.URL, Timeout: 5})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	httpReq := httptest.NewRequest("GET", "/collections/sentinel-2/items?limit=5", nil)
	req := &middleware.STACRequest{
		Request:     httpReq,
		Context:     httpReq.Context(),
		Collection:  "sentinel-2",
		RequestType: middleware.RequestTypeItems,
		SearchReq: &stac.SearchRequest{
			Filter:     "a = 1",
			FilterLang: "cql2-text",
			Limit:      5,
		},
	}

	if _, err := handler.Handle(context.Background(), req); err != nil {
		t.Fatalf("Handle: %v", err)
	}

	if cap.method != http.MethodPost {
		t.Errorf("method = %q, want POST", cap.method)
	}
	if cap.path != "/collections/sentinel-2/items" {
		t.Errorf("path = %q, want /collections/sentinel-2/items", cap.path)
	}
	if !strings.Contains(string(cap.body), `"filter":"a = 1"`) {
		t.Errorf("body missing filter literal: %s", cap.body)
	}
}

func TestHandle_NonSearchPassThrough(t *testing.T) {
	srv, cap := captureUpstream(t)

	handler, err := NewHandler(Config{UpstreamURL: srv.URL, Timeout: 5})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	httpReq := httptest.NewRequest("GET", "/collections/foo", nil)
	req := &middleware.STACRequest{
		Request:     httpReq,
		Context:     httpReq.Context(),
		Collection:  "foo",
		RequestType: middleware.RequestTypeCollection,
		// SearchReq nil
	}

	if _, err := handler.Handle(context.Background(), req); err != nil {
		t.Fatalf("Handle: %v", err)
	}

	if cap.method != http.MethodGet {
		t.Errorf("method = %q, want GET (pass-through)", cap.method)
	}
	if cap.path != "/collections/foo" {
		t.Errorf("path = %q, want /collections/foo", cap.path)
	}
	if len(cap.body) != 0 {
		t.Errorf("body should be empty, got %q", cap.body)
	}
}

func TestHandle_SearchReqNil_PassThrough(t *testing.T) {
	srv, cap := captureUpstream(t)

	handler, err := NewHandler(Config{UpstreamURL: srv.URL, Timeout: 5})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	// RequestTypeSearch but SearchReq nil should NOT re-serialize.
	httpReq := httptest.NewRequest("GET", "/search", nil)
	req := &middleware.STACRequest{
		Request:     httpReq,
		Context:     httpReq.Context(),
		RequestType: middleware.RequestTypeSearch,
		SearchReq:   nil,
	}

	if _, err := handler.Handle(context.Background(), req); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if cap.method != http.MethodGet {
		t.Errorf("method = %q, want GET", cap.method)
	}
}
