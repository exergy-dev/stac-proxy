package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestNewClient(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		baseURL     string
		opts        []ClientOption
		wantErr     bool
		errContains string
		validateFn  func(*testing.T, *Client)
	}{
		{
			name:    "valid URL without options",
			baseURL: "https://example.com",
			wantErr: false,
			validateFn: func(t *testing.T, c *Client) {
				if c.baseURL.String() != "https://example.com" {
					t.Errorf("baseURL = %s, want https://example.com", c.baseURL.String())
				}
				if c.timeout != 30*time.Second {
					t.Errorf("timeout = %v, want 30s", c.timeout)
				}
				if c.httpClient.Timeout != 30*time.Second {
					t.Errorf("httpClient.Timeout = %v, want 30s", c.httpClient.Timeout)
				}
			},
		},
		{
			name:    "valid URL with custom timeout",
			baseURL: "https://example.com",
			opts:    []ClientOption{WithTimeout(10 * time.Second)},
			wantErr: false,
			validateFn: func(t *testing.T, c *Client) {
				if c.timeout != 10*time.Second {
					t.Errorf("timeout = %v, want 10s", c.timeout)
				}
				if c.httpClient.Timeout != 10*time.Second {
					t.Errorf("httpClient.Timeout = %v, want 10s", c.httpClient.Timeout)
				}
			},
		},
		{
			name:    "valid URL with retry config",
			baseURL: "https://example.com",
			opts: []ClientOption{
				WithRetry(&RetryConfig{
					MaxRetries:     3,
					InitialBackoff: 100 * time.Millisecond,
					MaxBackoff:     5 * time.Second,
					RetryOn:        []int{502, 503, 504},
				}),
			},
			wantErr: false,
			validateFn: func(t *testing.T, c *Client) {
				if c.retry == nil {
					t.Fatal("retry config is nil")
				}
				if c.retry.MaxRetries != 3 {
					t.Errorf("MaxRetries = %d, want 3", c.retry.MaxRetries)
				}
				if c.retry.InitialBackoff != 100*time.Millisecond {
					t.Errorf("InitialBackoff = %v, want 100ms", c.retry.InitialBackoff)
				}
			},
		},
		{
			name:    "valid URL with custom transport",
			baseURL: "https://example.com",
			opts: []ClientOption{
				WithTransport(&mockTransport{}),
			},
			wantErr: false,
			validateFn: func(t *testing.T, c *Client) {
				if _, ok := c.httpClient.Transport.(*mockTransport); !ok {
					t.Error("expected custom transport to be set")
				}
			},
		},
		{
			name:    "URL with path",
			baseURL: "https://example.com/api/v1",
			wantErr: false,
			validateFn: func(t *testing.T, c *Client) {
				if c.baseURL.String() != "https://example.com/api/v1" {
					t.Errorf("baseURL = %s, want https://example.com/api/v1", c.baseURL.String())
				}
			},
		},
		{
			name:    "URL with query parameters",
			baseURL: "https://example.com?foo=bar",
			wantErr: false,
			validateFn: func(t *testing.T, c *Client) {
				if c.baseURL.RawQuery != "foo=bar" {
					t.Errorf("RawQuery = %s, want foo=bar", c.baseURL.RawQuery)
				}
			},
		},
		{
			name:        "invalid URL",
			baseURL:     "://invalid-url",
			wantErr:     true,
			errContains: "invalid base URL",
		},
		{
			name:        "empty URL",
			baseURL:     "",
			wantErr:     true,
			errContains: "invalid base URL",
		},
		{
			name:    "multiple options",
			baseURL: "https://example.com",
			opts: []ClientOption{
				WithTimeout(5 * time.Second),
				WithRetry(&RetryConfig{
					MaxRetries:     2,
					InitialBackoff: 50 * time.Millisecond,
					MaxBackoff:     1 * time.Second,
				}),
			},
			wantErr: false,
			validateFn: func(t *testing.T, c *Client) {
				if c.timeout != 5*time.Second {
					t.Errorf("timeout = %v, want 5s", c.timeout)
				}
				if c.retry == nil {
					t.Fatal("retry config is nil")
				}
				if c.retry.MaxRetries != 2 {
					t.Errorf("MaxRetries = %d, want 2", c.retry.MaxRetries)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			client, err := NewClient(tt.baseURL, tt.opts...)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("error = %v, want error containing %q", err, tt.errContains)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if client == nil {
				t.Fatal("client is nil")
			}

			if tt.validateFn != nil {
				tt.validateFn(t, client)
			}

			// Verify default transport settings
			if transport, ok := client.httpClient.Transport.(*http.Transport); ok {
				if transport.MaxIdleConns != 100 {
					t.Errorf("MaxIdleConns = %d, want 100", transport.MaxIdleConns)
				}
				if transport.MaxIdleConnsPerHost != 10 {
					t.Errorf("MaxIdleConnsPerHost = %d, want 10", transport.MaxIdleConnsPerHost)
				}
				if transport.IdleConnTimeout != 90*time.Second {
					t.Errorf("IdleConnTimeout = %v, want 90s", transport.IdleConnTimeout)
				}
			}
		})
	}
}

func TestClient_Do(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		method         string
		path           string
		body           io.Reader
		serverHandler  http.HandlerFunc
		wantErr        bool
		errContains    string
		validateReqFn  func(*testing.T, *http.Request)
		validateRespFn func(*testing.T, *http.Response)
	}{
		{
			name:   "successful GET request",
			method: http.MethodGet,
			path:   "/items/test-item",
			body:   nil,
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"id":"test-item"}`))
			},
			wantErr: false,
			validateReqFn: func(t *testing.T, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Errorf("Method = %s, want GET", r.Method)
				}
				if !strings.HasSuffix(r.URL.Path, "/items/test-item") {
					t.Errorf("Path = %s, want ending with /items/test-item", r.URL.Path)
				}
				acceptHeader := r.Header.Get("Accept")
				if acceptHeader != "application/geo+json, application/json" {
					t.Errorf("Accept header = %s, want application/geo+json, application/json", acceptHeader)
				}
			},
			validateRespFn: func(t *testing.T, resp *http.Response) {
				if resp.StatusCode != http.StatusOK {
					t.Errorf("StatusCode = %d, want 200", resp.StatusCode)
				}
				body, _ := io.ReadAll(resp.Body)
				if string(body) != `{"id":"test-item"}` {
					t.Errorf("Body = %s, want {\"id\":\"test-item\"}", string(body))
				}
			},
		},
		{
			name:   "successful POST request with body",
			method: http.MethodPost,
			path:   "/search",
			body:   bytes.NewBufferString(`{"limit":10}`),
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"type":"FeatureCollection","features":[]}`))
			},
			wantErr: false,
			validateReqFn: func(t *testing.T, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("Method = %s, want POST", r.Method)
				}
				contentType := r.Header.Get("Content-Type")
				if contentType != "application/json" {
					t.Errorf("Content-Type = %s, want application/json", contentType)
				}
				body, _ := io.ReadAll(r.Body)
				if string(body) != `{"limit":10}` {
					t.Errorf("Body = %s, want {\"limit\":10}", string(body))
				}
			},
			validateRespFn: func(t *testing.T, resp *http.Response) {
				if resp.StatusCode != http.StatusOK {
					t.Errorf("StatusCode = %d, want 200", resp.StatusCode)
				}
			},
		},
		{
			name:   "path with query parameters",
			method: http.MethodGet,
			path:   "/items?limit=10&offset=0",
			body:   nil,
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			},
			wantErr: false,
			validateReqFn: func(t *testing.T, r *http.Request) {
				if r.URL.Query().Get("limit") != "10" {
					t.Errorf("limit param = %s, want 10", r.URL.Query().Get("limit"))
				}
				if r.URL.Query().Get("offset") != "0" {
					t.Errorf("offset param = %s, want 0", r.URL.Query().Get("offset"))
				}
			},
		},
		{
			name:   "server returns 404",
			method: http.MethodGet,
			path:   "/not-found",
			body:   nil,
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte(`{"error":"not found"}`))
			},
			wantErr: false,
			validateRespFn: func(t *testing.T, resp *http.Response) {
				if resp.StatusCode != http.StatusNotFound {
					t.Errorf("StatusCode = %d, want 404", resp.StatusCode)
				}
			},
		},
		{
			name:   "server returns 500",
			method: http.MethodGet,
			path:   "/error",
			body:   nil,
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(`{"error":"internal error"}`))
			},
			wantErr: false,
			validateRespFn: func(t *testing.T, resp *http.Response) {
				if resp.StatusCode != http.StatusInternalServerError {
					t.Errorf("StatusCode = %d, want 500", resp.StatusCode)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var capturedReq *http.Request
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Capture request for validation
				body, _ := io.ReadAll(r.Body)
				r.Body = io.NopCloser(bytes.NewReader(body))
				capturedReq = r
				tt.serverHandler(w, r)
			}))
			defer server.Close()

			client, err := NewClient(server.URL)
			if err != nil {
				t.Fatalf("failed to create client: %v", err)
			}

			ctx := context.Background()
			resp, err := client.Do(ctx, tt.method, tt.path, tt.body)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("error = %v, want error containing %q", err, tt.errContains)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if resp == nil {
				t.Fatal("response is nil")
			}
			defer resp.Body.Close()

			if tt.validateReqFn != nil && capturedReq != nil {
				tt.validateReqFn(t, capturedReq)
			}

			if tt.validateRespFn != nil {
				tt.validateRespFn(t, resp)
			}
		})
	}
}

func TestClient_DoWithRetry(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		retryConfig    *RetryConfig
		serverBehavior func(attemptCount *int) http.HandlerFunc
		wantErr        bool
		errContains    string
		wantAttempts   int
	}{
		{
			name: "retry on 503 and succeed on second attempt",
			retryConfig: &RetryConfig{
				MaxRetries:     3,
				InitialBackoff: 10 * time.Millisecond,
				MaxBackoff:     100 * time.Millisecond,
				RetryOn:        []int{503},
			},
			serverBehavior: func(attemptCount *int) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					*attemptCount++
					if *attemptCount == 1 {
						w.WriteHeader(http.StatusServiceUnavailable)
						return
					}
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{"success":true}`))
				}
			},
			wantErr:      false,
			wantAttempts: 2,
		},
		{
			name: "retry on 502 until max retries",
			retryConfig: &RetryConfig{
				MaxRetries:     2,
				InitialBackoff: 10 * time.Millisecond,
				MaxBackoff:     100 * time.Millisecond,
				RetryOn:        []int{502},
			},
			serverBehavior: func(attemptCount *int) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					*attemptCount++
					w.WriteHeader(http.StatusBadGateway)
				}
			},
			wantErr:      true,
			errContains:  "max retries exceeded",
			wantAttempts: 3, // initial + 2 retries
		},
		{
			name: "no retry on 404",
			retryConfig: &RetryConfig{
				MaxRetries:     3,
				InitialBackoff: 10 * time.Millisecond,
				MaxBackoff:     100 * time.Millisecond,
				RetryOn:        []int{503},
			},
			serverBehavior: func(attemptCount *int) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					*attemptCount++
					w.WriteHeader(http.StatusNotFound)
					w.Write([]byte(`{"error":"not found"}`))
				}
			},
			wantErr:      false,
			wantAttempts: 1,
		},
		{
			name: "default retry on 5xx errors",
			retryConfig: &RetryConfig{
				MaxRetries:     2,
				InitialBackoff: 10 * time.Millisecond,
				MaxBackoff:     100 * time.Millisecond,
			},
			serverBehavior: func(attemptCount *int) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					*attemptCount++
					if *attemptCount <= 2 {
						w.WriteHeader(http.StatusInternalServerError)
						return
					}
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{"success":true}`))
				}
			},
			wantErr:      false,
			wantAttempts: 3,
		},
		{
			name: "retry on multiple status codes",
			retryConfig: &RetryConfig{
				MaxRetries:     3,
				InitialBackoff: 10 * time.Millisecond,
				MaxBackoff:     100 * time.Millisecond,
				RetryOn:        []int{502, 503, 504},
			},
			serverBehavior: func(attemptCount *int) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					*attemptCount++
					switch *attemptCount {
					case 1:
						w.WriteHeader(http.StatusBadGateway)
					case 2:
						w.WriteHeader(http.StatusServiceUnavailable)
					case 3:
						w.WriteHeader(http.StatusGatewayTimeout)
					default:
						w.WriteHeader(http.StatusOK)
					}
				}
			},
			wantErr:      false,
			wantAttempts: 4,
		},
		{
			name: "exponential backoff verification",
			retryConfig: &RetryConfig{
				MaxRetries:     3,
				InitialBackoff: 50 * time.Millisecond,
				MaxBackoff:     200 * time.Millisecond,
				RetryOn:        []int{503},
			},
			serverBehavior: func(attemptCount *int) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					*attemptCount++
					if *attemptCount <= 3 {
						w.WriteHeader(http.StatusServiceUnavailable)
						return
					}
					w.WriteHeader(http.StatusOK)
				}
			},
			wantErr:      false,
			wantAttempts: 4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			attemptCount := 0
			server := httptest.NewServer(tt.serverBehavior(&attemptCount))
			defer server.Close()

			client, err := NewClient(server.URL, WithRetry(tt.retryConfig))
			if err != nil {
				t.Fatalf("failed to create client: %v", err)
			}

			ctx := context.Background()
			resp, err := client.Do(ctx, http.MethodGet, "/test", nil)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("error = %v, want error containing %q", err, tt.errContains)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if resp == nil {
					t.Fatal("response is nil")
				}
				resp.Body.Close()
			}

			if attemptCount != tt.wantAttempts {
				t.Errorf("attemptCount = %d, want %d", attemptCount, tt.wantAttempts)
			}
		})
	}
}

func TestClient_ContextCancellation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		setupFn     func() (context.Context, context.CancelFunc)
		serverDelay time.Duration
		wantErr     bool
		errContains string
	}{
		{
			name: "context cancelled before request",
			setupFn: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(context.Background())
				cancel() // Cancel immediately
				return ctx, cancel
			},
			serverDelay: 0,
			wantErr:     true,
			errContains: "context canceled",
		},
		{
			name: "context timeout during request",
			setupFn: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 50*time.Millisecond)
			},
			serverDelay: 200 * time.Millisecond,
			wantErr:     true,
			errContains: "context deadline exceeded",
		},
		{
			name: "context valid for entire request",
			setupFn: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 500*time.Millisecond)
			},
			serverDelay: 10 * time.Millisecond,
			wantErr:     false,
		},
		{
			name: "context cancelled during retry",
			setupFn: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 100*time.Millisecond)
			},
			// Server slower than the context deadline so the request
			// blocks and the deadline trips. (Original case used a
			// 0-delay server expecting retries to kick in, but the
			// client only retries on configured status codes; without
			// that setup we exercise the cancel via a slow upstream.)
			serverDelay: 500 * time.Millisecond,
			wantErr:     true,
			errContains: "context deadline exceeded",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.serverDelay > 0 {
					time.Sleep(tt.serverDelay)
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			client, err := NewClient(server.URL)
			if err != nil {
				t.Fatalf("failed to create client: %v", err)
			}

			ctx, cancel := tt.setupFn()
			defer cancel()

			resp, err := client.Do(ctx, http.MethodGet, "/test", nil)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("error = %v, want error containing %q", err, tt.errContains)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if resp != nil {
					resp.Body.Close()
				}
			}
		})
	}
}

func TestClient_ContextCancellationDuringRetry(t *testing.T) {
	t.Parallel()

	// Test that context cancellation is respected during retry backoff
	attemptCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attemptCount++
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	retryConfig := &RetryConfig{
		MaxRetries:     10,
		InitialBackoff: 1 * time.Second, // Long backoff
		MaxBackoff:     5 * time.Second,
		RetryOn:        []int{503},
	}

	client, err := NewClient(server.URL, WithRetry(retryConfig))
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err = client.Do(ctx, http.MethodGet, "/test", nil)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("error = %v, want context.DeadlineExceeded", err)
	}

	// Should not wait for the full backoff period
	if elapsed > 500*time.Millisecond {
		t.Errorf("elapsed time = %v, expected cancellation to happen quickly", elapsed)
	}

	// Should have attempted at most 2 times before cancellation
	if attemptCount > 2 {
		t.Errorf("attemptCount = %d, expected few attempts before cancellation", attemptCount)
	}
}

func TestClient_Get(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("Method = %s, want GET", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":"test"}`))
	}))
	defer server.Close()

	client, err := NewClient(server.URL)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	ctx := context.Background()
	resp, err := client.Get(ctx, "/test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want 200", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if string(body) != `{"id":"test"}` {
		t.Errorf("Body = %s, want {\"id\":\"test\"}", string(body))
	}
}

func TestClient_Post(t *testing.T) {
	t.Parallel()

	var receivedBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Method = %s, want POST", r.Method)
		}
		receivedBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"success":true}`))
	}))
	defer server.Close()

	client, err := NewClient(server.URL)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	ctx := context.Background()
	requestBody := `{"limit":10}`
	resp, err := client.Post(ctx, "/search", strings.NewReader(requestBody))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want 200", resp.StatusCode)
	}

	if string(receivedBody) != requestBody {
		t.Errorf("received body = %s, want %s", string(receivedBody), requestBody)
	}
}

func TestClient_BaseURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		baseURL string
		want    string
	}{
		{
			name:    "simple URL",
			baseURL: "https://example.com",
			want:    "https://example.com",
		},
		{
			name:    "URL with path",
			baseURL: "https://example.com/api/v1",
			want:    "https://example.com/api/v1",
		},
		{
			name:    "URL with trailing slash",
			baseURL: "https://example.com/",
			want:    "https://example.com/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			client, err := NewClient(tt.baseURL)
			if err != nil {
				t.Fatalf("failed to create client: %v", err)
			}

			got := client.BaseURL()
			if got != tt.want {
				t.Errorf("BaseURL() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestClient_HeaderHandling(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		method          string
		body            io.Reader
		wantAccept      string
		wantContentType string
	}{
		{
			name:            "GET request headers",
			method:          http.MethodGet,
			body:            nil,
			wantAccept:      "application/geo+json, application/json",
			wantContentType: "",
		},
		{
			name:            "POST request headers",
			method:          http.MethodPost,
			body:            strings.NewReader(`{"test":"data"}`),
			wantAccept:      "application/geo+json, application/json",
			wantContentType: "application/json",
		},
		{
			name:            "PUT request headers",
			method:          http.MethodPut,
			body:            strings.NewReader(`{"update":"data"}`),
			wantAccept:      "application/geo+json, application/json",
			wantContentType: "application/json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var capturedReq *http.Request
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				capturedReq = r
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			client, err := NewClient(server.URL)
			if err != nil {
				t.Fatalf("failed to create client: %v", err)
			}

			ctx := context.Background()
			resp, err := client.Do(ctx, tt.method, "/test", tt.body)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			resp.Body.Close()

			if capturedReq == nil {
				t.Fatal("request was not captured")
			}

			accept := capturedReq.Header.Get("Accept")
			if accept != tt.wantAccept {
				t.Errorf("Accept header = %s, want %s", accept, tt.wantAccept)
			}

			contentType := capturedReq.Header.Get("Content-Type")
			if tt.wantContentType == "" {
				if contentType != "" {
					t.Errorf("Content-Type header = %s, want empty", contentType)
				}
			} else {
				if contentType != tt.wantContentType {
					t.Errorf("Content-Type header = %s, want %s", contentType, tt.wantContentType)
				}
			}
		})
	}
}

func TestClient_URLResolving(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		baseURL     string
		path        string
		wantURLPath string
	}{
		{
			name:        "simple path",
			baseURL:     "https://example.com",
			path:        "/items",
			wantURLPath: "/items",
		},
		{
			name:        "nested path",
			baseURL:     "https://example.com",
			path:        "/collections/test/items",
			wantURLPath: "/collections/test/items",
		},
		{
			name:        "base with path and request path",
			baseURL:     "https://example.com/api/v1",
			path:        "/items",
			wantURLPath: "/items",
		},
		{
			name:        "path with query",
			baseURL:     "https://example.com",
			path:        "/items?limit=10",
			wantURLPath: "/items",
		},
		{
			name:        "relative path",
			baseURL:     "https://example.com/api",
			path:        "items",
			wantURLPath: "/items",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var capturedURL *url.URL
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				capturedURL = r.URL
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			client, err := NewClient(server.URL)
			if err != nil {
				t.Fatalf("failed to create client: %v", err)
			}

			ctx := context.Background()
			resp, err := client.Do(ctx, http.MethodGet, tt.path, nil)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			resp.Body.Close()

			if capturedURL == nil {
				t.Fatal("URL was not captured")
			}

			if !strings.HasSuffix(capturedURL.Path, tt.wantURLPath) {
				t.Errorf("URL path = %s, want suffix %s", capturedURL.Path, tt.wantURLPath)
			}
		})
	}
}

func TestClient_Timeout(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		timeout     time.Duration
		serverDelay time.Duration
		wantErr     bool
		errContains string
	}{
		{
			name:        "request completes before timeout",
			timeout:     500 * time.Millisecond,
			serverDelay: 50 * time.Millisecond,
			wantErr:     false,
		},
		{
			name:        "request times out",
			timeout:     50 * time.Millisecond,
			serverDelay: 500 * time.Millisecond,
			wantErr:     true,
			errContains: "context deadline exceeded",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				time.Sleep(tt.serverDelay)
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			client, err := NewClient(server.URL, WithTimeout(tt.timeout))
			if err != nil {
				t.Fatalf("failed to create client: %v", err)
			}

			ctx := context.Background()
			resp, err := client.Do(ctx, http.MethodGet, "/test", nil)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("error = %v, want error containing %q", err, tt.errContains)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if resp != nil {
					resp.Body.Close()
				}
			}
		})
	}
}

func TestClient_LargeResponseBody(t *testing.T) {
	t.Parallel()

	// Create a large response body
	largeBody := strings.Repeat("x", 1024*1024) // 1MB

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(largeBody))
	}))
	defer server.Close()

	client, err := NewClient(server.URL)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	ctx := context.Background()
	resp, err := client.Do(ctx, http.MethodGet, "/large", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read body: %v", err)
	}

	if len(body) != len(largeBody) {
		t.Errorf("body length = %d, want %d", len(body), len(largeBody))
	}
}

func TestClient_ConnectionReuse(t *testing.T) {
	t.Parallel()

	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := NewClient(server.URL)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	ctx := context.Background()

	// Make multiple requests
	for i := 0; i < 5; i++ {
		resp, err := client.Get(ctx, "/test")
		if err != nil {
			t.Fatalf("request %d failed: %v", i, err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}

	if requestCount != 5 {
		t.Errorf("requestCount = %d, want 5", requestCount)
	}

	// Verify connection pool settings
	transport, ok := client.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatal("transport is not *http.Transport")
	}

	if transport.MaxIdleConns != 100 {
		t.Errorf("MaxIdleConns = %d, want 100", transport.MaxIdleConns)
	}

	if transport.MaxIdleConnsPerHost != 10 {
		t.Errorf("MaxIdleConnsPerHost = %d, want 10", transport.MaxIdleConnsPerHost)
	}
}

func TestClient_shouldRetry(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		retryConfig *RetryConfig
		statusCode  int
		want        bool
	}{
		{
			name:        "no retry config - retry on 500",
			retryConfig: nil,
			statusCode:  500,
			want:        true,
		},
		{
			name:        "no retry config - retry on 502",
			retryConfig: nil,
			statusCode:  502,
			want:        true,
		},
		{
			name:        "no retry config - no retry on 404",
			retryConfig: nil,
			statusCode:  404,
			want:        false,
		},
		{
			name:        "no retry config - no retry on 200",
			retryConfig: nil,
			statusCode:  200,
			want:        false,
		},
		{
			name: "custom retry on specific codes",
			retryConfig: &RetryConfig{
				MaxRetries: 3,
				RetryOn:    []int{503, 504},
			},
			statusCode: 503,
			want:       true,
		},
		{
			name: "custom retry - not in list",
			retryConfig: &RetryConfig{
				MaxRetries: 3,
				RetryOn:    []int{503, 504},
			},
			statusCode: 500,
			want:       false,
		},
		{
			name: "custom retry - empty list falls back to default",
			retryConfig: &RetryConfig{
				MaxRetries: 3,
				RetryOn:    []int{},
			},
			statusCode: 500,
			want:       true,
		},
		{
			name: "custom retry on 429 Too Many Requests",
			retryConfig: &RetryConfig{
				MaxRetries: 3,
				RetryOn:    []int{429},
			},
			statusCode: 429,
			want:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			client := &Client{
				retry: tt.retryConfig,
			}

			got := client.shouldRetry(tt.statusCode)
			if got != tt.want {
				t.Errorf("shouldRetry(%d) = %v, want %v", tt.statusCode, got, tt.want)
			}
		})
	}
}

func TestMin(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		a    time.Duration
		b    time.Duration
		want time.Duration
	}{
		{
			name: "a is smaller",
			a:    1 * time.Second,
			b:    2 * time.Second,
			want: 1 * time.Second,
		},
		{
			name: "b is smaller",
			a:    5 * time.Second,
			b:    3 * time.Second,
			want: 3 * time.Second,
		},
		{
			name: "equal values",
			a:    4 * time.Second,
			b:    4 * time.Second,
			want: 4 * time.Second,
		},
		{
			name: "zero and non-zero",
			a:    0,
			b:    1 * time.Second,
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := min(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("min(%v, %v) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestClientOption_WithTimeout(t *testing.T) {
	t.Parallel()

	client := &Client{
		httpClient: &http.Client{},
	}

	opt := WithTimeout(15 * time.Second)
	opt(client)

	if client.timeout != 15*time.Second {
		t.Errorf("timeout = %v, want 15s", client.timeout)
	}

	if client.httpClient.Timeout != 15*time.Second {
		t.Errorf("httpClient.Timeout = %v, want 15s", client.httpClient.Timeout)
	}
}

func TestClientOption_WithRetry(t *testing.T) {
	t.Parallel()

	client := &Client{}

	config := &RetryConfig{
		MaxRetries:     5,
		InitialBackoff: 200 * time.Millisecond,
		MaxBackoff:     10 * time.Second,
		RetryOn:        []int{502, 503},
	}

	opt := WithRetry(config)
	opt(client)

	if client.retry == nil {
		t.Fatal("retry is nil")
	}

	if client.retry.MaxRetries != 5 {
		t.Errorf("MaxRetries = %d, want 5", client.retry.MaxRetries)
	}

	if client.retry.InitialBackoff != 200*time.Millisecond {
		t.Errorf("InitialBackoff = %v, want 200ms", client.retry.InitialBackoff)
	}
}

func TestClientOption_WithTransport(t *testing.T) {
	t.Parallel()

	client := &Client{
		httpClient: &http.Client{},
	}

	transport := &mockTransport{}
	opt := WithTransport(transport)
	opt(client)

	if client.httpClient.Transport != transport {
		t.Error("transport was not set")
	}
}

func TestClient_MultipleStatusCodes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		statusCode int
		wantBody   string
	}{
		{name: "200 OK", statusCode: http.StatusOK, wantBody: "ok"},
		{name: "201 Created", statusCode: http.StatusCreated, wantBody: "created"},
		{name: "204 No Content", statusCode: http.StatusNoContent, wantBody: ""},
		{name: "400 Bad Request", statusCode: http.StatusBadRequest, wantBody: "bad request"},
		{name: "401 Unauthorized", statusCode: http.StatusUnauthorized, wantBody: "unauthorized"},
		{name: "403 Forbidden", statusCode: http.StatusForbidden, wantBody: "forbidden"},
		{name: "404 Not Found", statusCode: http.StatusNotFound, wantBody: "not found"},
		{name: "500 Internal Server Error", statusCode: http.StatusInternalServerError, wantBody: "internal error"},
		{name: "502 Bad Gateway", statusCode: http.StatusBadGateway, wantBody: "bad gateway"},
		{name: "503 Service Unavailable", statusCode: http.StatusServiceUnavailable, wantBody: "unavailable"},
		{name: "504 Gateway Timeout", statusCode: http.StatusGatewayTimeout, wantBody: "timeout"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				if tt.wantBody != "" {
					w.Write([]byte(tt.wantBody))
				}
			}))
			defer server.Close()

			client, err := NewClient(server.URL)
			if err != nil {
				t.Fatalf("failed to create client: %v", err)
			}

			ctx := context.Background()
			resp, err := client.Get(ctx, "/test")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tt.statusCode {
				t.Errorf("StatusCode = %d, want %d", resp.StatusCode, tt.statusCode)
			}

			body, _ := io.ReadAll(resp.Body)
			if string(body) != tt.wantBody {
				t.Errorf("Body = %s, want %s", string(body), tt.wantBody)
			}
		})
	}
}

func TestClient_EmptyResponse(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// No body written
	}))
	defer server.Close()

	client, err := NewClient(server.URL)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	ctx := context.Background()
	resp, err := client.Get(ctx, "/test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read body: %v", err)
	}

	if len(body) != 0 {
		t.Errorf("body length = %d, want 0", len(body))
	}
}

// mockTransport is a simple mock for http.RoundTripper
type mockTransport struct {
	roundTripFunc func(*http.Request) (*http.Response, error)
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if m.roundTripFunc != nil {
		return m.roundTripFunc(req)
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader("{}")),
		Header:     make(http.Header),
	}, nil
}
