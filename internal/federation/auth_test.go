package federation

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestNoOpAuthProvider tests the no-op authentication provider.
func TestNoOpAuthProvider(t *testing.T) {
	t.Parallel()

	provider := &NoOpAuthProvider{}

	t.Run("ApplyAuth", func(t *testing.T) {
		t.Parallel()

		req := httptest.NewRequest(http.MethodGet, "https://example.com/test", nil)
		ctx := context.Background()

		err := provider.ApplyAuth(ctx, req)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		// Verify no auth headers were added
		if auth := req.Header.Get("Authorization"); auth != "" {
			t.Errorf("expected no Authorization header, got: %s", auth)
		}
	})

	t.Run("Refresh", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		err := provider.Refresh(ctx)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

// TestBasicAuthProvider tests HTTP Basic authentication.
func TestBasicAuthProvider(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		username string
		password string
	}{
		{
			name:     "standard credentials",
			username: "testuser",
			password: "testpass",
		},
		{
			name:     "special characters in password",
			username: "user@example.com",
			password: "p@ssw0rd!$%",
		},
		{
			name:     "empty password",
			username: "testuser",
			password: "",
		},
		{
			name:     "empty username",
			username: "",
			password: "testpass",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			provider := &BasicAuthProvider{
				Username: tt.username,
				Password: tt.password,
			}

			req := httptest.NewRequest(http.MethodGet, "https://example.com/test", nil)
			ctx := context.Background()

			err := provider.ApplyAuth(ctx, req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Verify Basic auth header
			authHeader := req.Header.Get("Authorization")
			if !strings.HasPrefix(authHeader, "Basic ") {
				t.Errorf("expected Basic auth header, got: %s", authHeader)
			}

			// Decode and verify credentials
			encoded := strings.TrimPrefix(authHeader, "Basic ")
			decoded, err := base64.StdEncoding.DecodeString(encoded)
			if err != nil {
				t.Fatalf("failed to decode auth header: %v", err)
			}

			expected := tt.username + ":" + tt.password
			if string(decoded) != expected {
				t.Errorf("expected credentials %q, got %q", expected, string(decoded))
			}
		})
	}

	t.Run("Refresh does nothing", func(t *testing.T) {
		t.Parallel()

		provider := &BasicAuthProvider{
			Username: "user",
			Password: "pass",
		}

		ctx := context.Background()
		err := provider.Refresh(ctx)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

// TestBearerAuthProvider tests Bearer token authentication.
func TestBearerAuthProvider(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		token string
	}{
		{
			name:  "standard token",
			token: "abc123xyz",
		},
		{
			name:  "JWT token",
			token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
		},
		{
			name:  "empty token",
			token: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			provider := &BearerAuthProvider{
				Token: tt.token,
			}

			req := httptest.NewRequest(http.MethodGet, "https://example.com/test", nil)
			ctx := context.Background()

			err := provider.ApplyAuth(ctx, req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Verify Bearer auth header
			authHeader := req.Header.Get("Authorization")
			expected := "Bearer " + tt.token
			if authHeader != expected {
				t.Errorf("expected auth header %q, got %q", expected, authHeader)
			}
		})
	}

	t.Run("Refresh does nothing", func(t *testing.T) {
		t.Parallel()

		provider := &BearerAuthProvider{
			Token: "test-token",
		}

		ctx := context.Background()
		err := provider.Refresh(ctx)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

// TestAPIKeyAuthProvider tests API key authentication.
func TestAPIKeyAuthProvider(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		header  string
		value   string
		inQuery bool
	}{
		{
			name:    "header mode",
			header:  "X-API-Key",
			value:   "secret-key-123",
			inQuery: false,
		},
		{
			name:    "query mode",
			header:  "api_key",
			value:   "secret-key-456",
			inQuery: true,
		},
		{
			name:    "custom header name",
			header:  "X-Custom-Auth",
			value:   "custom-value",
			inQuery: false,
		},
		{
			name:    "query with special characters",
			header:  "key",
			value:   "value-with-special!@#$%",
			inQuery: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			provider := &APIKeyAuthProvider{
				Header:  tt.header,
				Value:   tt.value,
				InQuery: tt.inQuery,
			}

			req := httptest.NewRequest(http.MethodGet, "https://example.com/test?existing=param", nil)
			ctx := context.Background()

			err := provider.ApplyAuth(ctx, req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.inQuery {
				// Verify query parameter
				queryVal := req.URL.Query().Get(tt.header)
				if queryVal != tt.value {
					t.Errorf("expected query param %q=%q, got %q", tt.header, tt.value, queryVal)
				}

				// Verify existing query param is preserved
				if existing := req.URL.Query().Get("existing"); existing != "param" {
					t.Errorf("existing query param was not preserved")
				}
			} else {
				// Verify header
				headerVal := req.Header.Get(tt.header)
				if headerVal != tt.value {
					t.Errorf("expected header %q=%q, got %q", tt.header, tt.value, headerVal)
				}
			}
		})
	}

	t.Run("Refresh does nothing", func(t *testing.T) {
		t.Parallel()

		provider := &APIKeyAuthProvider{
			Header: "X-API-Key",
			Value:  "test-key",
		}

		ctx := context.Background()
		err := provider.Refresh(ctx)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

// TestCustomHeadersProvider tests custom header injection.
func TestCustomHeadersProvider(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		headers map[string]string
	}{
		{
			name: "single header",
			headers: map[string]string{
				"X-Custom-Header": "value",
			},
		},
		{
			name: "multiple headers",
			headers: map[string]string{
				"X-Header-1": "value1",
				"X-Header-2": "value2",
				"X-Header-3": "value3",
			},
		},
		{
			name:    "empty headers",
			headers: map[string]string{},
		},
		{
			name: "headers with special characters",
			headers: map[string]string{
				"X-Special": "value-with-special!@#$%",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			provider := &CustomHeadersProvider{
				Headers: tt.headers,
			}

			req := httptest.NewRequest(http.MethodGet, "https://example.com/test", nil)
			ctx := context.Background()

			err := provider.ApplyAuth(ctx, req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Verify all headers are set
			for key, expectedVal := range tt.headers {
				actualVal := req.Header.Get(key)
				if actualVal != expectedVal {
					t.Errorf("expected header %q=%q, got %q", key, expectedVal, actualVal)
				}
			}
		})
	}

	t.Run("overwrites existing headers", func(t *testing.T) {
		t.Parallel()

		provider := &CustomHeadersProvider{
			Headers: map[string]string{
				"X-Test": "new-value",
			},
		}

		req := httptest.NewRequest(http.MethodGet, "https://example.com/test", nil)
		req.Header.Set("X-Test", "old-value")
		ctx := context.Background()

		err := provider.ApplyAuth(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if val := req.Header.Get("X-Test"); val != "new-value" {
			t.Errorf("expected header to be overwritten, got %q", val)
		}
	})

	t.Run("Refresh does nothing", func(t *testing.T) {
		t.Parallel()

		provider := &CustomHeadersProvider{
			Headers: map[string]string{"X-Test": "value"},
		}

		ctx := context.Background()
		err := provider.Refresh(ctx)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

// TestChainedAuthProvider tests chaining multiple auth providers.
func TestChainedAuthProvider(t *testing.T) {
	t.Parallel()

	t.Run("applies all providers in order", func(t *testing.T) {
		t.Parallel()

		provider := &ChainedAuthProvider{
			Providers: []AuthProvider{
				&BasicAuthProvider{
					Username: "user",
					Password: "pass",
				},
				&CustomHeadersProvider{
					Headers: map[string]string{
						"X-Custom": "value",
					},
				},
				&APIKeyAuthProvider{
					Header:  "api_key",
					Value:   "key123",
					InQuery: true,
				},
			},
		}

		req := httptest.NewRequest(http.MethodGet, "https://example.com/test", nil)
		ctx := context.Background()

		err := provider.ApplyAuth(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Verify Basic auth
		if auth := req.Header.Get("Authorization"); !strings.HasPrefix(auth, "Basic ") {
			t.Errorf("expected Basic auth header, got: %s", auth)
		}

		// Verify custom header
		if custom := req.Header.Get("X-Custom"); custom != "value" {
			t.Errorf("expected X-Custom header, got: %s", custom)
		}

		// Verify API key in query
		if apiKey := req.URL.Query().Get("api_key"); apiKey != "key123" {
			t.Errorf("expected api_key query param, got: %s", apiKey)
		}
	})

	t.Run("empty providers", func(t *testing.T) {
		t.Parallel()

		provider := &ChainedAuthProvider{
			Providers: []AuthProvider{},
		}

		req := httptest.NewRequest(http.MethodGet, "https://example.com/test", nil)
		ctx := context.Background()

		err := provider.ApplyAuth(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("Refresh calls all providers", func(t *testing.T) {
		t.Parallel()

		provider := &ChainedAuthProvider{
			Providers: []AuthProvider{
				&NoOpAuthProvider{},
				&BasicAuthProvider{Username: "user", Password: "pass"},
				&BearerAuthProvider{Token: "token"},
			},
		}

		ctx := context.Background()
		err := provider.Refresh(ctx)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

// TestBuildAuthProvider tests the auth provider factory function.
func TestBuildAuthProvider(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		config         AuthConfig
		expectedType   string
		expectError    bool
		validateResult func(t *testing.T, provider AuthProvider)
	}{
		{
			name: "no auth",
			config: AuthConfig{
				Type: "none",
			},
			expectedType: "*federation.NoOpAuthProvider",
			expectError:  false,
		},
		{
			name: "empty type defaults to no auth",
			config: AuthConfig{
				Type: "",
			},
			expectedType: "*federation.NoOpAuthProvider",
			expectError:  false,
		},
		{
			name: "basic auth",
			config: AuthConfig{
				Type:     "basic",
				Username: "testuser",
				Password: "testpass",
			},
			expectedType: "*federation.BasicAuthProvider",
			expectError:  false,
			validateResult: func(t *testing.T, provider AuthProvider) {
				p := provider.(*BasicAuthProvider)
				if p.Username != "testuser" || p.Password != "testpass" {
					t.Errorf("basic auth credentials not set correctly")
				}
			},
		},
		{
			name: "bearer auth",
			config: AuthConfig{
				Type:  "bearer",
				Token: "test-token-123",
			},
			expectedType: "*federation.BearerAuthProvider",
			expectError:  false,
			validateResult: func(t *testing.T, provider AuthProvider) {
				p := provider.(*BearerAuthProvider)
				if p.Token != "test-token-123" {
					t.Errorf("bearer token not set correctly")
				}
			},
		},
		{
			name: "api key in header",
			config: AuthConfig{
				Type:         "api_key",
				APIKeyHeader: "X-API-Key",
				APIKeyValue:  "secret",
			},
			expectedType: "*federation.APIKeyAuthProvider",
			expectError:  false,
			validateResult: func(t *testing.T, provider AuthProvider) {
				p := provider.(*APIKeyAuthProvider)
				if p.Header != "X-API-Key" || p.Value != "secret" || p.InQuery {
					t.Errorf("api key provider not configured correctly")
				}
			},
		},
		{
			name: "api key in query",
			config: AuthConfig{
				Type:          "api_key",
				APIKeyHeader:  "api_key",
				APIKeyValue:   "secret",
				APIKeyInQuery: true,
			},
			expectedType: "*federation.APIKeyAuthProvider",
			expectError:  false,
			validateResult: func(t *testing.T, provider AuthProvider) {
				p := provider.(*APIKeyAuthProvider)
				if !p.InQuery {
					t.Errorf("api key should be in query")
				}
			},
		},
		{
			name: "custom headers",
			config: AuthConfig{
				Type: "custom",
				CustomHeaders: map[string]string{
					"X-Custom-1": "value1",
					"X-Custom-2": "value2",
				},
			},
			expectedType: "*federation.CustomHeadersProvider",
			expectError:  false,
			validateResult: func(t *testing.T, provider AuthProvider) {
				p := provider.(*CustomHeadersProvider)
				if len(p.Headers) != 2 {
					t.Errorf("expected 2 custom headers, got %d", len(p.Headers))
				}
			},
		},
		{
			name: "custom headers empty defaults to no-op",
			config: AuthConfig{
				Type:          "custom",
				CustomHeaders: map[string]string{},
			},
			expectedType: "*federation.NoOpAuthProvider",
			expectError:  false,
		},
		{
			name: "unknown type defaults to no-op",
			config: AuthConfig{
				Type: "unknown_type",
			},
			expectedType: "*federation.NoOpAuthProvider",
			expectError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			provider, err := BuildAuthProvider(tt.config)

			if tt.expectError {
				if err == nil {
					t.Fatal("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Check type
			actualType := getTypeName(provider)
			if actualType != tt.expectedType {
				t.Errorf("expected type %s, got %s", tt.expectedType, actualType)
			}

			// Additional validation
			if tt.validateResult != nil {
				tt.validateResult(t, provider)
			}
		})
	}
}

// TestBuildAuthProviderOAuth2 tests OAuth2 provider creation.
func TestBuildAuthProviderOAuth2(t *testing.T) {
	t.Run("valid oauth2 config", func(t *testing.T) {
		config := AuthConfig{
			Type: "oauth2",
			OAuth2: &OAuth2Config{
				TokenURL:     "https://auth.example.com/token",
				ClientID:     "client123",
				ClientSecret: "secret456",
				Scopes:       []string{"read", "write"},
			},
		}

		provider, err := BuildAuthProvider(config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if getTypeName(provider) != "*federation.OAuth2AuthProvider" {
			t.Errorf("expected OAuth2AuthProvider, got %s", getTypeName(provider))
		}
	})

	t.Run("oauth2 missing token URL", func(t *testing.T) {
		config := AuthConfig{
			Type: "oauth2",
			OAuth2: &OAuth2Config{
				ClientID:     "client123",
				ClientSecret: "secret456",
			},
		}

		_, err := BuildAuthProvider(config)
		if err == nil {
			t.Fatal("expected error for missing token URL")
		}
	})

	t.Run("oauth2 missing client ID", func(t *testing.T) {
		config := AuthConfig{
			Type: "oauth2",
			OAuth2: &OAuth2Config{
				TokenURL:     "https://auth.example.com/token",
				ClientSecret: "secret456",
			},
		}

		_, err := BuildAuthProvider(config)
		if err == nil {
			t.Fatal("expected error for missing client ID")
		}
	})

	t.Run("oauth2 nil config defaults to no-op", func(t *testing.T) {
		config := AuthConfig{
			Type:   "oauth2",
			OAuth2: nil,
		}

		provider, err := BuildAuthProvider(config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if getTypeName(provider) != "*federation.NoOpAuthProvider" {
			t.Errorf("expected NoOpAuthProvider for nil OAuth2 config")
		}
	})
}

// TestBuildAuthProviderAWSSigV4 tests AWS SigV4 provider creation.
func TestBuildAuthProviderAWSSigV4(t *testing.T) {
	t.Run("valid sigv4 config", func(t *testing.T) {
		config := AuthConfig{
			Type: "aws_sig_v4",
			AWSSigV4: &AWSSigV4Config{
				Region:    "us-east-1",
				Service:   "execute-api",
				AccessKey: "AKIAIOSFODNN7EXAMPLE",
				SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			},
		}

		provider, err := BuildAuthProvider(config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if getTypeName(provider) != "*federation.AWSSigV4Provider" {
			t.Errorf("expected AWSSigV4Provider, got %s", getTypeName(provider))
		}
	})

	t.Run("sigv4 missing region", func(t *testing.T) {
		config := AuthConfig{
			Type: "aws_sig_v4",
			AWSSigV4: &AWSSigV4Config{
				Service:   "execute-api",
				AccessKey: "AKIAIOSFODNN7EXAMPLE",
				SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			},
		}

		_, err := BuildAuthProvider(config)
		if err == nil {
			t.Fatal("expected error for missing region")
		}
	})

	t.Run("sigv4 nil config defaults to no-op", func(t *testing.T) {
		config := AuthConfig{
			Type:     "aws_sig_v4",
			AWSSigV4: nil,
		}

		provider, err := BuildAuthProvider(config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if getTypeName(provider) != "*federation.NoOpAuthProvider" {
			t.Errorf("expected NoOpAuthProvider for nil AWSSigV4 config")
		}
	})
}

// TestOAuth2AuthProvider tests the OAuth2 authentication provider.
func TestOAuth2AuthProvider(t *testing.T) {
	t.Run("successful token fetch", func(t *testing.T) {
		tokenResponse := map[string]interface{}{
			"access_token": "test-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Verify request
			if r.Method != http.MethodPost {
				t.Errorf("expected POST, got %s", r.Method)
			}
			if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
				t.Errorf("expected form content type, got %s", ct)
			}

			// Parse form data
			if err := r.ParseForm(); err != nil {
				t.Fatalf("failed to parse form: %v", err)
			}

			if r.Form.Get("grant_type") != "client_credentials" {
				t.Errorf("expected client_credentials grant type")
			}
			if r.Form.Get("client_id") != "test-client" {
				t.Errorf("expected client_id test-client, got %s", r.Form.Get("client_id"))
			}
			if r.Form.Get("client_secret") != "test-secret" {
				t.Errorf("expected client_secret test-secret, got %s", r.Form.Get("client_secret"))
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(tokenResponse)
		}))
		defer server.Close()

		config := &OAuth2Config{
			TokenURL:     server.URL,
			ClientID:     "test-client",
			ClientSecret: "test-secret",
		}

		provider, err := NewOAuth2AuthProvider(config)
		if err != nil {
			t.Fatalf("failed to create provider: %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "https://example.com/test", nil)
		ctx := context.Background()

		err = provider.ApplyAuth(ctx, req)
		if err != nil {
			t.Fatalf("failed to apply auth: %v", err)
		}

		authHeader := req.Header.Get("Authorization")
		expected := "Bearer test-access-token"
		if authHeader != expected {
			t.Errorf("expected auth header %q, got %q", expected, authHeader)
		}
	})

	t.Run("token caching and reuse", func(t *testing.T) {
		callCount := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			callCount++
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "cached-token",
				"expires_in":   3600,
			})
		}))
		defer server.Close()

		config := &OAuth2Config{
			TokenURL:     server.URL,
			ClientID:     "test-client",
			ClientSecret: "test-secret",
		}

		provider, err := NewOAuth2AuthProvider(config)
		if err != nil {
			t.Fatalf("failed to create provider: %v", err)
		}

		ctx := context.Background()

		// First request should fetch token
		req1 := httptest.NewRequest(http.MethodGet, "https://example.com/test1", nil)
		if err := provider.ApplyAuth(ctx, req1); err != nil {
			t.Fatalf("failed to apply auth: %v", err)
		}

		// Second request should reuse cached token
		req2 := httptest.NewRequest(http.MethodGet, "https://example.com/test2", nil)
		if err := provider.ApplyAuth(ctx, req2); err != nil {
			t.Fatalf("failed to apply auth: %v", err)
		}

		// Should only call token endpoint once
		if callCount != 1 {
			t.Errorf("expected 1 token request, got %d", callCount)
		}

		// Both requests should have same token
		if req1.Header.Get("Authorization") != req2.Header.Get("Authorization") {
			t.Errorf("expected same token on both requests")
		}
	})

	t.Run("token refresh on expiration", func(t *testing.T) {
		callCount := 0
		tokenValue := "token-1"

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			callCount++
			if callCount == 1 {
				tokenValue = "token-1"
			} else {
				tokenValue = "token-2"
			}
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": tokenValue,
				"expires_in":   1, // 1 second expiry
			})
		}))
		defer server.Close()

		config := &OAuth2Config{
			TokenURL:     server.URL,
			ClientID:     "test-client",
			ClientSecret: "test-secret",
		}

		provider, err := NewOAuth2AuthProvider(config)
		if err != nil {
			t.Fatalf("failed to create provider: %v", err)
		}

		ctx := context.Background()

		// First request
		req1 := httptest.NewRequest(http.MethodGet, "https://example.com/test1", nil)
		if err := provider.ApplyAuth(ctx, req1); err != nil {
			t.Fatalf("failed to apply auth: %v", err)
		}

		// Wait for token to expire (with buffer)
		time.Sleep(2 * time.Second)

		// Second request should fetch new token
		req2 := httptest.NewRequest(http.MethodGet, "https://example.com/test2", nil)
		if err := provider.ApplyAuth(ctx, req2); err != nil {
			t.Fatalf("failed to apply auth: %v", err)
		}

		// Should have called token endpoint twice
		if callCount != 2 {
			t.Errorf("expected 2 token requests, got %d", callCount)
		}
	})

	t.Run("concurrent requests use same token", func(t *testing.T) {
		var callCount int
		var mu sync.Mutex

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			callCount++
			mu.Unlock()

			// Simulate slow token endpoint
			time.Sleep(100 * time.Millisecond)

			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "concurrent-token",
				"expires_in":   3600,
			})
		}))
		defer server.Close()

		config := &OAuth2Config{
			TokenURL:     server.URL,
			ClientID:     "test-client",
			ClientSecret: "test-secret",
		}

		provider, err := NewOAuth2AuthProvider(config)
		if err != nil {
			t.Fatalf("failed to create provider: %v", err)
		}

		ctx := context.Background()

		// Launch concurrent requests
		var wg sync.WaitGroup
		numRequests := 10
		wg.Add(numRequests)

		for i := 0; i < numRequests; i++ {
			go func() {
				defer wg.Done()
				req := httptest.NewRequest(http.MethodGet, "https://example.com/test", nil)
				if err := provider.ApplyAuth(ctx, req); err != nil {
					t.Errorf("failed to apply auth: %v", err)
				}
			}()
		}

		wg.Wait()

		// Should only call token endpoint once despite concurrent requests
		mu.Lock()
		finalCount := callCount
		mu.Unlock()

		if finalCount != 1 {
			t.Errorf("expected 1 token request for concurrent calls, got %d", finalCount)
		}
	})

	t.Run("scopes and audience", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := r.ParseForm(); err != nil {
				t.Fatalf("failed to parse form: %v", err)
			}

			scope := r.Form.Get("scope")
			if scope != "read write admin" {
				t.Errorf("expected scopes 'read write admin', got %q", scope)
			}

			audience := r.Form.Get("audience")
			if audience != "https://api.example.com" {
				t.Errorf("expected audience 'https://api.example.com', got %q", audience)
			}

			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "token-with-scope",
				"expires_in":   3600,
			})
		}))
		defer server.Close()

		config := &OAuth2Config{
			TokenURL:     server.URL,
			ClientID:     "test-client",
			ClientSecret: "test-secret",
			Scopes:       []string{"read", "write", "admin"},
			Audience:     "https://api.example.com",
		}

		provider, err := NewOAuth2AuthProvider(config)
		if err != nil {
			t.Fatalf("failed to create provider: %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "https://example.com/test", nil)
		ctx := context.Background()

		if err := provider.ApplyAuth(ctx, req); err != nil {
			t.Fatalf("failed to apply auth: %v", err)
		}
	})

	t.Run("token server error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{
				"error":             "invalid_client",
				"error_description": "Client authentication failed",
			})
		}))
		defer server.Close()

		config := &OAuth2Config{
			TokenURL:     server.URL,
			ClientID:     "invalid-client",
			ClientSecret: "invalid-secret",
		}

		provider, err := NewOAuth2AuthProvider(config)
		if err != nil {
			t.Fatalf("failed to create provider: %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "https://example.com/test", nil)
		ctx := context.Background()

		err = provider.ApplyAuth(ctx, req)
		if err == nil {
			t.Fatal("expected error from token server")
		}
	})

	t.Run("invalid token response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("invalid json"))
		}))
		defer server.Close()

		config := &OAuth2Config{
			TokenURL:     server.URL,
			ClientID:     "test-client",
			ClientSecret: "test-secret",
		}

		provider, err := NewOAuth2AuthProvider(config)
		if err != nil {
			t.Fatalf("failed to create provider: %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "https://example.com/test", nil)
		ctx := context.Background()

		err = provider.ApplyAuth(ctx, req)
		if err == nil {
			t.Fatal("expected error for invalid JSON response")
		}
	})

	t.Run("manual refresh", func(t *testing.T) {
		callCount := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			callCount++
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "refreshed-token",
				"expires_in":   3600,
			})
		}))
		defer server.Close()

		config := &OAuth2Config{
			TokenURL:     server.URL,
			ClientID:     "test-client",
			ClientSecret: "test-secret",
		}

		provider, err := NewOAuth2AuthProvider(config)
		if err != nil {
			t.Fatalf("failed to create provider: %v", err)
		}

		ctx := context.Background()

		// Force refresh
		if err := provider.Refresh(ctx); err != nil {
			t.Fatalf("failed to refresh: %v", err)
		}

		// Should have fetched token
		if callCount != 1 {
			t.Errorf("expected 1 token request, got %d", callCount)
		}

		// Subsequent request should use cached token
		req := httptest.NewRequest(http.MethodGet, "https://example.com/test", nil)
		if err := provider.ApplyAuth(ctx, req); err != nil {
			t.Fatalf("failed to apply auth: %v", err)
		}

		if callCount != 1 {
			t.Errorf("expected token to be cached after refresh, got %d calls", callCount)
		}
	})

	t.Run("default expiry when not provided", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "token-no-expiry",
				// No expires_in field
			})
		}))
		defer server.Close()

		config := &OAuth2Config{
			TokenURL:     server.URL,
			ClientID:     "test-client",
			ClientSecret: "test-secret",
		}

		provider, err := NewOAuth2AuthProvider(config)
		if err != nil {
			t.Fatalf("failed to create provider: %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "https://example.com/test", nil)
		ctx := context.Background()

		if err := provider.ApplyAuth(ctx, req); err != nil {
			t.Fatalf("failed to apply auth: %v", err)
		}

		// Verify token was set
		if auth := req.Header.Get("Authorization"); auth != "Bearer token-no-expiry" {
			t.Errorf("unexpected auth header: %s", auth)
		}
	})
}

// TestNewOAuth2AuthProviderValidation tests OAuth2 provider validation.
func TestNewOAuth2AuthProviderValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		config      *OAuth2Config
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid config",
			config: &OAuth2Config{
				TokenURL:     "https://auth.example.com/token",
				ClientID:     "client123",
				ClientSecret: "secret456",
			},
			expectError: false,
		},
		{
			name: "missing token URL",
			config: &OAuth2Config{
				ClientID:     "client123",
				ClientSecret: "secret456",
			},
			expectError: true,
			errorMsg:    "token_url is required",
		},
		{
			name: "missing client ID",
			config: &OAuth2Config{
				TokenURL:     "https://auth.example.com/token",
				ClientSecret: "secret456",
			},
			expectError: true,
			errorMsg:    "client_id is required",
		},
		{
			name: "empty token URL",
			config: &OAuth2Config{
				TokenURL:     "",
				ClientID:     "client123",
				ClientSecret: "secret456",
			},
			expectError: true,
			errorMsg:    "token_url is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			provider, err := NewOAuth2AuthProvider(tt.config)

			if tt.expectError {
				if err == nil {
					t.Fatal("expected error but got none")
				}
				if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error to contain %q, got %q", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if provider == nil {
					t.Fatal("expected provider but got nil")
				}
			}
		})
	}
}

// TestAWSSigV4Provider tests AWS Signature V4 authentication.
func TestAWSSigV4Provider(t *testing.T) {
	t.Run("signs request correctly", func(t *testing.T) {
		config := &AWSSigV4Config{
			Region:    "us-east-1",
			Service:   "execute-api",
			AccessKey: "AKIAIOSFODNN7EXAMPLE",
			SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		}

		provider, err := NewAWSSigV4Provider(config)
		if err != nil {
			t.Fatalf("failed to create provider: %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "https://api.example.com/test", nil)
		ctx := context.Background()

		err = provider.ApplyAuth(ctx, req)
		if err != nil {
			t.Fatalf("failed to apply auth: %v", err)
		}

		// Verify signature headers are present
		if amzDate := req.Header.Get("X-Amz-Date"); amzDate == "" {
			t.Error("expected X-Amz-Date header")
		}

		authHeader := req.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "AWS4-HMAC-SHA256") {
			t.Errorf("expected AWS4-HMAC-SHA256 auth header, got: %s", authHeader)
		}

		// Verify authorization header contains expected components
		if !strings.Contains(authHeader, "Credential=AKIAIOSFODNN7EXAMPLE") {
			t.Error("authorization header missing credential")
		}
		if !strings.Contains(authHeader, "SignedHeaders=") {
			t.Error("authorization header missing signed headers")
		}
		if !strings.Contains(authHeader, "Signature=") {
			t.Error("authorization header missing signature")
		}
	})

	t.Run("signs POST request with body", func(t *testing.T) {
		config := &AWSSigV4Config{
			Region:    "us-west-2",
			Service:   "s3",
			AccessKey: "AKIAIOSFODNN7EXAMPLE",
			SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		}

		provider, err := NewAWSSigV4Provider(config)
		if err != nil {
			t.Fatalf("failed to create provider: %v", err)
		}

		body := strings.NewReader(`{"key": "value"}`)
		req := httptest.NewRequest(http.MethodPost, "https://api.example.com/test", body)
		ctx := context.Background()

		err = provider.ApplyAuth(ctx, req)
		if err != nil {
			t.Fatalf("failed to apply auth: %v", err)
		}

		// Verify headers are present
		if authHeader := req.Header.Get("Authorization"); authHeader == "" {
			t.Error("expected Authorization header")
		}
	})

	t.Run("signs request with query parameters", func(t *testing.T) {
		config := &AWSSigV4Config{
			Region:    "eu-west-1",
			Service:   "execute-api",
			AccessKey: "AKIAIOSFODNN7EXAMPLE",
			SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		}

		provider, err := NewAWSSigV4Provider(config)
		if err != nil {
			t.Fatalf("failed to create provider: %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "https://api.example.com/test?param1=value1&param2=value2", nil)
		ctx := context.Background()

		err = provider.ApplyAuth(ctx, req)
		if err != nil {
			t.Fatalf("failed to apply auth: %v", err)
		}

		// Verify signature was computed
		if authHeader := req.Header.Get("Authorization"); authHeader == "" {
			t.Error("expected Authorization header")
		}
	})

	t.Run("defaults service to execute-api", func(t *testing.T) {
		config := &AWSSigV4Config{
			Region: "us-east-1",
			// Service not specified
			AccessKey: "AKIAIOSFODNN7EXAMPLE",
			SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		}

		provider, err := NewAWSSigV4Provider(config)
		if err != nil {
			t.Fatalf("failed to create provider: %v", err)
		}

		if provider.config.Service != "execute-api" {
			t.Errorf("expected service to default to execute-api, got %s", provider.config.Service)
		}
	})

	t.Run("missing credentials returns error", func(t *testing.T) {
		config := &AWSSigV4Config{
			Region:  "us-east-1",
			Service: "s3",
			// No credentials
		}

		provider, err := NewAWSSigV4Provider(config)
		if err != nil {
			t.Fatalf("failed to create provider: %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "https://api.example.com/test", nil)
		ctx := context.Background()

		err = provider.ApplyAuth(ctx, req)
		if err == nil {
			t.Fatal("expected error for missing credentials")
		}
		if !strings.Contains(err.Error(), "credentials not configured") {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	t.Run("Refresh does nothing", func(t *testing.T) {
		config := &AWSSigV4Config{
			Region:    "us-east-1",
			Service:   "execute-api",
			AccessKey: "AKIAIOSFODNN7EXAMPLE",
			SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		}

		provider, err := NewAWSSigV4Provider(config)
		if err != nil {
			t.Fatalf("failed to create provider: %v", err)
		}

		ctx := context.Background()
		if err := provider.Refresh(ctx); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

// TestSigV4_HandlesNonAsciiPath is a regression test for
// H-federation-3: the previous hand-rolled signer used the raw URL
// path verbatim, so a path containing spaces, `+`, or non-ASCII bytes
// produced a canonical request that did not match what AWS would
// recompute on the server side, resulting in
// 403 SignatureDoesNotMatch. The aws-sdk-go-v2 signer URI-encodes the
// path correctly. We assert here that signing succeeds and produces
// well-formed Authorization / X-Amz-Date headers — the SDK is
// responsible for the actual canonical-request shape, and its own
// test suite validates that against AWS's published vectors.
func TestSigV4_HandlesNonAsciiPath(t *testing.T) {
	t.Parallel()
	config := &AWSSigV4Config{
		Region:    "us-east-1",
		Service:   "execute-api",
		AccessKey: "AKIAIOSFODNN7EXAMPLE",
		SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}
	provider, err := NewAWSSigV4Provider(config)
	if err != nil {
		t.Fatalf("NewAWSSigV4Provider: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet,
		"https://api.example.com/path%20with%20spaces/and+plus/", nil)

	if err := provider.ApplyAuth(context.Background(), req); err != nil {
		t.Fatalf("ApplyAuth on non-ASCII path: %v", err)
	}

	auth := req.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 ") {
		t.Errorf("Authorization = %q, want AWS4-HMAC-SHA256 prefix", auth)
	}
	if !strings.Contains(auth, "Credential=AKIAIOSFODNN7EXAMPLE/") {
		t.Errorf("Authorization missing Credential=: %q", auth)
	}
	if !strings.Contains(auth, "SignedHeaders=") {
		t.Errorf("Authorization missing SignedHeaders=: %q", auth)
	}
	if !strings.Contains(auth, "Signature=") {
		t.Errorf("Authorization missing Signature=: %q", auth)
	}
	if req.Header.Get("X-Amz-Date") == "" {
		t.Error("X-Amz-Date header missing")
	}
	if req.Header.Get("X-Amz-Content-Sha256") == "" {
		t.Error("X-Amz-Content-Sha256 header missing")
	}
}

// TestNewAWSSigV4ProviderValidation tests AWS SigV4 provider validation.
func TestNewAWSSigV4ProviderValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		config      *AWSSigV4Config
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid config",
			config: &AWSSigV4Config{
				Region:    "us-east-1",
				Service:   "s3",
				AccessKey: "AKIAIOSFODNN7EXAMPLE",
				SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			},
			expectError: false,
		},
		{
			name: "missing region",
			config: &AWSSigV4Config{
				Service:   "s3",
				AccessKey: "AKIAIOSFODNN7EXAMPLE",
				SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			},
			expectError: true,
			errorMsg:    "region is required",
		},
		{
			name: "empty region",
			config: &AWSSigV4Config{
				Region:    "",
				Service:   "s3",
				AccessKey: "AKIAIOSFODNN7EXAMPLE",
				SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			},
			expectError: true,
			errorMsg:    "region is required",
		},
		{
			name: "service defaults to execute-api",
			config: &AWSSigV4Config{
				Region:    "us-east-1",
				AccessKey: "AKIAIOSFODNN7EXAMPLE",
				SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			provider, err := NewAWSSigV4Provider(tt.config)

			if tt.expectError {
				if err == nil {
					t.Fatal("expected error but got none")
				}
				if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error to contain %q, got %q", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if provider == nil {
					t.Fatal("expected provider but got nil")
				}
			}
		})
	}
}

// Helper function to get the type name of a provider.
func getTypeName(provider AuthProvider) string {
	switch provider.(type) {
	case *NoOpAuthProvider:
		return "*federation.NoOpAuthProvider"
	case *BasicAuthProvider:
		return "*federation.BasicAuthProvider"
	case *BearerAuthProvider:
		return "*federation.BearerAuthProvider"
	case *APIKeyAuthProvider:
		return "*federation.APIKeyAuthProvider"
	case *CustomHeadersProvider:
		return "*federation.CustomHeadersProvider"
	case *ChainedAuthProvider:
		return "*federation.ChainedAuthProvider"
	case *OAuth2AuthProvider:
		return "*federation.OAuth2AuthProvider"
	case *AWSSigV4Provider:
		return "*federation.AWSSigV4Provider"
	default:
		return "unknown"
	}
}

// parseQueryString parses a URL-encoded query string.
func parseQueryString(query string) url.Values {
	values, _ := url.ParseQuery(query)
	return values
}

// TestOAuth2AuthProvider_FirstCallReturnsPopulatedToken guards Fix C5
// part 1: previously getToken returned `p.token` which was read BEFORE
// refreshToken executed, so the very first authenticated request
// shipped with `Authorization: Bearer ` (empty bearer). The fix
// returns the freshly-fetched token directly.
func TestOAuth2AuthProvider_FirstCallReturnsPopulatedToken(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "first-call-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer server.Close()

	provider, err := NewOAuth2AuthProvider(&OAuth2Config{
		TokenURL:     server.URL,
		ClientID:     "first-call-client",
		ClientSecret: "secret",
	})
	if err != nil {
		t.Fatalf("NewOAuth2AuthProvider: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "https://example.com/x", nil)
	if err := provider.ApplyAuth(context.Background(), req); err != nil {
		t.Fatalf("ApplyAuth: %v", err)
	}

	got := req.Header.Get("Authorization")
	if got != "Bearer first-call-token" {
		t.Fatalf("first-call Authorization = %q, want %q", got, "Bearer first-call-token")
	}
}

// TestOAuth2AuthProvider_ConcurrentRefreshUsesSingleflight guards Fix
// C5 part 2: concurrent fan-out callers hitting the token endpoint at
// the same time must collapse onto a single in-flight HTTP request via
// singleflight, rather than each acquiring the write lock and issuing
// their own POST one after another.
func TestOAuth2AuthProvider_ConcurrentRefreshUsesSingleflight(t *testing.T) {
	t.Parallel()

	var calls int64
	// Hold each token request open for a short window so concurrent
	// callers actually overlap on the singleflight slot. Without the
	// delay the first call could finish before the others arrive,
	// allowing the test to pass even without singleflight.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&calls, 1)
		time.Sleep(150 * time.Millisecond)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "sf-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer server.Close()

	provider, err := NewOAuth2AuthProvider(&OAuth2Config{
		TokenURL:     server.URL,
		ClientID:     "sf-client",
		ClientSecret: "secret",
	})
	if err != nil {
		t.Fatalf("NewOAuth2AuthProvider: %v", err)
	}

	const N = 50
	var wg sync.WaitGroup
	wg.Add(N)
	start := make(chan struct{})
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			<-start
			req := httptest.NewRequest(http.MethodGet, "https://example.com/x", nil)
			if err := provider.ApplyAuth(context.Background(), req); err != nil {
				t.Errorf("ApplyAuth: %v", err)
				return
			}
			if req.Header.Get("Authorization") != "Bearer sf-token" {
				t.Errorf("unexpected Authorization: %q", req.Header.Get("Authorization"))
			}
		}()
	}
	close(start)
	wg.Wait()

	got := atomic.LoadInt64(&calls)
	// Two is the practical upper bound: one in-flight singleflight
	// fetch plus, in the worst case, a second one if a goroutine
	// scheduled in just after the first refresh published the token.
	if got > 2 {
		t.Fatalf("token endpoint hit %d times, want <= 2 (singleflight collapse expected)", got)
	}
}
