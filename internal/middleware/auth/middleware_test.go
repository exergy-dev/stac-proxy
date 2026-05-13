// Package auth provides authentication middleware tests.
package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yourorg/stac-proxy/internal/middleware"
)

// mockProvider is a test implementation of Provider.
type mockProvider struct {
	name     string
	authFunc func(ctx context.Context, req *http.Request) (*Principal, error)
}

func (m *mockProvider) Name() string {
	return m.name
}

func (m *mockProvider) Authenticate(ctx context.Context, req *http.Request) (*Principal, error) {
	if m.authFunc != nil {
		return m.authFunc(ctx, req)
	}
	return nil, nil
}

func TestNewMiddleware(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		config         Config
		wantName       string
		wantPriority   int
		wantAnonymous  bool
		wantProviders  int
	}{
		{
			name: "default config",
			config: Config{
				AllowAnonymous: false,
				Providers:      nil,
			},
			wantName:      "auth",
			wantPriority:  middleware.PriorityAuth,
			wantAnonymous: false,
			wantProviders: 0,
		},
		{
			name: "with anonymous access",
			config: Config{
				AllowAnonymous: true,
				Providers:      nil,
			},
			wantName:      "auth",
			wantPriority:  middleware.PriorityAuth,
			wantAnonymous: true,
			wantProviders: 0,
		},
		{
			name: "with providers",
			config: Config{
				AllowAnonymous: false,
				Providers: []Provider{
					&mockProvider{name: "provider1"},
					&mockProvider{name: "provider2"},
				},
			},
			wantName:      "auth",
			wantPriority:  middleware.PriorityAuth,
			wantAnonymous: false,
			wantProviders: 2,
		},
		{
			name: "with providers and anonymous",
			config: Config{
				AllowAnonymous: true,
				Providers: []Provider{
					&mockProvider{name: "provider1"},
				},
			},
			wantName:      "auth",
			wantPriority:  middleware.PriorityAuth,
			wantAnonymous: true,
			wantProviders: 1,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			m := NewMiddleware(tt.config)

			if m == nil {
				t.Fatal("NewMiddleware returned nil")
			}

			if got := m.Name(); got != tt.wantName {
				t.Errorf("Name() = %q, want %q", got, tt.wantName)
			}

			if got := m.Priority(); got != tt.wantPriority {
				t.Errorf("Priority() = %d, want %d", got, tt.wantPriority)
			}

			if m.allowAnonymous != tt.wantAnonymous {
				t.Errorf("allowAnonymous = %v, want %v", m.allowAnonymous, tt.wantAnonymous)
			}

			if got := len(m.providers); got != tt.wantProviders {
				t.Errorf("len(providers) = %d, want %d", got, tt.wantProviders)
			}

			if m.anonPrincipal == nil {
				t.Error("anonPrincipal is nil")
			}

			if m.anonPrincipal != nil && !m.anonPrincipal.IsAnonymous() {
				t.Error("anonPrincipal is not anonymous")
			}
		})
	}
}

func TestMiddleware_ProcessRequest_ValidCredentials(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		provider      Provider
		setupRequest  func(*http.Request)
		wantPrincipal *Principal
		wantErr       bool
	}{
		{
			name: "successful authentication",
			provider: &mockProvider{
				name: "test",
				authFunc: func(ctx context.Context, req *http.Request) (*Principal, error) {
					return &Principal{
						ID:   "user123",
						Type: "user",
						Name: "Test User",
					}, nil
				},
			},
			setupRequest: func(req *http.Request) {
				req.Header.Set("Authorization", "Bearer token123")
			},
			wantPrincipal: &Principal{
				ID:   "user123",
				Type: "user",
				Name: "Test User",
			},
			wantErr: false,
		},
		{
			name: "successful authentication with roles",
			provider: &mockProvider{
				name: "test",
				authFunc: func(ctx context.Context, req *http.Request) (*Principal, error) {
					return &Principal{
						ID:    "user456",
						Type:  "user",
						Roles: []string{"admin", "user"},
					}, nil
				},
			},
			setupRequest: func(req *http.Request) {
				req.Header.Set("Authorization", "Bearer admin-token")
			},
			wantPrincipal: &Principal{
				ID:    "user456",
				Type:  "user",
				Roles: []string{"admin", "user"},
			},
			wantErr: false,
		},
		{
			name: "successful authentication with groups",
			provider: &mockProvider{
				name: "test",
				authFunc: func(ctx context.Context, req *http.Request) (*Principal, error) {
					return &Principal{
						ID:     "user789",
						Type:   "user",
						Groups: []string{"engineering", "devops"},
					}, nil
				},
			},
			setupRequest: func(req *http.Request) {
				req.Header.Set("Authorization", "Bearer group-token")
			},
			wantPrincipal: &Principal{
				ID:     "user789",
				Type:   "user",
				Groups: []string{"engineering", "devops"},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			m := NewMiddleware(Config{
				AllowAnonymous: false,
				Providers:      []Provider{tt.provider},
			})

			httpReq := httptest.NewRequest("GET", "/", nil)
			if tt.setupRequest != nil {
				tt.setupRequest(httpReq)
			}

			ctx := context.Background()
			stacReq := &middleware.STACRequest{
				Request: httpReq,
				Context: ctx,
			}

			result, err := m.ProcessRequest(ctx, stacReq)

			if (err != nil) != tt.wantErr {
				t.Errorf("ProcessRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if result == nil && !tt.wantErr {
				t.Fatal("ProcessRequest() returned nil result")
			}

			if !tt.wantErr {
				principal := PrincipalFromContext(result.Context)
				if principal == nil {
					t.Fatal("Principal not found in context")
				}

				if principal.ID != tt.wantPrincipal.ID {
					t.Errorf("Principal.ID = %q, want %q", principal.ID, tt.wantPrincipal.ID)
				}

				if principal.Type != tt.wantPrincipal.Type {
					t.Errorf("Principal.Type = %q, want %q", principal.Type, tt.wantPrincipal.Type)
				}
			}
		})
	}
}

func TestMiddleware_ProcessRequest_InvalidCredentials(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		provider     Provider
		setupRequest func(*http.Request)
		wantErrType  string
	}{
		{
			name: "authentication error",
			provider: &mockProvider{
				name: "test",
				authFunc: func(ctx context.Context, req *http.Request) (*Principal, error) {
					return nil, errors.New("invalid token")
				},
			},
			setupRequest: func(req *http.Request) {
				req.Header.Set("Authorization", "Bearer bad-token")
			},
			wantErrType: "missing_credentials",
		},
		{
			name: "expired token",
			provider: &mockProvider{
				name: "test",
				authFunc: func(ctx context.Context, req *http.Request) (*Principal, error) {
					return nil, errors.New("token expired")
				},
			},
			setupRequest: func(req *http.Request) {
				req.Header.Set("Authorization", "Bearer expired-token")
			},
			wantErrType: "missing_credentials",
		},
		{
			name: "malformed token",
			provider: &mockProvider{
				name: "test",
				authFunc: func(ctx context.Context, req *http.Request) (*Principal, error) {
					return nil, errors.New("malformed token")
				},
			},
			setupRequest: func(req *http.Request) {
				req.Header.Set("Authorization", "Bearer malformed")
			},
			wantErrType: "missing_credentials",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			m := NewMiddleware(Config{
				AllowAnonymous: false,
				Providers:      []Provider{tt.provider},
			})

			httpReq := httptest.NewRequest("GET", "/", nil)
			if tt.setupRequest != nil {
				tt.setupRequest(httpReq)
			}

			ctx := context.Background()
			stacReq := &middleware.STACRequest{
				Request: httpReq,
				Context: ctx,
			}

			result, err := m.ProcessRequest(ctx, stacReq)

			if err == nil {
				t.Fatal("ProcessRequest() expected error, got nil")
			}

			authErr, ok := err.(*middleware.AuthError)
			if !ok {
				t.Fatalf("expected *middleware.AuthError, got %T", err)
			}

			if authErr.Code != tt.wantErrType {
				t.Errorf("AuthError.Code = %q, want %q", authErr.Code, tt.wantErrType)
			}

			if result != nil {
				t.Error("ProcessRequest() should return nil result on error")
			}
		})
	}
}

func TestMiddleware_ProcessRequest_AnonymousAccess(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		allowAnonymous bool
		provider       Provider
		setupRequest   func(*http.Request)
		wantErr        bool
		wantAnonymous  bool
	}{
		{
			name:           "anonymous allowed - no credentials",
			allowAnonymous: true,
			provider: &mockProvider{
				name: "test",
				authFunc: func(ctx context.Context, req *http.Request) (*Principal, error) {
					// No credentials, return nil
					return nil, nil
				},
			},
			setupRequest:  func(req *http.Request) {},
			wantErr:       false,
			wantAnonymous: true,
		},
		{
			name:           "anonymous denied - no credentials",
			allowAnonymous: false,
			provider: &mockProvider{
				name: "test",
				authFunc: func(ctx context.Context, req *http.Request) (*Principal, error) {
					return nil, nil
				},
			},
			setupRequest:  func(req *http.Request) {},
			wantErr:       true,
			wantAnonymous: false,
		},
		{
			name:           "anonymous allowed - invalid credentials",
			allowAnonymous: true,
			provider: &mockProvider{
				name: "test",
				authFunc: func(ctx context.Context, req *http.Request) (*Principal, error) {
					return nil, errors.New("invalid token")
				},
			},
			setupRequest: func(req *http.Request) {
				req.Header.Set("Authorization", "Bearer invalid")
			},
			wantErr:       false,
			wantAnonymous: true,
		},
		{
			name:           "anonymous denied - invalid credentials",
			allowAnonymous: false,
			provider: &mockProvider{
				name: "test",
				authFunc: func(ctx context.Context, req *http.Request) (*Principal, error) {
					return nil, errors.New("invalid token")
				},
			},
			setupRequest: func(req *http.Request) {
				req.Header.Set("Authorization", "Bearer invalid")
			},
			wantErr:       true,
			wantAnonymous: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			m := NewMiddleware(Config{
				AllowAnonymous: tt.allowAnonymous,
				Providers:      []Provider{tt.provider},
			})

			httpReq := httptest.NewRequest("GET", "/", nil)
			if tt.setupRequest != nil {
				tt.setupRequest(httpReq)
			}

			ctx := context.Background()
			stacReq := &middleware.STACRequest{
				Request: httpReq,
				Context: ctx,
			}

			result, err := m.ProcessRequest(ctx, stacReq)

			if (err != nil) != tt.wantErr {
				t.Errorf("ProcessRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				principal := PrincipalFromContext(result.Context)
				if principal == nil {
					t.Fatal("Principal not found in context")
				}

				if principal.IsAnonymous() != tt.wantAnonymous {
					t.Errorf("Principal.IsAnonymous() = %v, want %v", principal.IsAnonymous(), tt.wantAnonymous)
				}

				if tt.wantAnonymous {
					if principal.ID != "anonymous" {
						t.Errorf("Anonymous principal ID = %q, want 'anonymous'", principal.ID)
					}
					if principal.Type != "anonymous" {
						t.Errorf("Anonymous principal Type = %q, want 'anonymous'", principal.Type)
					}
				}
			}
		})
	}
}

func TestMiddleware_ProcessRequest_ProviderChain(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		providers      []Provider
		setupRequest   func(*http.Request)
		wantPrincipal  *Principal
		wantErr        bool
		wantProviderID string
	}{
		{
			name: "first provider succeeds",
			providers: []Provider{
				&mockProvider{
					name: "provider1",
					authFunc: func(ctx context.Context, req *http.Request) (*Principal, error) {
						return &Principal{ID: "user1", Type: "user"}, nil
					},
				},
				&mockProvider{
					name: "provider2",
					authFunc: func(ctx context.Context, req *http.Request) (*Principal, error) {
						return &Principal{ID: "user2", Type: "user"}, nil
					},
				},
			},
			setupRequest: func(req *http.Request) {
				req.Header.Set("Authorization", "Bearer token1")
			},
			wantPrincipal:  &Principal{ID: "user1", Type: "user"},
			wantErr:        false,
			wantProviderID: "user1",
		},
		{
			name: "first provider fails, second succeeds",
			providers: []Provider{
				&mockProvider{
					name: "provider1",
					authFunc: func(ctx context.Context, req *http.Request) (*Principal, error) {
						return nil, errors.New("provider1 failed")
					},
				},
				&mockProvider{
					name: "provider2",
					authFunc: func(ctx context.Context, req *http.Request) (*Principal, error) {
						return &Principal{ID: "user2", Type: "user"}, nil
					},
				},
			},
			setupRequest: func(req *http.Request) {
				req.Header.Set("Authorization", "Bearer token2")
			},
			wantPrincipal:  &Principal{ID: "user2", Type: "user"},
			wantErr:        false,
			wantProviderID: "user2",
		},
		{
			name: "first provider returns nil, second succeeds",
			providers: []Provider{
				&mockProvider{
					name: "provider1",
					authFunc: func(ctx context.Context, req *http.Request) (*Principal, error) {
						// Provider doesn't apply to this request
						return nil, nil
					},
				},
				&mockProvider{
					name: "provider2",
					authFunc: func(ctx context.Context, req *http.Request) (*Principal, error) {
						return &Principal{ID: "user2", Type: "user"}, nil
					},
				},
			},
			setupRequest: func(req *http.Request) {
				req.Header.Set("Authorization", "Bearer token2")
			},
			wantPrincipal:  &Principal{ID: "user2", Type: "user"},
			wantErr:        false,
			wantProviderID: "user2",
		},
		{
			name: "all providers fail",
			providers: []Provider{
				&mockProvider{
					name: "provider1",
					authFunc: func(ctx context.Context, req *http.Request) (*Principal, error) {
						return nil, errors.New("provider1 failed")
					},
				},
				&mockProvider{
					name: "provider2",
					authFunc: func(ctx context.Context, req *http.Request) (*Principal, error) {
						return nil, errors.New("provider2 failed")
					},
				},
			},
			setupRequest: func(req *http.Request) {
				req.Header.Set("Authorization", "Bearer bad-token")
			},
			wantErr: true,
		},
		{
			name: "all providers return nil",
			providers: []Provider{
				&mockProvider{
					name: "provider1",
					authFunc: func(ctx context.Context, req *http.Request) (*Principal, error) {
						return nil, nil
					},
				},
				&mockProvider{
					name: "provider2",
					authFunc: func(ctx context.Context, req *http.Request) (*Principal, error) {
						return nil, nil
					},
				},
			},
			setupRequest: func(req *http.Request) {},
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			m := NewMiddleware(Config{
				AllowAnonymous: false,
				Providers:      tt.providers,
			})

			httpReq := httptest.NewRequest("GET", "/", nil)
			if tt.setupRequest != nil {
				tt.setupRequest(httpReq)
			}

			ctx := context.Background()
			stacReq := &middleware.STACRequest{
				Request: httpReq,
				Context: ctx,
			}

			result, err := m.ProcessRequest(ctx, stacReq)

			if (err != nil) != tt.wantErr {
				t.Errorf("ProcessRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				principal := PrincipalFromContext(result.Context)
				if principal == nil {
					t.Fatal("Principal not found in context")
				}

				if principal.ID != tt.wantPrincipal.ID {
					t.Errorf("Principal.ID = %q, want %q", principal.ID, tt.wantPrincipal.ID)
				}

				if principal.Type != tt.wantPrincipal.Type {
					t.Errorf("Principal.Type = %q, want %q", principal.Type, tt.wantPrincipal.Type)
				}
			}
		})
	}
}

func TestMiddleware_PrincipalFromContext(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		ctx       context.Context
		wantNil   bool
		wantID    string
		wantType  string
	}{
		{
			name:    "context without principal",
			ctx:     context.Background(),
			wantNil: true,
		},
		{
			name: "context with principal",
			ctx: context.WithValue(
				context.Background(),
				middleware.PrincipalKey,
				&Principal{ID: "user123", Type: "user"},
			),
			wantNil:  false,
			wantID:   "user123",
			wantType: "user",
		},
		{
			name: "context with anonymous principal",
			ctx: context.WithValue(
				context.Background(),
				middleware.PrincipalKey,
				AnonymousPrincipal(),
			),
			wantNil:  false,
			wantID:   "anonymous",
			wantType: "anonymous",
		},
		{
			name: "context with wrong value type",
			ctx: context.WithValue(
				context.Background(),
				middleware.PrincipalKey,
				"not-a-principal",
			),
			wantNil: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			principal := PrincipalFromContext(tt.ctx)

			if (principal == nil) != tt.wantNil {
				t.Errorf("PrincipalFromContext() = %v, wantNil %v", principal, tt.wantNil)
				return
			}

			if !tt.wantNil {
				if principal.ID != tt.wantID {
					t.Errorf("Principal.ID = %q, want %q", principal.ID, tt.wantID)
				}
				if principal.Type != tt.wantType {
					t.Errorf("Principal.Type = %q, want %q", principal.Type, tt.wantType)
				}
			}
		})
	}
}

func TestMiddleware_ContextPropagation(t *testing.T) {
	t.Parallel()

	provider := &mockProvider{
		name: "test",
		authFunc: func(ctx context.Context, req *http.Request) (*Principal, error) {
			return &Principal{
				ID:   "user123",
				Type: "user",
				Name: "Test User",
				Roles: []string{"admin"},
			}, nil
		},
	}

	m := NewMiddleware(Config{
		AllowAnonymous: false,
		Providers:      []Provider{provider},
	})

	httpReq := httptest.NewRequest("GET", "/", nil)
	httpReq.Header.Set("Authorization", "Bearer token123")

	ctx := context.Background()
	stacReq := &middleware.STACRequest{
		Request: httpReq,
		Context: ctx,
	}

	result, err := m.ProcessRequest(ctx, stacReq)
	if err != nil {
		t.Fatalf("ProcessRequest() error = %v", err)
	}

	// Verify principal is in result context
	principal := PrincipalFromContext(result.Context)
	if principal == nil {
		t.Fatal("Principal not found in result context")
	}

	if principal.ID != "user123" {
		t.Errorf("Principal.ID = %q, want 'user123'", principal.ID)
	}

	if principal.Type != "user" {
		t.Errorf("Principal.Type = %q, want 'user'", principal.Type)
	}

	if principal.Name != "Test User" {
		t.Errorf("Principal.Name = %q, want 'Test User'", principal.Name)
	}

	if len(principal.Roles) != 1 || principal.Roles[0] != "admin" {
		t.Errorf("Principal.Roles = %v, want ['admin']", principal.Roles)
	}

	// Verify context was propagated to request
	if result.Context != result.Context {
		t.Error("Context was not propagated to STACRequest")
	}
}

func TestMiddleware_AddProvider(t *testing.T) {
	t.Parallel()

	m := NewMiddleware(Config{
		AllowAnonymous: false,
		Providers:      nil,
	})

	if len(m.Providers()) != 0 {
		t.Fatalf("Initial providers count = %d, want 0", len(m.Providers()))
	}

	// Add first provider
	provider1 := &mockProvider{name: "provider1"}
	m.AddProvider(provider1)

	if len(m.Providers()) != 1 {
		t.Errorf("Providers count after AddProvider = %d, want 1", len(m.Providers()))
	}

	// Add second provider
	provider2 := &mockProvider{name: "provider2"}
	m.AddProvider(provider2)

	if len(m.Providers()) != 2 {
		t.Errorf("Providers count after second AddProvider = %d, want 2", len(m.Providers()))
	}

	// Verify providers are in order
	providers := m.Providers()
	if providers[0].Name() != "provider1" {
		t.Errorf("First provider name = %q, want 'provider1'", providers[0].Name())
	}
	if providers[1].Name() != "provider2" {
		t.Errorf("Second provider name = %q, want 'provider2'", providers[1].Name())
	}
}

func TestMiddleware_Providers(t *testing.T) {
	t.Parallel()

	provider1 := &mockProvider{name: "provider1"}
	provider2 := &mockProvider{name: "provider2"}

	m := NewMiddleware(Config{
		AllowAnonymous: false,
		Providers:      []Provider{provider1, provider2},
	})

	providers := m.Providers()

	if len(providers) != 2 {
		t.Errorf("Providers() count = %d, want 2", len(providers))
	}

	if providers[0].Name() != "provider1" {
		t.Errorf("First provider name = %q, want 'provider1'", providers[0].Name())
	}

	if providers[1].Name() != "provider2" {
		t.Errorf("Second provider name = %q, want 'provider2'", providers[1].Name())
	}
}

func TestMiddleware_ProcessRequest_ExtractCredentialsFromAuthorizationHeader(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		headerValue  string
		wantAuth     bool
		wantPrincipal string
	}{
		{
			name:         "bearer token",
			headerValue:  "Bearer token123",
			wantAuth:     true,
			wantPrincipal: "user-bearer",
		},
		{
			name:         "basic auth",
			headerValue:  "Basic dXNlcjpwYXNz",
			wantAuth:     true,
			wantPrincipal: "user-basic",
		},
		{
			name:         "custom scheme",
			headerValue:  "Custom token456",
			wantAuth:     true,
			wantPrincipal: "user-custom",
		},
		{
			name:        "empty header",
			headerValue: "",
			wantAuth:    false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			provider := &mockProvider{
				name: "test",
				authFunc: func(ctx context.Context, req *http.Request) (*Principal, error) {
					authHeader := req.Header.Get("Authorization")
					if authHeader == "" {
						return nil, nil
					}

					var id string
					if authHeader == "Bearer token123" {
						id = "user-bearer"
					} else if authHeader == "Basic dXNlcjpwYXNz" {
						id = "user-basic"
					} else if authHeader == "Custom token456" {
						id = "user-custom"
					} else {
						return nil, errors.New("unknown auth scheme")
					}

					return &Principal{ID: id, Type: "user"}, nil
				},
			}

			m := NewMiddleware(Config{
				AllowAnonymous: !tt.wantAuth,
				Providers:      []Provider{provider},
			})

			httpReq := httptest.NewRequest("GET", "/", nil)
			if tt.headerValue != "" {
				httpReq.Header.Set("Authorization", tt.headerValue)
			}

			ctx := context.Background()
			stacReq := &middleware.STACRequest{
				Request: httpReq,
				Context: ctx,
			}

			result, err := m.ProcessRequest(ctx, stacReq)
			if err != nil {
				t.Fatalf("ProcessRequest() error = %v", err)
			}

			principal := PrincipalFromContext(result.Context)
			if principal == nil {
				t.Fatal("Principal not found in context")
			}

			if tt.wantAuth && principal.ID != tt.wantPrincipal {
				t.Errorf("Principal.ID = %q, want %q", principal.ID, tt.wantPrincipal)
			}
		})
	}
}

func TestMiddleware_ProcessRequest_ExtractCredentialsFromAPIKeyHeader(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		headerName string
		apiKey     string
		wantAuth   bool
		wantUserID string
	}{
		{
			name:       "x-api-key header",
			headerName: "X-API-Key",
			apiKey:     "secret-key-123",
			wantAuth:   true,
			wantUserID: "apikey-user",
		},
		{
			name:       "custom api key header",
			headerName: "X-Custom-Key",
			apiKey:     "custom-456",
			wantAuth:   true,
			wantUserID: "custom-user",
		},
		{
			name:       "empty api key",
			headerName: "X-API-Key",
			apiKey:     "",
			wantAuth:   false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			provider := &mockProvider{
				name: "test",
				authFunc: func(ctx context.Context, req *http.Request) (*Principal, error) {
					apiKey := req.Header.Get(tt.headerName)
					if apiKey == "" {
						return nil, nil
					}

					var id string
					if apiKey == "secret-key-123" {
						id = "apikey-user"
					} else if apiKey == "custom-456" {
						id = "custom-user"
					} else {
						return nil, errors.New("invalid api key")
					}

					return &Principal{ID: id, Type: "service"}, nil
				},
			}

			m := NewMiddleware(Config{
				AllowAnonymous: !tt.wantAuth,
				Providers:      []Provider{provider},
			})

			httpReq := httptest.NewRequest("GET", "/", nil)
			if tt.apiKey != "" {
				httpReq.Header.Set(tt.headerName, tt.apiKey)
			}

			ctx := context.Background()
			stacReq := &middleware.STACRequest{
				Request: httpReq,
				Context: ctx,
			}

			result, err := m.ProcessRequest(ctx, stacReq)
			if err != nil {
				t.Fatalf("ProcessRequest() error = %v", err)
			}

			principal := PrincipalFromContext(result.Context)
			if principal == nil {
				t.Fatal("Principal not found in context")
			}

			if tt.wantAuth && principal.ID != tt.wantUserID {
				t.Errorf("Principal.ID = %q, want %q", principal.ID, tt.wantUserID)
			}
		})
	}
}

func TestMiddleware_ProcessRequest_ExtractCredentialsFromQueryParameter(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		paramName  string
		paramValue string
		wantAuth   bool
		wantUserID string
	}{
		{
			name:       "access_token query param",
			paramName:  "access_token",
			paramValue: "query-token-123",
			wantAuth:   true,
			wantUserID: "query-user",
		},
		{
			name:       "api_key query param",
			paramName:  "api_key",
			paramValue: "query-key-456",
			wantAuth:   true,
			wantUserID: "apikey-query-user",
		},
		{
			name:       "empty query param",
			paramName:  "access_token",
			paramValue: "",
			wantAuth:   false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			provider := &mockProvider{
				name: "test",
				authFunc: func(ctx context.Context, req *http.Request) (*Principal, error) {
					token := req.URL.Query().Get(tt.paramName)
					if token == "" {
						return nil, nil
					}

					var id string
					if token == "query-token-123" {
						id = "query-user"
					} else if token == "query-key-456" {
						id = "apikey-query-user"
					} else {
						return nil, errors.New("invalid token")
					}

					return &Principal{ID: id, Type: "user"}, nil
				},
			}

			m := NewMiddleware(Config{
				AllowAnonymous: !tt.wantAuth,
				Providers:      []Provider{provider},
			})

			url := "/"
			if tt.paramValue != "" {
				url += "?" + tt.paramName + "=" + tt.paramValue
			}

			httpReq := httptest.NewRequest("GET", url, nil)

			ctx := context.Background()
			stacReq := &middleware.STACRequest{
				Request: httpReq,
				Context: ctx,
			}

			result, err := m.ProcessRequest(ctx, stacReq)
			if err != nil {
				t.Fatalf("ProcessRequest() error = %v", err)
			}

			principal := PrincipalFromContext(result.Context)
			if principal == nil {
				t.Fatal("Principal not found in context")
			}

			if tt.wantAuth && principal.ID != tt.wantUserID {
				t.Errorf("Principal.ID = %q, want %q", principal.ID, tt.wantUserID)
			}
		})
	}
}

func TestMiddleware_ProcessResponse(t *testing.T) {
	t.Parallel()

	// The base middleware ProcessResponse is a no-op
	m := NewMiddleware(Config{
		AllowAnonymous: false,
		Providers:      nil,
	})

	ctx := context.Background()
	req := &middleware.STACRequest{
		Request: httptest.NewRequest("GET", "/", nil),
		Context: ctx,
	}

	resp := &middleware.STACResponse{
		StatusCode: http.StatusOK,
		Headers:    http.Header{},
		Body:       []byte(`{"test": "data"}`),
	}

	result, err := m.ProcessResponse(ctx, req, resp)
	if err != nil {
		t.Errorf("ProcessResponse() error = %v, want nil", err)
	}

	if result != resp {
		t.Error("ProcessResponse() should return the same response")
	}
}

func TestMiddleware_MultipleCredentialSources(t *testing.T) {
	t.Parallel()

	// Test that provider can check multiple credential sources
	provider := &mockProvider{
		name: "multi-source",
		authFunc: func(ctx context.Context, req *http.Request) (*Principal, error) {
			// Check Authorization header first
			if auth := req.Header.Get("Authorization"); auth != "" {
				return &Principal{ID: "header-user", Type: "user"}, nil
			}

			// Check API key header
			if apiKey := req.Header.Get("X-API-Key"); apiKey != "" {
				return &Principal{ID: "apikey-user", Type: "service"}, nil
			}

			// Check query parameter
			if token := req.URL.Query().Get("access_token"); token != "" {
				return &Principal{ID: "query-user", Type: "user"}, nil
			}

			return nil, nil
		},
	}

	tests := []struct {
		name          string
		setupRequest  func(*http.Request)
		wantUserID    string
		wantUserType  string
	}{
		{
			name: "authorization header takes precedence",
			setupRequest: func(req *http.Request) {
				req.Header.Set("Authorization", "Bearer token")
				req.Header.Set("X-API-Key", "apikey")
				req.URL.RawQuery = "access_token=query"
			},
			wantUserID:   "header-user",
			wantUserType: "user",
		},
		{
			name: "api key when no auth header",
			setupRequest: func(req *http.Request) {
				req.Header.Set("X-API-Key", "apikey")
				req.URL.RawQuery = "access_token=query"
			},
			wantUserID:   "apikey-user",
			wantUserType: "service",
		},
		{
			name: "query param when no headers",
			setupRequest: func(req *http.Request) {
				req.URL.RawQuery = "access_token=query"
			},
			wantUserID:   "query-user",
			wantUserType: "user",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			m := NewMiddleware(Config{
				AllowAnonymous: false,
				Providers:      []Provider{provider},
			})

			httpReq := httptest.NewRequest("GET", "/", nil)
			if tt.setupRequest != nil {
				tt.setupRequest(httpReq)
			}

			ctx := context.Background()
			stacReq := &middleware.STACRequest{
				Request: httpReq,
				Context: ctx,
			}

			result, err := m.ProcessRequest(ctx, stacReq)
			if err != nil {
				t.Fatalf("ProcessRequest() error = %v", err)
			}

			principal := PrincipalFromContext(result.Context)
			if principal == nil {
				t.Fatal("Principal not found in context")
			}

			if principal.ID != tt.wantUserID {
				t.Errorf("Principal.ID = %q, want %q", principal.ID, tt.wantUserID)
			}

			if principal.Type != tt.wantUserType {
				t.Errorf("Principal.Type = %q, want %q", principal.Type, tt.wantUserType)
			}
		})
	}
}

func TestPrincipal_HasRole(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		p     *Principal
		role  string
		want  bool
	}{
		{
			name: "has role",
			p: &Principal{
				Roles: []string{"admin", "user", "editor"},
			},
			role: "admin",
			want: true,
		},
		{
			name: "does not have role",
			p: &Principal{
				Roles: []string{"user", "editor"},
			},
			role: "admin",
			want: false,
		},
		{
			name: "empty roles",
			p: &Principal{
				Roles: []string{},
			},
			role: "admin",
			want: false,
		},
		{
			name: "nil roles",
			p:    &Principal{},
			role: "admin",
			want: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.p.HasRole(tt.role); got != tt.want {
				t.Errorf("HasRole(%q) = %v, want %v", tt.role, got, tt.want)
			}
		})
	}
}

func TestPrincipal_HasGroup(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		p     *Principal
		group string
		want  bool
	}{
		{
			name: "has group",
			p: &Principal{
				Groups: []string{"engineering", "devops", "platform"},
			},
			group: "devops",
			want:  true,
		},
		{
			name: "does not have group",
			p: &Principal{
				Groups: []string{"engineering", "platform"},
			},
			group: "devops",
			want:  false,
		},
		{
			name: "empty groups",
			p: &Principal{
				Groups: []string{},
			},
			group: "engineering",
			want:  false,
		},
		{
			name:  "nil groups",
			p:     &Principal{},
			group: "engineering",
			want:  false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.p.HasGroup(tt.group); got != tt.want {
				t.Errorf("HasGroup(%q) = %v, want %v", tt.group, got, tt.want)
			}
		})
	}
}

func TestPrincipal_CanAccessCollection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		p          *Principal
		collection string
		want       bool
	}{
		{
			name: "no restrictions - nil collections",
			p:    &Principal{},
			collection: "any-collection",
			want:       true,
		},
		{
			name: "no restrictions - empty collections",
			p: &Principal{
				Collections: []string{},
			},
			collection: "any-collection",
			want:       true,
		},
		{
			name: "has specific collection",
			p: &Principal{
				Collections: []string{"col1", "col2", "col3"},
			},
			collection: "col2",
			want:       true,
		},
		{
			name: "does not have collection",
			p: &Principal{
				Collections: []string{"col1", "col2"},
			},
			collection: "col3",
			want:       false,
		},
		{
			name: "wildcard access",
			p: &Principal{
				Collections: []string{"*"},
			},
			collection: "any-collection",
			want:       true,
		},
		{
			name: "wildcard with specific collections",
			p: &Principal{
				Collections: []string{"col1", "*"},
			},
			collection: "any-collection",
			want:       true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.p.CanAccessCollection(tt.collection); got != tt.want {
				t.Errorf("CanAccessCollection(%q) = %v, want %v", tt.collection, got, tt.want)
			}
		})
	}
}

func TestPrincipal_Clone(t *testing.T) {
	t.Parallel()

	original := &Principal{
		ID:    "user123",
		Type:  "user",
		Email: "user@example.com",
		Name:  "Test User",
		Groups: []string{"group1", "group2"},
		Roles: []string{"admin", "user"},
		Attributes: map[string]string{
			"key1": "value1",
			"key2": "value2",
		},
		Collections: []string{"col1", "col2"},
		Token:       "token123",
		ExpiresAt:   1234567890,
	}

	clone := original.Clone()

	// Verify all fields are copied
	if clone.ID != original.ID {
		t.Errorf("Clone.ID = %q, want %q", clone.ID, original.ID)
	}
	if clone.Type != original.Type {
		t.Errorf("Clone.Type = %q, want %q", clone.Type, original.Type)
	}
	if clone.Email != original.Email {
		t.Errorf("Clone.Email = %q, want %q", clone.Email, original.Email)
	}
	if clone.Name != original.Name {
		t.Errorf("Clone.Name = %q, want %q", clone.Name, original.Name)
	}
	if clone.Token != original.Token {
		t.Errorf("Clone.Token = %q, want %q", clone.Token, original.Token)
	}
	if clone.ExpiresAt != original.ExpiresAt {
		t.Errorf("Clone.ExpiresAt = %d, want %d", clone.ExpiresAt, original.ExpiresAt)
	}

	// Verify slices are deep copied
	if len(clone.Groups) != len(original.Groups) {
		t.Errorf("Clone.Groups length = %d, want %d", len(clone.Groups), len(original.Groups))
	}
	if len(clone.Roles) != len(original.Roles) {
		t.Errorf("Clone.Roles length = %d, want %d", len(clone.Roles), len(original.Roles))
	}
	if len(clone.Collections) != len(original.Collections) {
		t.Errorf("Clone.Collections length = %d, want %d", len(clone.Collections), len(original.Collections))
	}
	if len(clone.Attributes) != len(original.Attributes) {
		t.Errorf("Clone.Attributes length = %d, want %d", len(clone.Attributes), len(original.Attributes))
	}

	// Modify clone and verify original is unchanged
	clone.Groups[0] = "modified"
	if original.Groups[0] == "modified" {
		t.Error("Modifying clone.Groups affected original.Groups")
	}

	clone.Roles[0] = "modified"
	if original.Roles[0] == "modified" {
		t.Error("Modifying clone.Roles affected original.Roles")
	}

	clone.Collections[0] = "modified"
	if original.Collections[0] == "modified" {
		t.Error("Modifying clone.Collections affected original.Collections")
	}

	clone.Attributes["key1"] = "modified"
	if original.Attributes["key1"] == "modified" {
		t.Error("Modifying clone.Attributes affected original.Attributes")
	}
}

func TestPrincipal_Clone_NilSlices(t *testing.T) {
	t.Parallel()

	// Test cloning with nil slices
	original := &Principal{
		ID:   "user123",
		Type: "user",
	}

	clone := original.Clone()

	if clone.Groups != nil {
		t.Errorf("Clone.Groups = %v, want nil", clone.Groups)
	}
	if clone.Roles != nil {
		t.Errorf("Clone.Roles = %v, want nil", clone.Roles)
	}
	if clone.Attributes != nil {
		t.Errorf("Clone.Attributes = %v, want nil", clone.Attributes)
	}
	if clone.Collections != nil {
		t.Errorf("Clone.Collections = %v, want nil", clone.Collections)
	}
}

func TestAnonymousPrincipal(t *testing.T) {
	t.Parallel()

	anon := AnonymousPrincipal()

	if anon == nil {
		t.Fatal("AnonymousPrincipal() returned nil")
	}

	if anon.ID != "anonymous" {
		t.Errorf("ID = %q, want 'anonymous'", anon.ID)
	}

	if anon.Type != "anonymous" {
		t.Errorf("Type = %q, want 'anonymous'", anon.Type)
	}

	if !anon.IsAnonymous() {
		t.Error("IsAnonymous() = false, want true")
	}

	if anon.Attributes == nil {
		t.Error("Attributes is nil, want empty map")
	}

	if len(anon.Attributes) != 0 {
		t.Errorf("Attributes length = %d, want 0", len(anon.Attributes))
	}
}
