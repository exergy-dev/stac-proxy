package auth

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Test secret for HMAC signing
var testSecret = []byte("test-secret-key-for-jwt-signing")

// createTestToken creates a JWT token with the given claims and options
func createTestToken(claims jwt.MapClaims, secret []byte, expired bool, invalidSig bool) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	if invalidSig {
		// Sign with a different secret to create an invalid signature
		tokenString, _ := token.SignedString([]byte("wrong-secret"))
		return tokenString
	}

	tokenString, _ := token.SignedString(secret)
	return tokenString
}

// createTestTokenWithExp creates a token with specific expiration
func createTestTokenWithExp(claims jwt.MapClaims, secret []byte, exp time.Time) string {
	claims["exp"] = exp.Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString(secret)
	return tokenString
}

func TestNewBearerProvider(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		config    BearerConfig
		wantErr   bool
		errString string
		validate  func(*testing.T, *BearerProvider)
	}{
		{
			name: "valid config with secret",
			config: BearerConfig{
				Name:     "test-bearer",
				Issuer:   "https://issuer.example.com",
				Audience: "test-audience",
				Secret:   testSecret,
			},
			wantErr: false,
			validate: func(t *testing.T, p *BearerProvider) {
				if p == nil {
					t.Fatal("expected non-nil provider")
				}
				if p.name != "test-bearer" {
					t.Errorf("expected name=test-bearer, got %s", p.name)
				}
				if p.issuer != "https://issuer.example.com" {
					t.Errorf("expected issuer=https://issuer.example.com, got %s", p.issuer)
				}
				if p.audience != "test-audience" {
					t.Errorf("expected audience=test-audience, got %s", p.audience)
				}
				if p.keyFunc == nil {
					t.Error("expected keyFunc to be set")
				}
				if p.claimsFunc == nil {
					t.Error("expected claimsFunc to be set")
				}
			},
		},
		{
			name: "default name when not provided",
			config: BearerConfig{
				Secret: testSecret,
			},
			wantErr: false,
			validate: func(t *testing.T, p *BearerProvider) {
				if p.name != "bearer" {
					t.Errorf("expected default name=bearer, got %s", p.name)
				}
			},
		},
		{
			name: "valid config with JWKS URL",
			config: BearerConfig{
				Name:     "jwks-bearer",
				JWKSURL:  "https://example.com/.well-known/jwks.json",
				Issuer:   "https://issuer.example.com",
				Audience: "test-audience",
			},
			wantErr: false,
			validate: func(t *testing.T, p *BearerProvider) {
				if p.jwksURL != "https://example.com/.well-known/jwks.json" {
					t.Errorf("expected jwksURL to be set, got %s", p.jwksURL)
				}
				if p.keyFunc == nil {
					t.Error("expected keyFunc to be set")
				}
			},
		},
		{
			name: "custom claims function",
			config: BearerConfig{
				Secret: testSecret,
				ClaimsFunc: func(claims jwt.MapClaims) (*Principal, error) {
					return &Principal{ID: "custom"}, nil
				},
			},
			wantErr: false,
			validate: func(t *testing.T, p *BearerProvider) {
				if p.claimsFunc == nil {
					t.Error("expected custom claimsFunc to be set")
				}
			},
		},
		{
			name:      "error when neither secret nor JWKS URL provided",
			config:    BearerConfig{},
			wantErr:   true,
			errString: "either Secret or JWKSURL must be provided",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			provider, err := NewBearerProvider(tt.config)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errString != "" && err.Error() != tt.errString {
					t.Errorf("expected error %q, got %q", tt.errString, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.validate != nil {
				tt.validate(t, provider)
			}
		})
	}
}

func TestBearerProvider_Name(t *testing.T) {
	t.Parallel()

	provider, _ := NewBearerProvider(BearerConfig{
		Name:   "custom-name",
		Secret: testSecret,
	})

	if provider.Name() != "custom-name" {
		t.Errorf("expected Name()=custom-name, got %s", provider.Name())
	}
}

func TestBearerProvider_Authenticate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		config    BearerConfig
		setupReq  func() *http.Request
		wantNil   bool // true if we expect nil principal (not applicable)
		wantErr   bool
		errSubstr string
		validate  func(*testing.T, *Principal)
	}{
		{
			name: "valid JWT token with standard claims",
			config: BearerConfig{
				Secret: testSecret,
			},
			setupReq: func() *http.Request {
				claims := jwt.MapClaims{
					"sub":    "user123",
					"email":  "test@example.com",
					"name":   "Test User",
					"roles":  []interface{}{"admin", "user"},
					"groups": []interface{}{"engineering", "platform"},
					"exp":    time.Now().Add(time.Hour).Unix(),
					"iat":    time.Now().Unix(),
				}
				token := createTestToken(claims, testSecret, false, false)
				req := httptest.NewRequest("GET", "/test", nil)
				req.Header.Set("Authorization", "Bearer "+token)
				return req
			},
			wantErr: false,
			validate: func(t *testing.T, p *Principal) {
				if p == nil {
					t.Fatal("expected non-nil principal")
				}
				if p.ID != "user123" {
					t.Errorf("expected ID=user123, got %s", p.ID)
				}
				if p.Email != "test@example.com" {
					t.Errorf("expected Email=test@example.com, got %s", p.Email)
				}
				if p.Name != "Test User" {
					t.Errorf("expected Name=Test User, got %s", p.Name)
				}
				if p.Type != "user" {
					t.Errorf("expected Type=user, got %s", p.Type)
				}
				if len(p.Roles) != 2 {
					t.Errorf("expected 2 roles, got %d", len(p.Roles))
				}
				if !p.HasRole("admin") {
					t.Error("expected principal to have admin role")
				}
				if !p.HasRole("user") {
					t.Error("expected principal to have user role")
				}
				if len(p.Groups) != 2 {
					t.Errorf("expected 2 groups, got %d", len(p.Groups))
				}
				if !p.HasGroup("engineering") {
					t.Error("expected principal to have engineering group")
				}
				if !p.HasGroup("platform") {
					t.Error("expected principal to have platform group")
				}
				if p.Token == "" {
					t.Error("expected token to be set")
				}
				if p.ExpiresAt == 0 {
					t.Error("expected ExpiresAt to be set")
				}
			},
		},
		{
			name: "valid token with issuer validation",
			config: BearerConfig{
				Secret: testSecret,
				Issuer: "https://issuer.example.com",
			},
			setupReq: func() *http.Request {
				claims := jwt.MapClaims{
					"sub": "user123",
					"iss": "https://issuer.example.com",
					"exp": time.Now().Add(time.Hour).Unix(),
				}
				token := createTestToken(claims, testSecret, false, false)
				req := httptest.NewRequest("GET", "/test", nil)
				req.Header.Set("Authorization", "Bearer "+token)
				return req
			},
			wantErr: false,
			validate: func(t *testing.T, p *Principal) {
				if p == nil {
					t.Fatal("expected non-nil principal")
				}
			},
		},
		{
			name: "invalid issuer",
			config: BearerConfig{
				Secret: testSecret,
				Issuer: "https://expected-issuer.example.com",
			},
			setupReq: func() *http.Request {
				claims := jwt.MapClaims{
					"sub": "user123",
					"iss": "https://wrong-issuer.example.com",
					"exp": time.Now().Add(time.Hour).Unix(),
				}
				token := createTestToken(claims, testSecret, false, false)
				req := httptest.NewRequest("GET", "/test", nil)
				req.Header.Set("Authorization", "Bearer "+token)
				return req
			},
			wantErr:   true,
			errSubstr: "invalid issuer",
		},
		{
			name: "valid token with audience validation - string audience",
			config: BearerConfig{
				Secret:   testSecret,
				Audience: "expected-audience",
			},
			setupReq: func() *http.Request {
				claims := jwt.MapClaims{
					"sub": "user123",
					"aud": "expected-audience",
					"exp": time.Now().Add(time.Hour).Unix(),
				}
				token := createTestToken(claims, testSecret, false, false)
				req := httptest.NewRequest("GET", "/test", nil)
				req.Header.Set("Authorization", "Bearer "+token)
				return req
			},
			wantErr: false,
		},
		{
			name: "valid token with audience validation - array audience",
			config: BearerConfig{
				Secret:   testSecret,
				Audience: "expected-audience",
			},
			setupReq: func() *http.Request {
				claims := jwt.MapClaims{
					"sub": "user123",
					"aud": []interface{}{"other-audience", "expected-audience"},
					"exp": time.Now().Add(time.Hour).Unix(),
				}
				token := createTestToken(claims, testSecret, false, false)
				req := httptest.NewRequest("GET", "/test", nil)
				req.Header.Set("Authorization", "Bearer "+token)
				return req
			},
			wantErr: false,
		},
		{
			name: "invalid audience - string",
			config: BearerConfig{
				Secret:   testSecret,
				Audience: "expected-audience",
			},
			setupReq: func() *http.Request {
				claims := jwt.MapClaims{
					"sub": "user123",
					"aud": "wrong-audience",
					"exp": time.Now().Add(time.Hour).Unix(),
				}
				token := createTestToken(claims, testSecret, false, false)
				req := httptest.NewRequest("GET", "/test", nil)
				req.Header.Set("Authorization", "Bearer "+token)
				return req
			},
			wantErr:   true,
			errSubstr: "invalid audience",
		},
		{
			name: "invalid audience - array",
			config: BearerConfig{
				Secret:   testSecret,
				Audience: "expected-audience",
			},
			setupReq: func() *http.Request {
				claims := jwt.MapClaims{
					"sub": "user123",
					"aud": []interface{}{"wrong-audience-1", "wrong-audience-2"},
					"exp": time.Now().Add(time.Hour).Unix(),
				}
				token := createTestToken(claims, testSecret, false, false)
				req := httptest.NewRequest("GET", "/test", nil)
				req.Header.Set("Authorization", "Bearer "+token)
				return req
			},
			wantErr:   true,
			errSubstr: "invalid audience",
		},
		{
			name: "expired token",
			config: BearerConfig{
				Secret: testSecret,
			},
			setupReq: func() *http.Request {
				claims := jwt.MapClaims{
					"sub": "user123",
				}
				token := createTestTokenWithExp(claims, testSecret, time.Now().Add(-time.Hour))
				req := httptest.NewRequest("GET", "/test", nil)
				req.Header.Set("Authorization", "Bearer "+token)
				return req
			},
			wantErr:   true,
			errSubstr: "expired",
		},
		{
			name: "invalid signature",
			config: BearerConfig{
				Secret: testSecret,
			},
			setupReq: func() *http.Request {
				claims := jwt.MapClaims{
					"sub": "user123",
					"exp": time.Now().Add(time.Hour).Unix(),
				}
				token := createTestToken(claims, testSecret, false, true)
				req := httptest.NewRequest("GET", "/test", nil)
				req.Header.Set("Authorization", "Bearer "+token)
				return req
			},
			wantErr:   true,
			errSubstr: "invalid token",
		},
		{
			name: "no authorization header - returns nil",
			config: BearerConfig{
				Secret: testSecret,
			},
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "/test", nil)
				return req
			},
			wantNil: true,
		},
		{
			name: "wrong credential type - Basic auth - returns nil",
			config: BearerConfig{
				Secret: testSecret,
			},
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "/test", nil)
				req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
				return req
			},
			wantNil: true,
		},
		{
			name: "wrong credential type - API Key - returns nil",
			config: BearerConfig{
				Secret: testSecret,
			},
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "/test", nil)
				req.Header.Set("Authorization", "ApiKey some-api-key")
				return req
			},
			wantNil: true,
		},
		{
			name: "empty bearer token",
			config: BearerConfig{
				Secret: testSecret,
			},
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "/test", nil)
				req.Header.Set("Authorization", "Bearer ")
				return req
			},
			wantErr:   true,
			errSubstr: "empty bearer token",
		},
		{
			name: "custom claims mapper",
			config: BearerConfig{
				Secret: testSecret,
				ClaimsFunc: func(claims jwt.MapClaims) (*Principal, error) {
					return &Principal{
						ID:   "custom-id",
						Type: "service",
						Attributes: map[string]string{
							"custom": "value",
						},
					}, nil
				},
			},
			setupReq: func() *http.Request {
				claims := jwt.MapClaims{
					"sub": "original-sub",
					"exp": time.Now().Add(time.Hour).Unix(),
				}
				token := createTestToken(claims, testSecret, false, false)
				req := httptest.NewRequest("GET", "/test", nil)
				req.Header.Set("Authorization", "Bearer "+token)
				return req
			},
			wantErr: false,
			validate: func(t *testing.T, p *Principal) {
				if p.ID != "custom-id" {
					t.Errorf("expected custom ID, got %s", p.ID)
				}
				if p.Type != "service" {
					t.Errorf("expected Type=service, got %s", p.Type)
				}
				if p.Attributes["custom"] != "value" {
					t.Error("expected custom attribute to be set")
				}
			},
		},
		{
			name: "custom claims mapper returning error",
			config: BearerConfig{
				Secret: testSecret,
				ClaimsFunc: func(claims jwt.MapClaims) (*Principal, error) {
					return nil, fmt.Errorf("custom mapper error")
				},
			},
			setupReq: func() *http.Request {
				claims := jwt.MapClaims{
					"sub": "user123",
					"exp": time.Now().Add(time.Hour).Unix(),
				}
				token := createTestToken(claims, testSecret, false, false)
				req := httptest.NewRequest("GET", "/test", nil)
				req.Header.Set("Authorization", "Bearer "+token)
				return req
			},
			wantErr:   true,
			errSubstr: "failed to extract principal",
		},
		{
			name: "token without expiration",
			config: BearerConfig{
				Secret: testSecret,
			},
			setupReq: func() *http.Request {
				claims := jwt.MapClaims{
					"sub": "user123",
				}
				token := createTestToken(claims, testSecret, false, false)
				req := httptest.NewRequest("GET", "/test", nil)
				req.Header.Set("Authorization", "Bearer "+token)
				return req
			},
			wantErr: false,
			validate: func(t *testing.T, p *Principal) {
				if p.ID != "user123" {
					t.Errorf("expected ID=user123, got %s", p.ID)
				}
			},
		},
		{
			name: "malformed JWT token",
			config: BearerConfig{
				Secret: testSecret,
			},
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "/test", nil)
				req.Header.Set("Authorization", "Bearer not.a.valid.jwt")
				return req
			},
			wantErr:   true,
			errSubstr: "invalid token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			provider, err := NewBearerProvider(tt.config)
			if err != nil {
				t.Fatalf("failed to create provider: %v", err)
			}

			req := tt.setupReq()
			ctx := context.Background()

			principal, err := provider.Authenticate(ctx, req)

			if tt.wantNil {
				if principal != nil {
					t.Errorf("expected nil principal, got %+v", principal)
				}
				if err != nil {
					t.Errorf("expected nil error for non-applicable auth, got %v", err)
				}
				return
			}

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errSubstr != "" {
					if !containsString(err.Error(), tt.errSubstr) {
						t.Errorf("expected error containing %q, got %q", tt.errSubstr, err.Error())
					}
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.validate != nil {
				tt.validate(t, principal)
			}
		})
	}
}

func TestDefaultClaimsFunc(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		claims    jwt.MapClaims
		wantErr   bool
		errSubstr string
		validate  func(*testing.T, *Principal)
	}{
		{
			name: "all standard claims present",
			claims: jwt.MapClaims{
				"sub":    "user123",
				"email":  "test@example.com",
				"name":   "Test User",
				"roles":  []interface{}{"admin", "user"},
				"groups": []interface{}{"team-a", "team-b"},
				"exp":    time.Now().Add(time.Hour).Unix(),
			},
			wantErr: false,
			validate: func(t *testing.T, p *Principal) {
				if p.ID != "user123" {
					t.Errorf("expected ID=user123, got %s", p.ID)
				}
				if p.Email != "test@example.com" {
					t.Errorf("expected email=test@example.com, got %s", p.Email)
				}
				if p.Name != "Test User" {
					t.Errorf("expected name=Test User, got %s", p.Name)
				}
				if p.Type != "user" {
					t.Errorf("expected type=user, got %s", p.Type)
				}
				if len(p.Roles) != 2 {
					t.Errorf("expected 2 roles, got %d", len(p.Roles))
				}
				if len(p.Groups) != 2 {
					t.Errorf("expected 2 groups, got %d", len(p.Groups))
				}
			},
		},
		{
			name: "minimal claims - only sub",
			claims: jwt.MapClaims{
				"sub": "user456",
			},
			wantErr: false,
			validate: func(t *testing.T, p *Principal) {
				if p.ID != "user456" {
					t.Errorf("expected ID=user456, got %s", p.ID)
				}
				if p.Type != "user" {
					t.Errorf("expected type=user, got %s", p.Type)
				}
				if p.Attributes == nil {
					t.Error("expected attributes map to be initialized")
				}
			},
		},
		{
			name: "expired token in claims func",
			claims: jwt.MapClaims{
				"sub": "user123",
				"exp": float64(time.Now().Add(-time.Hour).Unix()),
			},
			wantErr:   true,
			errSubstr: "expired",
		},
		{
			name: "roles with non-string values - filtered out",
			claims: jwt.MapClaims{
				"sub":   "user123",
				"roles": []interface{}{"admin", 123, "user", nil},
			},
			wantErr: false,
			validate: func(t *testing.T, p *Principal) {
				if len(p.Roles) != 2 {
					t.Errorf("expected 2 roles (non-string filtered), got %d", len(p.Roles))
				}
				if !p.HasRole("admin") {
					t.Error("expected admin role")
				}
				if !p.HasRole("user") {
					t.Error("expected user role")
				}
			},
		},
		{
			name: "groups with non-string values - filtered out",
			claims: jwt.MapClaims{
				"sub":    "user123",
				"groups": []interface{}{"group-a", 456, "group-b", false},
			},
			wantErr: false,
			validate: func(t *testing.T, p *Principal) {
				if len(p.Groups) != 2 {
					t.Errorf("expected 2 groups (non-string filtered), got %d", len(p.Groups))
				}
				if !p.HasGroup("group-a") {
					t.Error("expected group-a")
				}
				if !p.HasGroup("group-b") {
					t.Error("expected group-b")
				}
			},
		},
		{
			name: "empty roles and groups arrays",
			claims: jwt.MapClaims{
				"sub":    "user123",
				"roles":  []interface{}{},
				"groups": []interface{}{},
			},
			wantErr: false,
			validate: func(t *testing.T, p *Principal) {
				if len(p.Roles) != 0 {
					t.Errorf("expected 0 roles, got %d", len(p.Roles))
				}
				if len(p.Groups) != 0 {
					t.Errorf("expected 0 groups, got %d", len(p.Groups))
				}
			},
		},
		{
			name: "expiration at boundary",
			claims: jwt.MapClaims{
				"sub": "user123",
				"exp": time.Now().Unix(), // Exactly now
			},
			wantErr: false, // Current implementation checks > not >=
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			principal, err := defaultClaimsFunc(tt.claims)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errSubstr != "" {
					if !containsString(err.Error(), tt.errSubstr) {
						t.Errorf("expected error containing %q, got %q", tt.errSubstr, err.Error())
					}
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.validate != nil {
				tt.validate(t, principal)
			}
		})
	}
}

func TestBearerProvider_KeyFunc_HMAC(t *testing.T) {
	t.Parallel()

	secret := []byte("test-secret")
	provider, err := NewBearerProvider(BearerConfig{
		Secret: secret,
	})
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	tests := []struct {
		name      string
		token     *jwt.Token
		wantErr   bool
		errSubstr string
	}{
		{
			name: "valid HMAC signing method",
			token: jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
				"sub": "test",
			}),
			wantErr: false,
		},
		{
			name: "invalid signing method - RSA",
			token: jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
				"sub": "test",
			}),
			wantErr:   true,
			errSubstr: "unexpected signing method",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			key, err := provider.keyFunc(tt.token)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errSubstr != "" {
					if !containsString(err.Error(), tt.errSubstr) {
						t.Errorf("expected error containing %q, got %q", tt.errSubstr, err.Error())
					}
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if key == nil {
				t.Error("expected non-nil key")
			}
		})
	}
}

func TestBearerProvider_JWKSKeyFunc_RejectsMissingKid(t *testing.T) {
	t.Parallel()

	provider, err := NewBearerProvider(BearerConfig{
		JWKSURL: "https://example.com/.well-known/jwks.json",
	})
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	// Token has no kid header; JWKS lookup requires one to pick the
	// right key, so we expect a friendly error rather than a network
	// call.
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": "test",
	})

	_, err = provider.jwksKeyFunc(token)
	if err == nil {
		t.Error("expected error for missing kid, got nil")
	}
	if !containsString(err.Error(), "kid") {
		t.Errorf("expected 'kid' in error, got %v", err)
	}
}

func TestBearerProvider_Integration(t *testing.T) {
	t.Parallel()

	// Create a provider
	provider, err := NewBearerProvider(BearerConfig{
		Name:     "integration-test",
		Secret:   testSecret,
		Issuer:   "https://auth.example.com",
		Audience: "api.example.com",
	})
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	// Create a valid token
	claims := jwt.MapClaims{
		"sub":    "integration-user",
		"email":  "integration@example.com",
		"name":   "Integration User",
		"iss":    "https://auth.example.com",
		"aud":    "api.example.com",
		"roles":  []interface{}{"developer", "tester"},
		"groups": []interface{}{"qa", "engineering"},
		"exp":    time.Now().Add(time.Hour).Unix(),
		"iat":    time.Now().Unix(),
	}
	token := createTestToken(claims, testSecret, false, false)

	// Create request with token
	req := httptest.NewRequest("GET", "/api/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	// Authenticate
	principal, err := provider.Authenticate(context.Background(), req)
	if err != nil {
		t.Fatalf("authentication failed: %v", err)
	}

	// Verify complete principal
	if principal == nil {
		t.Fatal("expected non-nil principal")
	}
	if principal.ID != "integration-user" {
		t.Errorf("expected ID=integration-user, got %s", principal.ID)
	}
	if principal.Email != "integration@example.com" {
		t.Errorf("expected email=integration@example.com, got %s", principal.Email)
	}
	if principal.Name != "Integration User" {
		t.Errorf("expected name=Integration User, got %s", principal.Name)
	}
	if !principal.HasRole("developer") {
		t.Error("expected developer role")
	}
	if !principal.HasRole("tester") {
		t.Error("expected tester role")
	}
	if !principal.HasGroup("qa") {
		t.Error("expected qa group")
	}
	if !principal.HasGroup("engineering") {
		t.Error("expected engineering group")
	}
	if principal.Token != token {
		t.Error("expected token to match original")
	}
	if principal.ExpiresAt == 0 {
		t.Error("expected expiration to be set")
	}
}

func TestBearerProvider_MultipleTokenFormats(t *testing.T) {
	t.Parallel()

	provider, err := NewBearerProvider(BearerConfig{
		Secret: testSecret,
	})
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	tests := []struct {
		name    string
		header  string
		wantNil bool
		wantErr bool
	}{
		{
			name:    "Bearer with leading spaces",
			header:  "  Bearer " + createTestToken(jwt.MapClaims{"sub": "test", "exp": time.Now().Add(time.Hour).Unix()}, testSecret, false, false),
			wantNil: true, // Header trimming is HTTP server's job, not ours
		},
		{
			name:    "bearer lowercase",
			header:  "bearer " + createTestToken(jwt.MapClaims{"sub": "test", "exp": time.Now().Add(time.Hour).Unix()}, testSecret, false, false),
			wantNil: true, // Case-sensitive check
		},
		{
			name:    "BEARER uppercase",
			header:  "BEARER " + createTestToken(jwt.MapClaims{"sub": "test", "exp": time.Now().Add(time.Hour).Unix()}, testSecret, false, false),
			wantNil: true, // Case-sensitive check
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set("Authorization", tt.header)

			principal, err := provider.Authenticate(context.Background(), req)

			if tt.wantNil {
				if principal != nil {
					t.Errorf("expected nil principal, got %+v", principal)
				}
			}

			if tt.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// Helper function to check if a string contains a substring
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && stringContains(s, substr)))
}

func stringContains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
