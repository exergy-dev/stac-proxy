package auth

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
				require.NotNil(t, p, "expected non-nil provider")
				assert.Equal(t, "test-bearer", p.name, "name")
				assert.Equal(t, "https://issuer.example.com", p.issuer, "issuer")
				assert.Equal(t, "test-audience", p.audience, "audience")
				assert.NotNil(t, p.staticSecret, "expected staticSecret to be set")
				assert.NotNil(t, p.claimsFunc, "expected claimsFunc to be set")
			},
		},
		{
			name: "default name when not provided",
			config: BearerConfig{
				Secret: testSecret,
			},
			wantErr: false,
			validate: func(t *testing.T, p *BearerProvider) {
				assert.Equal(t, "bearer", p.name, "default name")
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
				assert.NotNil(t, p.jwks, "expected JWKS client to be set")
				assert.Equal(t, "https://example.com/.well-known/jwks.json", p.jwks.url, "jwks URL")
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
				assert.NotNil(t, p.claimsFunc, "expected custom claimsFunc to be set")
			},
		},
		{
			name:      "error when neither secret nor JWKS URL provided",
			config:    BearerConfig{},
			wantErr:   true,
			errString: "bearer: either Secret or JWKSURL must be provided",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			provider, err := NewBearerProvider(tt.config)

			if tt.wantErr {
				require.Error(t, err, "expected error")
				if tt.errString != "" {
					assert.Equal(t, tt.errString, err.Error(), "expected error string")
				}
				return
			}

			require.NoError(t, err, "unexpected error")

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

	assert.Equal(t, "custom-name", provider.Name(), "Name()")
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
				require.NotNil(t, p, "expected non-nil principal")
				assert.Equal(t, "user123", p.ID, "ID")
				assert.Equal(t, "test@example.com", p.Email, "Email")
				assert.Equal(t, "Test User", p.Name, "Name")
				assert.Equal(t, "user", p.Type, "Type")
				assert.Len(t, p.Roles, 2, "expected 2 roles")
				assert.True(t, p.HasRole("admin"), "expected principal to have admin role")
				assert.True(t, p.HasRole("user"), "expected principal to have user role")
				assert.Len(t, p.Groups, 2, "expected 2 groups")
				assert.True(t, p.HasGroup("engineering"), "expected principal to have engineering group")
				assert.True(t, p.HasGroup("platform"), "expected principal to have platform group")
				assert.NotEmpty(t, p.Token, "expected token to be set")
				assert.NotZero(t, p.ExpiresAt, "expected ExpiresAt to be set")
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
				require.NotNil(t, p, "expected non-nil principal")
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
			name: "missing aud claim when audience configured fails closed",
			config: BearerConfig{
				Secret:   testSecret,
				Audience: "expected-audience",
			},
			setupReq: func() *http.Request {
				claims := jwt.MapClaims{
					"sub": "user123",
					"exp": time.Now().Add(time.Hour).Unix(),
					// no aud claim at all
				}
				token := createTestToken(claims, testSecret, false, false)
				req := httptest.NewRequest("GET", "/test", nil)
				req.Header.Set("Authorization", "Bearer "+token)
				return req
			},
			wantErr:   true,
			errSubstr: "aud claim is required",
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
				assert.Equal(t, "custom-id", p.ID, "expected custom ID")
				assert.Equal(t, "service", p.Type, "Type")
				assert.Equal(t, "value", p.Attributes["custom"], "expected custom attribute to be set")
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
				assert.Equal(t, "user123", p.ID, "ID")
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
			require.NoError(t, err, "failed to create provider")

			req := tt.setupReq()
			ctx := context.Background()

			principal, err := provider.Authenticate(ctx, req)

			if tt.wantNil {
				assert.Nil(t, principal, "expected nil principal")
				assert.NoError(t, err, "expected nil error for non-applicable auth")
				return
			}

			if tt.wantErr {
				require.Error(t, err, "expected error")
				if tt.errSubstr != "" {
					assert.Contains(t, err.Error(), tt.errSubstr, "expected error containing %q", tt.errSubstr)
				}
				return
			}

			require.NoError(t, err, "unexpected error")

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
				assert.Equal(t, "user123", p.ID, "ID")
				assert.Equal(t, "test@example.com", p.Email, "email")
				assert.Equal(t, "Test User", p.Name, "name")
				assert.Equal(t, "user", p.Type, "type")
				assert.Len(t, p.Roles, 2, "expected 2 roles")
				assert.Len(t, p.Groups, 2, "expected 2 groups")
			},
		},
		{
			name: "minimal claims - only sub",
			claims: jwt.MapClaims{
				"sub": "user456",
			},
			wantErr: false,
			validate: func(t *testing.T, p *Principal) {
				assert.Equal(t, "user456", p.ID, "ID")
				assert.Equal(t, "user", p.Type, "type")
				assert.NotNil(t, p.Attributes, "expected attributes map to be initialized")
			},
		},
		{
			// defaultClaimsFunc no longer validates expiration —
			// jwt.Parse (with leeway) is the canonical validator.
			// This case now just confirms the extractor still
			// records the exp value on the principal.
			name: "expired token recorded but not rejected",
			claims: jwt.MapClaims{
				"sub": "user123",
				"exp": float64(time.Now().Add(-time.Hour).Unix()),
			},
			wantErr: false,
			validate: func(t *testing.T, p *Principal) {
				assert.NotZero(t, p.ExpiresAt, "expected ExpiresAt to be recorded")
			},
		},
		{
			name: "roles with non-string values - filtered out",
			claims: jwt.MapClaims{
				"sub":   "user123",
				"roles": []interface{}{"admin", 123, "user", nil},
			},
			wantErr: false,
			validate: func(t *testing.T, p *Principal) {
				assert.Len(t, p.Roles, 2, "expected 2 roles (non-string filtered)")
				assert.True(t, p.HasRole("admin"), "expected admin role")
				assert.True(t, p.HasRole("user"), "expected user role")
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
				assert.Len(t, p.Groups, 2, "expected 2 groups (non-string filtered)")
				assert.True(t, p.HasGroup("group-a"), "expected group-a")
				assert.True(t, p.HasGroup("group-b"), "expected group-b")
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
				assert.Empty(t, p.Roles, "expected 0 roles")
				assert.Empty(t, p.Groups, "expected 0 groups")
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
				require.Error(t, err, "expected error")
				if tt.errSubstr != "" {
					assert.Contains(t, err.Error(), tt.errSubstr, "expected error containing %q", tt.errSubstr)
				}
				return
			}

			require.NoError(t, err, "unexpected error")

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
	require.NoError(t, err, "failed to create provider")

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

			key, err := provider.keyFuncFor(context.Background())(tt.token)

			if tt.wantErr {
				require.Error(t, err, "expected error")
				if tt.errSubstr != "" {
					assert.Contains(t, err.Error(), tt.errSubstr, "expected error containing %q", tt.errSubstr)
				}
				return
			}

			require.NoError(t, err, "unexpected error")

			assert.NotNil(t, key, "expected non-nil key")
		})
	}
}

func TestBearerProvider_JWKSKeyFunc_RejectsMissingKid(t *testing.T) {
	t.Parallel()

	provider, err := NewBearerProvider(BearerConfig{
		JWKSURL: "https://example.com/.well-known/jwks.json",
	})
	require.NoError(t, err, "failed to create provider")

	// Token has no kid header; JWKS lookup requires one to pick the
	// right key, so we expect a friendly error rather than a network
	// call.
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": "test",
	})

	_, err = provider.keyFuncFor(context.Background())(token)
	require.Error(t, err, "expected error for missing kid")
	assert.Contains(t, err.Error(), "kid", "expected 'kid' in error")
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
	require.NoError(t, err, "failed to create provider")

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
	require.NoError(t, err, "authentication failed")

	// Verify complete principal
	require.NotNil(t, principal, "expected non-nil principal")
	assert.Equal(t, "integration-user", principal.ID, "ID")
	assert.Equal(t, "integration@example.com", principal.Email, "email")
	assert.Equal(t, "Integration User", principal.Name, "name")
	assert.True(t, principal.HasRole("developer"), "expected developer role")
	assert.True(t, principal.HasRole("tester"), "expected tester role")
	assert.True(t, principal.HasGroup("qa"), "expected qa group")
	assert.True(t, principal.HasGroup("engineering"), "expected engineering group")
	assert.Equal(t, token, principal.Token, "expected token to match original")
	assert.NotZero(t, principal.ExpiresAt, "expected expiration to be set")
}

func TestBearerProvider_MultipleTokenFormats(t *testing.T) {
	t.Parallel()

	provider, err := NewBearerProvider(BearerConfig{
		Secret: testSecret,
	})
	require.NoError(t, err, "failed to create provider")

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
				assert.Nil(t, principal, "expected nil principal")
			}

			if tt.wantErr {
				assert.Error(t, err, "expected error")
			} else {
				assert.NoError(t, err, "unexpected error")
			}
		})
	}
}

// TestBearer_LeewayHonored verifies that the default 30s leeway lets
// a token that expired a few seconds ago through, while one that
// expired well outside the leeway window is still rejected.
func TestBearer_LeewayHonored(t *testing.T) {
	t.Parallel()

	provider, err := NewBearerProvider(BearerConfig{Secret: testSecret})
	require.NoError(t, err, "NewBearerProvider")

	// Expired 5s ago — inside the 30s default leeway, should pass.
	insideTok := createTestToken(jwt.MapClaims{
		"sub": "user",
		"exp": time.Now().Add(-5 * time.Second).Unix(),
	}, testSecret, false, false)
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+insideTok)
	_, err = provider.Authenticate(context.Background(), req)
	require.NoError(t, err, "expected token within leeway to pass")

	// Expired 60s ago — outside the 30s default leeway, should fail.
	outsideTok := createTestToken(jwt.MapClaims{
		"sub": "user",
		"exp": time.Now().Add(-60 * time.Second).Unix(),
	}, testSecret, false, false)
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.Header.Set("Authorization", "Bearer "+outsideTok)
	_, err = provider.Authenticate(context.Background(), req2)
	require.Error(t, err, "expected token outside leeway to be rejected")
}

// TestBearer_HSAlgorithmWithJWKSConfigRejected verifies that when the
// provider is configured for JWKS (asymmetric), an HS256 token is
// rejected by the algorithm allowlist before any signature check.
func TestBearer_HSAlgorithmWithJWKSConfigRejected(t *testing.T) {
	t.Parallel()

	// Serve a minimal (empty-keys) JWKS document. We don't expect
	// the parser to ever reach signature verification.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer srv.Close()

	provider, err := NewBearerProvider(BearerConfig{
		JWKSURL:               srv.URL,
		AllowInsecureHTTPJWKS: true,
	})
	require.NoError(t, err, "NewBearerProvider")

	// Mint an HS256 token with a known secret.
	hsTok := createTestToken(jwt.MapClaims{
		"sub": "attacker",
		"exp": time.Now().Add(time.Hour).Unix(),
	}, testSecret, false, false)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+hsTok)
	_, err = provider.Authenticate(context.Background(), req)
	require.Error(t, err, "expected HS256 token to be rejected under JWKS config")
}

// TestBearer_SecretAndJWKSMutuallyExclusive ensures NewBearerProvider
// rejects a config that sets both a static Secret and a JWKSURL — the
// algorithm allowlist depends on knowing which key source applies.
func TestBearer_SecretAndJWKSMutuallyExclusive(t *testing.T) {
	t.Parallel()

	_, err := NewBearerProvider(BearerConfig{
		Secret:  testSecret,
		JWKSURL: "https://example.com/jwks.json",
	})
	require.Error(t, err, "expected error when both Secret and JWKSURL are set")
	assert.Contains(t, err.Error(), "mutually exclusive", "expected 'mutually exclusive' in error")
}

// TestBearer_JWKSFetchRespectsRequestContext verifies the per-request
// context-threading contract (HIGH H-auth-5): when the inbound
// request's context is cancelled, an in-flight JWKS fetch must abort
// rather than running to completion against a detached
// context.Background().
func TestBearer_JWKSFetchRespectsRequestContext(t *testing.T) {
	t.Parallel()

	// JWKS endpoint that blocks for 1 second before responding,
	// honouring the inbound request's context (httptest hands the
	// server's request through; we observe r.Context().Done()).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(time.Second):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"keys":[]}`))
		case <-r.Context().Done():
			// Client gave up; just close.
			return
		}
	}))
	defer srv.Close()

	provider, err := NewBearerProvider(BearerConfig{
		JWKSURL:               srv.URL,
		AllowInsecureHTTPJWKS: true,
	})
	require.NoError(t, err, "NewBearerProvider")

	// Mint a syntactically-valid RS256 token (the keyFunc path is
	// what we're exercising, so signature validity is irrelevant).
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": "ctx-test",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	tok.Header["kid"] = "missing-kid"
	// Sign with garbage so the keyFunc is reached at least once. We
	// don't actually need a real signature because the JWKS server
	// hangs before returning any keys — the parser will block in
	// keyFunc waiting for the key, and that block must respect ctx.
	tokenString, err := tok.SigningString()
	require.NoError(t, err, "SigningString")
	tokenString = tokenString + ".bm9wZQ" // dummy signature; we won't get this far

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	req = req.WithContext(ctx)

	start := time.Now()
	_, err = provider.Authenticate(req.Context(), req)
	elapsed := time.Since(start)

	require.Error(t, err, "expected error from cancelled context")
	require.LessOrEqual(t, elapsed, 500*time.Millisecond, "Authenticate did not honour request context: took %v (want < 500ms)", elapsed)
}
