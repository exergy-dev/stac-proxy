package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/exergy-dev/stac-proxy/internal/middleware"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockProvider is a test implementation of Provider.
type mockProvider struct {
	name     string
	authFunc func(ctx context.Context, req *http.Request) (*Principal, error)
}

func (m *mockProvider) Name() string { return m.name }
func (m *mockProvider) Authenticate(ctx context.Context, req *http.Request) (*Principal, error) {
	if m.authFunc != nil {
		return m.authFunc(ctx, req)
	}
	return nil, nil
}

// echoHandler is the inner http.Handler used in tests; it copies the
// principal from context (if any) into a response header so tests can
// observe what the middleware set.
func echoHandler(w http.ResponseWriter, r *http.Request) {
	if p := PrincipalFromContext(r.Context()); p != nil {
		w.Header().Set("X-Test-Principal-ID", p.ID)
		w.Header().Set("X-Test-Principal-Type", p.Type)
	}
	w.WriteHeader(http.StatusOK)
}

func wrap(t *testing.T, cfg Config) http.Handler {
	t.Helper()
	return NewHTTPMiddleware(cfg)(http.HandlerFunc(echoHandler))
}

// TestHTTPMiddleware_ValidCredentials: a provider returns a principal
// → the inner handler sees it in context.
func TestHTTPMiddleware_ValidCredentials(t *testing.T) {
	h := wrap(t, Config{
		Providers: []Provider{&mockProvider{
			name: "test",
			authFunc: func(_ context.Context, _ *http.Request) (*Principal, error) {
				return &Principal{ID: "alice", Type: "user"}, nil
			},
		}},
	})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/x", nil))
	require.Equal(t, http.StatusOK, rr.Code, "status")
	assert.Equal(t, "alice", rr.Header().Get("X-Test-Principal-ID"), "principal ID")
}

// TestHTTPMiddleware_AnonymousAllowed: no provider authenticates AND
// AllowAnonymous is true → inner handler runs with anonymous principal.
func TestHTTPMiddleware_AnonymousAllowed(t *testing.T) {
	h := wrap(t, Config{AllowAnonymous: true})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/x", nil))
	require.Equal(t, http.StatusOK, rr.Code, "status")
	assert.Equal(t, "anonymous", rr.Header().Get("X-Test-Principal-Type"), "principal type")
}

// TestHTTPMiddleware_RejectsWhenAnonymousDisallowed: no provider matches,
// AllowAnonymous is false → 401, inner handler never runs.
func TestHTTPMiddleware_RejectsWhenAnonymousDisallowed(t *testing.T) {
	called := false
	h := NewHTTPMiddleware(Config{})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/x", nil))
	require.Equal(t, http.StatusUnauthorized, rr.Code, "status")
	assert.False(t, called, "inner handler ran despite missing credentials")
}

// TestHTTPMiddleware_ProviderChain: first provider returns nil-nil,
// second returns a principal → second's principal reaches the handler.
func TestHTTPMiddleware_ProviderChain(t *testing.T) {
	h := wrap(t, Config{
		Providers: []Provider{
			&mockProvider{name: "skip"},
			&mockProvider{
				name: "winner",
				authFunc: func(_ context.Context, _ *http.Request) (*Principal, error) {
					return &Principal{ID: "bob", Type: "user"}, nil
				},
			},
		},
	})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/x", nil))
	assert.Equal(t, "bob", rr.Header().Get("X-Test-Principal-ID"), "principal ID")
}

// TestHTTPMiddleware_ErroringProviderContinuesToNext: a provider
// returns (nil, err) → middleware moves to the next provider rather
// than denying the request.
func TestHTTPMiddleware_ErroringProviderContinuesToNext(t *testing.T) {
	h := wrap(t, Config{
		Providers: []Provider{
			&mockProvider{
				name: "erroring",
				authFunc: func(_ context.Context, _ *http.Request) (*Principal, error) {
					return nil, errors.New("transient")
				},
			},
			&mockProvider{
				name: "good",
				authFunc: func(_ context.Context, _ *http.Request) (*Principal, error) {
					return &Principal{ID: "carol", Type: "user"}, nil
				},
			},
		},
	})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/x", nil))
	assert.Equal(t, "carol", rr.Header().Get("X-Test-Principal-ID"), "principal ID")
}

// TestPrincipalFromContext: nil ctx value yields nil principal.
func TestPrincipalFromContext_Missing(t *testing.T) {
	p := PrincipalFromContext(context.Background())
	require.Nil(t, p, "want nil principal")
}

// claimingMockProvider is a mock that implements CredentialClaimer.
type claimingMockProvider struct {
	mockProvider
	claims bool
}

func (m *claimingMockProvider) ClaimsCredential(_ *http.Request) bool { return m.claims }

// TestProviderChain_BadSignatureBearerDoesNotFallThroughToAnonymous
// verifies the fail-closed contract for the auth chain (HIGH H-auth-1):
// when a Bearer token with a bad signature is presented and the bearer
// provider errors, the chain MUST return 401 even when AllowAnonymous
// is true. Otherwise an attacker could downgrade themselves to
// anonymous by presenting any garbage Bearer token.
func TestProviderChain_BadSignatureBearerDoesNotFallThroughToAnonymous(t *testing.T) {
	bearer, err := NewBearerProvider(BearerConfig{Secret: testSecret})
	require.NoError(t, err, "NewBearerProvider")

	// Mint a token signed with the WRONG secret so signature verification fails.
	bad := createTestToken(jwt.MapClaims{
		"sub": "attacker",
		"exp": time.Now().Add(time.Hour).Unix(),
	}, testSecret, false, true /*invalidSig*/)

	called := false
	h := NewHTTPMiddleware(Config{
		AllowAnonymous: true, // critical: anonymous WOULD be allowed if we fall through
		Providers:      []Provider{bearer},
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Set("Authorization", "Bearer "+bad)
	h.ServeHTTP(rr, req)

	require.Equal(t, http.StatusUnauthorized, rr.Code, "status: want 401 (fail-closed)")
	require.False(t, called, "inner handler ran despite bad-signature bearer token")
}

// TestProviderChain_ClaimingProviderErrorIsHardFailure verifies the
// generic CredentialClaimer fail-closed contract using a mock.
func TestProviderChain_ClaimingProviderErrorIsHardFailure(t *testing.T) {
	called := false
	h := NewHTTPMiddleware(Config{
		AllowAnonymous: true,
		Providers: []Provider{
			&claimingMockProvider{
				mockProvider: mockProvider{
					name: "claiming-erroring",
					authFunc: func(_ context.Context, _ *http.Request) (*Principal, error) {
						return nil, errors.New("invalid signature")
					},
				},
				claims: true,
			},
			// Even with a downstream provider that WOULD authenticate,
			// the chain must terminate at the claiming-provider error.
			&mockProvider{
				name: "would-grant",
				authFunc: func(_ context.Context, _ *http.Request) (*Principal, error) {
					return &Principal{ID: "should-not-reach", Type: "user"}, nil
				},
			},
		},
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/x", nil))

	require.Equal(t, http.StatusUnauthorized, rr.Code, "status")
	require.False(t, called, "inner handler ran despite claiming-provider error")
}

func TestPrincipalFromContext_Present(t *testing.T) {
	ctx := context.WithValue(context.Background(), middleware.PrincipalKey, &Principal{ID: "x", Type: "user"})
	p := PrincipalFromContext(ctx)
	require.NotNil(t, p, "want principal x")
	require.Equal(t, "x", p.ID, "want principal x")
}
