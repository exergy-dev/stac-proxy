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
	if rr.Code != http.StatusOK {
		t.Fatalf("status: want 200, got %d", rr.Code)
	}
	if rr.Header().Get("X-Test-Principal-ID") != "alice" {
		t.Errorf("principal ID: want alice, got %q", rr.Header().Get("X-Test-Principal-ID"))
	}
}

// TestHTTPMiddleware_AnonymousAllowed: no provider authenticates AND
// AllowAnonymous is true → inner handler runs with anonymous principal.
func TestHTTPMiddleware_AnonymousAllowed(t *testing.T) {
	h := wrap(t, Config{AllowAnonymous: true})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/x", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status: want 200, got %d", rr.Code)
	}
	if got := rr.Header().Get("X-Test-Principal-Type"); got != "anonymous" {
		t.Errorf("principal type: want anonymous, got %q", got)
	}
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
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status: want 401, got %d", rr.Code)
	}
	if called {
		t.Error("inner handler ran despite missing credentials")
	}
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
	if rr.Header().Get("X-Test-Principal-ID") != "bob" {
		t.Errorf("principal ID: want bob, got %q", rr.Header().Get("X-Test-Principal-ID"))
	}
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
	if rr.Header().Get("X-Test-Principal-ID") != "carol" {
		t.Errorf("principal ID: want carol, got %q", rr.Header().Get("X-Test-Principal-ID"))
	}
}

// TestPrincipalFromContext: nil ctx value yields nil principal.
func TestPrincipalFromContext_Missing(t *testing.T) {
	if p := PrincipalFromContext(context.Background()); p != nil {
		t.Fatalf("want nil principal, got %+v", p)
	}
}

func TestPrincipalFromContext_Present(t *testing.T) {
	ctx := context.WithValue(context.Background(), middleware.PrincipalKey, &Principal{ID: "x", Type: "user"})
	p := PrincipalFromContext(ctx)
	if p == nil || p.ID != "x" {
		t.Fatalf("want principal x, got %+v", p)
	}
}
