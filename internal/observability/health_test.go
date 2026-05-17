package observability

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// HealthChecker is now a thin adapter over alexliesenfeld/health. These
// tests cover only what this package owns: lazy build, the
// WithDisabledDetails default (no leakage of upstream URLs or error
// strings), and the liveness shortcut. Caching, status aggregation, and
// timeout semantics are tested by the library.

func TestHealth_DoesNotLeakErrorDetailsByDefault(t *testing.T) {
	t.Parallel()
	h := NewHealthChecker()
	defer h.Stop()
	const secret = "secret-upstream.internal:8080/probe"
	h.AddCheckFunc("upstream", func(ctx context.Context) error {
		return errors.New(secret)
	})

	rr := httptest.NewRecorder()
	h.HealthHandler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/health", nil))

	require.NotEqual(t, http.StatusOK, rr.Code, "unhealthy check should not return 200")
	require.NotContains(t, rr.Body.String(), secret, "error string leaked into body")
}

func TestHealth_HealthyReturns200(t *testing.T) {
	t.Parallel()
	h := NewHealthChecker()
	defer h.Stop()
	h.AddCheckFunc("upstream", func(ctx context.Context) error { return nil })

	rr := httptest.NewRecorder()
	h.HealthHandler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/health", nil))
	require.Equal(t, http.StatusOK, rr.Code, "body=%s", rr.Body.String())
}

func TestHealth_LivenessAlwaysOK(t *testing.T) {
	t.Parallel()
	h := NewHealthChecker()
	defer h.Stop()
	// Liveness must succeed regardless of registered (failing) checks.
	h.AddCheckFunc("noisy", func(ctx context.Context) error {
		return errors.New("broken")
	})

	rr := httptest.NewRecorder()
	h.LivenessHandler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/health/live", nil))
	require.Equal(t, http.StatusOK, rr.Code, "liveness status")
	require.Contains(t, rr.Body.String(), "alive", "liveness body missing 'alive'")
}

func TestHealth_LazyBuild_AddCheckBeforeHandler(t *testing.T) {
	t.Parallel()
	h := NewHealthChecker()
	defer h.Stop()
	h.AddCheckFunc("late", func(ctx context.Context) error { return nil })
	rr := httptest.NewRecorder()
	h.HealthHandler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/health", nil))
	require.Equal(t, http.StatusOK, rr.Code)
}

func TestNewOriginCheck_5xxIsDown(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	c := NewOriginCheck("origin", srv.URL, nil)
	require.Error(t, c.Check(context.Background()), "5xx upstream should fail check")
}

func TestNewOriginCheck_2xxIsUp(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	c := NewOriginCheck("origin", srv.URL, nil)
	require.NoError(t, c.Check(context.Background()), "2xx upstream should pass")
}
