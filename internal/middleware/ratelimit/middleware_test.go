package ratelimit

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/stac-proxy/internal/middleware"
	"github.com/yourorg/stac-proxy/internal/middleware/auth"
)

// errInternalTest simulates an internal limiter error.
var errInternalTest = errors.New("internal test error")

// MockLimiter is a configurable test Limiter.
type MockLimiter struct {
	AllowFunc func(ctx context.Context, key string, quota Quota) (bool, Info, error)
	mu        sync.Mutex
	calls     []MockLimiterCall
}

type MockLimiterCall struct {
	Key   string
	Quota Quota
}

func (m *MockLimiter) Allow(ctx context.Context, key string, quota Quota) (bool, Info, error) {
	m.mu.Lock()
	m.calls = append(m.calls, MockLimiterCall{Key: key, Quota: quota})
	m.mu.Unlock()
	if m.AllowFunc != nil {
		return m.AllowFunc(ctx, key, quota)
	}
	return true, Info{Limit: quota.Requests, Remaining: quota.Requests - 1, ResetAt: time.Now().Unix()}, nil
}

func (m *MockLimiter) Calls() []MockLimiterCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]MockLimiterCall(nil), m.calls...)
}

// wrap returns the middleware with a passthrough inner handler that
// returns 204 so tests can distinguish "inner ran" from "limited".
func wrap(cfg Config) http.Handler {
	return NewHTTPMiddleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
}

// TestHTTPMiddleware_Allows_AddsHeaders: when allowed, X-RateLimit-* headers
// are set and the inner handler runs.
func TestHTTPMiddleware_Allows_AddsHeaders(t *testing.T) {
	limiter := &MockLimiter{AllowFunc: func(_ context.Context, _ string, q Quota) (bool, Info, error) {
		return true, Info{Limit: 100, Remaining: 99, ResetAt: 1700000000}, nil
	}}
	h := wrap(Config{Limiter: limiter, DefaultQuota: Quota{Requests: 100, Window: time.Minute}})

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/x", nil))

	require.Equal(t, http.StatusNoContent, rr.Code, "status: want 204 (inner ran)")
	assert.Equal(t, "100", rr.Header().Get("X-RateLimit-Limit"), "X-RateLimit-Limit")
	assert.Equal(t, "99", rr.Header().Get("X-RateLimit-Remaining"), "X-RateLimit-Remaining")
	assert.Equal(t, "1700000000", rr.Header().Get("X-RateLimit-Reset"), "X-RateLimit-Reset")
}

// TestHTTPMiddleware_Denies_429_NoInner: limiter says no → 429 with
// Retry-After header, inner handler never runs.
func TestHTTPMiddleware_Denies_429_NoInner(t *testing.T) {
	limiter := &MockLimiter{AllowFunc: func(_ context.Context, _ string, _ Quota) (bool, Info, error) {
		return false, Info{Limit: 10, Remaining: 0, ResetAt: 1700000000, RetryAfter: 30}, nil
	}}
	innerCalled := false
	h := NewHTTPMiddleware(Config{Limiter: limiter})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		innerCalled = true
	}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/x", nil))

	require.Equal(t, http.StatusTooManyRequests, rr.Code, "status: want 429")
	assert.Equal(t, "30", rr.Header().Get("Retry-After"), "Retry-After")
	require.False(t, innerCalled, "inner handler ran despite 429")
}

// TestHTTPMiddleware_LimiterError_FailOpen: a limiter error allows the
// request through with no rate-limit headers (fail-open).
func TestHTTPMiddleware_LimiterError_FailOpen(t *testing.T) {
	limiter := &MockLimiter{AllowFunc: func(_ context.Context, _ string, _ Quota) (bool, Info, error) {
		return false, Info{}, errInternalTest
	}}
	h := wrap(Config{Limiter: limiter})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/x", nil))
	require.Equal(t, http.StatusNoContent, rr.Code, "status: want 204 (fail-open)")
	assert.Empty(t, rr.Header().Get("X-RateLimit-Limit"), "X-RateLimit-Limit set on fail-open path")
}

// TestHTTPMiddleware_KeysOnPrincipalThenIP: when an auth Principal is in
// context, KeyFunc receives its ID; otherwise it receives the empty
// principalID and the request's RemoteAddr.
func TestHTTPMiddleware_KeysOnPrincipalThenIP(t *testing.T) {
	limiter := &MockLimiter{}
	h := wrap(Config{Limiter: limiter, KeyFunc: DefaultKeyFunc})

	// Anonymous request — keyFunc should see empty principalID + RemoteAddr.
	req := httptest.NewRequest("GET", "/x", nil)
	req.RemoteAddr = "203.0.113.7:443"
	h.ServeHTTP(httptest.NewRecorder(), req)

	// Authenticated request.
	req2 := httptest.NewRequest("GET", "/x", nil)
	req2 = req2.WithContext(context.WithValue(req2.Context(), middleware.PrincipalKey, &auth.Principal{ID: "alice"}))
	h.ServeHTTP(httptest.NewRecorder(), req2)

	calls := limiter.Calls()
	require.Len(t, calls, 2, "limiter calls")
	// DefaultKeyFunc prefixes with "user:" / "ip:" — we just want to
	// confirm the anon path used the IP and the authed path used the
	// principal ID.
	assert.Contains(t, calls[0].Key, "203.0.113.7", "first call (anon) should include client IP")
	assert.Contains(t, calls[1].Key, "alice", "second call (authed) should include principal ID")
}

// TestHTTPMiddleware_QuotaFunc_RoleBased: a QuotaFunc receives the
// principal's roles and selects accordingly.
func TestHTTPMiddleware_QuotaFunc_RoleBased(t *testing.T) {
	limiter := &MockLimiter{}
	roleQuotas := map[string]Quota{
		"admin": {Requests: 10000, Window: time.Hour},
		"user":  {Requests: 100, Window: time.Hour},
	}
	h := wrap(Config{
		Limiter:      limiter,
		QuotaFunc:    RoleBasedQuotaFunc(roleQuotas, Quota{Requests: 10, Window: time.Hour}),
		DefaultQuota: Quota{Requests: 10, Window: time.Hour},
	})

	req := httptest.NewRequest("GET", "/x", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.PrincipalKey,
		&auth.Principal{ID: "alice", Roles: []string{"admin"}}))
	h.ServeHTTP(httptest.NewRecorder(), req)

	calls := limiter.Calls()
	assert.Equal(t, 10000, calls[0].Quota.Requests, "admin quota requests")
}

// TestHTTPMiddleware_DefaultsWired: nil Limiter/KeyFunc/QuotaFunc fall
// back to in-package defaults and don't panic.
func TestHTTPMiddleware_DefaultsWired(t *testing.T) {
	h := NewHTTPMiddleware(Config{
		DefaultQuota: Quota{Requests: 100, Window: time.Minute},
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/x", nil))
	_, err := strconv.Atoi(rr.Header().Get("X-RateLimit-Limit"))
	assert.NoError(t, err, "X-RateLimit-Limit not set with default limiter: %q", rr.Header().Get("X-RateLimit-Limit"))
}

// ---------------------------------------------------------------------
// Below: tests for helpers / limiter algorithm correctness. Orthogonal
// to the middleware shape.
// ---------------------------------------------------------------------

// TestKeyFunc_StripsRemoteAddrPort verifies that when the derived
// client IP is not in context, the fallback strips the ephemeral
// source port from r.RemoteAddr so requests from the same host
// share one bucket regardless of TCP connection identity.
func TestKeyFunc_StripsRemoteAddrPort(t *testing.T) {
	t.Parallel()

	mock := &MockLimiter{}
	mw := NewHTTPMiddleware(Config{
		Limiter:      mock,
		DefaultQuota: Quota{Requests: 100, Window: time.Minute},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	for _, addr := range []string{"203.0.113.5:11111", "203.0.113.5:22222"} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = addr
		mw.ServeHTTP(httptest.NewRecorder(), req)
	}

	mock.mu.Lock()
	defer mock.mu.Unlock()
	require.Len(t, mock.calls, 2, "limiter calls")
	assert.Equal(t, mock.calls[0].Key, mock.calls[1].Key, "ports leaked into key")
}
