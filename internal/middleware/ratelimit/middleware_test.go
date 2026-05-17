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

	if rr.Code != http.StatusNoContent {
		t.Fatalf("status: want 204 (inner ran), got %d", rr.Code)
	}
	if got := rr.Header().Get("X-RateLimit-Limit"); got != "100" {
		t.Errorf("X-RateLimit-Limit: want 100, got %q", got)
	}
	if got := rr.Header().Get("X-RateLimit-Remaining"); got != "99" {
		t.Errorf("X-RateLimit-Remaining: want 99, got %q", got)
	}
	if got := rr.Header().Get("X-RateLimit-Reset"); got != "1700000000" {
		t.Errorf("X-RateLimit-Reset: want 1700000000, got %q", got)
	}
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

	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("status: want 429, got %d", rr.Code)
	}
	if got := rr.Header().Get("Retry-After"); got != "30" {
		t.Errorf("Retry-After: want 30, got %q", got)
	}
	if innerCalled {
		t.Fatal("inner handler ran despite 429")
	}
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
	if rr.Code != http.StatusNoContent {
		t.Fatalf("status: want 204 (fail-open), got %d", rr.Code)
	}
	if rr.Header().Get("X-RateLimit-Limit") != "" {
		t.Errorf("X-RateLimit-Limit set on fail-open path")
	}
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
	if len(calls) != 2 {
		t.Fatalf("limiter calls: want 2, got %d", len(calls))
	}
	// DefaultKeyFunc prefixes with "user:" / "ip:" — we just want to
	// confirm the anon path used the IP and the authed path used the
	// principal ID.
	if !contains(calls[0].Key, "203.0.113.7") {
		t.Errorf("first call (anon) should include client IP: %q", calls[0].Key)
	}
	if !contains(calls[1].Key, "alice") {
		t.Errorf("second call (authed) should include principal ID: %q", calls[1].Key)
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
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
	if calls[0].Quota.Requests != 10000 {
		t.Errorf("admin quota: want 10000 requests, got %d", calls[0].Quota.Requests)
	}
}

// TestHTTPMiddleware_DefaultsWired: nil Limiter/KeyFunc/QuotaFunc fall
// back to in-package defaults and don't panic.
func TestHTTPMiddleware_DefaultsWired(t *testing.T) {
	h := NewHTTPMiddleware(Config{
		DefaultQuota: Quota{Requests: 100, Window: time.Minute},
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/x", nil))
	if _, err := strconv.Atoi(rr.Header().Get("X-RateLimit-Limit")); err != nil {
		t.Errorf("X-RateLimit-Limit not set with default limiter: %q", rr.Header().Get("X-RateLimit-Limit"))
	}
}

// ---------------------------------------------------------------------
// Below: tests for helpers / limiter algorithm correctness. Orthogonal
// to the middleware shape.
// ---------------------------------------------------------------------

func TestRoleBasedQuotaFunc(t *testing.T) {
	t.Parallel()
	defaultQ := Quota{Requests: 100, Window: time.Hour}
	roleQuotas := map[string]Quota{
		"admin": {Requests: 10000, Window: time.Hour},
		"user":  {Requests: 1000, Window: time.Hour},
	}
	qf := RoleBasedQuotaFunc(roleQuotas, defaultQ)

	if got := qf([]string{"admin"}, defaultQ); got.Requests != 10000 {
		t.Errorf("admin: want 10000 requests, got %d", got.Requests)
	}
	if got := qf([]string{"user"}, defaultQ); got.Requests != 1000 {
		t.Errorf("user: want 1000, got %d", got.Requests)
	}
	if got := qf([]string{"unknown"}, defaultQ); got.Requests != 100 {
		t.Errorf("unknown role: want default 100, got %d", got.Requests)
	}
	if got := qf(nil, defaultQ); got.Requests != 100 {
		t.Errorf("nil roles: want default 100, got %d", got.Requests)
	}
}

func TestDefaultQuotaFunc(t *testing.T) {
	t.Parallel()
	q := Quota{Requests: 42, Window: time.Minute}
	if got := DefaultQuotaFunc(nil, q); got.Requests != 42 {
		t.Errorf("DefaultQuotaFunc should return the default: %+v", got)
	}
}

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
	if len(mock.calls) != 2 {
		t.Fatalf("limiter calls = %d, want 2", len(mock.calls))
	}
	if mock.calls[0].Key != mock.calls[1].Key {
		t.Errorf("ports leaked into key: %q vs %q", mock.calls[0].Key, mock.calls[1].Key)
	}
}
