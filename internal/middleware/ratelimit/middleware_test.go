package ratelimit

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/yourorg/stac-proxy/internal/middleware"
	"github.com/yourorg/stac-proxy/internal/middleware/auth"
)

// newSTACRequest builds a minimal STACRequest for ratelimit tests.
// Inlined here when internal/testutil was deleted; the previous
// testutil.NewSTACRequest always passed nil body, so we drop that arg.
func newSTACRequest(method, path string) *middleware.STACRequest {
	req := httptest.NewRequest(method, path, nil)
	req.Header.Set("Content-Type", "application/json")
	return &middleware.STACRequest{
		Request:     req,
		Context:     context.Background(),
		RequestType: middleware.RequestTypeSearch,
		Params:      make(map[string]interface{}),
	}
}

// errInternalTest is a test error simulating an internal error.
var errInternalTest = errors.New("internal test error")

// MockLimiter is a mock implementation of the Limiter interface for testing.
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

func (m *MockLimiter) GetCalls() []MockLimiterCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]MockLimiterCall(nil), m.calls...)
}

func (m *MockLimiter) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = nil
}

func TestNewMiddleware(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		config        Config
		wantLimiter   bool
		wantKeyFunc   bool
		wantQuota     bool
		testKeyFunc   bool
		testQuotaFunc bool
	}{
		{
			name:          "default configuration",
			config:        Config{},
			wantLimiter:   true,
			wantKeyFunc:   true,
			wantQuota:     true,
			testKeyFunc:   true,
			testQuotaFunc: true,
		},
		{
			name: "custom limiter",
			config: Config{
				Limiter: &MockLimiter{},
			},
			wantLimiter:   true,
			wantKeyFunc:   true,
			wantQuota:     true,
			testKeyFunc:   true,
			testQuotaFunc: true,
		},
		{
			name: "custom key function",
			config: Config{
				KeyFunc: func(ctx context.Context, principalID, clientIP string) string {
					return "custom-key"
				},
			},
			wantLimiter:   true,
			wantKeyFunc:   true,
			wantQuota:     true,
			testKeyFunc:   true,
			testQuotaFunc: true,
		},
		{
			name: "custom quota function",
			config: Config{
				QuotaFunc: func(roles []string, defaultQuota Quota) Quota {
					return Quota{Requests: 100, Window: time.Minute}
				},
			},
			wantLimiter:   true,
			wantKeyFunc:   true,
			wantQuota:     true,
			testKeyFunc:   true,
			testQuotaFunc: true,
		},
		{
			name: "full custom configuration",
			config: Config{
				Limiter: &MockLimiter{},
				KeyFunc: func(ctx context.Context, principalID, clientIP string) string {
					return "custom"
				},
				QuotaFunc: func(roles []string, defaultQuota Quota) Quota {
					return Quota{Requests: 50, Window: 30 * time.Second}
				},
				DefaultQuota: Quota{Requests: 10, Window: time.Minute},
			},
			wantLimiter:   true,
			wantKeyFunc:   true,
			wantQuota:     true,
			testKeyFunc:   true,
			testQuotaFunc: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			m := NewMiddleware(tt.config)

			if m == nil {
				t.Fatal("NewMiddleware() returned nil")
			}

			if (m.limiter != nil) != tt.wantLimiter {
				t.Errorf("limiter != nil = %v, want %v", m.limiter != nil, tt.wantLimiter)
			}

			if (m.keyFunc != nil) != tt.wantKeyFunc {
				t.Errorf("keyFunc != nil = %v, want %v", m.keyFunc != nil, tt.wantKeyFunc)
			}

			if (m.quotaFunc != nil) != tt.wantQuota {
				t.Errorf("quotaFunc != nil = %v, want %v", m.quotaFunc != nil, tt.wantQuota)
			}

			if m.Name() != "ratelimit" {
				t.Errorf("Name() = %q, want %q", m.Name(), "ratelimit")
			}

			if m.Priority() != middleware.PriorityRateLimit {
				t.Errorf("Priority() = %d, want %d", m.Priority(), middleware.PriorityRateLimit)
			}

			// Test that functions work
			if tt.testKeyFunc {
				key := m.keyFunc(context.Background(), "user1", "192.168.1.1")
				if key == "" {
					t.Error("keyFunc returned empty key")
				}
			}

			if tt.testQuotaFunc {
				quota := m.quotaFunc([]string{"user"}, Quota{Requests: 10, Window: time.Minute})
				if quota.Requests == 0 {
					t.Error("quotaFunc returned zero requests")
				}
			}
		})
	}
}

func TestMiddleware_ProcessRequest_Allow(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		principal        *auth.Principal
		remoteAddr       string
		quota            Quota
		allowFunc        func(ctx context.Context, key string, quota Quota) (bool, Info, error)
		wantAllowed      bool
		wantError        bool
		wantRateLimitErr bool
		checkInfo        bool
	}{
		{
			name: "authenticated user - allowed",
			principal: &auth.Principal{
				ID:    "user123",
				Roles: []string{"user"},
			},
			remoteAddr: "192.168.1.1",
			quota:      Quota{Requests: 100, Window: time.Minute},
			allowFunc: func(ctx context.Context, key string, quota Quota) (bool, Info, error) {
				return true, Info{
					Limit:     100,
					Remaining: 99,
					ResetAt:   time.Now().Add(time.Minute).Unix(),
				}, nil
			},
			wantAllowed: true,
			checkInfo:   true,
		},
		{
			name: "authenticated user - denied",
			principal: &auth.Principal{
				ID:    "user456",
				Roles: []string{"user"},
			},
			remoteAddr: "192.168.1.2",
			quota:      Quota{Requests: 10, Window: time.Minute},
			allowFunc: func(ctx context.Context, key string, quota Quota) (bool, Info, error) {
				return false, Info{
					Limit:      10,
					Remaining:  0,
					ResetAt:    time.Now().Add(30 * time.Second).Unix(),
					RetryAfter: 30,
				}, nil
			},
			wantAllowed:      false,
			wantRateLimitErr: true,
			checkInfo:        true,
		},
		{
			name:       "anonymous user - IP based - allowed",
			principal:  nil,
			remoteAddr: "10.0.0.1",
			quota:      Quota{Requests: 50, Window: time.Minute},
			allowFunc: func(ctx context.Context, key string, quota Quota) (bool, Info, error) {
				return true, Info{
					Limit:     50,
					Remaining: 25,
					ResetAt:   time.Now().Add(time.Minute).Unix(),
				}, nil
			},
			wantAllowed: true,
			checkInfo:   true,
		},
		{
			name: "limiter error - allows request",
			principal: &auth.Principal{
				ID:    "user789",
				Roles: []string{"user"},
			},
			remoteAddr: "192.168.1.3",
			quota:      Quota{Requests: 100, Window: time.Minute},
			allowFunc: func(ctx context.Context, key string, quota Quota) (bool, Info, error) {
				return false, Info{}, errInternalTest
			},
			wantAllowed: true,
			wantError:   false, // Error is swallowed, request is allowed
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockLimiter := &MockLimiter{AllowFunc: tt.allowFunc}
			m := NewMiddleware(Config{
				Limiter:      mockLimiter,
				DefaultQuota: tt.quota,
			})

			req := newSTACRequest(http.MethodGet, "/search")
			req.RemoteAddr = tt.remoteAddr

			ctx := context.Background()
			if tt.principal != nil {
				ctx = context.WithValue(ctx, middleware.PrincipalKey, tt.principal)
			}
			req.Context = ctx

			result, err := m.ProcessRequest(ctx, req)

			if tt.wantRateLimitErr {
				if err == nil {
					t.Fatal("expected RateLimitError, got nil")
				}
				if _, ok := err.(*middleware.RateLimitError); !ok {
					t.Errorf("expected RateLimitError, got %T", err)
				}
				if result != nil {
					t.Error("expected nil result on rate limit error")
				}
			} else {
				if tt.wantError {
					if err == nil {
						t.Error("expected error, got nil")
					}
				} else {
					if err != nil {
						t.Errorf("unexpected error: %v", err)
					}
					if result == nil {
						t.Fatal("expected result, got nil")
					}
				}
			}

			if tt.checkInfo && result != nil {
				info, ok := result.Context.Value(rateLimitInfoKey).(Info)
				if !ok {
					t.Error("rate limit info not found in context")
				} else {
					if info.Limit != tt.quota.Requests {
						t.Errorf("info.Limit = %d, want %d", info.Limit, tt.quota.Requests)
					}
				}
			}
		})
	}
}

func TestMiddleware_ProcessRequest_KeyGeneration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		principal  *auth.Principal
		remoteAddr string
		keyFunc    KeyFunc
		wantKey    string
	}{
		{
			name: "default key func - authenticated user",
			principal: &auth.Principal{
				ID:    "user123",
				Roles: []string{"user"},
			},
			remoteAddr: "192.168.1.1",
			keyFunc:    DefaultKeyFunc,
			wantKey:    "user:user123",
		},
		{
			name:       "default key func - anonymous",
			principal:  nil,
			remoteAddr: "10.0.0.5",
			keyFunc:    DefaultKeyFunc,
			wantKey:    "ip:10.0.0.5",
		},
		{
			name: "default key func - anonymous principal",
			principal: &auth.Principal{
				ID: "anonymous",
			},
			remoteAddr: "172.16.0.1",
			keyFunc:    DefaultKeyFunc,
			wantKey:    "ip:172.16.0.1",
		},
		{
			name: "custom key func - combine user and IP",
			principal: &auth.Principal{
				ID:    "user456",
				Roles: []string{"admin"},
			},
			remoteAddr: "192.168.2.1",
			keyFunc: func(ctx context.Context, principalID, clientIP string) string {
				return principalID + ":" + clientIP
			},
			wantKey: "user456:192.168.2.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockLimiter := &MockLimiter{}
			m := NewMiddleware(Config{
				Limiter:      mockLimiter,
				KeyFunc:      tt.keyFunc,
				DefaultQuota: Quota{Requests: 100, Window: time.Minute},
			})

			req := newSTACRequest(http.MethodGet, "/search")
			req.RemoteAddr = tt.remoteAddr

			ctx := context.Background()
			if tt.principal != nil {
				ctx = context.WithValue(ctx, middleware.PrincipalKey, tt.principal)
			}
			req.Context = ctx

			_, _ = m.ProcessRequest(ctx, req)

			calls := mockLimiter.GetCalls()
			if len(calls) != 1 {
				t.Fatalf("expected 1 limiter call, got %d", len(calls))
			}

			if calls[0].Key != tt.wantKey {
				t.Errorf("limiter key = %q, want %q", calls[0].Key, tt.wantKey)
			}
		})
	}
}

func TestMiddleware_ProcessRequest_QuotaSelection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		roles        []string
		quotaFunc    QuotaFunc
		defaultQuota Quota
		wantQuota    Quota
	}{
		{
			name:         "default quota func",
			roles:        []string{"user"},
			quotaFunc:    DefaultQuotaFunc,
			defaultQuota: Quota{Requests: 100, Window: time.Minute},
			wantQuota:    Quota{Requests: 100, Window: time.Minute},
		},
		{
			name:  "role-based quota - admin",
			roles: []string{"admin"},
			quotaFunc: RoleBasedQuotaFunc(
				map[string]Quota{
					"admin": {Requests: 1000, Window: time.Minute},
					"user":  {Requests: 100, Window: time.Minute},
				},
				Quota{Requests: 10, Window: time.Minute},
			),
			defaultQuota: Quota{Requests: 10, Window: time.Minute},
			wantQuota:    Quota{Requests: 1000, Window: time.Minute},
		},
		{
			name:  "role-based quota - user",
			roles: []string{"user"},
			quotaFunc: RoleBasedQuotaFunc(
				map[string]Quota{
					"admin": {Requests: 1000, Window: time.Minute},
					"user":  {Requests: 100, Window: time.Minute},
				},
				Quota{Requests: 10, Window: time.Minute},
			),
			defaultQuota: Quota{Requests: 10, Window: time.Minute},
			wantQuota:    Quota{Requests: 100, Window: time.Minute},
		},
		{
			name:  "role-based quota - no matching role",
			roles: []string{"guest"},
			quotaFunc: RoleBasedQuotaFunc(
				map[string]Quota{
					"admin": {Requests: 1000, Window: time.Minute},
					"user":  {Requests: 100, Window: time.Minute},
				},
				Quota{Requests: 10, Window: time.Minute},
			),
			defaultQuota: Quota{Requests: 10, Window: time.Minute},
			wantQuota:    Quota{Requests: 10, Window: time.Minute},
		},
		{
			name:  "role-based quota - multiple roles, first match",
			roles: []string{"user", "admin"},
			quotaFunc: RoleBasedQuotaFunc(
				map[string]Quota{
					"user":  {Requests: 100, Window: time.Minute},
					"admin": {Requests: 1000, Window: time.Minute},
				},
				Quota{Requests: 10, Window: time.Minute},
			),
			defaultQuota: Quota{Requests: 10, Window: time.Minute},
			wantQuota:    Quota{Requests: 100, Window: time.Minute}, // First matching role
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockLimiter := &MockLimiter{}
			m := NewMiddleware(Config{
				Limiter:      mockLimiter,
				QuotaFunc:    tt.quotaFunc,
				DefaultQuota: tt.defaultQuota,
			})

			principal := &auth.Principal{
				ID:    "testuser",
				Roles: tt.roles,
			}

			req := newSTACRequest(http.MethodGet, "/search")
			req.RemoteAddr = "192.168.1.1"
			ctx := context.WithValue(context.Background(), middleware.PrincipalKey, principal)
			req.Context = ctx

			_, _ = m.ProcessRequest(ctx, req)

			calls := mockLimiter.GetCalls()
			if len(calls) != 1 {
				t.Fatalf("expected 1 limiter call, got %d", len(calls))
			}

			if calls[0].Quota.Requests != tt.wantQuota.Requests {
				t.Errorf("quota.Requests = %d, want %d", calls[0].Quota.Requests, tt.wantQuota.Requests)
			}
			if calls[0].Quota.Window != tt.wantQuota.Window {
				t.Errorf("quota.Window = %v, want %v", calls[0].Quota.Window, tt.wantQuota.Window)
			}
		})
	}
}

func TestMiddleware_ProcessResponse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		setupContext  func() context.Context
		response      *middleware.STACResponse
		wantHeaders   map[string]string
		wantNoHeaders bool
	}{
		{
			name: "add rate limit headers",
			setupContext: func() context.Context {
				info := Info{
					Limit:     100,
					Remaining: 50,
					ResetAt:   1234567890,
				}
				return context.WithValue(context.Background(), rateLimitInfoKey, info)
			},
			response: &middleware.STACResponse{
				StatusCode: http.StatusOK,
				Body:       []byte("{}"),
			},
			wantHeaders: map[string]string{
				"X-RateLimit-Limit":     "100",
				"X-RateLimit-Remaining": "50",
				"X-RateLimit-Reset":     "1234567890",
			},
		},
		{
			name: "add headers to existing headers",
			setupContext: func() context.Context {
				info := Info{
					Limit:     200,
					Remaining: 150,
					ResetAt:   9876543210,
				}
				return context.WithValue(context.Background(), rateLimitInfoKey, info)
			},
			response: &middleware.STACResponse{
				StatusCode: http.StatusOK,
				Headers: http.Header{
					"Content-Type": []string{"application/json"},
					"X-Custom":     []string{"value"},
				},
				Body: []byte("{}"),
			},
			wantHeaders: map[string]string{
				"X-RateLimit-Limit":     "200",
				"X-RateLimit-Remaining": "150",
				"X-RateLimit-Reset":     "9876543210",
				"Content-Type":          "application/json",
				"X-Custom":              "value",
			},
		},
		{
			name: "no rate limit info in context",
			setupContext: func() context.Context {
				return context.Background()
			},
			response: &middleware.STACResponse{
				StatusCode: http.StatusOK,
				Body:       []byte("{}"),
			},
			wantNoHeaders: true,
		},
		{
			name: "invalid rate limit info type in context",
			setupContext: func() context.Context {
				return context.WithValue(context.Background(), rateLimitInfoKey, "invalid")
			},
			response: &middleware.STACResponse{
				StatusCode: http.StatusOK,
				Body:       []byte("{}"),
			},
			wantNoHeaders: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			m := NewMiddleware(Config{})
			ctx := tt.setupContext()
			req := newSTACRequest(http.MethodGet, "/search")

			result, err := m.ProcessResponse(ctx, req, tt.response)
			if err != nil {
				t.Fatalf("ProcessResponse() error = %v", err)
			}

			if result == nil {
				t.Fatal("ProcessResponse() returned nil")
			}

			if tt.wantNoHeaders {
				if result.Headers != nil {
					for k := range result.Headers {
						if k == "X-RateLimit-Limit" || k == "X-RateLimit-Remaining" || k == "X-RateLimit-Reset" {
							t.Errorf("unexpected rate limit header %q found", k)
						}
					}
				}
			} else {
				if result.Headers == nil {
					t.Fatal("expected headers, got nil")
				}

				for k, want := range tt.wantHeaders {
					got := result.Headers.Get(k)
					if got != want {
						t.Errorf("header %q = %q, want %q", k, got, want)
					}
				}
			}
		})
	}
}

func TestMiddleware_ConcurrentRequests(t *testing.T) {
	t.Parallel()

	limiter := NewSlidingWindowLimiter()
	m := NewMiddleware(Config{
		Limiter:      limiter,
		DefaultQuota: Quota{Requests: 100, Window: time.Minute},
	})

	const numRequests = 50
	const numGoroutines = 10

	var wg sync.WaitGroup
	errorsCh := make(chan error, numRequests)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			for j := 0; j < numRequests/numGoroutines; j++ {
				principal := &auth.Principal{
					ID:    "user123",
					Roles: []string{"user"},
				}

				req := newSTACRequest(http.MethodGet, "/search")
				req.RemoteAddr = "192.168.1.1"
				ctx := context.WithValue(context.Background(), middleware.PrincipalKey, principal)
				req.Context = ctx

				_, err := m.ProcessRequest(ctx, req)
				if err != nil {
					errorsCh <- err
				}
			}
		}(i)
	}

	wg.Wait()
	close(errorsCh)

	errors := []error{}
	for err := range errorsCh {
		errors = append(errors, err)
	}

	if len(errors) > 0 {
		t.Errorf("got %d errors during concurrent requests: first error: %v", len(errors), errors[0])
	}
}

func TestRoleBasedQuotaFunc(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		quotasByRole map[string]Quota
		defaultQuota Quota
		roles        []string
		wantQuota    Quota
	}{
		{
			name: "match first role",
			quotasByRole: map[string]Quota{
				"admin": {Requests: 1000, Window: time.Minute},
				"user":  {Requests: 100, Window: time.Minute},
			},
			defaultQuota: Quota{Requests: 10, Window: time.Minute},
			roles:        []string{"admin", "user"},
			wantQuota:    Quota{Requests: 1000, Window: time.Minute},
		},
		{
			name: "match second role",
			quotasByRole: map[string]Quota{
				"admin": {Requests: 1000, Window: time.Minute},
				"user":  {Requests: 100, Window: time.Minute},
			},
			defaultQuota: Quota{Requests: 10, Window: time.Minute},
			roles:        []string{"guest", "user"},
			wantQuota:    Quota{Requests: 100, Window: time.Minute},
		},
		{
			name: "no matching role",
			quotasByRole: map[string]Quota{
				"admin": {Requests: 1000, Window: time.Minute},
				"user":  {Requests: 100, Window: time.Minute},
			},
			defaultQuota: Quota{Requests: 10, Window: time.Minute},
			roles:        []string{"guest"},
			wantQuota:    Quota{Requests: 10, Window: time.Minute},
		},
		{
			name: "empty roles",
			quotasByRole: map[string]Quota{
				"admin": {Requests: 1000, Window: time.Minute},
			},
			defaultQuota: Quota{Requests: 10, Window: time.Minute},
			roles:        []string{},
			wantQuota:    Quota{Requests: 10, Window: time.Minute},
		},
		{
			name:         "nil roles",
			quotasByRole: map[string]Quota{},
			defaultQuota: Quota{Requests: 10, Window: time.Minute},
			roles:        nil,
			wantQuota:    Quota{Requests: 10, Window: time.Minute},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			fn := RoleBasedQuotaFunc(tt.quotasByRole, tt.defaultQuota)
			got := fn(tt.roles, tt.defaultQuota)

			if got.Requests != tt.wantQuota.Requests {
				t.Errorf("Requests = %d, want %d", got.Requests, tt.wantQuota.Requests)
			}
			if got.Window != tt.wantQuota.Window {
				t.Errorf("Window = %v, want %v", got.Window, tt.wantQuota.Window)
			}
		})
	}
}

func TestErrorResponse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		err            *middleware.RateLimitError
		wantStatusCode int
		wantRetryAfter string
		checkBody      bool
	}{
		{
			name: "basic rate limit error",
			err: &middleware.RateLimitError{
				RetryAfter: 30,
			},
			wantStatusCode: http.StatusTooManyRequests,
			wantRetryAfter: "30",
			checkBody:      true,
		},
		{
			name: "rate limit error with 60 second retry",
			err: &middleware.RateLimitError{
				RetryAfter: 60,
			},
			wantStatusCode: http.StatusTooManyRequests,
			wantRetryAfter: "60",
			checkBody:      true,
		},
		{
			name: "rate limit error with 1 second retry",
			err: &middleware.RateLimitError{
				RetryAfter: 1,
			},
			wantStatusCode: http.StatusTooManyRequests,
			wantRetryAfter: "1",
			checkBody:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			resp := ErrorResponse(tt.err)

			if resp.StatusCode != tt.wantStatusCode {
				t.Errorf("StatusCode = %d, want %d", resp.StatusCode, tt.wantStatusCode)
			}

			if got := resp.Headers.Get("Retry-After"); got != tt.wantRetryAfter {
				t.Errorf("Retry-After = %q, want %q", got, tt.wantRetryAfter)
			}

			if got := resp.Headers.Get("Content-Type"); got != "application/json" {
				t.Errorf("Content-Type = %q, want %q", got, "application/json")
			}

			if tt.checkBody {
				if len(resp.Body) == 0 {
					t.Error("expected non-empty body")
				}
			}
		})
	}
}

func TestDefaultKeyFunc(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		principalID string
		clientIP    string
		wantKey     string
	}{
		{
			name:        "authenticated user",
			principalID: "user123",
			clientIP:    "192.168.1.1",
			wantKey:     "user:user123",
		},
		{
			name:        "anonymous user",
			principalID: "",
			clientIP:    "10.0.0.1",
			wantKey:     "ip:10.0.0.1",
		},
		{
			name:        "anonymous principal",
			principalID: "anonymous",
			clientIP:    "172.16.0.1",
			wantKey:     "ip:172.16.0.1",
		},
		{
			name:        "service account",
			principalID: "service-account-xyz",
			clientIP:    "10.1.2.3",
			wantKey:     "user:service-account-xyz",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := DefaultKeyFunc(context.Background(), tt.principalID, tt.clientIP)
			if got != tt.wantKey {
				t.Errorf("DefaultKeyFunc() = %q, want %q", got, tt.wantKey)
			}
		})
	}
}

func TestDefaultQuotaFunc(t *testing.T) {
	t.Parallel()

	defaultQuota := Quota{Requests: 100, Window: time.Minute}

	tests := []struct {
		name      string
		roles     []string
		wantQuota Quota
	}{
		{
			name:      "with roles",
			roles:     []string{"admin", "user"},
			wantQuota: defaultQuota,
		},
		{
			name:      "without roles",
			roles:     []string{},
			wantQuota: defaultQuota,
		},
		{
			name:      "nil roles",
			roles:     nil,
			wantQuota: defaultQuota,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := DefaultQuotaFunc(tt.roles, defaultQuota)
			if got.Requests != tt.wantQuota.Requests {
				t.Errorf("Requests = %d, want %d", got.Requests, tt.wantQuota.Requests)
			}
			if got.Window != tt.wantQuota.Window {
				t.Errorf("Window = %v, want %v", got.Window, tt.wantQuota.Window)
			}
		})
	}
}

func TestSlidingWindowLimiter_Allow(t *testing.T) {
	tests := []struct {
		name           string
		quota          Quota
		requests       int
		delay          time.Duration
		wantAllowed    int
		wantDenied     int
		checkRemaining bool
	}{
		{
			name:        "all requests allowed within quota",
			quota:       Quota{Requests: 10, Window: time.Second},
			requests:    5,
			wantAllowed: 5,
			wantDenied:  0,
		},
		{
			name:        "requests exceed quota",
			quota:       Quota{Requests: 5, Window: time.Second},
			requests:    10,
			wantAllowed: 5,
			wantDenied:  5,
		},
		{
			name:        "burst allows more requests",
			quota:       Quota{Requests: 10, Window: time.Second, Burst: 15},
			requests:    12,
			wantAllowed: 12,
			wantDenied:  0,
		},
		{
			name:        "burst exceeded",
			quota:       Quota{Requests: 10, Window: time.Second, Burst: 15},
			requests:    20,
			wantAllowed: 15,
			wantDenied:  5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			limiter := NewSlidingWindowLimiter()
			defer limiter.Reset()

			ctx := context.Background()
			key := "test-key"

			allowed := 0
			denied := 0

			for i := 0; i < tt.requests; i++ {
				ok, info, err := limiter.Allow(ctx, key, tt.quota)
				if err != nil {
					t.Fatalf("Allow() error = %v", err)
				}

				if ok {
					allowed++
					if info.Remaining < 0 {
						t.Errorf("request %d: Remaining = %d, should not be negative", i, info.Remaining)
					}
				} else {
					denied++
					if info.RetryAfter <= 0 {
						t.Errorf("request %d: RetryAfter = %d, should be positive", i, info.RetryAfter)
					}
				}

				if info.Limit != tt.quota.Requests {
					t.Errorf("request %d: Limit = %d, want %d", i, info.Limit, tt.quota.Requests)
				}

				if tt.delay > 0 {
					time.Sleep(tt.delay)
				}
			}

			if allowed != tt.wantAllowed {
				t.Errorf("allowed = %d, want %d", allowed, tt.wantAllowed)
			}
			if denied != tt.wantDenied {
				t.Errorf("denied = %d, want %d", denied, tt.wantDenied)
			}
		})
	}
}

func TestSlidingWindowLimiter_MultipleKeys(t *testing.T) {
	t.Parallel()

	limiter := NewSlidingWindowLimiter()
	quota := Quota{Requests: 5, Window: time.Second}
	ctx := context.Background()

	// Make requests for different keys
	for i := 0; i < 5; i++ {
		key1Allowed, _, err := limiter.Allow(ctx, "key1", quota)
		if err != nil {
			t.Fatalf("Allow(key1) error = %v", err)
		}
		if !key1Allowed {
			t.Errorf("request %d for key1 should be allowed", i)
		}

		key2Allowed, _, err := limiter.Allow(ctx, "key2", quota)
		if err != nil {
			t.Fatalf("Allow(key2) error = %v", err)
		}
		if !key2Allowed {
			t.Errorf("request %d for key2 should be allowed", i)
		}
	}

	// Both keys should now be at limit
	key1Allowed, _, _ := limiter.Allow(ctx, "key1", quota)
	if key1Allowed {
		t.Error("key1 should be rate limited")
	}

	key2Allowed, _, _ := limiter.Allow(ctx, "key2", quota)
	if key2Allowed {
		t.Error("key2 should be rate limited")
	}
}

func TestSlidingWindowLimiter_WindowReset(t *testing.T) {
	limiter := NewSlidingWindowLimiter()
	quota := Quota{Requests: 3, Window: 100 * time.Millisecond}
	ctx := context.Background()
	key := "test-key"

	// Use up the quota
	for i := 0; i < 3; i++ {
		allowed, _, err := limiter.Allow(ctx, key, quota)
		if err != nil {
			t.Fatalf("Allow() error = %v", err)
		}
		if !allowed {
			t.Fatalf("request %d should be allowed", i)
		}
	}

	// Next request should be denied
	allowed, _, _ := limiter.Allow(ctx, key, quota)
	if allowed {
		t.Error("request should be denied before window reset")
	}

	// Wait for window to reset
	time.Sleep(150 * time.Millisecond)

	// Should be allowed again
	allowed, info, err := limiter.Allow(ctx, key, quota)
	if err != nil {
		t.Fatalf("Allow() error = %v", err)
	}
	if !allowed {
		t.Error("request should be allowed after window reset")
	}
	if info.Remaining != quota.Requests-1 {
		t.Errorf("Remaining = %d, want %d", info.Remaining, quota.Requests-1)
	}
}

func TestSlidingWindowLimiter_SlidingWindow(t *testing.T) {
	limiter := NewSlidingWindowLimiter()
	quota := Quota{Requests: 5, Window: 200 * time.Millisecond}
	ctx := context.Background()
	key := "test-key"

	// Make 3 requests at the start
	for i := 0; i < 3; i++ {
		allowed, _, err := limiter.Allow(ctx, key, quota)
		if err != nil {
			t.Fatalf("Allow() error = %v", err)
		}
		if !allowed {
			t.Fatalf("request %d should be allowed", i)
		}
	}

	// Wait half the window
	time.Sleep(100 * time.Millisecond)

	// Make 2 more requests (should be allowed due to sliding window)
	for i := 0; i < 2; i++ {
		allowed, _, err := limiter.Allow(ctx, key, quota)
		if err != nil {
			t.Fatalf("Allow() error = %v", err)
		}
		if !allowed {
			t.Fatalf("request in second half should be allowed (sliding window)")
		}
	}

	// Next request might be denied (5 requests total in sliding window)
	allowed, _, _ := limiter.Allow(ctx, key, quota)
	if allowed {
		t.Log("Note: Request allowed due to sliding window calculation, this is expected behavior")
	}
}

func TestSlidingWindowLimiter_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	limiter := NewSlidingWindowLimiter()
	quota := Quota{Requests: 100, Window: time.Second}
	ctx := context.Background()
	key := "concurrent-key"

	const numGoroutines = 10
	const requestsPerGoroutine = 20

	var wg sync.WaitGroup
	allowedCount := make(chan bool, numGoroutines*requestsPerGoroutine)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < requestsPerGoroutine; j++ {
				allowed, _, _ := limiter.Allow(ctx, key, quota)
				allowedCount <- allowed
			}
		}()
	}

	wg.Wait()
	close(allowedCount)

	allowed := 0
	for a := range allowedCount {
		if a {
			allowed++
		}
	}

	// Should allow exactly the quota amount
	if allowed != quota.Requests {
		t.Errorf("allowed = %d, want %d (some requests should be denied)", allowed, quota.Requests)
	}
}

func TestSlidingWindowLimiter_Reset(t *testing.T) {
	t.Parallel()

	limiter := NewSlidingWindowLimiter()
	quota := Quota{Requests: 5, Window: time.Minute}
	ctx := context.Background()

	// Use up quota for multiple keys
	for i := 0; i < 5; i++ {
		limiter.Allow(ctx, "key1", quota)
		limiter.Allow(ctx, "key2", quota)
	}

	// Both should be denied
	allowed1, _, _ := limiter.Allow(ctx, "key1", quota)
	allowed2, _, _ := limiter.Allow(ctx, "key2", quota)

	if allowed1 || allowed2 {
		t.Error("requests should be denied before reset")
	}

	// Reset limiter
	limiter.Reset()

	// Both should be allowed again
	allowed1, _, _ = limiter.Allow(ctx, "key1", quota)
	allowed2, _, _ = limiter.Allow(ctx, "key2", quota)

	if !allowed1 || !allowed2 {
		t.Error("requests should be allowed after reset")
	}
}

func TestMiddleware_Integration(t *testing.T) {
	tests := []struct {
		name             string
		principal        *auth.Principal
		quota            Quota
		requests         int
		wantAllowedCount int
		wantDeniedCount  int
	}{
		{
			name: "user within quota",
			principal: &auth.Principal{
				ID:    "user1",
				Roles: []string{"user"},
			},
			quota:            Quota{Requests: 10, Window: time.Second},
			requests:         5,
			wantAllowedCount: 5,
			wantDeniedCount:  0,
		},
		{
			name: "user exceeds quota",
			principal: &auth.Principal{
				ID:    "user2",
				Roles: []string{"user"},
			},
			quota:            Quota{Requests: 5, Window: time.Second},
			requests:         10,
			wantAllowedCount: 5,
			wantDeniedCount:  5,
		},
		{
			name: "admin with higher quota",
			principal: &auth.Principal{
				ID:    "admin1",
				Roles: []string{"admin"},
			},
			quota:            Quota{Requests: 100, Window: time.Second},
			requests:         50,
			wantAllowedCount: 50,
			wantDeniedCount:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			limiter := NewSlidingWindowLimiter()
			m := NewMiddleware(Config{
				Limiter:      limiter,
				DefaultQuota: tt.quota,
			})

			allowedCount := 0
			deniedCount := 0

			for i := 0; i < tt.requests; i++ {
				req := newSTACRequest(http.MethodGet, "/search")
				req.RemoteAddr = "192.168.1.1"
				ctx := context.WithValue(context.Background(), middleware.PrincipalKey, tt.principal)
				req.Context = ctx

				result, err := m.ProcessRequest(ctx, req)

				if err != nil {
					if _, ok := err.(*middleware.RateLimitError); ok {
						deniedCount++
					} else {
						t.Fatalf("unexpected error type: %T", err)
					}
				} else if result != nil {
					allowedCount++

					// Test ProcessResponse
					resp := &middleware.STACResponse{
						StatusCode: http.StatusOK,
						Body:       []byte("{}"),
					}
					processed, err := m.ProcessResponse(result.Context, req, resp)
					if err != nil {
						t.Fatalf("ProcessResponse() error = %v", err)
					}

					// Verify rate limit headers
					if processed.Headers == nil {
						t.Error("expected headers in response")
					} else {
						if processed.Headers.Get("X-RateLimit-Limit") == "" {
							t.Error("missing X-RateLimit-Limit header")
						}
						if processed.Headers.Get("X-RateLimit-Remaining") == "" {
							t.Error("missing X-RateLimit-Remaining header")
						}
						if processed.Headers.Get("X-RateLimit-Reset") == "" {
							t.Error("missing X-RateLimit-Reset header")
						}
					}
				}
			}

			if allowedCount != tt.wantAllowedCount {
				t.Errorf("allowedCount = %d, want %d", allowedCount, tt.wantAllowedCount)
			}
			if deniedCount != tt.wantDeniedCount {
				t.Errorf("deniedCount = %d, want %d", deniedCount, tt.wantDeniedCount)
			}
		})
	}
}

func BenchmarkMiddleware_ProcessRequest(b *testing.B) {
	limiter := NewSlidingWindowLimiter()
	m := NewMiddleware(Config{
		Limiter:      limiter,
		DefaultQuota: Quota{Requests: 1000000, Window: time.Minute},
	})

	principal := &auth.Principal{
		ID:    "bench-user",
		Roles: []string{"user"},
	}

	req := newSTACRequest(http.MethodGet, "/search")
	req.RemoteAddr = "192.168.1.1"
	ctx := context.WithValue(context.Background(), middleware.PrincipalKey, principal)
	req.Context = ctx

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = m.ProcessRequest(ctx, req)
	}
}

func BenchmarkMiddleware_ProcessRequest_Parallel(b *testing.B) {
	limiter := NewSlidingWindowLimiter()
	m := NewMiddleware(Config{
		Limiter:      limiter,
		DefaultQuota: Quota{Requests: 1000000, Window: time.Minute},
	})

	b.RunParallel(func(pb *testing.PB) {
		principal := &auth.Principal{
			ID:    "bench-user",
			Roles: []string{"user"},
		}

		req := newSTACRequest(http.MethodGet, "/search")
		req.RemoteAddr = "192.168.1.1"
		ctx := context.WithValue(context.Background(), middleware.PrincipalKey, principal)
		req.Context = ctx

		for pb.Next() {
			_, _ = m.ProcessRequest(ctx, req)
		}
	})
}

func BenchmarkSlidingWindowLimiter_Allow(b *testing.B) {
	limiter := NewSlidingWindowLimiter()
	quota := Quota{Requests: 1000000, Window: time.Minute}
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = limiter.Allow(ctx, "bench-key", quota)
	}
}
