// Package observability provides health check endpoints.
package observability

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

// HealthChecker manages health checks for the proxy.
type HealthChecker struct {
	checks       map[string]Check
	mu           sync.RWMutex
	checkTimeout time.Duration
}

// Check defines a single health check.
type Check interface {
	Name() string
	Check(ctx context.Context) CheckResult
}

// CheckResult contains the result of a health check.
type CheckResult struct {
	Status  Status        `json:"status"`
	Message string        `json:"message,omitempty"`
	Latency time.Duration `json:"latency_ms,omitempty"`
	Details interface{}   `json:"details,omitempty"`
}

// Status represents a health check status.
type Status string

const (
	StatusHealthy   Status = "healthy"
	StatusUnhealthy Status = "unhealthy"
	StatusDegraded  Status = "degraded"
)

// HealthResponse is the JSON response for health endpoints.
type HealthResponse struct {
	Status  Status                 `json:"status"`
	Checks  map[string]CheckResult `json:"checks,omitempty"`
	Version string                 `json:"version,omitempty"`
	Uptime  string                 `json:"uptime,omitempty"`
}

// NewHealthChecker creates a new health checker.
func NewHealthChecker() *HealthChecker {
	return &HealthChecker{
		checks:       make(map[string]Check),
		checkTimeout: 5 * time.Second,
	}
}

// AddCheck registers a health check.
func (h *HealthChecker) AddCheck(check Check) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.checks[check.Name()] = check
}

// AddCheckFunc is a convenience wrapper that registers a check from a
// function. Useful for ad-hoc origin/upstream probes that don't need
// a dedicated Check type.
func (h *HealthChecker) AddCheckFunc(name string, fn func(ctx context.Context) error) {
	h.AddCheck(funcCheck{name: name, fn: fn})
}

// Start is a no-op today; reserved for a future background-poll mode
// that pre-warms results so /health responses don't block on the
// first request. Callers may invoke it for forward-compatibility.
func (h *HealthChecker) Start() {}

// Stop is the symmetric no-op for Start.
func (h *HealthChecker) Stop() {}

type funcCheck struct {
	name string
	fn   func(ctx context.Context) error
}

func (c funcCheck) Name() string { return c.name }
func (c funcCheck) Check(ctx context.Context) CheckResult {
	if err := c.fn(ctx); err != nil {
		return CheckResult{Status: StatusUnhealthy, Message: err.Error()}
	}
	return CheckResult{Status: StatusHealthy}
}

// RemoveCheck removes a health check.
func (h *HealthChecker) RemoveCheck(name string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.checks, name)
}

// RunChecks executes all health checks and returns the results.
func (h *HealthChecker) RunChecks(ctx context.Context) HealthResponse {
	h.mu.RLock()
	checks := make(map[string]Check, len(h.checks))
	for k, v := range h.checks {
		checks[k] = v
	}
	h.mu.RUnlock()

	results := make(map[string]CheckResult)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for name, check := range checks {
		wg.Add(1)
		go func(name string, check Check) {
			defer wg.Done()

			checkCtx, cancel := context.WithTimeout(ctx, h.checkTimeout)
			defer cancel()

			start := time.Now()
			result := check.Check(checkCtx)
			result.Latency = time.Since(start)

			mu.Lock()
			results[name] = result
			mu.Unlock()
		}(name, check)
	}

	wg.Wait()

	// Determine overall status
	overallStatus := StatusHealthy
	for _, result := range results {
		if result.Status == StatusUnhealthy {
			overallStatus = StatusUnhealthy
			break
		}
		if result.Status == StatusDegraded && overallStatus == StatusHealthy {
			overallStatus = StatusDegraded
		}
	}

	return HealthResponse{
		Status: overallStatus,
		Checks: results,
	}
}

// HealthHandler returns an http.HandlerFunc for health checks.
func (h *HealthChecker) HealthHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		response := h.RunChecks(r.Context())

		w.Header().Set("Content-Type", "application/json")
		if response.Status == StatusUnhealthy {
			w.WriteHeader(http.StatusServiceUnavailable)
		} else {
			w.WriteHeader(http.StatusOK)
		}

		json.NewEncoder(w).Encode(response)
	}
}

// LivenessHandler returns an http.HandlerFunc for liveness probes.
func (h *HealthChecker) LivenessHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "alive"})
	}
}

// ReadinessHandler returns an http.HandlerFunc for readiness probes.
func (h *HealthChecker) ReadinessHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		response := h.RunChecks(r.Context())

		w.Header().Set("Content-Type", "application/json")
		if response.Status == StatusUnhealthy {
			w.WriteHeader(http.StatusServiceUnavailable)
		} else {
			w.WriteHeader(http.StatusOK)
		}

		json.NewEncoder(w).Encode(response)
	}
}

// OriginCheck checks the health of an upstream origin.
type OriginCheck struct {
	name    string
	url     string
	client  *http.Client
	timeout time.Duration
}

// NewOriginCheck creates a new origin health check.
func NewOriginCheck(name, url string) *OriginCheck {
	return &OriginCheck{
		name: name,
		url:  url,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
		timeout: 5 * time.Second,
	}
}

// Name returns the check name.
func (c *OriginCheck) Name() string {
	return c.name
}

// Check performs the health check.
func (c *OriginCheck) Check(ctx context.Context) CheckResult {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return CheckResult{
			Status:  StatusUnhealthy,
			Message: err.Error(),
		}
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return CheckResult{
			Status:  StatusUnhealthy,
			Message: err.Error(),
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 500 {
		return CheckResult{
			Status:  StatusUnhealthy,
			Message: "Origin returned 5xx error",
			Details: map[string]int{"status_code": resp.StatusCode},
		}
	}

	if resp.StatusCode >= 400 {
		return CheckResult{
			Status:  StatusDegraded,
			Message: "Origin returned 4xx error",
			Details: map[string]int{"status_code": resp.StatusCode},
		}
	}

	return CheckResult{
		Status:  StatusHealthy,
		Message: "Origin is healthy",
		Details: map[string]int{"status_code": resp.StatusCode},
	}
}

// CacheCheck checks the health of the cache store.
type CacheCheck struct {
	name  string
	check func(ctx context.Context) error
}

// NewCacheCheck creates a new cache health check.
func NewCacheCheck(name string, check func(ctx context.Context) error) *CacheCheck {
	return &CacheCheck{
		name:  name,
		check: check,
	}
}

// Name returns the check name.
func (c *CacheCheck) Name() string {
	return c.name
}

// Check performs the health check.
func (c *CacheCheck) Check(ctx context.Context) CheckResult {
	if err := c.check(ctx); err != nil {
		return CheckResult{
			Status:  StatusDegraded,
			Message: err.Error(),
		}
	}
	return CheckResult{
		Status:  StatusHealthy,
		Message: "Cache is healthy",
	}
}
