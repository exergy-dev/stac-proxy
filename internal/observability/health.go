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
//
// When Verbose is false (the default), the JSON returned by the
// HTTP handlers strips per-check `message` and `details` fields so
// upstream URLs, error strings, and other topology hints don't leak
// to whoever can reach `/health`. Operators inside trusted networks
// can flip Verbose=true via config to get the full payload.
//
// Probe-result cache (M-observability-1): per-check results are
// memoized for CheckCacheTTL so a load balancer probing every second
// doesn't fan out to every upstream on every request. A background
// goroutine started by Start() refreshes results every
// RefreshInterval; HTTP probes always serve the last cached value
// and trigger an opportunistic background refresh when the entry is
// older than CheckCacheTTL but never block on the upstream.
type HealthChecker struct {
	checks       map[string]Check
	mu           sync.RWMutex
	checkTimeout time.Duration
	Verbose      bool

	// CheckCacheTTL is how long a per-check result is served from cache
	// before an opportunistic background refresh is triggered. Defaults
	// to 10s when zero.
	CheckCacheTTL time.Duration
	// RefreshInterval is the period of the background refresh
	// goroutine started by Start(). Defaults to 30s when zero.
	RefreshInterval time.Duration

	cache       map[string]cachedResult
	cacheMu     sync.Mutex
	refreshing  map[string]struct{} // guards against concurrent background refreshes for the same check
	stopCh      chan struct{}
	stopOnce    sync.Once
	startedOnce sync.Once
}

// cachedResult is a per-check entry in the probe cache.
type cachedResult struct {
	result CheckResult
	at     time.Time
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

// defaultCheckCacheTTL is the default TTL for cached probe results.
const defaultCheckCacheTTL = 10 * time.Second

// defaultRefreshInterval is the default period of the background
// refresh loop started by Start().
const defaultRefreshInterval = 30 * time.Second

// NewHealthChecker creates a new health checker.
func NewHealthChecker() *HealthChecker {
	return &HealthChecker{
		checks:          make(map[string]Check),
		checkTimeout:    5 * time.Second,
		CheckCacheTTL:   defaultCheckCacheTTL,
		RefreshInterval: defaultRefreshInterval,
		cache:           make(map[string]cachedResult),
		refreshing:      make(map[string]struct{}),
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

// Start launches a background goroutine that refreshes every
// registered check at RefreshInterval. Idempotent; subsequent calls
// are no-ops. Stop() halts the goroutine.
func (h *HealthChecker) Start() {
	h.startedOnce.Do(func() {
		h.stopCh = make(chan struct{})
		interval := h.RefreshInterval
		if interval <= 0 {
			interval = defaultRefreshInterval
		}
		go h.refreshLoop(interval)
	})
}

// Stop signals the background refresh goroutine to exit. Idempotent.
func (h *HealthChecker) Stop() {
	h.stopOnce.Do(func() {
		if h.stopCh != nil {
			close(h.stopCh)
		}
	})
}

// refreshLoop periodically refreshes all registered checks. Runs
// until Stop() is called.
func (h *HealthChecker) refreshLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Prime the cache immediately so the first probe sees fresh data.
	h.refreshAll(context.Background())
	for {
		select {
		case <-h.stopCh:
			return
		case <-ticker.C:
			h.refreshAll(context.Background())
		}
	}
}

// refreshAll runs every registered check synchronously and updates
// the cache. Used by both the background loop and Start()'s prime.
func (h *HealthChecker) refreshAll(ctx context.Context) {
	h.mu.RLock()
	checks := make(map[string]Check, len(h.checks))
	for k, v := range h.checks {
		checks[k] = v
	}
	h.mu.RUnlock()

	for name, check := range checks {
		h.runAndCache(ctx, name, check)
	}
}

// runAndCache executes a single check (with timeout) and stores the
// result in the cache.
func (h *HealthChecker) runAndCache(ctx context.Context, name string, check Check) CheckResult {
	checkCtx, cancel := context.WithTimeout(ctx, h.checkTimeout)
	defer cancel()

	start := time.Now()
	result := check.Check(checkCtx)
	result.Latency = time.Since(start)

	h.cacheMu.Lock()
	h.cache[name] = cachedResult{result: result, at: time.Now()}
	delete(h.refreshing, name)
	h.cacheMu.Unlock()
	return result
}

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

// RunChecks returns the latest known per-check results. Cached entries
// younger than CheckCacheTTL are served immediately. Stale entries are
// served immediately too, but spawn a background refresh so the next
// probe sees fresh data — slow upstreams therefore can't block the
// /health probe past the cache window. Cache misses (no entry yet) run
// the check synchronously so the very first probe still produces real
// data.
func (h *HealthChecker) RunChecks(ctx context.Context) HealthResponse {
	h.mu.RLock()
	checks := make(map[string]Check, len(h.checks))
	for k, v := range h.checks {
		checks[k] = v
	}
	h.mu.RUnlock()

	ttl := h.CheckCacheTTL
	if ttl <= 0 {
		ttl = defaultCheckCacheTTL
	}

	results := make(map[string]CheckResult, len(checks))
	now := time.Now()

	for name, check := range checks {
		h.cacheMu.Lock()
		entry, hit := h.cache[name]
		h.cacheMu.Unlock()

		if !hit {
			// No cached entry — run synchronously so the very first
			// probe returns a real value rather than a placeholder.
			results[name] = h.runAndCache(ctx, name, check)
			continue
		}

		results[name] = entry.result
		if now.Sub(entry.at) >= ttl {
			h.tryBackgroundRefresh(name, check)
		}
	}

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

// tryBackgroundRefresh spawns a goroutine to refresh a check, but only
// if no other refresh is already in flight for this check. Probes that
// arrive while a refresh is running just keep serving the stale value.
func (h *HealthChecker) tryBackgroundRefresh(name string, check Check) {
	h.cacheMu.Lock()
	if _, busy := h.refreshing[name]; busy {
		h.cacheMu.Unlock()
		return
	}
	h.refreshing[name] = struct{}{}
	h.cacheMu.Unlock()

	go h.runAndCache(context.Background(), name, check)
}

// HealthHandler returns an http.HandlerFunc for health checks.
func (h *HealthChecker) HealthHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		response := h.RunChecks(r.Context())
		h.redact(&response)

		w.Header().Set("Content-Type", "application/json")
		if response.Status == StatusUnhealthy {
			w.WriteHeader(http.StatusServiceUnavailable)
		} else {
			w.WriteHeader(http.StatusOK)
		}

		json.NewEncoder(w).Encode(response)
	}
}

// redact strips per-check Message and Details fields when Verbose is
// off so the public response carries only the overall + per-check
// status enum, not upstream URLs / 4xx/5xx specifics / etc.
func (h *HealthChecker) redact(r *HealthResponse) {
	if h.Verbose {
		return
	}
	for name, c := range r.Checks {
		r.Checks[name] = CheckResult{Status: c.Status, Latency: c.Latency}
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
		h.redact(&response)

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
