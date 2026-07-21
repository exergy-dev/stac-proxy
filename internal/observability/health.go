// Package observability: health checks — thin adapter over
// github.com/alexliesenfeld/health.
//
// The underlying library handles per-check timeout, result caching,
// status aggregation, and the JSON handler. This wrapper preserves the
// proxy's construct-then-add-checks-then-mount pattern by deferring
// construction of the lib checker until the first handler call.
package observability

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/alexliesenfeld/health"
)

// Check is an alias for the library's Check type so callers can register
// checks without importing the library directly.
type Check = health.Check

// HealthChecker collects checks and lazily builds the underlying
// library Checker on first handler request. This matches the wiring
// order in main.go: NewHealthChecker → AddCheck (per origin) → mount
// router with HealthHandler().
type HealthChecker struct {
	mu       sync.Mutex
	pending  []Check
	timeout  time.Duration
	cacheTTL time.Duration

	checker health.Checker
	handler http.HandlerFunc
}

// NewHealthChecker creates a HealthChecker with sane defaults
// (5s per-check timeout, 10s result cache).
func NewHealthChecker() *HealthChecker {
	return &HealthChecker{timeout: 5 * time.Second, cacheTTL: 10 * time.Second}
}

// AddCheck registers a check; must be called before HealthHandler() /
// Start(). Calls after the lib checker has been built will return an
// error via panic at construction time.
func (h *HealthChecker) AddCheck(c Check) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.pending = append(h.pending, c)
}

// AddCheckFunc is a convenience wrapper that registers a Check from a
// function.
func (h *HealthChecker) AddCheckFunc(name string, fn func(ctx context.Context) error) {
	h.AddCheck(Check{Name: name, Check: fn})
}

// Start initializes the underlying checker if not already built.
// Idempotent.
func (h *HealthChecker) Start() { h.build() }

// Stop halts the underlying checker. Idempotent and safe to call
// before Start.
func (h *HealthChecker) Stop() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.checker != nil {
		h.checker.Stop()
	}
}

func (h *HealthChecker) build() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.checker != nil {
		return
	}
	opts := []health.CheckerOption{
		health.WithTimeout(h.timeout),
		health.WithCacheDuration(h.cacheTTL),
		health.WithDisabledDetails(), // never leak upstream URLs or error strings
	}
	for _, c := range h.pending {
		opts = append(opts, health.WithCheck(c))
	}
	h.checker = health.NewChecker(opts...)
	h.handler = health.NewHandler(h.checker)
}

// HealthHandler returns an http.HandlerFunc that runs all registered
// checks and reports aggregated status.
func (h *HealthChecker) HealthHandler() http.HandlerFunc {
	h.build()
	return h.handler
}

// ReadinessHandler is identical to HealthHandler — readiness is "all
// checks pass" in this proxy.
func (h *HealthChecker) ReadinessHandler() http.HandlerFunc {
	return h.HealthHandler()
}

// LivenessHandler returns a constant 200 — the process is alive iff
// the HTTP server is responding.
func (h *HealthChecker) LivenessHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "alive"})
	}
}

// NewOriginCheck returns a Check that probes an upstream STAC origin
// via the supplied *http.Client. Pass the federation OriginClient's
// HTTPClient() so probes traverse the same transport stack
// (M-observability-2). nil client falls back to http.DefaultClient.
func NewOriginCheck(name, url string, client *http.Client) Check {
	if client == nil {
		client = http.DefaultClient
	}
	return Check{
		Name: name,
		Check: func(ctx context.Context) error {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				return err
			}
			resp, err := client.Do(req)
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			if resp.StatusCode >= 500 {
				return fmt.Errorf("origin returned status %d", resp.StatusCode)
			}
			return nil
		},
	}
}
