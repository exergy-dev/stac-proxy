package observability

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestHealth_NoDetailsByDefault is the C5 regression test: by default,
// /health responses must not include per-check Message or Details
// fields, since those would leak upstream URLs and error strings to
// whoever can reach the endpoint.
func TestHealth_NoDetailsByDefault(t *testing.T) {
	h := NewHealthChecker()
	h.AddCheckFunc("upstream-secret-host", func(ctx context.Context) error {
		return errors.New("dial tcp 10.0.0.42:8080: connection refused")
	})

	rr := httptest.NewRecorder()
	h.HealthHandler().ServeHTTP(rr, httptest.NewRequest("GET", "/health", nil))

	body := rr.Body.String()

	// The secret-y bits must NOT be in the body.
	for _, leak := range []string{
		"10.0.0.42",
		"connection refused",
		"dial tcp",
	} {
		if strings.Contains(body, leak) {
			t.Errorf("health body leaked %q in default (Verbose=false) mode: %s", leak, body)
		}
	}

	// The status enum is still present.
	var resp HealthResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Status != StatusUnhealthy {
		t.Errorf("Status = %q, want %q", resp.Status, StatusUnhealthy)
	}
	for _, c := range resp.Checks {
		if c.Message != "" {
			t.Errorf("per-check Message leaked: %q", c.Message)
		}
		if c.Details != nil {
			t.Errorf("per-check Details leaked: %v", c.Details)
		}
	}
}

// TestHealth_VerboseEmitsDetails confirms the opt-in works: with
// Verbose=true the full payload comes through for operators on
// trusted networks.
func TestHealth_VerboseEmitsDetails(t *testing.T) {
	h := NewHealthChecker()
	h.Verbose = true
	h.AddCheckFunc("upstream", func(ctx context.Context) error {
		return errors.New("dial tcp 10.0.0.42:8080: connection refused")
	})

	rr := httptest.NewRecorder()
	h.HealthHandler().ServeHTTP(rr, httptest.NewRequest("GET", "/health", nil))

	if !strings.Contains(rr.Body.String(), "10.0.0.42") {
		t.Errorf("Verbose mode dropped check details: %s", rr.Body.String())
	}
}

// TestHealth_CachesResultsBetweenProbes is the M-observability-1
// regression: 10 probes within ~1s must NOT call the underlying check
// 10 times. The cache must collapse them to a single invocation (the
// first miss; subsequent calls land within CheckCacheTTL and serve the
// cached value without spawning refreshes).
func TestHealth_CachesResultsBetweenProbes(t *testing.T) {
	h := NewHealthChecker()
	h.CheckCacheTTL = 5 * time.Second

	var calls int64
	h.AddCheckFunc("upstream", func(ctx context.Context) error {
		atomic.AddInt64(&calls, 1)
		return nil
	})

	for i := 0; i < 10; i++ {
		rr := httptest.NewRecorder()
		h.HealthHandler().ServeHTTP(rr, httptest.NewRequest("GET", "/health", nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("probe %d: status = %d", i, rr.Code)
		}
	}

	if got := atomic.LoadInt64(&calls); got != 1 {
		t.Errorf("check invocations = %d, want 1 (cache should collapse repeat probes)", got)
	}
}

// TestHealth_ServesStaleDuringSlowCheck verifies that once a cached
// "healthy" result is in place, a subsequent probe returns within ~1ms
// even when the underlying check would take 5s — the slow check runs
// in the background and the probe serves the stale cached value.
func TestHealth_ServesStaleDuringSlowCheck(t *testing.T) {
	h := NewHealthChecker()
	// TTL of 0 forces every post-prime probe to look stale, so we
	// always trigger the background-refresh path on the second probe.
	h.CheckCacheTTL = 1 * time.Nanosecond

	var slow atomic.Bool
	h.AddCheckFunc("slow-upstream", func(ctx context.Context) error {
		if slow.Load() {
			select {
			case <-time.After(5 * time.Second):
			case <-ctx.Done():
			}
		}
		return nil
	})

	// First probe — primes the cache fast (slow flag still false).
	rr1 := httptest.NewRecorder()
	h.HealthHandler().ServeHTTP(rr1, httptest.NewRequest("GET", "/health", nil))
	if rr1.Code != http.StatusOK {
		t.Fatalf("prime probe: status = %d", rr1.Code)
	}

	// Now flip the check to slow. The next probe should NOT block on
	// the underlying check; it should return the cached value
	// immediately and spawn a background refresh.
	slow.Store(true)

	start := time.Now()
	rr2 := httptest.NewRecorder()
	h.HealthHandler().ServeHTTP(rr2, httptest.NewRequest("GET", "/health", nil))
	elapsed := time.Since(start)

	if rr2.Code != http.StatusOK {
		t.Fatalf("stale probe: status = %d", rr2.Code)
	}
	if elapsed > 200*time.Millisecond {
		t.Errorf("stale probe took %s; expected <200ms (slow upstream should not block)", elapsed)
	}
}

// TestHealth_RunChecksConcurrent ensures the cache is goroutine-safe
// under concurrent probe load — no panics, no data races, every probe
// returns a result.
func TestHealth_RunChecksConcurrent(t *testing.T) {
	h := NewHealthChecker()
	h.CheckCacheTTL = 50 * time.Millisecond
	h.AddCheckFunc("c", func(ctx context.Context) error { return nil })

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp := h.RunChecks(context.Background())
			if resp.Status != StatusHealthy {
				t.Errorf("status = %q, want healthy", resp.Status)
			}
		}()
	}
	wg.Wait()
}
