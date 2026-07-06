package httpx

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"sync"
	"time"
)

// ErrCircuitOpen is returned by BreakerTransport.RoundTrip without
// dialing when the origin's circuit is open. Callers can errors.Is
// against it to distinguish fast-fail from a live upstream failure.
var ErrCircuitOpen = errors.New("circuit breaker open")

// BreakerConfig tunes a per-origin circuit breaker. Zero values take
// the defaults documented per field.
type BreakerConfig struct {
	// FailureThreshold is the number of CONSECUTIVE failures that
	// opens the circuit. Default 5.
	FailureThreshold int
	// OpenBase is the first open period. Each re-open (a failed
	// half-open probe) doubles it, capped at OpenMax. Full jitter
	// ([d/2, d]) is applied so replicas don't probe a recovering
	// origin in lockstep. Defaults 10s / 2m.
	OpenBase time.Duration
	OpenMax  time.Duration
	// HalfOpenProbes is how many concurrent trial requests may pass
	// while half-open. Default 1.
	HalfOpenProbes int
}

func (c BreakerConfig) withDefaults() BreakerConfig {
	if c.FailureThreshold <= 0 {
		c.FailureThreshold = 5
	}
	if c.OpenBase <= 0 {
		c.OpenBase = 10 * time.Second
	}
	if c.OpenMax <= 0 {
		c.OpenMax = 2 * time.Minute
	}
	if c.OpenMax < c.OpenBase {
		c.OpenMax = c.OpenBase
	}
	if c.HalfOpenProbes <= 0 {
		c.HalfOpenProbes = 1
	}
	return c
}

type breakerState int

const (
	stateClosed breakerState = iota
	stateOpen
	stateHalfOpen
)

// BreakerTransport is a circuit-breaking http.RoundTripper. Sits
// OUTERMOST in the per-origin transport stack (outside auth and
// retry) so one user-visible request contributes one sample no matter
// how many retry attempts it fanned into, and so an open circuit
// fast-fails before the auth layer spends an OAuth2 token fetch on a
// dead origin.
//
// Failure classification:
//   - transport error → failure, EXCEPT context.Canceled: a canceled
//     parent (client disconnect, sibling completion under the
//     aggregate-timeout context) says nothing about origin health.
//     context.DeadlineExceeded DOES count — the origin was too slow.
//   - HTTP 5xx → failure.
//   - Everything else (2xx/3xx/4xx, including 429) → success. 4xx is
//     the caller's fault, not the origin's.
//
// State transitions are logged via slog — with logs-only
// observability these lines ARE the operator's breaker dashboard.
type BreakerTransport struct {
	inner  http.RoundTripper
	name   string
	cfg    BreakerConfig
	logger *slog.Logger

	mu          sync.Mutex
	state       breakerState
	consecFails int
	reopens     int
	openUntil   time.Time
	probes      int
}

// NewBreakerTransport wraps inner with a circuit breaker. name is the
// origin ID used in log fields and error messages. A nil logger
// falls back to slog.Default().
func NewBreakerTransport(inner http.RoundTripper, name string, cfg BreakerConfig, logger *slog.Logger) *BreakerTransport {
	if inner == nil {
		inner = http.DefaultTransport
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &BreakerTransport{
		inner:  inner,
		name:   name,
		cfg:    cfg.withDefaults(),
		logger: logger,
	}
}

// RoundTrip implements http.RoundTripper.
func (b *BreakerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := b.admit(); err != nil {
		return nil, err
	}
	resp, err := b.inner.RoundTrip(req)
	b.record(resp, err)
	return resp, err
}

// admit decides whether the request may pass in the current state.
func (b *BreakerTransport) admit() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	switch b.state {
	case stateClosed:
		return nil
	case stateOpen:
		if time.Now().Before(b.openUntil) {
			return fmt.Errorf("origin %s: %w", b.name, ErrCircuitOpen)
		}
		b.state = stateHalfOpen
		b.probes = 1
		b.logger.Info("circuit breaker half-open; probing origin",
			"origin", b.name)
		return nil
	default: // stateHalfOpen
		if b.probes >= b.cfg.HalfOpenProbes {
			return fmt.Errorf("origin %s: %w", b.name, ErrCircuitOpen)
		}
		b.probes++
		return nil
	}
}

// record classifies the outcome and drives state transitions.
func (b *BreakerTransport) record(resp *http.Response, err error) {
	// Neutral: a canceled parent context is not an origin-health
	// signal. Release a half-open probe slot without judging.
	if err != nil && errors.Is(err, context.Canceled) {
		b.mu.Lock()
		if b.state == stateHalfOpen && b.probes > 0 {
			b.probes--
		}
		b.mu.Unlock()
		return
	}
	failure := err != nil || (resp != nil && resp.StatusCode >= 500)

	b.mu.Lock()
	defer b.mu.Unlock()
	if failure {
		switch b.state {
		case stateClosed:
			b.consecFails++
			if b.consecFails >= b.cfg.FailureThreshold {
				b.reopens = 0
				b.open("consecutive_failures", b.consecFails)
			}
		case stateHalfOpen:
			b.reopens++
			b.open("probe_failed", b.reopens)
		case stateOpen:
			// A request admitted before the circuit opened; nothing to do.
		}
		return
	}
	// Success.
	if b.state != stateClosed {
		b.logger.Info("circuit breaker closed; origin recovered",
			"origin", b.name)
	}
	b.state = stateClosed
	b.consecFails = 0
	b.reopens = 0
	b.probes = 0
}

// open transitions to the open state with an exponentially growing,
// fully jittered period. Caller holds b.mu.
func (b *BreakerTransport) open(reasonKey string, reasonVal int) {
	period := b.cfg.OpenBase << b.reopens
	if period > b.cfg.OpenMax || period <= 0 { // <=0 guards shift overflow
		period = b.cfg.OpenMax
	}
	half := period / 2
	period = half + rand.N(half+1)
	b.state = stateOpen
	b.openUntil = time.Now().Add(period)
	b.consecFails = 0
	b.probes = 0
	b.logger.Warn("circuit breaker opened; fast-failing origin",
		"origin", b.name,
		reasonKey, reasonVal,
		"open_for", period.Round(time.Millisecond).String(),
	)
}
