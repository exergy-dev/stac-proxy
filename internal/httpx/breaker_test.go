package httpx

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// scriptedRT returns queued outcomes in order, repeating the last one.
type scriptedRT struct {
	outcomes []scriptedOutcome
	calls    int
}

type scriptedOutcome struct {
	status int
	err    error
}

func (s *scriptedRT) RoundTrip(*http.Request) (*http.Response, error) {
	i := s.calls
	if i >= len(s.outcomes) {
		i = len(s.outcomes) - 1
	}
	s.calls++
	o := s.outcomes[i]
	if o.err != nil {
		return nil, o.err
	}
	return &http.Response{
		StatusCode: o.status,
		Body:       io.NopCloser(strings.NewReader("")),
		Header:     http.Header{},
	}, nil
}

func repeat(o scriptedOutcome, n int) []scriptedOutcome {
	out := make([]scriptedOutcome, n)
	for i := range out {
		out[i] = o
	}
	return out
}

func newReq(t *testing.T) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "http://origin.test/search", nil)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func TestBreaker_OpensAfterConsecutiveFailures(t *testing.T) {
	t.Parallel()
	inner := &scriptedRT{outcomes: repeat(scriptedOutcome{err: errors.New("dial refused")}, 10)}
	b := NewBreakerTransport(inner, "usgs", BreakerConfig{FailureThreshold: 3, OpenBase: time.Hour}, nil)

	for i := 0; i < 3; i++ {
		_, err := b.RoundTrip(newReq(t))
		if err == nil || errors.Is(err, ErrCircuitOpen) {
			t.Fatalf("request %d: want live upstream error, got %v", i, err)
		}
	}
	// Threshold reached: next request must fast-fail without dialing.
	_, err := b.RoundTrip(newReq(t))
	if !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("want ErrCircuitOpen after threshold, got %v", err)
	}
	if inner.calls != 3 {
		t.Fatalf("inner must not be dialed while open; calls=%d", inner.calls)
	}
}

func TestBreaker_5xxCountsCanceledDoesNot(t *testing.T) {
	t.Parallel()
	t.Run("5xx opens", func(t *testing.T) {
		inner := &scriptedRT{outcomes: repeat(scriptedOutcome{status: 502}, 10)}
		b := NewBreakerTransport(inner, "o", BreakerConfig{FailureThreshold: 2, OpenBase: time.Hour}, nil)
		for i := 0; i < 2; i++ {
			resp, err := b.RoundTrip(newReq(t))
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
		}
		if _, err := b.RoundTrip(newReq(t)); !errors.Is(err, ErrCircuitOpen) {
			t.Fatalf("want open after 5xx run, got %v", err)
		}
	})
	t.Run("canceled is neutral", func(t *testing.T) {
		inner := &scriptedRT{outcomes: repeat(scriptedOutcome{err: context.Canceled}, 10)}
		b := NewBreakerTransport(inner, "o", BreakerConfig{FailureThreshold: 2, OpenBase: time.Hour}, nil)
		for i := 0; i < 10; i++ {
			_, _ = b.RoundTrip(newReq(t))
		}
		if inner.calls != 10 {
			t.Fatalf("canceled requests must keep flowing; calls=%d", inner.calls)
		}
	})
	t.Run("deadline exceeded counts", func(t *testing.T) {
		inner := &scriptedRT{outcomes: repeat(scriptedOutcome{err: context.DeadlineExceeded}, 10)}
		b := NewBreakerTransport(inner, "o", BreakerConfig{FailureThreshold: 2, OpenBase: time.Hour}, nil)
		_, _ = b.RoundTrip(newReq(t))
		_, _ = b.RoundTrip(newReq(t))
		if _, err := b.RoundTrip(newReq(t)); !errors.Is(err, ErrCircuitOpen) {
			t.Fatalf("timeouts must open the circuit, got %v", err)
		}
	})
	t.Run("4xx and 429 do not count", func(t *testing.T) {
		inner := &scriptedRT{outcomes: repeat(scriptedOutcome{status: 429}, 10)}
		b := NewBreakerTransport(inner, "o", BreakerConfig{FailureThreshold: 2, OpenBase: time.Hour}, nil)
		for i := 0; i < 10; i++ {
			resp, err := b.RoundTrip(newReq(t))
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
		}
		if inner.calls != 10 {
			t.Fatalf("4xx must not trip the breaker; calls=%d", inner.calls)
		}
	})
}

func TestBreaker_HalfOpenRecovery(t *testing.T) {
	t.Parallel()
	// 2 failures open the circuit; the probe after the open period
	// succeeds and closes it.
	outcomes := append(repeat(scriptedOutcome{err: errors.New("down")}, 2),
		repeat(scriptedOutcome{status: 200}, 10)...)
	inner := &scriptedRT{outcomes: outcomes}
	b := NewBreakerTransport(inner, "o", BreakerConfig{
		FailureThreshold: 2,
		OpenBase:         20 * time.Millisecond,
		OpenMax:          40 * time.Millisecond,
	}, nil)

	_, _ = b.RoundTrip(newReq(t))
	_, _ = b.RoundTrip(newReq(t))
	if _, err := b.RoundTrip(newReq(t)); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("want open, got %v", err)
	}

	time.Sleep(45 * time.Millisecond) // past the jittered open period

	resp, err := b.RoundTrip(newReq(t)) // half-open probe → success → closed
	if err != nil {
		t.Fatalf("probe should pass: %v", err)
	}
	resp.Body.Close()

	resp, err = b.RoundTrip(newReq(t)) // closed again
	if err != nil {
		t.Fatalf("circuit should be closed after successful probe: %v", err)
	}
	resp.Body.Close()
}

func TestBreaker_FailedProbeReopensLonger(t *testing.T) {
	t.Parallel()
	inner := &scriptedRT{outcomes: repeat(scriptedOutcome{err: errors.New("down")}, 100)}
	base := 20 * time.Millisecond
	b := NewBreakerTransport(inner, "o", BreakerConfig{
		FailureThreshold: 1,
		OpenBase:         base,
		OpenMax:          time.Hour,
	}, nil)

	_, _ = b.RoundTrip(newReq(t)) // opens (reopens=0, period ~[10,20]ms)
	time.Sleep(25 * time.Millisecond)
	_, err := b.RoundTrip(newReq(t)) // half-open probe → fails → re-open doubled
	if errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("probe should have been admitted, got fast-fail")
	}

	b.mu.Lock()
	remaining := time.Until(b.openUntil)
	reopens := b.reopens
	b.mu.Unlock()
	if reopens != 1 {
		t.Fatalf("want reopens=1 after failed probe, got %d", reopens)
	}
	if remaining <= base/2 {
		t.Fatalf("re-open period must grow (remaining %v, base %v)", remaining, base)
	}
}

func TestBreaker_HalfOpenAdmitsLimitedProbes(t *testing.T) {
	t.Parallel()
	blockCh := make(chan struct{})
	inner := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		<-blockCh
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{}}, nil
	})
	b := NewBreakerTransport(inner, "o", BreakerConfig{
		FailureThreshold: 1,
		OpenBase:         time.Nanosecond, // immediately eligible for half-open
		HalfOpenProbes:   1,
	}, nil)
	// Force the open-and-eligible-for-probe state directly.
	b.mu.Lock()
	b.state = stateOpen
	b.openUntil = time.Now().Add(-time.Millisecond)
	b.mu.Unlock()

	probeDone := make(chan error, 1)
	go func() {
		resp, err := b.RoundTrip(newReq(t))
		if resp != nil {
			resp.Body.Close()
		}
		probeDone <- err
	}()
	// Give the probe a moment to occupy the slot.
	time.Sleep(10 * time.Millisecond)
	_, err := b.RoundTrip(newReq(t))
	if !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("second request during half-open probe must fast-fail, got %v", err)
	}
	close(blockCh)
	if err := <-probeDone; err != nil {
		t.Fatalf("probe failed: %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
