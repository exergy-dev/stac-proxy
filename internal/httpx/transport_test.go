package httpx

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeRT is a per-test http.RoundTripper that drives a sequence of
// response/error pairs and records the request body each attempt saw.
type fakeRT struct {
	attempt   atomic.Int32
	responses []fakeResp
	bodies    []string
}

type fakeResp struct {
	status     int
	retryAfter string
	err        error
}

func (f *fakeRT) RoundTrip(req *http.Request) (*http.Response, error) {
	i := int(f.attempt.Load())
	f.attempt.Add(1)

	// Record body each attempt saw (drain whatever is in req.Body).
	if req.Body != nil {
		b, _ := io.ReadAll(req.Body)
		f.bodies = append(f.bodies, string(b))
		_ = req.Body.Close()
	} else {
		f.bodies = append(f.bodies, "")
	}

	if i >= len(f.responses) {
		return nil, fmt.Errorf("fakeRT: unexpected attempt %d", i)
	}
	r := f.responses[i]
	if r.err != nil {
		return nil, r.err
	}
	hdr := make(http.Header)
	if r.retryAfter != "" {
		hdr.Set("Retry-After", r.retryAfter)
	}
	return &http.Response{
		StatusCode: r.status,
		Header:     hdr,
		Body:       io.NopCloser(strings.NewReader("")),
		Request:    req,
	}, nil
}

func newPOST(t *testing.T, body string) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost, "http://example/test",
		strings.NewReader(body),
	)
	require.NoError(t, err)
	require.NoError(t, BufferAndSetGetBody(req))
	return req
}

// All retry-on-POST tests below opt in via RetryNonIdempotent: true so
// they continue to exercise the retry semantics they were written for.
// The default-deny behavior is asserted by
// TestRetryTransport_DoesNotRetryPOSTByDefault. (HIGH H-httpx-1)

func TestRetryTransport_503ThenSuccess_ReplaysPOSTBody(t *testing.T) {
	f := &fakeRT{responses: []fakeResp{
		{status: 503, retryAfter: "0"},
		{status: 200},
	}}
	rt := NewRetryTransport(f, RetryConfig{
		MaxRetries:         3,
		InitialBackoff:     1 * time.Millisecond,
		MaxBackoff:         5 * time.Millisecond,
		RetryNonIdempotent: true,
	})

	req := newPOST(t, "hello")
	resp, err := rt.RoundTrip(req)
	require.NoError(t, err, "unexpected err")
	require.Equal(t, 200, resp.StatusCode)
	require.Len(t, f.bodies, 2, "expected 2 attempts")
	for i, b := range f.bodies {
		assert.Equal(t, "hello", b, "attempt %d body", i)
	}
}

func TestRetryTransport_RetryAfterZero_NoDelay(t *testing.T) {
	f := &fakeRT{responses: []fakeResp{
		{status: 503, retryAfter: "0"},
		{status: 200},
	}}
	rt := NewRetryTransport(f, RetryConfig{
		MaxRetries:         2,
		InitialBackoff:     1 * time.Second, // would dominate without Retry-After
		MaxBackoff:         1 * time.Second,
		RetryNonIdempotent: true,
	})
	start := time.Now()
	resp, err := rt.RoundTrip(newPOST(t, "x"))
	dur := time.Since(start)
	require.NoError(t, err)
	resp.Body.Close()
	require.LessOrEqual(t, dur, 500*time.Millisecond, "Retry-After: 0 should be near-instant; took %s", dur)
}

func TestRetryTransport_RetryAfterOne_Honored(t *testing.T) {
	f := &fakeRT{responses: []fakeResp{
		{status: 503, retryAfter: "1"},
		{status: 200},
	}}
	rt := NewRetryTransport(f, RetryConfig{
		MaxRetries:         2,
		InitialBackoff:     1 * time.Millisecond,
		MaxBackoff:         2 * time.Second,
		RetryNonIdempotent: true,
	})
	start := time.Now()
	resp, err := rt.RoundTrip(newPOST(t, "x"))
	dur := time.Since(start)
	require.NoError(t, err)
	resp.Body.Close()
	require.GreaterOrEqual(t, dur, 900*time.Millisecond, "Retry-After: 1 should wait ~1s; took %s", dur)
}

func TestRetryTransport_GivesUpAfterMaxRetries(t *testing.T) {
	f := &fakeRT{responses: []fakeResp{
		{status: 503},
		{status: 503},
		{status: 503},
	}}
	rt := NewRetryTransport(f, RetryConfig{
		MaxRetries:         2, // 3 total attempts
		InitialBackoff:     1 * time.Millisecond,
		MaxBackoff:         5 * time.Millisecond,
		RetryNonIdempotent: true,
	})
	resp, err := rt.RoundTrip(newPOST(t, "x"))
	require.NoError(t, err, "retry exhaustion should surface the final response, not an error")
	resp.Body.Close()
	require.Equal(t, 503, resp.StatusCode, "final status")
	require.Equal(t, int32(3), f.attempt.Load(), "attempts")
}

func TestRetryTransport_NoRetryOn4xx(t *testing.T) {
	f := &fakeRT{responses: []fakeResp{
		{status: 404},
	}}
	rt := NewRetryTransport(f, RetryConfig{
		MaxRetries:         3,
		InitialBackoff:     1 * time.Millisecond,
		MaxBackoff:         5 * time.Millisecond,
		RetryNonIdempotent: true,
	})
	resp, err := rt.RoundTrip(newPOST(t, "x"))
	require.NoError(t, err)
	require.Equal(t, 404, resp.StatusCode)
	require.Equal(t, int32(1), f.attempt.Load(), "attempts")
}

func TestRetryTransport_NoRetryOn200(t *testing.T) {
	f := &fakeRT{responses: []fakeResp{{status: 200}}}
	rt := NewRetryTransport(f, RetryConfig{
		MaxRetries:         3,
		InitialBackoff:     1 * time.Millisecond,
		MaxBackoff:         5 * time.Millisecond,
		RetryNonIdempotent: true,
	})
	resp, err := rt.RoundTrip(newPOST(t, "x"))
	require.NoError(t, err)
	require.Equal(t, 200, resp.StatusCode)
	require.Equal(t, int32(1), f.attempt.Load(), "attempts")
}

func TestRetryTransport_ContextCancellationAbortsBackoff(t *testing.T) {
	f := &fakeRT{responses: []fakeResp{
		{status: 503}, // forces a backoff before next attempt
		{status: 200},
	}}
	rt := NewRetryTransport(f, RetryConfig{
		MaxRetries:         2,
		InitialBackoff:     500 * time.Millisecond,
		MaxBackoff:         1 * time.Second,
		RetryNonIdempotent: true,
	})

	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"http://example/test", strings.NewReader("x"))
	require.NoError(t, err)
	require.NoError(t, BufferAndSetGetBody(req))

	// Cancel shortly after the call starts.
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	resp, err := rt.RoundTrip(req)
	dur := time.Since(start)
	if err == nil {
		resp.Body.Close()
		require.Fail(t, "expected context cancellation error")
	}
	require.ErrorIs(t, err, context.Canceled)
	require.LessOrEqual(t, dur, 400*time.Millisecond, "cancellation should abort the 500ms backoff fast; took %s", dur)
}

func TestRetryTransport_CustomRetryOn(t *testing.T) {
	// 429 isn't 5xx but listed explicitly; should retry.
	f := &fakeRT{responses: []fakeResp{
		{status: 429, retryAfter: "0"},
		{status: 200},
	}}
	rt := NewRetryTransport(f, RetryConfig{
		MaxRetries:         2,
		InitialBackoff:     1 * time.Millisecond,
		MaxBackoff:         5 * time.Millisecond,
		RetryOn:            []int{429},
		RetryNonIdempotent: true,
	})
	resp, err := rt.RoundTrip(newPOST(t, "x"))
	require.NoError(t, err)
	require.Equal(t, 200, resp.StatusCode)
	require.Equal(t, int32(2), f.attempt.Load(), "attempts")
}

func TestRetryTransport_ZeroMaxRetries_PassesThrough(t *testing.T) {
	// MaxRetries: 0 returns the inner transport directly, so this case
	// is unaffected by the POST/PATCH gating.
	f := &fakeRT{responses: []fakeResp{{status: 503}}}
	rt := NewRetryTransport(f, RetryConfig{MaxRetries: 0})
	resp, err := rt.RoundTrip(newPOST(t, "x"))
	require.NoError(t, err)
	require.Equal(t, 503, resp.StatusCode, "no retry")
	require.Equal(t, int32(1), f.attempt.Load(), "attempts")
}

// TestRetryTransport_DoesNotRetryPOSTByDefault (HIGH H-httpx-1):
// without the RetryNonIdempotent opt-in, a failing POST must NOT be
// retried even though the configuration would otherwise allow it.
// Otherwise the federation /search path (POST) and any other
// non-idempotent upstream call could be silently re-applied after a
// transport hiccup, producing duplicate side effects.
//
// Uses an httptest.Server so the test exercises the real
// http.DefaultTransport path (the default `inner` for
// NewRetryTransport) end-to-end, not just the fakeRT.
func TestRetryTransport_DoesNotRetryPOSTByDefault(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hits.Add(1)
		if n == 1 {
			http.Error(w, "boom", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	rt := NewRetryTransport(http.DefaultTransport, RetryConfig{
		MaxRetries:     3,
		InitialBackoff: 1 * time.Millisecond,
		MaxBackoff:     5 * time.Millisecond,
		// RetryNonIdempotent intentionally false (the default).
	})

	req, err := http.NewRequest(http.MethodPost, srv.URL, strings.NewReader("payload"))
	require.NoError(t, err)
	require.NoError(t, BufferAndSetGetBody(req))

	resp, err := rt.RoundTrip(req)
	require.NoError(t, err, "unexpected err")
	resp.Body.Close()

	assert.Equal(t, int32(1), hits.Load(), "upstream attempts (POST must not be retried by default)")
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode, "first failure surfaced as-is")
}

// TestRetryTransport_RetriesPOSTWhenOptedIn covers the opt-in path:
// when RetryNonIdempotent is true, a POST that initially fails with
// 503 IS retried and the second attempt's success is returned.
func TestRetryTransport_RetriesPOSTWhenOptedIn(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hits.Add(1)
		if n == 1 {
			http.Error(w, "transient", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	rt := NewRetryTransport(http.DefaultTransport, RetryConfig{
		MaxRetries:         3,
		InitialBackoff:     1 * time.Millisecond,
		MaxBackoff:         5 * time.Millisecond,
		RetryNonIdempotent: true,
	})

	req, err := http.NewRequest(http.MethodPost, srv.URL, strings.NewReader("payload"))
	require.NoError(t, err)
	require.NoError(t, BufferAndSetGetBody(req))

	resp, err := rt.RoundTrip(req)
	require.NoError(t, err, "unexpected err")
	resp.Body.Close()

	assert.Equal(t, int32(2), hits.Load(), "upstream attempts (POST should retry when opted in)")
	assert.Equal(t, http.StatusOK, resp.StatusCode, "retry recovered")
}

// TestRetryTransport_StillRetriesGETByDefault is a sanity check: the
// no-POST/PATCH-by-default policy must not regress idempotent-method
// retries.
func TestRetryTransport_StillRetriesGETByDefault(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hits.Add(1)
		if n == 1 {
			http.Error(w, "transient", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	rt := NewRetryTransport(http.DefaultTransport, RetryConfig{
		MaxRetries:     3,
		InitialBackoff: 1 * time.Millisecond,
		MaxBackoff:     5 * time.Millisecond,
	})

	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	require.NoError(t, err)
	resp, err := rt.RoundTrip(req)
	require.NoError(t, err, "unexpected err")
	resp.Body.Close()

	assert.Equal(t, int32(2), hits.Load(), "upstream attempts (GET should still retry)")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestBufferAndSetGetBody(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "http://x", strings.NewReader("payload"))
	require.NoError(t, err)
	require.NoError(t, BufferAndSetGetBody(req))
	require.NotNil(t, req.GetBody, "GetBody not installed")
	require.Equal(t, int64(len("payload")), req.ContentLength, "ContentLength")

	// Drain the first body.
	b1, _ := io.ReadAll(req.Body)
	require.Equal(t, "payload", string(b1), "first body")

	// Replay via GetBody twice.
	for i := 0; i < 2; i++ {
		rc, err := req.GetBody()
		require.NoError(t, err)
		b, _ := io.ReadAll(rc)
		require.Equal(t, "payload", string(b), "replay %d body", i)
	}
}

func TestBufferAndSetGetBody_NilBody(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "http://x", nil)
	require.NoError(t, err)
	require.NoError(t, BufferAndSetGetBody(req), "unexpected err")
	require.Nil(t, req.GetBody, "GetBody should not be set for nil body")
}
