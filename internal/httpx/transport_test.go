package httpx

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
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
	if err != nil {
		t.Fatal(err)
	}
	if err := BufferAndSetGetBody(req); err != nil {
		t.Fatal(err)
	}
	return req
}

func TestRetryTransport_503ThenSuccess_ReplaysPOSTBody(t *testing.T) {
	f := &fakeRT{responses: []fakeResp{
		{status: 503, retryAfter: "0"},
		{status: 200},
	}}
	rt := NewRetryTransport(f, RetryConfig{
		MaxRetries:     3,
		InitialBackoff: 1 * time.Millisecond,
		MaxBackoff:     5 * time.Millisecond,
	})

	req := newPOST(t, "hello")
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("got %d, want 200", resp.StatusCode)
	}
	if len(f.bodies) != 2 {
		t.Fatalf("expected 2 attempts, got %d", len(f.bodies))
	}
	for i, b := range f.bodies {
		if b != "hello" {
			t.Errorf("attempt %d saw body %q, want %q", i, b, "hello")
		}
	}
}

func TestRetryTransport_RetryAfterZero_NoDelay(t *testing.T) {
	f := &fakeRT{responses: []fakeResp{
		{status: 503, retryAfter: "0"},
		{status: 200},
	}}
	rt := NewRetryTransport(f, RetryConfig{
		MaxRetries:     2,
		InitialBackoff: 1 * time.Second, // would dominate without Retry-After
		MaxBackoff:     1 * time.Second,
	})
	start := time.Now()
	resp, err := rt.RoundTrip(newPOST(t, "x"))
	dur := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if dur > 500*time.Millisecond {
		t.Fatalf("Retry-After: 0 should be near-instant; took %s", dur)
	}
}

func TestRetryTransport_RetryAfterOne_Honored(t *testing.T) {
	f := &fakeRT{responses: []fakeResp{
		{status: 503, retryAfter: "1"},
		{status: 200},
	}}
	rt := NewRetryTransport(f, RetryConfig{
		MaxRetries:     2,
		InitialBackoff: 1 * time.Millisecond,
		MaxBackoff:     2 * time.Second,
	})
	start := time.Now()
	resp, err := rt.RoundTrip(newPOST(t, "x"))
	dur := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if dur < 900*time.Millisecond {
		t.Fatalf("Retry-After: 1 should wait ~1s; took %s", dur)
	}
}

func TestRetryTransport_GivesUpAfterMaxRetries(t *testing.T) {
	f := &fakeRT{responses: []fakeResp{
		{status: 503},
		{status: 503},
		{status: 503},
	}}
	rt := NewRetryTransport(f, RetryConfig{
		MaxRetries:     2, // 3 total attempts
		InitialBackoff: 1 * time.Millisecond,
		MaxBackoff:     5 * time.Millisecond,
	})
	resp, err := rt.RoundTrip(newPOST(t, "x"))
	if err == nil {
		resp.Body.Close()
		t.Fatal("expected error after exhausting retries")
	}
	if !strings.Contains(err.Error(), "max retries exceeded") {
		t.Fatalf("err = %v, want max-retries wrapper", err)
	}
	if int(f.attempt.Load()) != 3 {
		t.Fatalf("attempts = %d, want 3", f.attempt.Load())
	}
}

func TestRetryTransport_NoRetryOn4xx(t *testing.T) {
	f := &fakeRT{responses: []fakeResp{
		{status: 404},
	}}
	rt := NewRetryTransport(f, RetryConfig{
		MaxRetries:     3,
		InitialBackoff: 1 * time.Millisecond,
		MaxBackoff:     5 * time.Millisecond,
	})
	resp, err := rt.RoundTrip(newPOST(t, "x"))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 404 {
		t.Fatalf("got %d, want 404", resp.StatusCode)
	}
	if int(f.attempt.Load()) != 1 {
		t.Fatalf("attempts = %d, want 1", f.attempt.Load())
	}
}

func TestRetryTransport_NoRetryOn200(t *testing.T) {
	f := &fakeRT{responses: []fakeResp{{status: 200}}}
	rt := NewRetryTransport(f, RetryConfig{
		MaxRetries:     3,
		InitialBackoff: 1 * time.Millisecond,
		MaxBackoff:     5 * time.Millisecond,
	})
	resp, err := rt.RoundTrip(newPOST(t, "x"))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("got %d, want 200", resp.StatusCode)
	}
	if int(f.attempt.Load()) != 1 {
		t.Fatalf("attempts = %d, want 1", f.attempt.Load())
	}
}

func TestRetryTransport_ContextCancellationAbortsBackoff(t *testing.T) {
	f := &fakeRT{responses: []fakeResp{
		{status: 503}, // forces a backoff before next attempt
		{status: 200},
	}}
	rt := NewRetryTransport(f, RetryConfig{
		MaxRetries:     2,
		InitialBackoff: 500 * time.Millisecond,
		MaxBackoff:     1 * time.Second,
	})

	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"http://example/test", strings.NewReader("x"))
	if err != nil {
		t.Fatal(err)
	}
	if err := BufferAndSetGetBody(req); err != nil {
		t.Fatal(err)
	}

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
		t.Fatal("expected context cancellation error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if dur > 400*time.Millisecond {
		t.Fatalf("cancellation should abort the 500ms backoff fast; took %s", dur)
	}
}

func TestRetryTransport_CustomRetryOn(t *testing.T) {
	// 429 isn't 5xx but listed explicitly; should retry.
	f := &fakeRT{responses: []fakeResp{
		{status: 429, retryAfter: "0"},
		{status: 200},
	}}
	rt := NewRetryTransport(f, RetryConfig{
		MaxRetries:     2,
		InitialBackoff: 1 * time.Millisecond,
		MaxBackoff:     5 * time.Millisecond,
		RetryOn:        []int{429},
	})
	resp, err := rt.RoundTrip(newPOST(t, "x"))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("got %d, want 200", resp.StatusCode)
	}
	if int(f.attempt.Load()) != 2 {
		t.Fatalf("attempts = %d, want 2", f.attempt.Load())
	}
}

func TestRetryTransport_ZeroMaxRetries_PassesThrough(t *testing.T) {
	f := &fakeRT{responses: []fakeResp{{status: 503}}}
	rt := NewRetryTransport(f, RetryConfig{MaxRetries: 0})
	resp, err := rt.RoundTrip(newPOST(t, "x"))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 503 {
		t.Fatalf("got %d, want 503 (no retry)", resp.StatusCode)
	}
	if int(f.attempt.Load()) != 1 {
		t.Fatalf("attempts = %d, want 1", f.attempt.Load())
	}
}

func TestBufferAndSetGetBody(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "http://x", strings.NewReader("payload"))
	if err != nil {
		t.Fatal(err)
	}
	if err := BufferAndSetGetBody(req); err != nil {
		t.Fatal(err)
	}
	if req.GetBody == nil {
		t.Fatal("GetBody not installed")
	}
	if req.ContentLength != int64(len("payload")) {
		t.Fatalf("ContentLength = %d, want %d", req.ContentLength, len("payload"))
	}

	// Drain the first body.
	b1, _ := io.ReadAll(req.Body)
	if string(b1) != "payload" {
		t.Fatalf("first body = %q", b1)
	}

	// Replay via GetBody twice.
	for i := 0; i < 2; i++ {
		rc, err := req.GetBody()
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(rc)
		if string(b) != "payload" {
			t.Fatalf("replay %d body = %q", i, b)
		}
	}
}

func TestBufferAndSetGetBody_NilBody(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "http://x", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := BufferAndSetGetBody(req); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if req.GetBody != nil {
		t.Fatal("GetBody should not be set for nil body")
	}
}
