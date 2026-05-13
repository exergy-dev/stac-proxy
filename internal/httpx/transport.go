// Package httpx provides shared HTTP utilities (retrying transport,
// hop-by-hop header stripping, X-Forwarded-* header propagation, and
// a buffering ResponseWriter) used by the proxy and federation
// packages. Stdlib only.
package httpx

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// RetryConfig controls the retry behavior of NewRetryTransport.
//
// MaxRetries is the number of retries after the initial attempt
// (so total attempts == MaxRetries+1 when at least one retry fires).
// InitialBackoff is the first inter-attempt delay; the delay doubles
// each iteration and is capped at MaxBackoff.
// RetryOn lists the HTTP status codes that should trigger a retry; if
// nil/empty all 5xx responses are retried.
type RetryConfig struct {
	MaxRetries     int
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
	RetryOn        []int
}

// NewRetryTransport wraps inner with retry semantics: bounded
// exponential backoff capped at MaxBackoff; upstream Retry-After
// (delta-seconds form) takes precedence over the next backoff
// iteration; body replay via req.GetBody if set; default RetryOn = all
// 5xx; returns the first non-retryable response (success or 4xx) OR
// the last error after MaxRetries.
//
// If inner is nil, http.DefaultTransport is used.
func NewRetryTransport(inner http.RoundTripper, cfg RetryConfig) http.RoundTripper {
	if inner == nil {
		inner = http.DefaultTransport
	}
	return &retryTransport{inner: inner, cfg: cfg}
}

type retryTransport struct {
	inner http.RoundTripper
	cfg   RetryConfig
}

// RoundTrip implements http.RoundTripper.
//
// The body (if any) is replayed via req.GetBody before each retry
// attempt (never before the first attempt — the caller already supplied
// req.Body for that). An upstream Retry-After header in delta-seconds
// form is honored for the next iteration in preference to the
// exponential schedule.
func (t *retryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx := req.Context()

	// If retries are disabled, behave as a transparent pass-through.
	if t.cfg.MaxRetries <= 0 {
		return t.inner.RoundTrip(req)
	}

	var lastErr error
	backoff := t.cfg.InitialBackoff
	nextDelay := backoff

	for attempt := 0; attempt <= t.cfg.MaxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(nextDelay):
				backoff = minDuration(backoff*2, t.cfg.MaxBackoff)
				nextDelay = backoff
			}
			if req.GetBody != nil {
				rc, err := req.GetBody()
				if err != nil {
					return nil, fmt.Errorf("rewind request body for retry: %w", err)
				}
				req.Body = rc
			}
		}

		resp, err := t.inner.RoundTrip(req)
		if err != nil {
			lastErr = err
			continue
		}

		if !t.shouldRetry(resp.StatusCode) {
			return resp, nil
		}

		// Honor upstream Retry-After (delta-seconds form) for the next
		// attempt, in preference to the exponential schedule.
		if ra := resp.Header.Get("Retry-After"); ra != "" {
			if secs, perr := strconv.Atoi(ra); perr == nil && secs >= 0 {
				d := time.Duration(secs) * time.Second
				if t.cfg.MaxBackoff > 0 && d > t.cfg.MaxBackoff {
					d = t.cfg.MaxBackoff
				}
				nextDelay = d
			}
		}

		resp.Body.Close()
		lastErr = fmt.Errorf("received status %d", resp.StatusCode)
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("retry transport: no attempts made")
	}
	return nil, fmt.Errorf("max retries exceeded: %w", lastErr)
}

func (t *retryTransport) shouldRetry(statusCode int) bool {
	if len(t.cfg.RetryOn) == 0 {
		return statusCode >= 500
	}
	for _, code := range t.cfg.RetryOn {
		if statusCode == code {
			return true
		}
	}
	return false
}

// BufferAndSetGetBody reads req.Body into a []byte once and installs
// req.GetBody so RetryTransport (or http.Client) can replay it.
// No-op when req.Body == nil. Caller still owns the (now-buffered)
// request.
func BufferAndSetGetBody(req *http.Request) error {
	if req == nil || req.Body == nil {
		return nil
	}
	b, err := io.ReadAll(req.Body)
	if err != nil {
		_ = req.Body.Close()
		return fmt.Errorf("buffer request body: %w", err)
	}
	if cerr := req.Body.Close(); cerr != nil {
		return fmt.Errorf("close request body: %w", cerr)
	}
	req.Body = io.NopCloser(bytes.NewReader(b))
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(b)), nil
	}
	// Keep ContentLength accurate for the replayed body.
	req.ContentLength = int64(len(b))
	return nil
}

func minDuration(a, b time.Duration) time.Duration {
	if b <= 0 {
		return a
	}
	if a < b {
		return a
	}
	return b
}
