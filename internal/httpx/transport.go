// Package httpx provides shared HTTP utilities used by the proxy and
// federation packages.
package httpx

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/hashicorp/go-retryablehttp"
)

// RetryConfig controls the retry behavior of NewRetryTransport.
//
// MaxRetries is the number of retries after the initial attempt (so
// total attempts == MaxRetries+1 when at least one retry fires).
// InitialBackoff is the minimum inter-attempt delay; the delay grows
// exponentially and is capped at MaxBackoff. RetryOn lists the HTTP
// status codes that should trigger a retry; if nil/empty, all 5xx
// responses are retried (network errors always retry).
//
// RetryNonIdempotent opts in to retrying methods that may not be
// safe to replay. By default POST and PATCH are NOT retried even on
// transport errors or 5xx -- the transport cannot, in general, know
// whether a non-idempotent request was actually applied upstream
// before the connection failed, and replaying it can produce
// duplicate side effects (double-write, double-charge, etc.).
// Set RetryNonIdempotent=true ONLY when the upstream contract for
// these methods is known to be idempotent (e.g. a STAC search
// endpoint that the operator has verified is read-only).
// (HIGH H-httpx-1)
type RetryConfig struct {
	MaxRetries         int
	InitialBackoff     time.Duration
	MaxBackoff         time.Duration
	RetryOn            []int
	RetryNonIdempotent bool
}

// NewRetryTransport wraps inner with retry semantics backed by
// hashicorp/go-retryablehttp: bounded exponential backoff capped at
// MaxBackoff, upstream Retry-After honored for the next iteration,
// body replay via req.GetBody (or library-managed buffering when
// GetBody is absent). Returns the first non-retryable response
// (success or 4xx) OR the last response/error after MaxRetries.
//
// Non-idempotent methods (POST, PATCH) bypass the retry layer
// entirely by default and go straight to inner.RoundTrip -- see
// RetryConfig.RetryNonIdempotent for the safety rationale.
// (HIGH H-httpx-1)
//
// If inner is nil, http.DefaultTransport is used.
func NewRetryTransport(inner http.RoundTripper, cfg RetryConfig) http.RoundTripper {
	if inner == nil {
		inner = http.DefaultTransport
	}
	if cfg.MaxRetries <= 0 {
		return inner
	}

	rc := retryablehttp.NewClient()
	rc.HTTPClient = &http.Client{Transport: inner}
	rc.RetryMax = cfg.MaxRetries
	rc.RetryWaitMin = cfg.InitialBackoff
	rc.RetryWaitMax = cfg.MaxBackoff
	rc.Logger = nil
	rc.CheckRetry = checkRetryFunc(cfg.RetryOn)
	rc.ErrorHandler = retryablehttp.PassthroughErrorHandler

	retryRT := &retryablehttp.RoundTripper{Client: rc}
	if cfg.RetryNonIdempotent {
		return retryRT
	}
	return &methodGatedTransport{retry: retryRT, passthrough: inner}
}

// methodGatedTransport routes idempotent methods through the retry
// layer and non-idempotent methods (POST, PATCH) directly to the
// underlying transport. This is the default safety posture: we
// cannot, in general, know whether a non-idempotent request that
// failed mid-flight was already applied upstream, so replaying it
// risks duplicate side effects (double-write, double-charge, etc.).
// (HIGH H-httpx-1)
type methodGatedTransport struct {
	retry       http.RoundTripper
	passthrough http.RoundTripper
}

func (t *methodGatedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	switch req.Method {
	case http.MethodPost, http.MethodPatch:
		return t.passthrough.RoundTrip(req)
	default:
		return t.retry.RoundTrip(req)
	}
}

// checkRetryFunc returns a retryablehttp.CheckRetry that retries on
// any RoundTrip error AND on either (a) any status in retryOn when
// non-empty, or (b) any 5xx response otherwise. Context cancellation
// short-circuits without retry.
//
// Method-level safety (the don't-retry-POST/PATCH default) is enforced
// upstream of this function by methodGatedTransport in
// NewRetryTransport -- see HIGH H-httpx-1.
func checkRetryFunc(retryOn []int) retryablehttp.CheckRetry {
	return func(ctx context.Context, resp *http.Response, err error) (bool, error) {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		if err != nil {
			return true, nil
		}
		if len(retryOn) == 0 {
			return resp.StatusCode >= 500, nil
		}
		for _, code := range retryOn {
			if resp.StatusCode == code {
				return true, nil
			}
		}
		return false, nil
	}
}

// BufferAndSetGetBody reads req.Body into a []byte once and installs
// req.GetBody so retry transports (or http.Client) can replay it.
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
	req.ContentLength = int64(len(b))
	return nil
}
