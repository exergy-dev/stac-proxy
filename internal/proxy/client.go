// Package proxy provides the single-origin proxy handler.
package proxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/yourorg/stac-proxy/internal/middleware"
)

// forwardedFromKey carries the originating request's identity through
// context so the client can populate X-Forwarded-* on the outbound
// request — without having to thread a *http.Request through every
// call site.
type forwardedFromKeyType struct{}

var forwardedFromKey forwardedFromKeyType

type forwardedFrom struct {
	remoteAddr string
	proto      string
	host       string
}

// withForwardedFrom attaches the originating request's identity (used
// for X-Forwarded-*) to ctx.
func withForwardedFrom(ctx context.Context, req *http.Request) context.Context {
	scheme := "http"
	if req.TLS != nil {
		scheme = "https"
	}
	if v := req.Header.Get("X-Forwarded-Proto"); v != "" {
		// Trusted upstream may have set this — preserve.
		scheme = v
	}
	return context.WithValue(ctx, forwardedFromKey, forwardedFrom{
		remoteAddr: req.RemoteAddr,
		proto:      scheme,
		host:       req.Host,
	})
}

// applyForwardedHeaders sets X-Forwarded-{For,Proto,Host} on req based
// on the identity captured by withForwardedFrom. No-op if ctx carries
// no identity (e.g. unit tests that call client.Do directly).
func applyForwardedHeaders(ctx context.Context, req *http.Request) {
	v, ok := ctx.Value(forwardedFromKey).(forwardedFrom)
	if !ok {
		return
	}
	if v.remoteAddr != "" {
		clientIP, _, err := net.SplitHostPort(v.remoteAddr)
		if err != nil {
			clientIP = v.remoteAddr
		}
		// Append to existing chain if any.
		if prior := req.Header.Get("X-Forwarded-For"); prior != "" {
			req.Header.Set("X-Forwarded-For", prior+", "+clientIP)
		} else {
			req.Header.Set("X-Forwarded-For", clientIP)
		}
	}
	if v.proto != "" {
		req.Header.Set("X-Forwarded-Proto", v.proto)
	}
	if v.host != "" {
		req.Header.Set("X-Forwarded-Host", v.host)
	}
}

// Client is an HTTP client for communicating with an upstream STAC server.
type Client struct {
	httpClient *http.Client
	baseURL    *url.URL
	timeout    time.Duration
	retry      *RetryConfig
}

// RetryConfig contains retry settings.
type RetryConfig struct {
	MaxRetries     int
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
	RetryOn        []int
}

// ClientOption is a function that configures a Client.
type ClientOption func(*Client)

// WithTimeout sets the client timeout.
func WithTimeout(timeout time.Duration) ClientOption {
	return func(c *Client) {
		c.timeout = timeout
		c.httpClient.Timeout = timeout
	}
}

// WithRetry sets the retry configuration.
func WithRetry(config *RetryConfig) ClientOption {
	return func(c *Client) {
		c.retry = config
	}
}

// WithTransport sets a custom HTTP transport.
func WithTransport(transport http.RoundTripper) ClientOption {
	return func(c *Client) {
		c.httpClient.Transport = transport
	}
}

// WithMaxIdleConnsPerHost tunes the upstream connection pool. The
// default (10) is too low for a proxy under load; production
// deployments should set this to 100+ and tune empirically.
func WithMaxIdleConnsPerHost(n int) ClientOption {
	return func(c *Client) {
		if t, ok := c.httpClient.Transport.(*http.Transport); ok && n > 0 {
			t.MaxIdleConnsPerHost = n
		}
	}
}

// NewClient creates a new proxy client.
func NewClient(baseURL string, opts ...ClientOption) (*Client, error) {
	if baseURL == "" {
		return nil, fmt.Errorf("invalid base URL: must not be empty")
	}
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}

	c := &Client{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     90 * time.Second,
			},
		},
		baseURL: parsed,
		timeout: 30 * time.Second,
	}

	for _, opt := range opts {
		opt(c)
	}

	return c, nil
}

// Do executes an HTTP request to the upstream server. `path` may
// include a query string (e.g. "/items?limit=10"); it's parsed so the
// query is preserved when resolving against the base URL rather than
// being escaped into the path component.
//
// When a retry policy is configured and a body is supplied, the body is
// buffered so retries can replay it; http.Client honors req.GetBody for
// this purpose, so it is wired here.
func (c *Client) Do(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	ref, err := url.Parse(path)
	if err != nil {
		return nil, fmt.Errorf("invalid path %q: %w", path, err)
	}
	reqURL := c.baseURL.ResolveReference(ref)

	retryable := c.retry != nil && c.retry.MaxRetries > 0
	var bodyBuf []byte
	if retryable && body != nil {
		bodyBuf, err = io.ReadAll(body)
		if err != nil {
			return nil, fmt.Errorf("buffer request body for retry: %w", err)
		}
		body = bytes.NewReader(bodyBuf)
	}

	req, err := http.NewRequestWithContext(ctx, method, reqURL.String(), body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	if retryable && bodyBuf != nil {
		req.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(bodyBuf)), nil
		}
	}

	req.Header.Set("Accept", "application/geo+json, application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	middleware.ForwardRequestID(ctx, req)
	applyForwardedHeaders(ctx, req)

	if retryable {
		return c.doWithRetry(ctx, req)
	}

	return c.httpClient.Do(req)
}

// doWithRetry executes the request with retry logic. The request body
// (if any) is replayed via req.GetBody before each retry, and an
// upstream-provided Retry-After header is honored in preference to the
// exponential-backoff schedule for the next iteration.
func (c *Client) doWithRetry(ctx context.Context, req *http.Request) (*http.Response, error) {
	var lastErr error
	backoff := c.retry.InitialBackoff
	nextDelay := backoff

	for attempt := 0; attempt <= c.retry.MaxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(nextDelay):
				backoff = min(backoff*2, c.retry.MaxBackoff)
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

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		if !c.shouldRetry(resp.StatusCode) {
			return resp, nil
		}

		// Honor upstream Retry-After (delta-seconds form) for the next attempt.
		if ra := resp.Header.Get("Retry-After"); ra != "" {
			if secs, perr := strconv.Atoi(ra); perr == nil && secs >= 0 {
				d := time.Duration(secs) * time.Second
				if d > c.retry.MaxBackoff {
					d = c.retry.MaxBackoff
				}
				nextDelay = d
			}
		}

		resp.Body.Close()
		lastErr = fmt.Errorf("received status %d", resp.StatusCode)
	}

	return nil, fmt.Errorf("max retries exceeded: %w", lastErr)
}

// shouldRetry checks if the status code should trigger a retry.
func (c *Client) shouldRetry(statusCode int) bool {
	if c.retry == nil || len(c.retry.RetryOn) == 0 {
		// Default: retry on 5xx errors
		return statusCode >= 500
	}
	for _, code := range c.retry.RetryOn {
		if statusCode == code {
			return true
		}
	}
	return false
}

// Get performs a GET request.
func (c *Client) Get(ctx context.Context, path string) (*http.Response, error) {
	return c.Do(ctx, http.MethodGet, path, nil)
}

// Post performs a POST request.
func (c *Client) Post(ctx context.Context, path string, body io.Reader) (*http.Response, error) {
	return c.Do(ctx, http.MethodPost, path, body)
}

// BaseURL returns the client's base URL.
func (c *Client) BaseURL() string {
	return c.baseURL.String()
}

// min returns the smaller of two durations.
func min(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
