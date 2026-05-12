// Package proxy provides the single-origin proxy handler.
package proxy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/yourorg/stac-proxy/internal/middleware"
)

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
func (c *Client) Do(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	ref, err := url.Parse(path)
	if err != nil {
		return nil, fmt.Errorf("invalid path %q: %w", path, err)
	}
	reqURL := c.baseURL.ResolveReference(ref)

	req, err := http.NewRequestWithContext(ctx, method, reqURL.String(), body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/geo+json, application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	// Forward the inbound request ID so logs across the proxy and
	// upstream can be correlated. Falls through silently if no
	// request ID is in context.
	if rid, ok := ctx.Value(middleware.RequestIDKey).(string); ok && rid != "" {
		req.Header.Set("X-Request-ID", rid)
	}

	if c.retry != nil && c.retry.MaxRetries > 0 {
		return c.doWithRetry(ctx, req)
	}

	return c.httpClient.Do(req)
}

// doWithRetry executes the request with retry logic.
func (c *Client) doWithRetry(ctx context.Context, req *http.Request) (*http.Response, error) {
	var lastErr error
	backoff := c.retry.InitialBackoff

	for attempt := 0; attempt <= c.retry.MaxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
				backoff = min(backoff*2, c.retry.MaxBackoff)
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
