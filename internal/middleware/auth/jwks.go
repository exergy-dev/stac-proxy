package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// JWKSClientConfig is the optional configuration for NewJWKSClientFromConfig.
// Prefer NewJWKSClient unless you specifically need to override the safe
// defaults (e.g. tests that need to talk to a plain-HTTP httptest server).
type JWKSClientConfig struct {
	HTTPClient *http.Client
	TTL        time.Duration
	// AllowInsecureHTTP bypasses the https-only check. Test-only —
	// production deployments MUST use https://.
	AllowInsecureHTTP bool
}

// JWKSClient fetches and caches a JWKS (JSON Web Key Set) document
// keyed by the JWT `kid` header. Behaviour:
//
//   - Initial Key() call lazily fetches and caches the document.
//   - Cache lifetime is `ttl` (default 1 hour); after expiry the next
//     Key() triggers a refresh.
//   - A cache miss for a known-good URL also forces a refresh — this
//     is the key-rotation path (issuer publishes a new kid before any
//     token uses it).
//   - Concurrent refreshes for the same URL collapse to a single
//     upstream request via singleflight.
type JWKSClient struct {
	url    string
	http   *http.Client
	ttl    time.Duration
	group  singleflight.Group

	mu     sync.RWMutex
	keys   map[string]interface{}
	expiry time.Time
}

// NewJWKSClient constructs a client for the given JWKS URL. httpClient
// may be nil (a 10s-timeout default is used); ttl may be zero (1h
// default). The URL MUST use the https scheme — plaintext JWKS fetches
// are a credential-substitution risk. For tests that need plain HTTP,
// use NewJWKSClientFromConfig with AllowInsecureHTTP=true.
func NewJWKSClient(url string, httpClient *http.Client, ttl time.Duration) (*JWKSClient, error) {
	return NewJWKSClientFromConfig(url, JWKSClientConfig{HTTPClient: httpClient, TTL: ttl})
}

// NewJWKSClientFromConfig is the all-knobs constructor.
func NewJWKSClientFromConfig(url string, cfg JWKSClientConfig) (*JWKSClient, error) {
	if !cfg.AllowInsecureHTTP {
		if !strings.HasPrefix(strings.ToLower(url), "https://") {
			return nil, fmt.Errorf("jwks: URL must use https scheme, got %q", url)
		}
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	ttl := cfg.TTL
	if ttl <= 0 {
		ttl = time.Hour
	}
	return &JWKSClient{url: url, http: httpClient, ttl: ttl, keys: map[string]interface{}{}}, nil
}

// Key returns the public key for the given `kid`, fetching and
// caching the JWKS document as needed. Errors propagate from the
// underlying HTTP call or JWK parsing.
func (c *JWKSClient) Key(ctx context.Context, kid string) (interface{}, error) {
	if k, ok := c.lookup(kid); ok {
		return k, nil
	}
	if err := c.refresh(ctx); err != nil {
		return nil, err
	}
	if k, ok := c.lookup(kid); ok {
		return k, nil
	}
	return nil, fmt.Errorf("jwks: kid %q not present after refresh", kid)
}

func (c *JWKSClient) lookup(kid string) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if time.Now().After(c.expiry) {
		return nil, false
	}
	k, ok := c.keys[kid]
	return k, ok
}

// refresh fetches the JWKS document once, parses every key, and
// swaps it in atomically. Concurrent callers for the same URL share
// the single in-flight request via singleflight.
func (c *JWKSClient) refresh(ctx context.Context) error {
	_, err, _ := c.group.Do("refresh", func() (interface{}, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
		if err != nil {
			return nil, err
		}
		resp, err := c.http.Do(req)
		if err != nil {
			return nil, fmt.Errorf("jwks: fetch %s: %w", c.url, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("jwks: %s returned %d", c.url, resp.StatusCode)
		}
		var doc JWKSResponse
		if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
			return nil, fmt.Errorf("jwks: decode: %w", err)
		}
		out := make(map[string]interface{}, len(doc.Keys))
		for _, jwk := range doc.Keys {
			key, err := parseJWK(jwk)
			if err != nil {
				continue // skip individual bad keys; the rest of the set is still usable
			}
			out[jwk.Kid] = key
		}
		c.mu.Lock()
		c.keys = out
		c.expiry = time.Now().Add(c.ttl)
		c.mu.Unlock()
		return nil, nil
	})
	return err
}
