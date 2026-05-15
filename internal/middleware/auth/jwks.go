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
	// MinRefreshInterval is the minimum time between JWKS refreshes
	// triggered by an unknown kid. Default: 30s. Without this floor an
	// attacker can flood the IdP by presenting tokens with random kid
	// values; singleflight collapses concurrent requests but does
	// nothing for serial bursts.
	MinRefreshInterval time.Duration
	// NegativeCacheTTL is how long an "unknown kid" answer is cached
	// before we'll consider another refresh for that kid. Default:
	// 60s. Invalidated immediately on any successful refresh so key
	// rotation isn't delayed.
	NegativeCacheTTL time.Duration
	// now is an injectable clock for tests. nil → time.Now.
	now func() time.Time
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
	url   string
	http  *http.Client
	ttl   time.Duration
	group singleflight.Group

	// minRefreshInterval and negCacheTTL throttle the "unknown kid →
	// refresh" path. See JWKSClientConfig for rationale.
	minRefreshInterval time.Duration
	negCacheTTL        time.Duration
	now                func() time.Time

	mu     sync.RWMutex
	keys   map[string]interface{}
	expiry time.Time
	// lastRefreshAttempt tracks when refresh() last ran (success OR
	// failure), so unknown-kid lookups can short-circuit until the
	// floor elapses.
	lastRefreshAttempt time.Time
	// negKids holds kids that were absent from the JWKS document at
	// the listed time + negCacheTTL. Cleared on every successful
	// refresh so rotation isn't delayed.
	negKids map[string]time.Time
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
	minRefresh := cfg.MinRefreshInterval
	if minRefresh <= 0 {
		minRefresh = 30 * time.Second
	}
	negTTL := cfg.NegativeCacheTTL
	if negTTL <= 0 {
		negTTL = 60 * time.Second
	}
	now := cfg.now
	if now == nil {
		now = time.Now
	}
	return &JWKSClient{
		url:                url,
		http:               httpClient,
		ttl:                ttl,
		minRefreshInterval: minRefresh,
		negCacheTTL:        negTTL,
		now:                now,
		keys:               map[string]interface{}{},
		negKids:            map[string]time.Time{},
	}, nil
}

// Key returns the public key for the given `kid`, fetching and
// caching the JWKS document as needed. Errors propagate from the
// underlying HTTP call or JWK parsing.
//
// To prevent unknown-kid floods (an attacker streams tokens with random
// kid values to force unbounded JWKS fetches against the IdP), this
// path is throttled by:
//   - a minimum-refresh-interval floor: if the previous refresh
//     happened within MinRefreshInterval and the kid is still absent,
//     return "kid not found" without a network call;
//   - a short negative cache: an unknown kid is cached for
//     NegativeCacheTTL. The negative cache is cleared on any
//     successful refresh so genuine key rotation isn't delayed.
func (c *JWKSClient) Key(ctx context.Context, kid string) (interface{}, error) {
	if k, ok := c.lookup(kid); ok {
		return k, nil
	}
	if c.shouldShortCircuit(kid) {
		return nil, fmt.Errorf("jwks: kid %q not present (negative-cached)", kid)
	}
	if err := c.refresh(ctx); err != nil {
		return nil, err
	}
	if k, ok := c.lookup(kid); ok {
		return k, nil
	}
	c.markNegative(kid)
	return nil, fmt.Errorf("jwks: kid %q not present after refresh", kid)
}

func (c *JWKSClient) lookup(kid string) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.now().After(c.expiry) {
		return nil, false
	}
	k, ok := c.keys[kid]
	return k, ok
}

// shouldShortCircuit returns true when an unknown-kid lookup must NOT
// trigger a network refresh: either the kid is in the negative cache
// (still within negCacheTTL) or the last refresh attempt is within
// MinRefreshInterval.
func (c *JWKSClient) shouldShortCircuit(kid string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	now := c.now()
	if expiry, ok := c.negKids[kid]; ok && now.Before(expiry) {
		return true
	}
	if !c.lastRefreshAttempt.IsZero() && now.Sub(c.lastRefreshAttempt) < c.minRefreshInterval {
		return true
	}
	return false
}

func (c *JWKSClient) markNegative(kid string) {
	c.mu.Lock()
	c.negKids[kid] = c.now().Add(c.negCacheTTL)
	c.mu.Unlock()
}

// refresh fetches the JWKS document once, parses every key, and
// swaps it in atomically. Concurrent callers for the same URL share
// the single in-flight request via singleflight.
func (c *JWKSClient) refresh(ctx context.Context) error {
	_, err, _ := c.group.Do("refresh", func() (interface{}, error) {
		// Record the attempt regardless of outcome so the
		// MinRefreshInterval floor applies to failures too.
		c.mu.Lock()
		c.lastRefreshAttempt = c.now()
		c.mu.Unlock()

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
		c.expiry = c.now().Add(c.ttl)
		// A successful refresh clears the negative cache: a kid that
		// was absent before may have just been published (rotation).
		c.negKids = map[string]time.Time{}
		c.mu.Unlock()
		return nil, nil
	})
	return err
}
