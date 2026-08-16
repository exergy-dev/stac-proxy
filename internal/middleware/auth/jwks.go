package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// JWKSResponse represents the JWKS response.
type JWKSResponse struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a JSON Web Key.
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// parseJWK parses a JWK into a crypto key.
func parseJWK(jwk JWK) (interface{}, error) {
	switch jwk.Kty {
	case "RSA":
		return parseRSAKey(jwk)
	case "EC":
		return parseECKey(jwk)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", jwk.Kty)
	}
}

// parseRSAKey reconstructs an *rsa.PublicKey from a JWK (RFC 7518 §6.3.1).
func parseRSAKey(jwk JWK) (interface{}, error) {
	if jwk.N == "" || jwk.E == "" {
		return nil, errors.New("RSA JWK missing n or e")
	}
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("RSA n decode: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("RSA e decode: %w", err)
	}
	e := 0
	for _, b := range eBytes {
		e = e<<8 | int(b)
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}, nil
}

// parseECKey reconstructs an *ecdsa.PublicKey from a JWK (RFC 7518 §6.2.1).
func parseECKey(jwk JWK) (interface{}, error) {
	if jwk.X == "" || jwk.Y == "" || jwk.Crv == "" {
		return nil, errors.New("EC JWK missing x, y, or crv")
	}
	var curve elliptic.Curve
	switch jwk.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported EC curve: %s", jwk.Crv)
	}
	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("EC x decode: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return nil, fmt.Errorf("EC y decode: %w", err)
	}
	return &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(xBytes), Y: new(big.Int).SetBytes(yBytes)}, nil
}

// JWKSClientConfig is the optional configuration for NewJWKSClient.
// The zero value gives safe defaults; individual fields exist to
// override them (e.g. tests that need to talk to a plain-HTTP
// httptest server set AllowInsecureHTTP).
type JWKSClientConfig struct {
	HTTPClient *http.Client
	TTL        time.Duration
	// HardTTL is the maximum age the cache will be served past, even
	// during issuer outage. Beyond HardTTL the entries are treated as
	// missing. Default: 24h. HardTTL must be ≥ TTL; if smaller, it is
	// raised to TTL.
	HardTTL time.Duration
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
	// Logger receives structured warnings for individual JWK parse
	// failures (with jwk_kid / jwk_use / jwk_kty attributes) and for
	// background refresh failures during stale-while-revalidate. nil →
	// slog.Default().
	Logger *slog.Logger
	// LifetimeCtx bounds background (stale-while-revalidate) refreshes so
	// they are cancelled at process shutdown instead of running detached.
	// nil → context.Background() (unbounded, legacy behavior). Production
	// callers should thread main's root/lifetime context here.
	LifetimeCtx context.Context
	// now is an injectable clock for tests. nil → time.Now.
	now func() time.Time
}

// cachedKey holds a parsed verification key together with the algorithm
// it was published with. Binding alg to the cached entry lets callers
// reject tokens that claim a *different* alg for the same kid (an
// attacker who knows the public key forging an unexpected algorithm).
type cachedKey struct {
	key interface{}
	alg string
}

// JWKSClient fetches and caches a JWKS (JSON Web Key Set) document
// keyed by the JWT `kid` header. Behaviour:
//
//   - Initial Key() call lazily fetches and caches the document.
//   - Cache lifetime is `ttl` (default 1 hour); after expiry the next
//     Key() call returns the *last good* keys and triggers a background
//     refresh (stale-while-revalidate). On IdP outage requests continue
//     to be served from the stale cache until HardTTL elapses, at which
//     point the entries are treated as missing.
//   - A cache miss for a known-good URL also forces a refresh — this
//     is the key-rotation path (issuer publishes a new kid before any
//     token uses it).
//   - Concurrent refreshes for the same URL collapse to a single
//     upstream request via singleflight.
type JWKSClient struct {
	url   string
	http  *http.Client
	ttl   time.Duration
	hard  time.Duration
	group singleflight.Group

	// minRefreshInterval and negCacheTTL throttle the "unknown kid →
	// refresh" path. See JWKSClientConfig for rationale.
	minRefreshInterval time.Duration
	negCacheTTL        time.Duration
	logger             *slog.Logger
	now                func() time.Time

	// lifetimeCtx bounds background refreshes; cancelled at shutdown.
	// refreshTimeout is the per-attempt deadline layered on top of it,
	// derived from the HTTP client's Timeout (default 10s).
	lifetimeCtx    context.Context
	refreshTimeout time.Duration

	mu         sync.RWMutex
	keys       map[string]cachedKey
	softExpiry time.Time // re-fetch in background after this
	hardExpiry time.Time // discard entirely after this
	bgRefresh  bool      // a background refresh is in flight
	// lastRefreshAttempt tracks when refresh() last ran (success OR
	// failure), so unknown-kid lookups can short-circuit until the
	// floor elapses.
	lastRefreshAttempt time.Time
	// negKids holds kids that were absent from the JWKS document at
	// the listed time + negCacheTTL. Cleared on every successful
	// refresh so rotation isn't delayed.
	negKids map[string]time.Time
}

// NewJWKSClient constructs a client for the given JWKS URL. The zero
// JWKSClientConfig is valid: a 10s-timeout HTTP client, 1h TTL, and
// 24h HardTTL are used. The URL MUST use the https scheme — plaintext
// JWKS fetches are a credential-substitution risk; tests that need
// plain HTTP set AllowInsecureHTTP.
func NewJWKSClient(url string, cfg JWKSClientConfig) (*JWKSClient, error) {
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
	hard := cfg.HardTTL
	if hard <= 0 {
		hard = 24 * time.Hour
	}
	if hard < ttl {
		hard = ttl
	}
	minRefresh := cfg.MinRefreshInterval
	if minRefresh <= 0 {
		minRefresh = 30 * time.Second
	}
	negTTL := cfg.NegativeCacheTTL
	if negTTL <= 0 {
		negTTL = 60 * time.Second
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	now := cfg.now
	if now == nil {
		now = time.Now
	}
	lifetimeCtx := cfg.LifetimeCtx
	if lifetimeCtx == nil {
		lifetimeCtx = context.Background()
	}
	// Per-attempt background-refresh deadline mirrors the HTTP client's
	// own timeout so behavior is unchanged when the request-scoped ctx
	// isn't available (background path).
	refreshTimeout := httpClient.Timeout
	if refreshTimeout <= 0 {
		refreshTimeout = 10 * time.Second
	}
	return &JWKSClient{
		url:                url,
		http:               httpClient,
		ttl:                ttl,
		hard:               hard,
		minRefreshInterval: minRefresh,
		negCacheTTL:        negTTL,
		logger:             logger,
		now:                now,
		lifetimeCtx:        lifetimeCtx,
		refreshTimeout:     refreshTimeout,
		keys:               map[string]cachedKey{},
		negKids:            map[string]time.Time{},
	}, nil
}

// Key returns the public key for the given `kid`, fetching and caching
// the JWKS document as needed. It is a thin wrapper around
// KeyWithAlg that drops the bound algorithm for callers that don't
// need it. Prefer KeyWithAlg in new code so the token's alg can be
// cross-checked against the JWK's declared alg (defense against
// alg-confusion forgeries that present a known kid with a different
// algorithm).
func (c *JWKSClient) Key(ctx context.Context, kid string) (interface{}, error) {
	k, _, err := c.KeyWithAlg(ctx, kid)
	return k, err
}

// KeyWithAlg returns the verification key and the algorithm bound to
// it at JWKS-publish time. Errors propagate from the underlying HTTP
// call or JWK parsing.
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
//
// Stale-while-revalidate: when the soft TTL has elapsed but the hard
// TTL has not, the cached key is returned immediately and a background
// refresh is kicked off so the next caller sees fresh data without the
// current request blocking on the issuer. If the issuer is down we
// keep serving stale until HardTTL elapses.
func (c *JWKSClient) KeyWithAlg(ctx context.Context, kid string) (interface{}, string, error) {
	if entry, state := c.lookup(kid); state != lookupMiss {
		if state == lookupStale {
			c.maybeKickBackgroundRefresh()
		}
		return entry.key, entry.alg, nil
	}
	if c.shouldShortCircuit(kid) {
		return nil, "", fmt.Errorf("jwks: kid %q not present (negative-cached)", kid)
	}
	if err := c.refresh(ctx); err != nil {
		return nil, "", err
	}
	if entry, state := c.lookup(kid); state != lookupMiss {
		return entry.key, entry.alg, nil
	}
	c.markNegative(kid)
	return nil, "", fmt.Errorf("jwks: kid %q not present after refresh", kid)
}

// lookupState distinguishes a fresh hit (within soft TTL), a stale-but-
// servable hit (between soft and hard TTL), and a miss (kid absent or
// past hard TTL).
type lookupState int

const (
	lookupMiss lookupState = iota
	lookupFresh
	lookupStale
)

func (c *JWKSClient) lookup(kid string) (cachedKey, lookupState) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	now := c.now()
	if !c.hardExpiry.IsZero() && now.After(c.hardExpiry) {
		return cachedKey{}, lookupMiss
	}
	k, ok := c.keys[kid]
	if !ok {
		return cachedKey{}, lookupMiss
	}
	if c.softExpiry.IsZero() || now.After(c.softExpiry) {
		return k, lookupStale
	}
	return k, lookupFresh
}

// maybeKickBackgroundRefresh launches a non-blocking refresh if one
// isn't already in flight. The refresh is decoupled from the originating
// request (so it isn't cancelled when that request finishes) but is
// bounded by the client's lifetime context — so it IS cancelled at
// process shutdown — plus a per-attempt refreshTimeout that preserves
// the previous HTTP-client-timeout bound.
func (c *JWKSClient) maybeKickBackgroundRefresh() {
	c.mu.Lock()
	if c.bgRefresh {
		c.mu.Unlock()
		return
	}
	c.bgRefresh = true
	c.mu.Unlock()

	go func() {
		defer func() {
			c.mu.Lock()
			c.bgRefresh = false
			c.mu.Unlock()
		}()
		ctx, cancel := context.WithTimeout(c.lifetimeCtx, c.refreshTimeout)
		defer cancel()
		if err := c.refresh(ctx); err != nil {
			c.logger.Warn("jwks: background refresh failed; serving stale",
				"url", c.url,
				"error", err,
			)
		}
	}()
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
		out := make(map[string]cachedKey, len(doc.Keys))
		for _, jwk := range doc.Keys {
			// Skip non-signing keys. RFC 7517 §4.2: `use` may be
			// absent (treated as multi-purpose) or `sig` (signing).
			// Anything else — notably `enc` — must NOT be admitted to
			// the verification cache; an encryption key being used to
			// verify a signature is a credential-substitution risk.
			if jwk.Use != "" && jwk.Use != "sig" {
				c.logger.Warn("jwks: skipping non-signing key",
					"jwk_kid", jwk.Kid,
					"jwk_use", jwk.Use,
					"jwk_kty", jwk.Kty,
				)
				continue
			}
			key, err := parseJWK(jwk)
			if err != nil {
				// Log and skip individual bad keys; the rest of the
				// set is still usable. Structured fields let operators
				// pinpoint a misbehaving IdP entry.
				c.logger.Warn("jwks: skipping unparseable key",
					"jwk_kid", jwk.Kid,
					"jwk_use", jwk.Use,
					"jwk_kty", jwk.Kty,
					"error", err,
				)
				continue
			}
			out[jwk.Kid] = cachedKey{key: key, alg: jwk.Alg}
		}
		c.mu.Lock()
		c.keys = out
		now := c.now()
		c.softExpiry = now.Add(c.ttl)
		c.hardExpiry = now.Add(c.hard)
		// A successful refresh clears the negative cache: a kid that
		// was absent before may have just been published (rotation).
		c.negKids = map[string]time.Time{}
		c.mu.Unlock()
		return nil, nil
	})
	return err
}
