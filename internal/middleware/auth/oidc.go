// Package auth provides authentication middleware and providers.
package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// OIDCProvider validates tokens using OIDC/JWKS.
type OIDCProvider struct {
	name         string
	issuer     string
	audience   string
	jwksURL    string
	httpClient *http.Client
	keyCache   *jwksCache
	claimsFunc func(claims map[string]interface{}) (*Principal, error)
}

// OIDCConfig configures the OIDC provider.
type OIDCConfig struct {
	Name       string
	Issuer     string
	Audience   string
	JWKSURL    string
	HTTPClient *http.Client
	ClaimsFunc func(claims map[string]interface{}) (*Principal, error)
	CacheTTL   time.Duration
}

// jwksCache caches JWKS keys.
type jwksCache struct {
	mu       sync.RWMutex
	keys     map[string]interface{}
	expiry   time.Time
	ttl      time.Duration
	jwksURL  string
	client   *http.Client
	fetching sync.Mutex
}

// JWKSResponse represents the JWKS response.
type JWKSResponse struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a JSON Web Key.
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// NewOIDCProvider creates a new OIDC authentication provider.
func NewOIDCProvider(cfg OIDCConfig) (*OIDCProvider, error) {
	if cfg.JWKSURL == "" {
		return nil, errors.New("JWKS URL is required")
	}

	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}

	ttl := cfg.CacheTTL
	if ttl == 0 {
		ttl = 1 * time.Hour
	}

	return &OIDCProvider{
		name:     cfg.Name,
		issuer:   cfg.Issuer,
		audience: cfg.Audience,
		jwksURL:  cfg.JWKSURL,
		keyCache: &jwksCache{
			keys:    make(map[string]interface{}),
			ttl:     ttl,
			jwksURL: cfg.JWKSURL,
			client:  client,
		},
		httpClient: client,
		claimsFunc: cfg.ClaimsFunc,
	}, nil
}

// Name returns the provider name.
func (p *OIDCProvider) Name() string {
	return p.name
}

// Authenticate validates an OIDC token.
func (p *OIDCProvider) Authenticate(ctx context.Context, req *http.Request) (*Principal, error) {
	// Extract token from Authorization header
	authHeader := req.Header.Get("Authorization")
	if authHeader == "" {
		return nil, nil // No token, let next provider try
	}

	if !strings.HasPrefix(authHeader, "Bearer ") {
		return nil, nil // Not a Bearer token
	}

	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenStr == "" {
		return nil, fmt.Errorf("empty bearer token")
	}

	// Parse token without verification first to get the key ID
	token, _, err := jwt.NewParser().ParseUnverified(tokenStr, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	kid, ok := token.Header["kid"].(string)
	if !ok {
		return nil, errors.New("token missing kid header")
	}

	// Get the key from cache
	key, err := p.keyCache.getKey(ctx, kid)
	if err != nil {
		return nil, fmt.Errorf("failed to get signing key: %w", err)
	}

	// Parse and validate the token
	claims := jwt.MapClaims{}
	token, err = jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		return key, nil
	}, jwt.WithIssuer(p.issuer), jwt.WithAudience(p.audience))

	if err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	// Build principal from claims
	principal := &Principal{
		Type:       "user",
		Attributes: make(map[string]string),
	}

	// Extract standard claims
	if sub, ok := claims["sub"].(string); ok {
		principal.ID = sub
	}
	if email, ok := claims["email"].(string); ok {
		principal.Email = email
	}
	if name, ok := claims["name"].(string); ok {
		principal.Name = name
	}

	// Extract roles from various claim locations
	principal.Roles = extractRoles(claims)

	// Copy string claims to attributes
	for k, v := range claims {
		if s, ok := v.(string); ok {
			principal.Attributes[k] = s
		}
	}

	// Apply custom claims mapping if configured
	if p.claimsFunc != nil {
		customPrincipal, err := p.claimsFunc(claims)
		if err != nil {
			return nil, fmt.Errorf("claims mapping failed: %w", err)
		}
		if customPrincipal != nil {
			principal = customPrincipal
		}
	}

	return principal, nil
}

// getKey retrieves a signing key from the cache or fetches from JWKS endpoint.
func (c *jwksCache) getKey(ctx context.Context, kid string) (interface{}, error) {
	c.mu.RLock()
	if time.Now().Before(c.expiry) {
		if key, ok := c.keys[kid]; ok {
			c.mu.RUnlock()
			return key, nil
		}
	}
	c.mu.RUnlock()

	// Need to refresh
	if err := c.refresh(ctx); err != nil {
		return nil, err
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	key, ok := c.keys[kid]
	if !ok {
		return nil, fmt.Errorf("key %s not found in JWKS", kid)
	}
	return key, nil
}

// refresh fetches keys from the JWKS endpoint.
func (c *jwksCache) refresh(ctx context.Context) error {
	c.fetching.Lock()
	defer c.fetching.Unlock()

	// Double-check after acquiring lock
	c.mu.RLock()
	if time.Now().Before(c.expiry) {
		c.mu.RUnlock()
		return nil
	}
	c.mu.RUnlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.jwksURL, nil)
	if err != nil {
		return err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS request failed with status %d", resp.StatusCode)
	}

	var jwks JWKSResponse
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return err
	}

	keys := make(map[string]interface{})
	for _, jwk := range jwks.Keys {
		key, err := parseJWK(jwk)
		if err != nil {
			continue // Skip invalid keys
		}
		keys[jwk.Kid] = key
	}

	c.mu.Lock()
	c.keys = keys
	c.expiry = time.Now().Add(c.ttl)
	c.mu.Unlock()

	return nil
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

// parseRSAKey parses an RSA public key from JWK.
func parseRSAKey(jwk JWK) (interface{}, error) {
	// Implementation would decode n and e from base64url and construct rsa.PublicKey
	// For brevity, returning a placeholder error
	return nil, errors.New("RSA key parsing not fully implemented")
}

// parseECKey parses an EC public key from JWK.
func parseECKey(jwk JWK) (interface{}, error) {
	// Implementation would decode x, y, crv and construct ecdsa.PublicKey
	return nil, errors.New("EC key parsing not fully implemented")
}

// extractRoles extracts roles from common JWT claim locations.
func extractRoles(claims jwt.MapClaims) []string {
	var roles []string

	// Try "roles" claim
	if r, ok := claims["roles"].([]interface{}); ok {
		for _, role := range r {
			if s, ok := role.(string); ok {
				roles = append(roles, s)
			}
		}
	}

	// Try "realm_access.roles" (Keycloak)
	if ra, ok := claims["realm_access"].(map[string]interface{}); ok {
		if r, ok := ra["roles"].([]interface{}); ok {
			for _, role := range r {
				if s, ok := role.(string); ok {
					roles = append(roles, s)
				}
			}
		}
	}

	// Try "groups" claim
	if g, ok := claims["groups"].([]interface{}); ok {
		for _, group := range g {
			if s, ok := group.(string); ok {
				roles = append(roles, s)
			}
		}
	}

	return roles
}
