// Package auth provides authentication middleware and providers.
package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// OIDCProvider validates tokens using OIDC/JWKS.
type OIDCProvider struct {
	name       string
	issuer     string
	audience   string
	jwksURL    string
	httpClient *http.Client
	jwks       *JWKSClient
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
		name:       cfg.Name,
		issuer:     cfg.Issuer,
		audience:   cfg.Audience,
		jwksURL:    cfg.JWKSURL,
		jwks:       NewJWKSClient(cfg.JWKSURL, client, ttl),
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

	key, err := p.jwks.Key(ctx, kid)
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

// parseRSAKey reconstructs an *rsa.PublicKey from the n/e fields of
// a JWK (RFC 7518 §6.3.1). Both are base64url-encoded big-endian
// integers; we decode them with no padding and build the key.
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
	// Right-pad e to int. Common values are 65537 (3 bytes) or 3.
	e := 0
	for _, b := range eBytes {
		e = e<<8 | int(b)
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: e,
	}, nil
}

// parseECKey reconstructs an *ecdsa.PublicKey from the x/y/crv fields
// of a JWK (RFC 7518 §6.2.1). Supported curves: P-256, P-384, P-521.
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
	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}, nil
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
