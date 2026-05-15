// Package auth provides authentication middleware and providers.
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
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// discoveryDoc is the subset of an OIDC discovery document we care
// about (RFC 8414 / OIDC Discovery 1.0 §4).
type discoveryDoc struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

// OIDCProvider validates tokens using OIDC/JWKS.
type OIDCProvider struct {
	name       string
	issuer     string
	audience   string
	jwks       *JWKSClient
	claimsFunc func(claims jwt.MapClaims) (*Principal, error)
}

// OIDCConfig configures the OIDC provider.
type OIDCConfig struct {
	Name string
	// IssuerURL is the canonical OIDC issuer. When set, the
	// constructor fetches {IssuerURL}/.well-known/openid-configuration
	// to discover the jwks_uri and validates the document's `issuer`
	// field matches.
	IssuerURL string
	// Issuer is the value compared against the JWT `iss` claim. If
	// empty and IssuerURL is set, IssuerURL is used.
	Issuer   string
	Audience string
	// JWKSURL, when set, overrides any jwks_uri discovered via
	// IssuerURL. When IssuerURL is empty, JWKSURL is required.
	JWKSURL    string
	HTTPClient *http.Client
	ClaimsFunc func(claims jwt.MapClaims) (*Principal, error)
	CacheTTL   time.Duration
	// AllowInsecureHTTP relaxes the https-only check on IssuerURL and
	// the resulting JWKS URL. Test-only.
	AllowInsecureHTTP bool
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
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// NewOIDCProvider creates a new OIDC authentication provider.
//
// When IssuerURL is set, the constructor performs OIDC discovery
// against {IssuerURL}/.well-known/openid-configuration. The discovered
// `issuer` field MUST match IssuerURL (defense against a hostile
// metadata document); the `jwks_uri` is used unless an explicit
// JWKSURL overrides it.
func NewOIDCProvider(cfg OIDCConfig) (*OIDCProvider, error) {
	jwksURL := cfg.JWKSURL
	issuer := cfg.Issuer

	if cfg.IssuerURL != "" {
		if !cfg.AllowInsecureHTTP {
			if !strings.HasPrefix(strings.ToLower(cfg.IssuerURL), "https://") {
				return nil, fmt.Errorf("oidc: IssuerURL must use https scheme, got %q", cfg.IssuerURL)
			}
		}
		doc, err := fetchDiscovery(cfg.IssuerURL, cfg.HTTPClient)
		if err != nil {
			return nil, fmt.Errorf("oidc: discovery: %w", err)
		}
		if doc.Issuer != cfg.IssuerURL {
			return nil, fmt.Errorf("oidc: discovery issuer mismatch: doc=%q config=%q", doc.Issuer, cfg.IssuerURL)
		}
		if jwksURL == "" {
			jwksURL = doc.JWKSURI
		}
		if issuer == "" {
			issuer = cfg.IssuerURL
		}
	}

	if jwksURL == "" {
		return nil, errors.New("JWKS URL is required")
	}

	jwks, err := NewJWKSClientFromConfig(jwksURL, JWKSClientConfig{
		HTTPClient:        cfg.HTTPClient,
		TTL:               cfg.CacheTTL,
		AllowInsecureHTTP: cfg.AllowInsecureHTTP,
	})
	if err != nil {
		return nil, err
	}

	return &OIDCProvider{
		name:       cfg.Name,
		issuer:     issuer,
		audience:   cfg.Audience,
		jwks:       jwks,
		claimsFunc: cfg.ClaimsFunc,
	}, nil
}

// fetchDiscovery retrieves and decodes an OIDC discovery document
// from {issuerURL}/.well-known/openid-configuration. A short request
// timeout is enforced regardless of the caller's HTTP client config —
// discovery must not hang at startup.
func fetchDiscovery(issuerURL string, httpClient *http.Client) (*discoveryDoc, error) {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	url := strings.TrimRight(issuerURL, "/") + "/.well-known/openid-configuration"
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: status %d", url, resp.StatusCode)
	}
	var doc discoveryDoc
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode discovery: %w", err)
	}
	return &doc, nil
}

// Name returns the provider name.
func (p *OIDCProvider) Name() string {
	return p.name
}

// ClaimsCredential reports whether the request bears a Bearer
// Authorization header (which OIDC consumes as an ID/access token).
// See CredentialClaimer for the fail-closed contract.
func (p *OIDCProvider) ClaimsCredential(req *http.Request) bool {
	return strings.HasPrefix(req.Header.Get("Authorization"), "Bearer ")
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

	// Parse and validate the token. Restrict to RSA/EC algorithms:
	// JWKS keys are RSA or EC (parseJWK rejects others), so HMAC algs
	// must be excluded. Without this allowlist an attacker who knows
	// the public key can forge an HS256 token using the PEM-encoded
	// public-key bytes as the HMAC secret — jwt.ParseWithClaims would
	// hand the *rsa.PublicKey to the HS256 verifier and accept the
	// forgery (alg-confusion attack).
	claims := jwt.MapClaims{}
	token, err = jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		return key, nil
	},
		jwt.WithValidMethods([]string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}),
		jwt.WithIssuer(p.issuer),
		jwt.WithAudience(p.audience),
	)

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
