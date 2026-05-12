// Package auth provides authentication providers.
package auth

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// BearerProvider authenticates requests using Bearer tokens (JWT).
type BearerProvider struct {
	name       string
	issuer     string
	audience   string
	jwksURL    string
	jwks       *JWKSClient // nil when using static Secret
	keyFunc    jwt.Keyfunc
	claimsFunc func(claims jwt.MapClaims) (*Principal, error)
}

// BearerConfig contains configuration for the Bearer provider.
type BearerConfig struct {
	Name     string
	Issuer   string
	Audience string
	JWKSURL  string
	// Optional custom claims extraction
	ClaimsFunc func(claims jwt.MapClaims) (*Principal, error)
	// Optional static secret for HMAC tokens
	Secret []byte
}

// NewBearerProvider creates a new Bearer token authentication provider.
func NewBearerProvider(cfg BearerConfig) (*BearerProvider, error) {
	p := &BearerProvider{
		name:       cfg.Name,
		issuer:     cfg.Issuer,
		audience:   cfg.Audience,
		jwksURL:    cfg.JWKSURL,
		claimsFunc: cfg.ClaimsFunc,
	}

	if p.name == "" {
		p.name = "bearer"
	}

	if cfg.Secret != nil {
		// Use static HMAC secret
		p.keyFunc = func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return cfg.Secret, nil
		}
	} else if cfg.JWKSURL != "" {
		// Use JWKS for key lookup. The JWKSClient caches keys and
		// refreshes on cache miss (covers the key-rotation case).
		p.jwks = NewJWKSClient(cfg.JWKSURL, nil, time.Hour)
		p.keyFunc = p.jwksKeyFunc
	} else {
		return nil, fmt.Errorf("either Secret or JWKSURL must be provided")
	}

	if p.claimsFunc == nil {
		p.claimsFunc = defaultClaimsFunc
	}

	return p, nil
}

// Name returns the provider name.
func (p *BearerProvider) Name() string {
	return p.name
}

// Authenticate validates a Bearer token and returns a Principal.
func (p *BearerProvider) Authenticate(ctx context.Context, req *http.Request) (*Principal, error) {
	// Extract token from Authorization header
	authHeader := req.Header.Get("Authorization")
	if authHeader == "" {
		return nil, nil // No token, let next provider try
	}

	if !strings.HasPrefix(authHeader, "Bearer ") {
		return nil, nil // Not a Bearer token
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenString == "" {
		return nil, fmt.Errorf("empty bearer token")
	}

	// Parse and validate the token
	token, err := jwt.Parse(tokenString, p.keyFunc, jwt.WithValidMethods([]string{
		jwt.SigningMethodRS256.Name,
		jwt.SigningMethodRS384.Name,
		jwt.SigningMethodRS512.Name,
		jwt.SigningMethodHS256.Name,
		jwt.SigningMethodHS384.Name,
		jwt.SigningMethodHS512.Name,
		jwt.SigningMethodES256.Name,
		jwt.SigningMethodES384.Name,
		jwt.SigningMethodES512.Name,
	}))
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("token is not valid")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims format")
	}

	// Validate issuer
	if p.issuer != "" {
		iss, _ := claims["iss"].(string)
		if iss != p.issuer {
			return nil, fmt.Errorf("invalid issuer: expected %s, got %s", p.issuer, iss)
		}
	}

	// Validate audience
	if p.audience != "" {
		aud, ok := claims["aud"]
		if ok {
			valid := false
			switch v := aud.(type) {
			case string:
				valid = v == p.audience
			case []interface{}:
				for _, a := range v {
					if s, ok := a.(string); ok && s == p.audience {
						valid = true
						break
					}
				}
			}
			if !valid {
				return nil, fmt.Errorf("invalid audience")
			}
		}
	}

	// Extract principal from claims
	principal, err := p.claimsFunc(claims)
	if err != nil {
		return nil, fmt.Errorf("failed to extract principal: %w", err)
	}

	principal.Token = tokenString
	if exp, ok := claims["exp"].(float64); ok {
		principal.ExpiresAt = int64(exp)
	}

	return principal, nil
}

// jwksKeyFunc resolves a token's signing key against the JWKS
// endpoint. Returns the matching public key (RSA or EC) for the
// token's `kid` header. A cache miss triggers a single coalesced
// refresh of the JWKS document so key rotation works transparently.
func (p *BearerProvider) jwksKeyFunc(token *jwt.Token) (interface{}, error) {
	if p.jwks == nil {
		return nil, fmt.Errorf("jwks client not initialised")
	}
	kid, _ := token.Header["kid"].(string)
	if kid == "" {
		return nil, fmt.Errorf("token missing kid header")
	}
	switch token.Method.(type) {
	case *jwt.SigningMethodRSA, *jwt.SigningMethodRSAPSS, *jwt.SigningMethodECDSA:
		// ok — JWKS keys are RSA or EC.
	default:
		return nil, fmt.Errorf("unexpected signing method for JWKS: %v", token.Header["alg"])
	}
	return p.jwks.Key(context.Background(), kid)
}

// defaultClaimsFunc extracts a Principal from standard JWT claims.
func defaultClaimsFunc(claims jwt.MapClaims) (*Principal, error) {
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

	// Extract roles
	if roles, ok := claims["roles"].([]interface{}); ok {
		for _, r := range roles {
			if s, ok := r.(string); ok {
				principal.Roles = append(principal.Roles, s)
			}
		}
	}

	// Extract groups
	if groups, ok := claims["groups"].([]interface{}); ok {
		for _, g := range groups {
			if s, ok := g.(string); ok {
				principal.Groups = append(principal.Groups, s)
			}
		}
	}

	// Handle expiration
	if exp, ok := claims["exp"].(float64); ok {
		principal.ExpiresAt = int64(exp)
		if time.Now().Unix() > principal.ExpiresAt {
			return nil, fmt.Errorf("token has expired")
		}
	}

	return principal, nil
}
