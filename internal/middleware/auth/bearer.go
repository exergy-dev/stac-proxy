// Package auth provides authentication providers.
package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// defaultLeeway is the clock-skew tolerance applied to JWT temporal
// claims (exp/nbf/iat) when BearerConfig.Leeway is zero.
const defaultLeeway = 30 * time.Second

// BearerProvider authenticates requests using Bearer tokens (JWT).
type BearerProvider struct {
	name         string
	issuer       string
	audience     string
	jwksURL      string
	jwks         *JWKSClient // nil when using static Secret
	keyFunc      jwt.Keyfunc
	claimsFunc   func(claims jwt.MapClaims) (*Principal, error)
	leeway       time.Duration
	validMethods []string
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
	// Leeway is the clock-skew tolerance for exp/nbf/iat validation.
	// Zero selects the default (30s).
	Leeway time.Duration
	// AllowInsecureHTTPJWKS bypasses the https-only check on JWKSURL.
	// Test-only.
	AllowInsecureHTTPJWKS bool
}

// NewBearerProvider creates a new Bearer token authentication provider.
func NewBearerProvider(cfg BearerConfig) (*BearerProvider, error) {
	if cfg.Secret != nil && cfg.JWKSURL != "" {
		return nil, errors.New("bearer: Secret and JWKSURL are mutually exclusive")
	}

	p := &BearerProvider{
		name:       cfg.Name,
		issuer:     cfg.Issuer,
		audience:   cfg.Audience,
		jwksURL:    cfg.JWKSURL,
		claimsFunc: cfg.ClaimsFunc,
		leeway:     cfg.Leeway,
	}

	if p.name == "" {
		p.name = "bearer"
	}
	if p.leeway <= 0 {
		p.leeway = defaultLeeway
	}

	if cfg.Secret != nil {
		// Use static HMAC secret. Restrict the algorithm allowlist to
		// HMAC variants so an attacker can't smuggle in an asymmetric
		// algorithm and pass our shared-secret key off as a public key.
		p.validMethods = []string{
			jwt.SigningMethodHS256.Name,
			jwt.SigningMethodHS384.Name,
			jwt.SigningMethodHS512.Name,
		}
		p.keyFunc = func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return cfg.Secret, nil
		}
	} else if cfg.JWKSURL != "" {
		// Use JWKS for key lookup. The JWKSClient caches keys and
		// refreshes on cache miss (covers the key-rotation case).
		// Restrict to asymmetric algorithms — HMAC must never be
		// accepted alongside JWKS-published public keys.
		jwks, err := NewJWKSClientFromConfig(cfg.JWKSURL, JWKSClientConfig{
			TTL:               time.Hour,
			AllowInsecureHTTP: cfg.AllowInsecureHTTPJWKS,
		})
		if err != nil {
			return nil, err
		}
		p.jwks = jwks
		p.validMethods = []string{
			jwt.SigningMethodRS256.Name,
			jwt.SigningMethodRS384.Name,
			jwt.SigningMethodRS512.Name,
			jwt.SigningMethodES256.Name,
			jwt.SigningMethodES384.Name,
			jwt.SigningMethodES512.Name,
		}
		// p.keyFunc is set to the context-less variant for backward
		// compatibility with callers that exercise keyFunc directly
		// (tests, debugging). Authenticate replaces it per-call with
		// jwksKeyFuncFor(req.Context()) so the JWKS fetch honours the
		// request deadline.
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

// ClaimsCredential reports whether the request bears a Bearer
// Authorization header. When this returns true, the auth chain treats
// any error from Authenticate as a hard failure (401) rather than
// falling through to the next provider — required to prevent a bad
// signature from being silently downgraded to anonymous.
func (p *BearerProvider) ClaimsCredential(req *http.Request) bool {
	authHeader := req.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return false
	}
	// "Bearer " on its own (empty token) is still a Bearer credential
	// presentation — Authenticate will reject it with an error and the
	// chain MUST fail closed rather than try the next provider.
	return true
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

	// Select the keyFunc. For the JWKS path we build a per-call closure
	// that captures req.Context(), so a slow JWKS fetch honours the
	// caller's deadline instead of running against a fresh
	// context.Background() that outlives the request.
	keyFunc := p.keyFunc
	if p.jwks != nil {
		keyFunc = p.jwksKeyFuncFor(req.Context())
	}

	// Parse and validate the token. The valid-methods allowlist was
	// narrowed at construction time to match the configured key
	// source (HMAC for static secret, RS*/ES* for JWKS) so we never
	// accept an algorithm that's incompatible with the key material.
	token, err := jwt.Parse(
		tokenString,
		keyFunc,
		jwt.WithValidMethods(p.validMethods),
		jwt.WithLeeway(p.leeway),
	)
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

	// Validate audience. When an audience is configured, the token MUST
	// carry an aud claim that matches; a missing aud is a hard failure
	// rather than a silent pass-through.
	if p.audience != "" {
		aud, ok := claims["aud"]
		if !ok {
			return nil, fmt.Errorf("missing audience claim")
		}
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

// jwksKeyFuncFor returns a jwt.Keyfunc closure that performs the JWKS
// lookup using the supplied context. Authenticate uses this so a slow
// JWKS fetch honours the inbound request's deadline / cancellation
// instead of detaching to context.Background() (which would outlive
// the caller).
//
// When the JWKS document declared an `alg` for the looked-up kid the
// closure additionally rejects tokens whose header `alg` differs from
// the cached value — defense against an attacker presenting a known
// kid with an unexpected algorithm (alg-confusion variant).
func (p *BearerProvider) jwksKeyFuncFor(ctx context.Context) jwt.Keyfunc {
	return func(token *jwt.Token) (interface{}, error) {
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
		key, alg, err := p.jwks.KeyWithAlg(ctx, kid)
		if err != nil {
			return nil, err
		}
		if alg != "" {
			tokAlg, _ := token.Header["alg"].(string)
			if tokAlg != alg {
				return nil, fmt.Errorf("jwks: token alg %q does not match key alg %q for kid %q", tokAlg, alg, kid)
			}
		}
		return key, nil
	}
}

// jwksKeyFunc is a context-less convenience wrapper retained for
// tests that need to exercise the keyFunc shape directly (it uses
// context.Background()). Production traffic flows through
// jwksKeyFuncFor with the request context.
func (p *BearerProvider) jwksKeyFunc(token *jwt.Token) (interface{}, error) {
	return p.jwksKeyFuncFor(context.Background())(token)
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

	// Record expiration on the principal. Validation of exp (with the
	// configured leeway) happens in jwt.Parse — re-checking here would
	// short-circuit the leeway tolerance.
	if exp, ok := claims["exp"].(float64); ok {
		principal.ExpiresAt = int64(exp)
	}

	return principal, nil
}
