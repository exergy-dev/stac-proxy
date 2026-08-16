// Package auth: Bearer (JWT) token provider.
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
	jwks         *JWKSClient // nil when using static Secret
	staticSecret []byte      // nil when using JWKS
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
	// LifetimeCtx bounds the JWKS client's background key-refresh
	// goroutine so it is cancelled at process shutdown. nil →
	// context.Background(). Only relevant for the JWKS (asymmetric) path.
	LifetimeCtx context.Context
}

var (
	hmacMethods = []string{
		jwt.SigningMethodHS256.Name, jwt.SigningMethodHS384.Name, jwt.SigningMethodHS512.Name,
	}
	asymmetricMethods = []string{
		jwt.SigningMethodRS256.Name, jwt.SigningMethodRS384.Name, jwt.SigningMethodRS512.Name,
		jwt.SigningMethodES256.Name, jwt.SigningMethodES384.Name, jwt.SigningMethodES512.Name,
	}
)

// NewBearerProvider creates a new Bearer token authentication provider.
func NewBearerProvider(cfg BearerConfig) (*BearerProvider, error) {
	if cfg.Secret != nil && cfg.JWKSURL != "" {
		return nil, errors.New("bearer: Secret and JWKSURL are mutually exclusive")
	}
	if cfg.Secret == nil && cfg.JWKSURL == "" {
		return nil, errors.New("bearer: either Secret or JWKSURL must be provided")
	}

	p := &BearerProvider{
		name:       cfg.Name,
		issuer:     cfg.Issuer,
		audience:   cfg.Audience,
		claimsFunc: cfg.ClaimsFunc,
		leeway:     cfg.Leeway,
	}
	if p.name == "" {
		p.name = "bearer"
	}
	if p.leeway <= 0 {
		p.leeway = defaultLeeway
	}
	if p.claimsFunc == nil {
		p.claimsFunc = defaultClaimsFunc
	}

	if cfg.Secret != nil {
		// HMAC allowlist prevents an attacker from smuggling an
		// asymmetric algorithm to pass off shared-secret material as a
		// public key.
		p.staticSecret = cfg.Secret
		p.validMethods = hmacMethods
	} else {
		jwks, err := NewJWKSClient(cfg.JWKSURL, JWKSClientConfig{
			TTL:               time.Hour,
			AllowInsecureHTTP: cfg.AllowInsecureHTTPJWKS,
			LifetimeCtx:       cfg.LifetimeCtx,
		})
		if err != nil {
			return nil, err
		}
		p.jwks = jwks
		p.validMethods = asymmetricMethods
	}
	return p, nil
}

// Name returns the provider name.
func (p *BearerProvider) Name() string { return p.name }

// ClaimsCredential reports whether the request bears a Bearer header.
// Returning true here makes the chain fail closed on any Authenticate
// error rather than fall through to anonymous.
func (p *BearerProvider) ClaimsCredential(req *http.Request) bool {
	return strings.HasPrefix(req.Header.Get("Authorization"), "Bearer ")
}

// Authenticate validates a Bearer token and returns a Principal.
func (p *BearerProvider) Authenticate(ctx context.Context, req *http.Request) (*Principal, error) {
	authHeader := req.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		return nil, nil
	}
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenString == "" {
		return nil, errors.New("empty bearer token")
	}

	opts := []jwt.ParserOption{
		jwt.WithValidMethods(p.validMethods),
		jwt.WithLeeway(p.leeway),
	}
	if p.issuer != "" {
		opts = append(opts, jwt.WithIssuer(p.issuer))
	}
	if p.audience != "" {
		opts = append(opts, jwt.WithAudience(p.audience))
	}

	token, err := jwt.Parse(tokenString, p.keyFuncFor(ctx), opts...)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}
	if !token.Valid {
		return nil, errors.New("token is not valid")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid claims format")
	}

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

// keyFuncFor returns a jwt.Keyfunc closure bound to ctx. The JWKS path
// uses ctx so a slow fetch honours the request deadline; the HMAC path
// just returns the static secret.
//
// JWKS branch additionally rejects tokens whose header alg differs from
// the JWK's declared alg (alg-confusion defense for a known kid).
func (p *BearerProvider) keyFuncFor(ctx context.Context) jwt.Keyfunc {
	if p.staticSecret != nil {
		secret := p.staticSecret
		return func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return secret, nil
		}
	}
	return func(token *jwt.Token) (interface{}, error) {
		kid, _ := token.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("token missing kid header")
		}
		switch token.Method.(type) {
		case *jwt.SigningMethodRSA, *jwt.SigningMethodRSAPSS, *jwt.SigningMethodECDSA:
		default:
			return nil, fmt.Errorf("unexpected signing method for JWKS: %v", token.Header["alg"])
		}
		key, alg, err := p.jwks.KeyWithAlg(ctx, kid)
		if err != nil {
			return nil, err
		}
		if alg != "" {
			if tokAlg, _ := token.Header["alg"].(string); tokAlg != alg {
				return nil, fmt.Errorf("jwks: token alg %q does not match key alg %q for kid %q", tokAlg, alg, kid)
			}
		}
		return key, nil
	}
}

// defaultClaimsFunc extracts a Principal from standard JWT claims.
// Unlike the OIDC provider's extractRoles helper, this keeps `roles`
// and `groups` as distinct Principal fields — bearer-authed callers
// expect them separate.
func defaultClaimsFunc(claims jwt.MapClaims) (*Principal, error) {
	principal := &Principal{Type: "user", Attributes: make(map[string]string)}
	if sub, ok := claims["sub"].(string); ok {
		principal.ID = sub
	}
	if email, ok := claims["email"].(string); ok {
		principal.Email = email
	}
	if name, ok := claims["name"].(string); ok {
		principal.Name = name
	}
	for _, key := range []string{"roles", "groups"} {
		if arr, ok := claims[key].([]interface{}); ok {
			for _, x := range arr {
				if s, ok := x.(string); ok {
					if key == "roles" {
						principal.Roles = append(principal.Roles, s)
					} else {
						principal.Groups = append(principal.Groups, s)
					}
				}
			}
		}
	}
	if exp, ok := claims["exp"].(float64); ok {
		principal.ExpiresAt = int64(exp)
	}
	return principal, nil
}
