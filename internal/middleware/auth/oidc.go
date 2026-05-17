// Package auth: OIDC provider — thin adapter over coreos/go-oidc.
//
// Discovery, issuer validation, JWKS fetching, and JWT signature/aud/iss/exp
// checks are all delegated to go-oidc. This package keeps only the
// proxy-specific surface: Principal construction, attribute allowlisting,
// role extraction from common claim shapes (roles / realm_access /
// groups), and server-side auth_method stamping.
package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
)

// OIDCProvider validates OIDC ID tokens via go-oidc.
type OIDCProvider struct {
	name           string
	verifier       *oidc.IDTokenVerifier
	claimsFunc     func(claims jwt.MapClaims) (*Principal, error)
	attributeAllow map[string]struct{}
}

// defaultOIDCAttributeAllowlist is the set of token claim names that may
// be copied verbatim into Principal.Attributes when
// OIDCConfig.AttributeAllowlist is unset. "auth_method" is intentionally
// absent — the provider always sets it server-side.
var defaultOIDCAttributeAllowlist = []string{
	"email", "preferred_username", "name", "groups",
}

// OIDCConfig configures the OIDC provider.
type OIDCConfig struct {
	Name string
	// IssuerURL is the canonical OIDC issuer; discovery hits
	// {IssuerURL}/.well-known/openid-configuration. Required.
	IssuerURL string
	// Audience is checked against the token `aud` claim.
	Audience string
	// HTTPClient overrides the default http.DefaultClient used during
	// discovery and JWKS fetches.
	HTTPClient *http.Client
	// ClaimsFunc, when non-nil, replaces the default Principal-from-claims
	// mapping. Returns nil to fall through to default extraction.
	ClaimsFunc func(claims jwt.MapClaims) (*Principal, error)
	// AllowInsecureHTTP relaxes the https-only check on IssuerURL.
	// Test-only.
	AllowInsecureHTTP bool
	// AttributeAllowlist is the set of token claim names copied verbatim
	// into Principal.Attributes. nil → defaultOIDCAttributeAllowlist.
	// Use an explicit empty slice to disable claim copying.
	AttributeAllowlist []string
}

// NewOIDCProvider creates a new OIDC authentication provider.
func NewOIDCProvider(cfg OIDCConfig) (*OIDCProvider, error) {
	if cfg.IssuerURL == "" {
		return nil, errors.New("oidc: IssuerURL is required")
	}
	if !cfg.AllowInsecureHTTP && !strings.HasPrefix(strings.ToLower(cfg.IssuerURL), "https://") {
		return nil, fmt.Errorf("oidc: IssuerURL must use https scheme, got %q", cfg.IssuerURL)
	}

	ctx := context.Background()
	if cfg.HTTPClient != nil {
		ctx = oidc.ClientContext(ctx, cfg.HTTPClient)
	}
	// Bound discovery — never block startup indefinitely on a slow IdP.
	dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	provider, err := oidc.NewProvider(dctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("oidc: discovery: %w", err)
	}

	verifierCfg := &oidc.Config{
		ClientID:             cfg.Audience,
		SkipClientIDCheck:    cfg.Audience == "",
		SupportedSigningAlgs: []string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"},
	}
	verifier := provider.Verifier(verifierCfg)

	allow := cfg.AttributeAllowlist
	if allow == nil {
		allow = defaultOIDCAttributeAllowlist
	}
	allowSet := make(map[string]struct{}, len(allow))
	for _, name := range allow {
		allowSet[name] = struct{}{}
	}

	return &OIDCProvider{
		name:           cfg.Name,
		verifier:       verifier,
		claimsFunc:     cfg.ClaimsFunc,
		attributeAllow: allowSet,
	}, nil
}

// Name returns the provider name.
func (p *OIDCProvider) Name() string { return p.name }

// ClaimsCredential reports whether the request bears a Bearer
// Authorization header. See CredentialClaimer for the fail-closed
// contract.
func (p *OIDCProvider) ClaimsCredential(req *http.Request) bool {
	return strings.HasPrefix(req.Header.Get("Authorization"), "Bearer ")
}

// Authenticate validates an OIDC ID token from the Authorization header.
func (p *OIDCProvider) Authenticate(ctx context.Context, req *http.Request) (*Principal, error) {
	authHeader := req.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		return nil, nil
	}
	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenStr == "" {
		return nil, errors.New("empty bearer token")
	}

	idToken, err := p.verifier.Verify(ctx, tokenStr)
	if err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	var claims jwt.MapClaims
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("decode claims: %w", err)
	}

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
	principal.Roles = extractRoles(claims)

	for k, v := range claims {
		if _, ok := p.attributeAllow[k]; !ok {
			continue
		}
		if s, ok := v.(string); ok {
			principal.Attributes[k] = s
		}
	}

	if p.claimsFunc != nil {
		custom, err := p.claimsFunc(claims)
		if err != nil {
			return nil, fmt.Errorf("claims mapping failed: %w", err)
		}
		if custom != nil {
			principal = custom
			if principal.Attributes == nil {
				principal.Attributes = make(map[string]string)
			}
		}
	}

	// Stamp server-managed attribute AFTER claim copy and AFTER any
	// custom claimsFunc swap, so a token claiming auth_method (or a
	// custom mapping that forgets to set it) cannot override what
	// downstream authz relies on.
	principal.Attributes["auth_method"] = "oidc"
	return principal, nil
}

// extractRoles extracts roles from common JWT claim locations: `roles`,
// `realm_access.roles` (Keycloak), and `groups`.
func extractRoles(claims jwt.MapClaims) []string {
	var roles []string
	appendStrings := func(v interface{}) {
		arr, ok := v.([]interface{})
		if !ok {
			return
		}
		for _, x := range arr {
			if s, ok := x.(string); ok {
				roles = append(roles, s)
			}
		}
	}
	appendStrings(claims["roles"])
	if ra, ok := claims["realm_access"].(map[string]interface{}); ok {
		appendStrings(ra["roles"])
	}
	appendStrings(claims["groups"])
	return roles
}
