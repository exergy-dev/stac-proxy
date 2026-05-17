package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// OIDCProvider is now a thin adapter over coreos/go-oidc. These tests
// cover only the surface this package owns:
//   - https-only check on IssuerURL (unless AllowInsecureHTTP)
//   - attribute allowlist filtering (M-auth-4)
//   - server-side auth_method stamp
//   - alg-confusion rejection (delegated to go-oidc's SupportedSigningAlgs)
//
// go-oidc itself handles discovery, issuer/aud validation, JWKS fetching
// and JWT signature verification; we don't re-test those.

type oidcTestServer struct {
	srv  *httptest.Server
	priv *rsa.PrivateKey
	kid  string
}

func newOIDCServer(t *testing.T) *oidcTestServer {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "rsa")
	const kid = "test-kid"

	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":   srv.URL,
			"jwks_uri": srv.URL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(JWKSResponse{
			Keys: []JWK{{
				Kty: "RSA",
				Kid: kid,
				Use: "sig",
				Alg: "RS256",
				N:   base64.RawURLEncoding.EncodeToString(priv.PublicKey.N.Bytes()),
				E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(priv.PublicKey.E)).Bytes()),
			}},
		})
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &oidcTestServer{srv: srv, priv: priv, kid: kid}
}

func (s *oidcTestServer) sign(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	if _, ok := claims["iss"]; !ok {
		claims["iss"] = s.srv.URL
	}
	if _, ok := claims["exp"]; !ok {
		claims["exp"] = time.Now().Add(time.Hour).Unix()
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = s.kid
	signed, err := tok.SignedString(s.priv)
	require.NoError(t, err, "sign")
	return signed
}

func (s *oidcTestServer) provider(t *testing.T, audience string, allowlist []string) *OIDCProvider {
	t.Helper()
	p, err := NewOIDCProvider(OIDCConfig{
		Name:               "oidc",
		IssuerURL:          s.srv.URL,
		Audience:           audience,
		AllowInsecureHTTP:  true,
		AttributeAllowlist: allowlist,
	})
	require.NoError(t, err, "NewOIDCProvider")
	return p
}

func TestOIDC_RejectsHTTPIssuerByDefault(t *testing.T) {
	t.Parallel()
	_, err := NewOIDCProvider(OIDCConfig{
		Name:      "oidc",
		IssuerURL: "http://insecure.example",
	})
	require.Error(t, err, "expected https-required error")
	assert.Contains(t, err.Error(), "https", "error should mention https")
}

func TestOIDC_RequiresIssuerURL(t *testing.T) {
	t.Parallel()
	_, err := NewOIDCProvider(OIDCConfig{Name: "oidc"})
	require.Error(t, err, "expected error for missing IssuerURL")
}

func TestOIDC_ValidTokenRoundTrip(t *testing.T) {
	t.Parallel()
	s := newOIDCServer(t)
	p := s.provider(t, "stac-proxy", nil)

	signed := s.sign(t, jwt.MapClaims{
		"aud":   "stac-proxy",
		"sub":   "user-1",
		"email": "user@example.com",
		"name":  "Alice",
	})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+signed)

	princ, err := p.Authenticate(context.Background(), req)
	require.NoError(t, err, "Authenticate")
	assert.Equal(t, "user-1", princ.ID, "ID")
	assert.Equal(t, "user@example.com", princ.Email, "Email")
	assert.Equal(t, "Alice", princ.Name, "Name")
}

// M-auth-4: claims not on the allowlist must never reach Attributes.
func TestOIDC_OnlyAllowlistedClaimsCopied(t *testing.T) {
	t.Parallel()
	s := newOIDCServer(t)
	p := s.provider(t, "stac-proxy", nil) // default allowlist

	signed := s.sign(t, jwt.MapClaims{
		"aud":       "stac-proxy",
		"sub":       "user-1",
		"email":     "user@example.com",
		"evil_attr": "spoofed",
	})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+signed)
	princ, err := p.Authenticate(context.Background(), req)
	require.NoError(t, err, "Authenticate")
	assert.Equal(t, "user@example.com", princ.Attributes["email"], "email missing")
	_, ok := princ.Attributes["evil_attr"]
	assert.False(t, ok, "non-allowlisted claim leaked")
}

// auth_method must always be "oidc"; a token claiming otherwise — even
// with auth_method on the allowlist — must not override the server stamp.
func TestOIDC_AuthMethodSetServerSide(t *testing.T) {
	t.Parallel()
	s := newOIDCServer(t)
	p := s.provider(t, "stac-proxy", []string{"email", "auth_method"})

	signed := s.sign(t, jwt.MapClaims{
		"aud":         "stac-proxy",
		"sub":         "user-2",
		"auth_method": "spoofed",
	})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+signed)
	princ, err := p.Authenticate(context.Background(), req)
	require.NoError(t, err, "Authenticate")
	require.Equal(t, "oidc", princ.Attributes["auth_method"], "auth_method")
}

// Regression: an attacker holding only the public RSA key tries to forge
// an HS256 token using the public-key bytes as the HMAC secret. The
// SupportedSigningAlgs allowlist on the verifier must reject this.
func TestOIDC_RejectsHS256ForgedWithPublicKey(t *testing.T) {
	t.Parallel()
	s := newOIDCServer(t)
	p := s.provider(t, "stac-proxy", nil)

	// Forge an HS256 token; secret value doesn't matter — go-oidc will
	// reject before any signature check because HS256 is not in
	// SupportedSigningAlgs.
	forged := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": s.srv.URL,
		"aud": "stac-proxy",
		"sub": "attacker",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	forged.Header["kid"] = s.kid
	tokenStr, err := forged.SignedString([]byte("any-secret"))
	require.NoError(t, err, "sign forged")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	princ, err := p.Authenticate(context.Background(), req)
	require.Error(t, err, "forged HS256 accepted; principal=%+v", princ)
}

func TestOIDC_RolesExtractedFromCommonClaims(t *testing.T) {
	t.Parallel()
	s := newOIDCServer(t)
	p := s.provider(t, "stac-proxy", nil)

	signed := s.sign(t, jwt.MapClaims{
		"aud": "stac-proxy",
		"sub": "user-3",
		"realm_access": map[string]interface{}{
			"roles": []interface{}{"admin", "editor"},
		},
		"groups": []interface{}{"team-a"},
	})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+signed)
	princ, err := p.Authenticate(context.Background(), req)
	require.NoError(t, err, "Authenticate")
	roles := map[string]bool{}
	for _, r := range princ.Roles {
		roles[r] = true
	}
	for _, want := range []string{"admin", "editor", "team-a"} {
		assert.True(t, roles[want], "missing role %q in %v", want, princ.Roles)
	}
}
