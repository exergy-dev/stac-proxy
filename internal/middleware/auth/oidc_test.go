package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// newTLSDiscoveryServer spins up an HTTPS test server that serves a
// discovery document at /.well-known/openid-configuration and a stub
// JWKS at /jwks. The discovery doc's `issuer` defaults to the
// server's own URL but can be overridden for negative tests.
func newTLSDiscoveryServer(t *testing.T, issuerOverride string) (*httptest.Server, *http.Client) {
	t.Helper()
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		issuer := srv.URL
		if issuerOverride != "" {
			issuer = issuerOverride
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":   issuer,
			"jwks_uri": srv.URL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"keys":[]}`))
	})
	srv = httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)

	// HTTP client that trusts the httptest TLS cert.
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test-only
		},
	}
	return srv, client
}

func TestOIDC_DiscoveryUsesJWKSURI(t *testing.T) {
	t.Parallel()

	srv, client := newTLSDiscoveryServer(t, "")

	p, err := NewOIDCProvider(OIDCConfig{
		Name:       "oidc",
		IssuerURL:  srv.URL,
		Audience:   "stac-proxy",
		HTTPClient: client,
	})
	if err != nil {
		t.Fatalf("NewOIDCProvider: %v", err)
	}
	if p == nil || p.jwks == nil {
		t.Fatal("expected provider with jwks client")
	}
	want := srv.URL + "/jwks"
	if p.jwks.url != want {
		t.Fatalf("expected jwks URL %q, got %q", want, p.jwks.url)
	}
	// Issuer should default to IssuerURL when Issuer is empty.
	if p.issuer != srv.URL {
		t.Fatalf("expected issuer %q, got %q", srv.URL, p.issuer)
	}
}

func TestOIDC_DiscoveryMismatchIssuer(t *testing.T) {
	t.Parallel()

	srv, client := newTLSDiscoveryServer(t, "https://attacker.example")

	_, err := NewOIDCProvider(OIDCConfig{
		Name:       "oidc",
		IssuerURL:  srv.URL,
		HTTPClient: client,
	})
	if err == nil {
		t.Fatal("expected error on issuer mismatch, got nil")
	}
	if !strings.Contains(err.Error(), "issuer mismatch") {
		t.Errorf("expected 'issuer mismatch' in error, got: %v", err)
	}
}

func TestOIDC_RejectsHTTPIssuer(t *testing.T) {
	t.Parallel()

	_, err := NewOIDCProvider(OIDCConfig{
		Name:      "oidc",
		IssuerURL: "http://insecure.example",
	})
	if err == nil {
		t.Fatal("expected error for non-https IssuerURL, got nil")
	}
	if !strings.Contains(err.Error(), "https") {
		t.Errorf("expected error to mention https, got: %v", err)
	}
}

// TestOIDC_ExplicitJWKSURLOverridesDiscovery verifies that when both
// IssuerURL and an explicit JWKSURL are set, the explicit URL wins.
func TestOIDC_ExplicitJWKSURLOverridesDiscovery(t *testing.T) {
	t.Parallel()

	srv, client := newTLSDiscoveryServer(t, "")
	override := srv.URL + "/override-jwks"

	p, err := NewOIDCProvider(OIDCConfig{
		Name:       "oidc",
		IssuerURL:  srv.URL,
		JWKSURL:    override,
		HTTPClient: client,
	})
	if err != nil {
		t.Fatalf("NewOIDCProvider: %v", err)
	}
	if p.jwks.url != override {
		t.Fatalf("expected explicit JWKSURL %q, got %q", override, p.jwks.url)
	}
}

// TestOIDC_RejectsHS256ForgedWithPublicKey is a regression test for the
// JWT algorithm-confusion attack: an attacker who has the (public) RSA
// key from the JWKS forges an HS256 token using the PEM-encoded public
// key bytes as the HMAC secret. Without an explicit valid-methods
// allowlist, jwt.ParseWithClaims hands the *rsa.PublicKey to the HS256
// verifier and accepts the forgery. The provider MUST restrict
// verification to RSA/EC algorithms.
func TestOIDC_RejectsHS256ForgedWithPublicKey(t *testing.T) {
	t.Parallel()

	// Generate an RSA keypair; only the public half is published.
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	const kid = "test-kid"

	// JWKS server that publishes the public key under `kid`.
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
				N:   base64.RawURLEncoding.EncodeToString(priv.PublicKey.N.Bytes()),
				E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(priv.PublicKey.E)).Bytes()),
			}},
		})
	})
	srv = httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test-only
		},
	}

	provider, err := NewOIDCProvider(OIDCConfig{
		Name:       "oidc",
		IssuerURL:  srv.URL,
		Audience:   "stac-proxy",
		HTTPClient: client,
	})
	if err != nil {
		t.Fatalf("NewOIDCProvider: %v", err)
	}

	// Forge an HS256 token whose "secret" is the DER-encoded SubjectPublicKeyInfo
	// bytes of the public key — the canonical form an attacker pulls
	// from the JWKS and feeds to the HS256 verifier.
	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	forged := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": srv.URL,
		"aud": "stac-proxy",
		"sub": "attacker",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	forged.Header["kid"] = kid
	tokenStr, err := forged.SignedString(pubBytes)
	if err != nil {
		t.Fatalf("sign forged token: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)

	principal, err := provider.Authenticate(context.Background(), req)
	if err == nil {
		t.Fatalf("expected error rejecting HS256-forged token, got principal=%+v", principal)
	}
	if principal != nil {
		t.Fatalf("expected nil principal on forged token, got %+v", principal)
	}
}

// newOIDCWithSigningKey spins up an HTTPS test server that publishes
// the given public key under `kid` and returns a constructed provider.
// Helper used by the attribute-allowlist tests below.
func newOIDCWithSigningKey(t *testing.T, kid string, pub *rsa.PublicKey, audience string, allowlist []string) *OIDCProvider {
	t.Helper()
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
				N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
			}},
		})
	})
	srv = httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test-only
		},
	}

	p, err := NewOIDCProvider(OIDCConfig{
		Name:               "oidc",
		IssuerURL:          srv.URL,
		Audience:           audience,
		HTTPClient:         client,
		AttributeAllowlist: allowlist,
	})
	if err != nil {
		t.Fatalf("NewOIDCProvider: %v", err)
	}
	return p
}

// TestOIDC_OnlyAllowlistedClaimsCopied verifies that string claims not
// on the allowlist (e.g. an attacker-controlled "evil_attr") never
// reach Principal.Attributes. (M-auth-4)
func TestOIDC_OnlyAllowlistedClaimsCopied(t *testing.T) {
	t.Parallel()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	const kid = "test-kid"
	provider := newOIDCWithSigningKey(t, kid, &priv.PublicKey, "stac-proxy", nil) // default allowlist

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":       provider.issuer,
		"aud":       "stac-proxy",
		"sub":       "user-1",
		"exp":       time.Now().Add(time.Hour).Unix(),
		"email":     "user@example.com",
		"evil_attr": "spoofed",
	})
	tok.Header["kid"] = kid
	signed, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+signed)
	princ, err := provider.Authenticate(context.Background(), req)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if got, want := princ.Attributes["email"], "user@example.com"; got != want {
		t.Errorf("expected email=%q, got %q", want, got)
	}
	if got, ok := princ.Attributes["evil_attr"]; ok {
		t.Errorf("non-allowlisted claim leaked into attributes: %q", got)
	}
}

// TestOIDC_AuthMethodSetServerSide verifies that auth_method is always
// set to "oidc" by the provider and a token claiming a different value
// cannot override it.
func TestOIDC_AuthMethodSetServerSide(t *testing.T) {
	t.Parallel()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	const kid = "test-kid"
	// Include "auth_method" on the allowlist explicitly so we exercise
	// the worst case: even when the operator lists it, the server-side
	// stamp must still win.
	provider := newOIDCWithSigningKey(t, kid, &priv.PublicKey, "stac-proxy",
		[]string{"email", "auth_method"})

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":         provider.issuer,
		"aud":         "stac-proxy",
		"sub":         "user-2",
		"exp":         time.Now().Add(time.Hour).Unix(),
		"auth_method": "spoofed",
	})
	tok.Header["kid"] = kid
	signed, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+signed)
	princ, err := provider.Authenticate(context.Background(), req)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if got := princ.Attributes["auth_method"]; got != "oidc" {
		t.Fatalf("auth_method must be set server-side; want \"oidc\", got %q", got)
	}
}

// silence unused-import warnings if the suite is ever stripped.
var _ = fmt.Sprintf
