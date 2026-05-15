package auth

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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

// silence unused-import warnings if the suite is ever stripped.
var _ = fmt.Sprintf
