package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/exergy-dev/stac-proxy/internal/config"
	"github.com/exergy-dev/stac-proxy/internal/federation"
	"github.com/exergy-dev/stac-proxy/internal/middleware/auth"
	"github.com/exergy-dev/stac-proxy/internal/observability"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAuthProviderWiring_AllConfiguredTypesAreActive verifies that
// every documented auth provider type is wired through the same
// switch as production (HIGH H-config-3). Previously oidc/basic/mtls
// were silently skipped — a config asking for `type: oidc` would
// startup clean and serve traffic with zero auth. The fix maps every
// supported type and errors on unknown types.
func TestAuthProviderWiring_AllConfiguredTypesAreActive(t *testing.T) {
	t.Parallel()

	// Generate a CA cert for mTLS and a basic htpasswd-style hash.
	caFile := writeSelfSignedCAForAuthTest(t)

	// OIDC discovery now uses go-oidc which requires a live discovery
	// endpoint at provider construction time.
	oidcSrv := newAuthWiringOIDCDiscovery(t)

	cfg := &config.Config{
		Middleware: []config.MiddlewareConfig{{
			Name: "auth",
			Config: map[string]interface{}{
				"allow_anonymous": true,
				"providers": []interface{}{
					map[string]interface{}{
						"type":     "bearer",
						"issuer":   "https://issuer.example.com",
						"audience": "test",
						"secret":   "shhh",
					},
					map[string]interface{}{
						"type":        "api_key",
						"header_name": "X-API-Key",
					},
					map[string]interface{}{
						"type":                "oidc",
						"issuer_url":          oidcSrv.URL,
						"audience":            "test",
						"allow_insecure_http": true,
					},
					map[string]interface{}{
						"type":  "basic",
						"realm": "test",
						"users": []interface{}{
							map[string]interface{}{
								"username":      "alice",
								"password_hash": "$2a$10$abcdefghijklmnopqrstuv",
							},
						},
					},
					map[string]interface{}{
						"type":              "mtls",
						"trusted_ca_file":   caFile,
						"require_client_ca": true,
					},
				},
			},
		}},
	}

	// Drive the config through the real switch by collecting the
	// providers as buildAuthHTTPMiddleware would.
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	rawCfg := cfg.Middleware[0].Config
	providersRaw := rawCfg["providers"].([]interface{})

	got := make([]auth.Provider, 0, len(providersRaw))
	for i, pCfg := range providersRaw {
		p, err := buildAuthProvider(context.Background(), pCfg.(map[string]interface{}), logger)
		require.NoErrorf(t, err, "providers[%d]", i)
		require.NotNilf(t, p, "providers[%d]: returned nil without error", i)
		got = append(got, p)
	}

	wantTypes := []string{
		"*auth.BearerProvider",
		"*auth.APIKeyProvider",
		"*auth.OIDCProvider",
		"*auth.BasicAuthProvider",
		"*auth.MTLSProvider",
	}
	require.Len(t, got, len(wantTypes), "provider count")
	for i, p := range got {
		typ := reflect.TypeOf(p).String()
		assert.Equalf(t, wantTypes[i], typ, "providers[%d]", i)
	}

	// Unknown type should produce an error rather than silently drop.
	_, err := buildAuthProvider(context.Background(), map[string]interface{}{"type": "made_up"}, logger)
	assert.Error(t, err, "expected error for unknown auth provider type")
}

// writeSelfSignedCAForAuthTest writes a minimal self-signed CA cert
// PEM for the mTLS provider's TrustedCAs path.
func writeSelfSignedCAForAuthTest(t *testing.T) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "genkey")
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err, "createcert")
	dir := t.TempDir()
	path := filepath.Join(dir, "ca.pem")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600), "writefile")
	return path
}

// TestBuildFederationHandler_CopiesEveryConfiguredField asserts that
// every documented field on config.OriginConfig / OriginAuthConfig and
// the new server.public_base_url reach the federation.Origin / Handler
// without being silently dropped. This is the round-trip test that
// would have caught the class of bug where a YAML field was wired into
// the config struct but never copied into the federation layer
// (ForwardUserIdentity, Retry, MaxIdleConnsPerHost, MaxResponseBytes,
// AWSSigV4, ProxyBaseURL all shipped broken in v0.1.0).
//
// When a new field is added to config.OriginConfig, this test must be
// updated — that is the point.
func TestBuildFederationHandler_CopiesEveryConfiguredField(t *testing.T) {
	t.Parallel()

	const publicBaseURL = "https://stac.example.com"

	cfg := &config.Config{
		Mode: "federation",
		Server: config.ServerConfig{
			Host:          "0.0.0.0",
			Port:          8080,
			PublicBaseURL: publicBaseURL,
		},
		Federation: &config.FederationConfig{
			AllowPrivateOrigins: true, // BaseURL below uses example.com (public)
			CursorSecret:        "test-secret-must-be-long-enough-for-hmac",
			MaxConcurrent:       7,
			AggregateTimeout:    11 * time.Second,
			DefaultPageSize:     42,
			MaxPageSize:         420,
			Origins: []config.OriginConfig{{
				ID:                  "primary",
				Name:                "Primary",
				Description:         "An origin with every field set.",
				BaseURL:             "https://upstream.example.com/stac",
				Enabled:             true,
				Timeout:             13 * time.Second,
				MaxIdleConnsPerHost: 17,
				Retry: &config.RetryConfig{
					MaxRetries:     3,
					InitialBackoff: 250 * time.Millisecond,
					MaxBackoff:     5 * time.Second,
					RetryOn:        []int{502, 503, 504},
				},
				Collections:             []string{"sentinel-2", "landsat-8"},
				ExcludeCollections:      []string{"private"},
				Priority:                99,
				ReadOnly:                true,
				Searchable:              true,
				AutoDiscover:            true,
				DiscoveryInterval:       30 * time.Minute,
				CollectionPrefix:        "p_",
				CollectionMapping:       map[string]string{"a": "b"},
				StripPathPrefix:         "/v1",
				SupportsFilterExtension: true,
				MaxResponseBytes:        64 << 20,
				ForwardUserIdentity:     true,
				RewriteAssets:           "proxy",
				AssetSignTTL:            7 * time.Minute,
				Pagination: &config.PaginationConfig{
					Adapter:     "next_url",
					OffsetParam: "page",
					TokenParam:  "next",
				},
				Auth: &config.OriginAuthConfig{
					Type:          "oauth2",
					Username:      "u",
					Password:      "p",
					Token:         "tok",
					APIKeyHeader:  "X-API-Key",
					APIKeyValue:   "v",
					APIKeyInQuery: true,
					CustomHeaders: map[string]string{"X-Tenant": "acme"},
					OAuth2: &config.OAuth2Config{
						TokenURL:     "https://idp.example.com/token",
						ClientID:     "cid",
						ClientSecret: "csec",
						Scopes:       []string{"read"},
						Audience:     "stac-api",
					},
					AWSSigV4: &config.AWSSigV4Config{
						Region:    "us-west-2",
						Service:   "s3",
						AccessKey: "AKIA",
						SecretKey: "SECRET",
					},
				},
			}},
		},
	}
	require.NoError(t, cfg.Validate(), "Validate")

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	health := observability.NewHealthChecker()

	handler, err := buildFederationHandler(context.Background(), cfg, logger, health, nil)
	require.NoError(t, err, "buildFederationHandler")

	assert.Equal(t, publicBaseURL, handler.ProxyBaseURL(), "ProxyBaseURL")

	oc := handler.OriginClient("primary")
	require.NotNil(t, oc, "origin client 'primary' missing")
	got := oc.Origin()
	in := cfg.Federation.Origins[0]

	// Build the expected federation.Origin once and compare with
	// DeepEqual. This catches any new field added to federation.Origin
	// that the builder forgets to populate from config — exactly the
	// class of bug this test exists to prevent.
	expectedOrigin := &federation.Origin{
		ID:                  in.ID,
		Name:                in.Name,
		Description:         in.Description,
		BaseURL:             in.BaseURL,
		Enabled:             in.Enabled,
		Timeout:             in.Timeout,
		MaxIdleConnsPerHost: in.MaxIdleConnsPerHost,
		Retry: &federation.RetryPolicy{
			MaxRetries:     in.Retry.MaxRetries,
			InitialBackoff: in.Retry.InitialBackoff,
			MaxBackoff:     in.Retry.MaxBackoff,
			RetryOn:        in.Retry.RetryOn,
		},
		Collections:             in.Collections,
		ExcludeCollections:      in.ExcludeCollections,
		Priority:                in.Priority,
		ReadOnly:                in.ReadOnly,
		Searchable:              in.Searchable,
		AutoDiscover:            in.AutoDiscover,
		DiscoveryInterval:       in.DiscoveryInterval,
		CollectionPrefix:        in.CollectionPrefix,
		CollectionMapping:       in.CollectionMapping,
		StripPathPrefix:         in.StripPathPrefix,
		SupportsFilterExtension: in.SupportsFilterExtension,
		MaxResponseBytes:        in.MaxResponseBytes,
		ForwardUserIdentity:     in.ForwardUserIdentity,
		RewriteAssets:           in.RewriteAssets,
		AssetSignTTL:            in.AssetSignTTL,
		Pagination: federation.PaginationSpec{
			Adapter:     in.Pagination.Adapter,
			OffsetParam: in.Pagination.OffsetParam,
			TokenParam:  in.Pagination.TokenParam,
		},
		Auth: federation.AuthConfig{
			Type:          in.Auth.Type,
			Username:      in.Auth.Username,
			Password:      in.Auth.Password,
			Token:         in.Auth.Token,
			APIKeyHeader:  in.Auth.APIKeyHeader,
			APIKeyValue:   in.Auth.APIKeyValue,
			APIKeyInQuery: in.Auth.APIKeyInQuery,
			CustomHeaders: in.Auth.CustomHeaders,
			OAuth2: &federation.OAuth2Config{
				TokenURL:     in.Auth.OAuth2.TokenURL,
				ClientID:     in.Auth.OAuth2.ClientID,
				ClientSecret: in.Auth.OAuth2.ClientSecret,
				Scopes:       in.Auth.OAuth2.Scopes,
				Audience:     in.Auth.OAuth2.Audience,
			},
			AWSSigV4: &federation.AWSSigV4Config{
				Region:    in.Auth.AWSSigV4.Region,
				Service:   in.Auth.AWSSigV4.Service,
				AccessKey: in.Auth.AWSSigV4.AccessKey,
				SecretKey: in.Auth.AWSSigV4.SecretKey,
			},
		},
	}

	if !reflect.DeepEqual(got, expectedOrigin) {
		assert.Failf(t, "federation.Origin not fully populated from config",
			"got:\n%+v\nwant:\n%+v", got, expectedOrigin)
	}
}

// TestBuildFederationHandler_SingleModeWiresPublicBaseURL verifies that
// the single-origin → federation-of-1 path also picks up
// server.public_base_url. Without this, single-mode deployments emit
// relative `next` links and break `rewrite_assets: proxy`.
func TestBuildFederationHandler_SingleModeWiresPublicBaseURL(t *testing.T) {
	t.Parallel()

	const publicBaseURL = "https://stac.example.com"

	cfg := &config.Config{
		Mode: "single",
		Server: config.ServerConfig{
			Host:          "0.0.0.0",
			Port:          8080,
			PublicBaseURL: publicBaseURL,
		},
		Upstream: &config.UpstreamConfig{
			URL:                     "https://upstream.example.com/stac",
			Timeout:                 10 * time.Second,
			SupportsFilterExtension: true,
		},
	}
	require.NoError(t, cfg.Validate(), "Validate")

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	health := observability.NewHealthChecker()
	handler, err := buildFederationHandler(context.Background(), cfg, logger, health, nil)
	require.NoError(t, err, "buildFederationHandler")
	assert.Equalf(t, publicBaseURL, handler.ProxyBaseURL(), "ProxyBaseURL (single-mode dropped server.public_base_url)")
}

// newAuthWiringOIDCDiscovery spins up a minimal OIDC discovery server
// for the auth-wiring smoke test. It only needs to serve a valid
// discovery document — token verification is not exercised here.
func newAuthWiringOIDCDiscovery(t *testing.T) *httptest.Server {
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
		_, _ = w.Write([]byte(`{"keys":[]}`))
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// TestServerIsUnauthenticated verifies the warn-condition predicate: it
// reports true when nothing in the middleware chain rejects anonymous
// requests, and false once auth (allow_anonymous: false) or an authz
// enforcer gates the server.
func TestServerIsUnauthenticated(t *testing.T) {
	authBlock := func(allowAnon bool) config.MiddlewareConfig {
		return config.MiddlewareConfig{
			Name: "auth",
			Config: map[string]interface{}{
				"allow_anonymous": allowAnon,
				"providers": []interface{}{
					map[string]interface{}{"type": "bearer", "secret": "s"},
				},
			},
		}
	}

	tests := []struct {
		name string
		cfg  *config.Config
		want bool
	}{
		{
			name: "no auth, no authz → open",
			cfg:  &config.Config{},
			want: true,
		},
		{
			name: "auth block allows anonymous → open",
			cfg:  &config.Config{Middleware: []config.MiddlewareConfig{authBlock(true)}},
			want: true,
		},
		{
			name: "auth block without allow_anonymous key defaults open",
			cfg: &config.Config{Middleware: []config.MiddlewareConfig{{
				Name:   "auth",
				Config: map[string]interface{}{},
			}}},
			want: true,
		},
		{
			name: "auth required (allow_anonymous: false) → closed",
			cfg:  &config.Config{Middleware: []config.MiddlewareConfig{authBlock(false)}},
			want: false,
		},
		{
			name: "authz OPA enforcer gates anonymous → closed",
			cfg:  &config.Config{Authz: &config.AuthzConfig{OPA: &config.OPAConfig{Embedded: true}}},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, serverIsUnauthenticated(tt.cfg))
		})
	}
}

// TestAuthProviderWiring_APIKeyCredentials proves the api_key provider
// receives its credentials from YAML — before this wiring, only
// header_name/query_param were passed, so every configured key 401'd.
func TestAuthProviderWiring_APIKeyCredentials(t *testing.T) {
	t.Parallel()

	pMap := map[string]interface{}{
		"type":        "api_key",
		"header_name": "X-API-Key",
		"hmac_secret": "stable-test-secret",
		"keys": []interface{}{
			map[string]interface{}{
				"key":   "good-key-123",
				"name":  "svc-alpha",
				"roles": []interface{}{"data_scientist"},
				// enabled omitted -> defaults true for inline entries
			},
			map[string]interface{}{
				"key":     "revoked-key",
				"name":    "svc-old",
				"enabled": false,
			},
		},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	p, err := buildAuthProvider(context.Background(), pMap, logger)
	require.NoError(t, err)

	authed := func(key string) (*auth.Principal, error) {
		r := httptest.NewRequest(http.MethodGet, "/search", nil)
		r.Header.Set("X-API-Key", key)
		return p.Authenticate(context.Background(), r)
	}

	principal, err := authed("good-key-123")
	require.NoError(t, err, "configured key must authenticate")
	require.NotNil(t, principal)
	assert.Equal(t, []string{"data_scientist"}, principal.Roles, "roles from YAML must land on the principal")

	_, err = authed("revoked-key")
	assert.Error(t, err, "enabled: false key must be rejected")

	_, err = authed("never-configured")
	assert.Error(t, err, "unknown key must be rejected")

	// allow_query_param defaults false: a key in the query string
	// alone is never read — the provider reports "no credential"
	// (nil, nil), so the request cannot authenticate through it.
	r := httptest.NewRequest(http.MethodGet, "/search?api_key=good-key-123", nil)
	qp, err := p.Authenticate(context.Background(), r)
	assert.NoError(t, err)
	assert.Nil(t, qp, "query-param key must not authenticate without allow_query_param")

	// Missing 'key' field is a hard config error.
	_, err = buildAuthProvider(context.Background(), map[string]interface{}{
		"type": "api_key",
		"keys": []interface{}{map[string]interface{}{"name": "keyless"}},
	}, logger)
	assert.ErrorContains(t, err, "missing required field 'key'")
}
