package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/yourorg/stac-proxy/internal/config"
	"github.com/yourorg/stac-proxy/internal/federation"
	"github.com/yourorg/stac-proxy/internal/middleware/auth"
	"github.com/yourorg/stac-proxy/internal/observability"
)

// TestNewMetricsServer_ShutdownDrainsListener verifies that the
// metrics *http.Server returned by newMetricsServer is shutdown-able
// (Fix H-server-tls-2 — previously the metrics goroutine was orphaned
// past SIGTERM because the *http.Server was not retained by the
// caller).
//
// We start the server on an ephemeral port, then call Shutdown and
// assert that ListenAndServe returns http.ErrServerClosed within
// the deadline. If the caller had not retained the handle, this
// test could not even be expressed.
func TestNewMetricsServer_ShutdownDrainsListener(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	metrics := observability.NewMetrics("test_shutdown")

	// Port 0 → kernel picks a free port.
	srv := newMetricsServer(config.MetricsConfig{
		Enabled:  true,
		BindAddr: "127.0.0.1:0",
	}, metrics, logger)

	// We need to bind explicitly so we know the port — ListenAndServe
	// would block. Use a separate listener and Serve.
	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- srv.Serve(ln)
	}()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	select {
	case err := <-serveErr:
		if err != nil && err != http.ErrServerClosed {
			t.Fatalf("Serve returned unexpected error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return within 5s of Shutdown")
	}
}

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
						"issuer":              "https://issuer.example.com",
						"audience":            "test",
						"jwks_url":            "https://issuer.example.com/.well-known/jwks.json",
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
		p, err := buildAuthProvider(pCfg.(map[string]interface{}), logger)
		if err != nil {
			t.Fatalf("providers[%d]: %v", i, err)
		}
		if p == nil {
			t.Fatalf("providers[%d]: returned nil without error", i)
		}
		got = append(got, p)
	}

	wantTypes := []string{
		"*auth.BearerProvider",
		"*auth.APIKeyProvider",
		"*auth.OIDCProvider",
		"*auth.BasicAuthProvider",
		"*auth.MTLSProvider",
	}
	if len(got) != len(wantTypes) {
		t.Fatalf("provider count = %d, want %d", len(got), len(wantTypes))
	}
	for i, p := range got {
		typ := reflect.TypeOf(p).String()
		if typ != wantTypes[i] {
			t.Errorf("providers[%d] = %s, want %s", i, typ, wantTypes[i])
		}
	}

	// Unknown type should produce an error rather than silently drop.
	if _, err := buildAuthProvider(map[string]interface{}{"type": "made_up"}, logger); err == nil {
		t.Error("expected error for unknown auth provider type, got nil")
	}
}

// writeSelfSignedCAForAuthTest writes a minimal self-signed CA cert
// PEM for the mTLS provider's TrustedCAs path.
func writeSelfSignedCAForAuthTest(t *testing.T) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
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
	if err != nil {
		t.Fatalf("createcert: %v", err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("writefile: %v", err)
	}
	return path
}

// TestParallelShutdown_BothServersDrain models the run() shutdown
// path: a main http.Server and a metrics http.Server are both
// shut down in parallel via WaitGroup. Verifies that both
// goroutines complete and Wait returns.
func TestParallelShutdown_BothServersDrain(t *testing.T) {
	t.Parallel()

	mkServer := func() (*http.Server, net.Listener) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		s := &http.Server{
			Handler:           http.NewServeMux(),
			ReadHeaderTimeout: time.Second,
		}
		go func() {
			_ = s.Serve(ln)
		}()
		return s, ln
	}

	mainSrv, mainLn := mkServer()
	metricsSrv, metricsLn := mkServer()
	_, _ = mainLn, metricsLn // listeners owned by Server

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = mainSrv.Shutdown(shutdownCtx)
		}()
		go func() {
			defer wg.Done()
			_ = metricsSrv.Shutdown(shutdownCtx)
		}()
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success: both shut down cleanly.
	case <-time.After(5 * time.Second):
		t.Fatal("parallel Shutdown did not complete within 5s")
	}
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
			ConflictStrategy:    "priority",
			CursorSecret:        "test-secret-must-be-long-enough-for-hmac",
			MaxConcurrent:       7,
			AggregateTimeout:    11 * time.Second,
			DefaultPageSize:     42,
			MaxPageSize:         420,
			Origins: []config.OriginConfig{{
				ID:                      "primary",
				Name:                    "Primary",
				Description:             "An origin with every field set.",
				BaseURL:                 "https://upstream.example.com/stac",
				Enabled:                 true,
				Timeout:                 13 * time.Second,
				MaxIdleConnsPerHost:     17,
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
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	health := observability.NewHealthChecker()

	handler, err := buildFederationHandler(context.Background(), cfg, logger, health, nil)
	if err != nil {
		t.Fatalf("buildFederationHandler: %v", err)
	}

	if got, want := handler.ProxyBaseURL(), publicBaseURL; got != want {
		t.Errorf("ProxyBaseURL = %q, want %q", got, want)
	}

	oc := handler.OriginClient("primary")
	if oc == nil {
		t.Fatal("origin client 'primary' missing")
	}
	got := oc.Origin()
	in := cfg.Federation.Origins[0]

	// Scalars and slices on Origin
	checks := []struct {
		name        string
		got, expect any
	}{
		{"ID", got.ID, in.ID},
		{"Name", got.Name, in.Name},
		{"Description", got.Description, in.Description},
		{"BaseURL", got.BaseURL, in.BaseURL},
		{"Enabled", got.Enabled, in.Enabled},
		{"Timeout", got.Timeout, in.Timeout},
		{"MaxIdleConnsPerHost", got.MaxIdleConnsPerHost, in.MaxIdleConnsPerHost},
		{"Collections", got.Collections, in.Collections},
		{"ExcludeCollections", got.ExcludeCollections, in.ExcludeCollections},
		{"Priority", got.Priority, in.Priority},
		{"ReadOnly", got.ReadOnly, in.ReadOnly},
		{"Searchable", got.Searchable, in.Searchable},
		{"AutoDiscover", got.AutoDiscover, in.AutoDiscover},
		{"DiscoveryInterval", got.DiscoveryInterval, in.DiscoveryInterval},
		{"CollectionPrefix", got.CollectionPrefix, in.CollectionPrefix},
		{"CollectionMapping", got.CollectionMapping, in.CollectionMapping},
		{"StripPathPrefix", got.StripPathPrefix, in.StripPathPrefix},
		{"SupportsFilterExtension", got.SupportsFilterExtension, in.SupportsFilterExtension},
		{"MaxResponseBytes", got.MaxResponseBytes, in.MaxResponseBytes},
		{"ForwardUserIdentity", got.ForwardUserIdentity, in.ForwardUserIdentity},
		{"RewriteAssets", got.RewriteAssets, in.RewriteAssets},
		{"AssetSignTTL", got.AssetSignTTL, in.AssetSignTTL},
	}
	for _, c := range checks {
		if !reflect.DeepEqual(c.got, c.expect) {
			t.Errorf("Origin.%s = %v, want %v", c.name, c.got, c.expect)
		}
	}

	// Pagination round-trip
	wantPag := federation.PaginationSpec{
		Adapter:     in.Pagination.Adapter,
		OffsetParam: in.Pagination.OffsetParam,
		TokenParam:  in.Pagination.TokenParam,
	}
	if !reflect.DeepEqual(got.Pagination, wantPag) {
		t.Errorf("Origin.Pagination = %+v, want %+v", got.Pagination, wantPag)
	}

	// Retry policy round-trip
	if got.Retry == nil {
		t.Fatalf("Origin.Retry nil; want %+v", in.Retry)
	}
	wantRetry := struct {
		MaxRetries     int
		InitialBackoff time.Duration
		MaxBackoff     time.Duration
		RetryOn        []int
	}{in.Retry.MaxRetries, in.Retry.InitialBackoff, in.Retry.MaxBackoff, in.Retry.RetryOn}
	gotRetry := struct {
		MaxRetries     int
		InitialBackoff time.Duration
		MaxBackoff     time.Duration
		RetryOn        []int
	}{got.Retry.MaxRetries, got.Retry.InitialBackoff, got.Retry.MaxBackoff, got.Retry.RetryOn}
	if !reflect.DeepEqual(gotRetry, wantRetry) {
		t.Errorf("Origin.Retry = %+v, want %+v", gotRetry, wantRetry)
	}

	// Auth scalars
	a := got.Auth
	ia := in.Auth
	authChecks := []struct {
		name        string
		got, expect any
	}{
		{"Type", a.Type, ia.Type},
		{"Username", a.Username, ia.Username},
		{"Password", a.Password, ia.Password},
		{"Token", a.Token, ia.Token},
		{"APIKeyHeader", a.APIKeyHeader, ia.APIKeyHeader},
		{"APIKeyValue", a.APIKeyValue, ia.APIKeyValue},
		{"APIKeyInQuery", a.APIKeyInQuery, ia.APIKeyInQuery},
		{"CustomHeaders", a.CustomHeaders, ia.CustomHeaders},
	}
	for _, c := range authChecks {
		if !reflect.DeepEqual(c.got, c.expect) {
			t.Errorf("Origin.Auth.%s = %v, want %v", c.name, c.got, c.expect)
		}
	}
	if a.OAuth2 == nil {
		t.Fatal("Origin.Auth.OAuth2 nil")
	}
	if a.OAuth2.TokenURL != ia.OAuth2.TokenURL ||
		a.OAuth2.ClientID != ia.OAuth2.ClientID ||
		a.OAuth2.ClientSecret != ia.OAuth2.ClientSecret ||
		a.OAuth2.Audience != ia.OAuth2.Audience ||
		!reflect.DeepEqual(a.OAuth2.Scopes, ia.OAuth2.Scopes) {
		t.Errorf("Origin.Auth.OAuth2 mismatch: got %+v, want %+v", a.OAuth2, ia.OAuth2)
	}
	if a.AWSSigV4 == nil {
		t.Fatal("Origin.Auth.AWSSigV4 nil — config field dropped on the floor")
	}
	if a.AWSSigV4.Region != ia.AWSSigV4.Region ||
		a.AWSSigV4.Service != ia.AWSSigV4.Service ||
		a.AWSSigV4.AccessKey != ia.AWSSigV4.AccessKey ||
		a.AWSSigV4.SecretKey != ia.AWSSigV4.SecretKey {
		t.Errorf("Origin.Auth.AWSSigV4 mismatch: got %+v, want %+v", a.AWSSigV4, ia.AWSSigV4)
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
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	health := observability.NewHealthChecker()
	handler, err := buildFederationHandler(context.Background(), cfg, logger, health, nil)
	if err != nil {
		t.Fatalf("buildFederationHandler: %v", err)
	}
	if got, want := handler.ProxyBaseURL(), publicBaseURL; got != want {
		t.Errorf("ProxyBaseURL = %q, want %q (single-mode dropped server.public_base_url)", got, want)
	}
}
