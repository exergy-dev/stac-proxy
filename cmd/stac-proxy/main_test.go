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
