package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/exergy-dev/stac-proxy/internal/config"
)

func TestServer_ReadHeaderTimeoutSet(t *testing.T) {
	t.Parallel()

	srv, err := New(Config{
		ServerConfig: &config.ServerConfig{Host: "127.0.0.1", Port: 0},
		Handler:      http.NewServeMux(),
	})
	require.NoError(t, err, "New")
	require.Greater(t, srv.httpServer.ReadHeaderTimeout, time.Duration(0),
		"expected ReadHeaderTimeout > 0, got %v", srv.httpServer.ReadHeaderTimeout)
}

// TestServer_MaxHeaderBytes_Returns431 asserts that a request whose
// headers exceed the configured MaxHeaderBytes is rejected with HTTP
// 431 rather than being buffered up to Go's 1 MiB default.
func TestServer_MaxHeaderBytes_Returns431(t *testing.T) {
	t.Parallel()

	srv, err := New(Config{
		ServerConfig: &config.ServerConfig{
			Host:           "127.0.0.1",
			Port:           0,
			MaxHeaderBytes: 4 * 1024,
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	})
	require.NoError(t, err, "New")

	go func() { _ = srv.Start() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	// Wait for the listener to bind and report a concrete port.
	var base string
	require.Eventually(t, func() bool {
		addr := srv.Addr()
		if strings.HasSuffix(addr, ":0") {
			return false
		}
		base = "http://" + addr
		return true
	}, 3*time.Second, 5*time.Millisecond, "server did not start listening")

	req, err := http.NewRequest(http.MethodGet, base+"/", nil)
	require.NoError(t, err, "NewRequest")
	// A single oversized header comfortably past the 4 KiB cap (net/http
	// also reserves slack for the request line, so overshoot generously).
	req.Header.Set("X-Big", strings.Repeat("a", 64*1024))

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err, "Do")
	defer resp.Body.Close()

	assert.Equal(t, http.StatusRequestHeaderFieldsTooLarge, resp.StatusCode,
		"expected 431 for oversized request headers, got %d", resp.StatusCode)
}

// TestTLSConfig_NoExplicitCipherSuites_HasH2Protocols asserts that
// loadTLSConfig defers cipher selection to crypto/tls (no explicit
// CipherSuites list — see comment on loadTLSConfig for rationale) and
// that ALPN advertises both h2 and http/1.1 so HTTP/2 negotiates.
func TestTLSConfig_NoExplicitCipherSuites_HasH2Protocols(t *testing.T) {
	t.Parallel()

	certFile, keyFile := writeSelfSignedCert(t)

	tlsCfg, err := loadTLSConfig(config.TLSConfig{
		CertFile: certFile,
		KeyFile:  keyFile,
	})
	require.NoError(t, err, "loadTLSConfig")

	assert.Empty(t, tlsCfg.CipherSuites,
		"expected no explicit CipherSuites (Go's defaults are vetted), got %d entries: %v",
		len(tlsCfg.CipherSuites), tlsCfg.CipherSuites)

	hasH2 := false
	hasHTTP11 := false
	for _, p := range tlsCfg.NextProtos {
		switch p {
		case "h2":
			hasH2 = true
		case "http/1.1":
			hasHTTP11 = true
		}
	}
	assert.True(t, hasH2, "NextProtos missing %q (HTTP/2 ALPN); got %v", "h2", tlsCfg.NextProtos)
	assert.True(t, hasHTTP11, "NextProtos missing %q; got %v", "http/1.1", tlsCfg.NextProtos)
}

// writeSelfSignedCert generates an ephemeral self-signed certificate
// and returns the (certFile, keyFile) paths. Files live under
// t.TempDir so go test cleans up automatically.
func writeSelfSignedCert(t *testing.T) (string, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "generate key")
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err, "create cert")
	keyDER, err := x509.MarshalECPrivateKey(priv)
	require.NoError(t, err, "marshal key")

	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	require.NoError(t,
		os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0o600),
		"write cert")
	require.NoError(t,
		os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600),
		"write key")
	return certPath, keyPath
}
