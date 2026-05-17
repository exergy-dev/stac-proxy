package server

import (
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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yourorg/stac-proxy/internal/config"
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
