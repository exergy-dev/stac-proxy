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

	"github.com/yourorg/stac-proxy/internal/config"
)

func TestServer_ReadHeaderTimeoutSet(t *testing.T) {
	t.Parallel()

	srv, err := New(Config{
		ServerConfig: &config.ServerConfig{Host: "127.0.0.1", Port: 0},
		Handler:      http.NewServeMux(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if srv.httpServer.ReadHeaderTimeout <= 0 {
		t.Fatalf("expected ReadHeaderTimeout > 0, got %v", srv.httpServer.ReadHeaderTimeout)
	}
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
	if err != nil {
		t.Fatalf("loadTLSConfig: %v", err)
	}

	if got := len(tlsCfg.CipherSuites); got != 0 {
		t.Errorf("expected no explicit CipherSuites (Go's defaults are vetted), got %d entries: %v", got, tlsCfg.CipherSuites)
	}

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
	if !hasH2 {
		t.Errorf("NextProtos missing %q (HTTP/2 ALPN); got %v", "h2", tlsCfg.NextProtos)
	}
	if !hasHTTP11 {
		t.Errorf("NextProtos missing %q; got %v", "http/1.1", tlsCfg.NextProtos)
	}
}

// writeSelfSignedCert generates an ephemeral self-signed certificate
// and returns the (certFile, keyFile) paths. Files live under
// t.TempDir so go test cleans up automatically.
func writeSelfSignedCert(t *testing.T) (string, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}

	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certPath, keyPath
}
