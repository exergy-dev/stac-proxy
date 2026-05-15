package server

import (
	"net/http"
	"testing"

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
