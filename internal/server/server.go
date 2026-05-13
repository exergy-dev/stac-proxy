// Package server provides the HTTP server implementation.
package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/yourorg/stac-proxy/internal/config"
)

// Server represents the HTTP server.
type Server struct {
	httpServer *http.Server
	listener   net.Listener
	logger     *slog.Logger
	cfg        *config.ServerConfig
}

// Config contains server configuration.
type Config struct {
	ServerConfig *config.ServerConfig
	Handler      http.Handler
	Logger       *slog.Logger
}

// New creates a new HTTP server.
func New(cfg Config) (*Server, error) {
	if cfg.ServerConfig == nil {
		cfg.ServerConfig = &config.ServerConfig{
			Host: "0.0.0.0",
			Port: 8080,
		}
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.NewJSONHandler(os.Stdout, nil))
	}

	addr := fmt.Sprintf("%s:%d", cfg.ServerConfig.Host, cfg.ServerConfig.Port)

	httpServer := &http.Server{
		Addr:         addr,
		Handler:      cfg.Handler,
		ReadTimeout:  cfg.ServerConfig.Timeouts.Read,
		WriteTimeout: cfg.ServerConfig.Timeouts.Write,
		IdleTimeout:  cfg.ServerConfig.Timeouts.Idle,
	}

	// Set default timeouts if not configured
	if httpServer.ReadTimeout == 0 {
		httpServer.ReadTimeout = 30 * time.Second
	}
	if httpServer.WriteTimeout == 0 {
		httpServer.WriteTimeout = 60 * time.Second
	}
	if httpServer.IdleTimeout == 0 {
		httpServer.IdleTimeout = 120 * time.Second
	}

	// Configure TLS if enabled
	if cfg.ServerConfig.TLS.Enabled {
		tlsConfig, err := loadTLSConfig(cfg.ServerConfig.TLS)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS config: %w", err)
		}
		httpServer.TLSConfig = tlsConfig
	}

	return &Server{
		httpServer: httpServer,
		logger:     logger,
		cfg:        cfg.ServerConfig,
	}, nil
}

// Start starts the HTTP server.
func (s *Server) Start() error {
	addr := s.httpServer.Addr

	var err error
	s.listener, err = net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	s.logger.Info("Server starting",
		"addr", addr,
		"tls", s.cfg.TLS.Enabled,
	)

	if s.cfg.TLS.Enabled {
		return s.httpServer.ServeTLS(s.listener, s.cfg.TLS.CertFile, s.cfg.TLS.KeyFile)
	}

	return s.httpServer.Serve(s.listener)
}

// Shutdown gracefully shuts down the server.
func (s *Server) Shutdown(ctx context.Context) error {
	s.logger.Info("Shutting down server")
	return s.httpServer.Shutdown(ctx)
}

// Addr returns the server's listen address.
func (s *Server) Addr() string {
	if s.listener != nil {
		return s.listener.Addr().String()
	}
	return s.httpServer.Addr
}

// loadTLSConfig loads TLS configuration from files.
func loadTLSConfig(cfg config.TLSConfig) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}, nil
}
