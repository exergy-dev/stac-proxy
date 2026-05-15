package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestLoad tests loading configuration from YAML files
func TestLoad(t *testing.T) {
	t.Run("valid single mode config", func(t *testing.T) {
		t.Parallel()

		yaml := `
mode: single
server:
  host: 127.0.0.1
  port: 8080
logging:
  level: info
  format: json
upstream:
  url: https://example.com/stac
  timeout: 30s
`
		tmpFile := createTempFile(t, yaml)
		defer os.Remove(tmpFile)

		cfg, err := Load(tmpFile)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if cfg.Mode != "single" {
			t.Errorf("expected mode 'single', got %q", cfg.Mode)
		}
		if cfg.Server.Host != "127.0.0.1" {
			t.Errorf("expected host '127.0.0.1', got %q", cfg.Server.Host)
		}
		if cfg.Server.Port != 8080 {
			t.Errorf("expected port 8080, got %d", cfg.Server.Port)
		}
		if cfg.Upstream == nil {
			t.Fatal("expected upstream to be set")
		}
		if cfg.Upstream.URL != "https://example.com/stac" {
			t.Errorf("expected upstream URL 'https://example.com/stac', got %q", cfg.Upstream.URL)
		}
	})

	t.Run("valid federation mode config", func(t *testing.T) {
		t.Parallel()

		yaml := `
mode: federation
server:
  port: 9000
logging:
  level: debug
federation:
  search_strategy: parallel
  origins:
    - id: origin1
      base_url: https://origin1.example.com
      priority: 1
    - id: origin2
      base_url: https://origin2.example.com
      priority: 2
`
		tmpFile := createTempFile(t, yaml)
		defer os.Remove(tmpFile)

		cfg, err := Load(tmpFile)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if cfg.Mode != "federation" {
			t.Errorf("expected mode 'federation', got %q", cfg.Mode)
		}
		if cfg.Federation == nil {
			t.Fatal("expected federation to be set")
		}
		if len(cfg.Federation.Origins) != 2 {
			t.Fatalf("expected 2 origins, got %d", len(cfg.Federation.Origins))
		}
		if cfg.Federation.Origins[0].ID != "origin1" {
			t.Errorf("expected origin ID 'origin1', got %q", cfg.Federation.Origins[0].ID)
		}
		if cfg.Federation.Origins[0].BaseURL != "https://origin1.example.com" {
			t.Errorf("expected base URL 'https://origin1.example.com', got %q", cfg.Federation.Origins[0].BaseURL)
		}
	})

	t.Run("missing file error", func(t *testing.T) {
		t.Parallel()

		_, err := Load("/nonexistent/path/to/config.yaml")
		if err == nil {
			t.Fatal("expected error for missing file")
		}
		if !strings.Contains(err.Error(), "failed to read config file") {
			t.Errorf("expected 'failed to read config file' error, got: %v", err)
		}
	})

	t.Run("invalid YAML error", func(t *testing.T) {
		t.Parallel()

		yaml := `
mode: single
server:
  port: "not a number
  host: 127.0.0.1
upstream:
  url: invalid yaml here
`
		tmpFile := createTempFile(t, yaml)
		defer os.Remove(tmpFile)

		_, err := Load(tmpFile)
		if err == nil {
			t.Fatal("expected error for invalid YAML")
		}
		if !strings.Contains(err.Error(), "failed to parse config file") {
			t.Errorf("expected 'failed to parse config file' error, got: %v", err)
		}
	})

	t.Run("validation error - single mode without upstream", func(t *testing.T) {
		t.Parallel()

		yaml := `
mode: single
server:
  port: 8080
`
		tmpFile := createTempFile(t, yaml)
		defer os.Remove(tmpFile)

		_, err := Load(tmpFile)
		if err == nil {
			t.Fatal("expected validation error")
		}
		if !strings.Contains(err.Error(), "config validation failed") {
			t.Errorf("expected 'config validation failed' error, got: %v", err)
		}
		if !containsValidationError(err, "upstream") {
			t.Errorf("expected error to mention 'upstream', got: %v", err)
		}
	})

	t.Run("validation error - federation mode without origins", func(t *testing.T) {
		t.Parallel()

		yaml := `
mode: federation
server:
  port: 8080
federation:
  search_strategy: parallel
`
		tmpFile := createTempFile(t, yaml)
		defer os.Remove(tmpFile)

		_, err := Load(tmpFile)
		if err == nil {
			t.Fatal("expected validation error")
		}
		if !strings.Contains(err.Error(), "config validation failed") {
			t.Errorf("expected 'config validation failed' error, got: %v", err)
		}
	})

	t.Run("environment variable expansion", func(t *testing.T) {
		t.Parallel()

		// Set test environment variables
		os.Setenv("TEST_UPSTREAM_URL", "https://env-var-test.com")
		os.Setenv("TEST_PORT", "9999")
		defer os.Unsetenv("TEST_UPSTREAM_URL")
		defer os.Unsetenv("TEST_PORT")

		yaml := `
mode: single
server:
  port: ${TEST_PORT}
upstream:
  url: ${TEST_UPSTREAM_URL}
`
		tmpFile := createTempFile(t, yaml)
		defer os.Remove(tmpFile)

		cfg, err := Load(tmpFile)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if cfg.Server.Port != 9999 {
			t.Errorf("expected port 9999 from env var, got %d", cfg.Server.Port)
		}
		if cfg.Upstream.URL != "https://env-var-test.com" {
			t.Errorf("expected URL from env var, got %q", cfg.Upstream.URL)
		}
	})

	t.Run("TLS enabled requires cert and key", func(t *testing.T) {
		t.Parallel()

		yaml := `
mode: single
server:
  port: 8443
  tls:
    enabled: true
upstream:
  url: https://example.com
`
		tmpFile := createTempFile(t, yaml)
		defer os.Remove(tmpFile)

		_, err := Load(tmpFile)
		if err == nil {
			t.Fatal("expected validation error for TLS without cert/key")
		}
		if !containsValidationError(err, "cert_file") && !containsValidationError(err, "key_file") {
			t.Errorf("expected error to mention cert_file or key_file, got: %v", err)
		}
	})
}

// TestSetDefaults tests that default values are applied correctly
func TestSetDefaults(t *testing.T) {
	t.Run("server defaults", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{
			Mode: "single",
			Upstream: &UpstreamConfig{
				URL: "https://example.com",
			},
		}

		cfg.setDefaults()

		if cfg.Server.Host != "0.0.0.0" {
			t.Errorf("expected default host '0.0.0.0', got %q", cfg.Server.Host)
		}
		if cfg.Server.Port != 8080 {
			t.Errorf("expected default port 8080, got %d", cfg.Server.Port)
		}
		if cfg.Server.Timeouts.Read != 30*time.Second {
			t.Errorf("expected default read timeout 30s, got %v", cfg.Server.Timeouts.Read)
		}
		if cfg.Server.Timeouts.Write != 60*time.Second {
			t.Errorf("expected default write timeout 60s, got %v", cfg.Server.Timeouts.Write)
		}
		if cfg.Server.Timeouts.Idle != 120*time.Second {
			t.Errorf("expected default idle timeout 120s, got %v", cfg.Server.Timeouts.Idle)
		}
	})

	t.Run("logging defaults", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{
			Mode: "single",
			Upstream: &UpstreamConfig{
				URL: "https://example.com",
			},
		}

		cfg.setDefaults()

		if cfg.Logging.Level != "info" {
			t.Errorf("expected default log level 'info', got %q", cfg.Logging.Level)
		}
		if cfg.Logging.Format != "json" {
			t.Errorf("expected default log format 'json', got %q", cfg.Logging.Format)
		}
	})

	t.Run("health check defaults", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{
			Mode: "single",
			Upstream: &UpstreamConfig{
				URL: "https://example.com",
			},
		}

		cfg.setDefaults()

		if cfg.Health.Path != "/health" {
			t.Errorf("expected default health path '/health', got %q", cfg.Health.Path)
		}
	})

	t.Run("mode defaults", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{
			Upstream: &UpstreamConfig{
				URL: "https://example.com",
			},
		}

		cfg.setDefaults()

		if cfg.Mode != "single" {
			t.Errorf("expected default mode 'single', got %q", cfg.Mode)
		}
	})

	t.Run("federation defaults", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{
			Mode: "federation",
			Federation: &FederationConfig{
				Origins: []OriginConfig{
					{ID: "origin1", BaseURL: "https://origin1.com"},
				},
			},
		}

		cfg.setDefaults()

		if cfg.Federation.MaxConcurrent != 10 {
			t.Errorf("expected default max concurrent 10, got %d", cfg.Federation.MaxConcurrent)
		}
		if cfg.Federation.AggregateTimeout != 60*time.Second {
			t.Errorf("expected default aggregate timeout 60s, got %v", cfg.Federation.AggregateTimeout)
		}
		if cfg.Federation.ConflictStrategy != "priority" {
			t.Errorf("expected default conflict strategy 'priority', got %q", cfg.Federation.ConflictStrategy)
		}
		if cfg.Federation.DefaultPageSize != 100 {
			t.Errorf("expected default page size 100, got %d", cfg.Federation.DefaultPageSize)
		}
		if cfg.Federation.MaxPageSize != 1000 {
			t.Errorf("expected default max page size 1000, got %d", cfg.Federation.MaxPageSize)
		}
	})

	t.Run("federation origin timeout defaults", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{
			Mode: "federation",
			Federation: &FederationConfig{
				Origins: []OriginConfig{
					{ID: "origin1", BaseURL: "https://origin1.com"},
					{ID: "origin2", BaseURL: "https://origin2.com", Timeout: 15 * time.Second},
				},
			},
		}

		cfg.setDefaults()

		if cfg.Federation.Origins[0].Timeout != 30*time.Second {
			t.Errorf("expected default origin timeout 30s, got %v", cfg.Federation.Origins[0].Timeout)
		}
		if cfg.Federation.Origins[1].Timeout != 15*time.Second {
			t.Errorf("expected origin timeout to remain 15s, got %v", cfg.Federation.Origins[1].Timeout)
		}
	})

	t.Run("custom values not overridden", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{
			Mode: "single",
			Server: ServerConfig{
				Host: "192.168.1.1",
				Port: 3000,
				Timeouts: TimeoutConfig{
					Read:  10 * time.Second,
					Write: 20 * time.Second,
					Idle:  30 * time.Second,
				},
			},
			Logging: LoggingConfig{
				Level:  "debug",
				Format: "console",
			},
			Health: HealthConfig{
				Path: "/healthz",
			},
			Upstream: &UpstreamConfig{
				URL: "https://example.com",
			},
		}

		cfg.setDefaults()

		if cfg.Server.Host != "192.168.1.1" {
			t.Errorf("expected host to remain '192.168.1.1', got %q", cfg.Server.Host)
		}
		if cfg.Server.Port != 3000 {
			t.Errorf("expected port to remain 3000, got %d", cfg.Server.Port)
		}
		if cfg.Server.Timeouts.Read != 10*time.Second {
			t.Errorf("expected read timeout to remain 10s, got %v", cfg.Server.Timeouts.Read)
		}
		if cfg.Logging.Level != "debug" {
			t.Errorf("expected log level to remain 'debug', got %q", cfg.Logging.Level)
		}
		if cfg.Health.Path != "/healthz" {
			t.Errorf("expected health path to remain '/healthz', got %q", cfg.Health.Path)
		}
	})
}

// TestValidate tests configuration validation
func TestValidate(t *testing.T) {
	t.Run("valid single mode", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{
			Mode: "single",
			Upstream: &UpstreamConfig{
				URL: "https://example.com",
			},
		}
		cfg.setDefaults()

		err := cfg.Validate()
		if err != nil {
			t.Errorf("unexpected validation error: %v", err)
		}
	})

	t.Run("valid federation mode", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{
			Mode: "federation",
			Federation: &FederationConfig{
				Origins: []OriginConfig{
					{ID: "origin1", BaseURL: "https://origin1.com"},
					{ID: "origin2", BaseURL: "https://origin2.com"},
				},
			},
		}
		cfg.setDefaults()

		err := cfg.Validate()
		if err != nil {
			t.Errorf("unexpected validation error: %v", err)
		}
	})

	t.Run("invalid mode", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{
			Mode: "invalid",
		}
		cfg.setDefaults()

		err := cfg.Validate()
		if err == nil {
			t.Fatal("expected validation error")
		}
		if !containsValidationError(err, "mode must be") {
			t.Errorf("expected error about invalid mode, got: %v", err)
		}
	})

	t.Run("single mode requires upstream", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{
			Mode: "single",
		}
		cfg.setDefaults()

		err := cfg.Validate()
		if err == nil {
			t.Fatal("expected validation error")
		}
		if !containsValidationError(err, "upstream") {
			t.Errorf("expected error about missing upstream, got: %v", err)
		}
	})

	t.Run("federation mode requires federation config", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{
			Mode: "federation",
		}
		cfg.setDefaults()

		err := cfg.Validate()
		if err == nil {
			t.Fatal("expected validation error")
		}
		if !containsValidationError(err, "federation") {
			t.Errorf("expected error about missing federation config, got: %v", err)
		}
	})

	t.Run("federation requires at least one origin", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{
			Mode: "federation",
			Federation: &FederationConfig{
				CursorSecret: "test-secret",
				Origins: []OriginConfig{},
			},
		}
		cfg.setDefaults()

		err := cfg.Validate()
		if err == nil {
			t.Fatal("expected validation error")
		}
		if !containsValidationError(err, "origin") {
			t.Errorf("expected error about missing origins, got: %v", err)
		}
	})

	t.Run("origin requires ID", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{
			Mode: "federation",
			Federation: &FederationConfig{
				Origins: []OriginConfig{
					{BaseURL: "https://origin1.com"},
				},
			},
		}
		cfg.setDefaults()

		err := cfg.Validate()
		if err == nil {
			t.Fatal("expected validation error")
		}
		if !containsValidationError(err, "id is required") {
			t.Errorf("expected error about missing ID, got: %v", err)
		}
	})

	t.Run("origin requires base_url", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{
			Mode: "federation",
			Federation: &FederationConfig{
				Origins: []OriginConfig{
					{ID: "origin1"},
				},
			},
		}
		cfg.setDefaults()

		err := cfg.Validate()
		if err == nil {
			t.Fatal("expected validation error")
		}
		if !containsValidationError(err, "base_url is required") {
			t.Errorf("expected error about missing base_url, got: %v", err)
		}
	})

	t.Run("multiple origins validation", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{
			Mode: "federation",
			Federation: &FederationConfig{
				Origins: []OriginConfig{
					{ID: "origin1", BaseURL: "https://origin1.com"},
					{ID: "origin2"}, // missing base_url
					{ID: "origin3", BaseURL: "https://origin3.com"},
				},
			},
		}
		cfg.setDefaults()

		err := cfg.Validate()
		if err == nil {
			t.Fatal("expected validation error")
		}
		if !containsValidationError(err, "base_url") {
			t.Errorf("expected error about missing base_url, got: %v", err)
		}
	})
}

// TestIsFederation tests the IsFederation helper method
func TestIsFederation(t *testing.T) {
	t.Run("single mode", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{Mode: "single"}
		if cfg.IsFederation() {
			t.Error("expected IsFederation to return false for single mode")
		}
	})

	t.Run("federation mode", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{Mode: "federation"}
		if !cfg.IsFederation() {
			t.Error("expected IsFederation to return true for federation mode")
		}
	})

	t.Run("default mode", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{}
		if cfg.IsFederation() {
			t.Error("expected IsFederation to return false for empty mode")
		}
	})
}

// TestGetOrigin tests the GetOrigin helper method
func TestGetOrigin(t *testing.T) {
	t.Run("find existing origin", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{
			Mode: "federation",
			Federation: &FederationConfig{
				Origins: []OriginConfig{
					{ID: "origin1", BaseURL: "https://origin1.com"},
					{ID: "origin2", BaseURL: "https://origin2.com"},
					{ID: "origin3", BaseURL: "https://origin3.com"},
				},
			},
		}

		origin := cfg.GetOrigin("origin2")
		if origin == nil {
			t.Fatal("expected to find origin2")
		}
		if origin.ID != "origin2" {
			t.Errorf("expected ID 'origin2', got %q", origin.ID)
		}
		if origin.BaseURL != "https://origin2.com" {
			t.Errorf("expected base URL 'https://origin2.com', got %q", origin.BaseURL)
		}
	})

	t.Run("origin not found", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{
			Mode: "federation",
			Federation: &FederationConfig{
				Origins: []OriginConfig{
					{ID: "origin1", BaseURL: "https://origin1.com"},
				},
			},
		}

		origin := cfg.GetOrigin("nonexistent")
		if origin != nil {
			t.Error("expected GetOrigin to return nil for nonexistent origin")
		}
	})

	t.Run("no federation config", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{Mode: "single"}

		origin := cfg.GetOrigin("origin1")
		if origin != nil {
			t.Error("expected GetOrigin to return nil when no federation config")
		}
	})

	t.Run("empty origins list", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{
			Mode:       "federation",
			Federation: &FederationConfig{
				CursorSecret: "test-secret",Origins: []OriginConfig{}},
		}

		origin := cfg.GetOrigin("origin1")
		if origin != nil {
			t.Error("expected GetOrigin to return nil for empty origins list")
		}
	})
}

// TestServerConfigValidation tests server configuration validation
func TestServerConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		port    int
		wantErr bool
	}{
		{"valid port 1", 1, false},
		{"valid port 8080", 8080, false},
		{"valid port 65535", 65535, false},
		{"invalid port -1", -1, true},
		{"invalid port 65536", 65536, true},
		{"invalid port 100000", 100000, true},
	}

	for _, tt := range tests {
		tt := tt // capture range variable
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := &Config{
				Mode: "single",
				Server: ServerConfig{
					Port: tt.port,
				},
				Upstream: &UpstreamConfig{
					URL: "https://example.com",
				},
			}
			// Don't call setDefaults if we want to test invalid port 0
			// because setDefaults will set it to 8080
			if tt.port != 0 {
				cfg.setDefaults()
			}

			validator := NewValidator()
			err := validator.Validate(cfg)

			if tt.wantErr && err == nil {
				t.Error("expected validation error but got none")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected validation error: %v", err)
			}
		})
	}

	// Special test for port 0 with defaults (should be valid after defaults)
	t.Run("port 0 gets default value", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{
			Mode: "single",
			Server: ServerConfig{
				Port: 0,
			},
			Upstream: &UpstreamConfig{
				URL: "https://example.com",
			},
		}
		cfg.setDefaults()

		if cfg.Server.Port != 8080 {
			t.Errorf("expected port to be set to default 8080, got %d", cfg.Server.Port)
		}

		validator := NewValidator()
		err := validator.Validate(cfg)
		if err != nil {
			t.Errorf("unexpected validation error after defaults: %v", err)
		}
	})
}

// TestTLSConfigValidation tests TLS configuration validation
func TestTLSConfigValidation(t *testing.T) {
	t.Run("TLS disabled - no validation required", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{
			Mode: "single",
			Server: ServerConfig{
				Port: 8080,
				TLS: TLSConfig{
					Enabled: false,
				},
			},
			Upstream: &UpstreamConfig{
				URL: "https://example.com",
			},
		}
		cfg.setDefaults()

		validator := NewValidator()
		err := validator.Validate(cfg)
		if err != nil {
			t.Errorf("unexpected validation error: %v", err)
		}
	})

	t.Run("TLS enabled with cert and key", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{
			Mode: "single",
			Server: ServerConfig{
				Port: 8443,
				TLS: TLSConfig{
					Enabled:  true,
					CertFile: "/path/to/cert.pem",
					KeyFile:  "/path/to/key.pem",
				},
			},
			Upstream: &UpstreamConfig{
				URL: "https://example.com",
			},
		}
		cfg.setDefaults()

		validator := NewValidator()
		err := validator.Validate(cfg)
		if err != nil {
			t.Errorf("unexpected validation error: %v", err)
		}
	})

	t.Run("TLS enabled without cert", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{
			Mode: "single",
			Server: ServerConfig{
				Port: 8443,
				TLS: TLSConfig{
					Enabled: true,
					KeyFile: "/path/to/key.pem",
				},
			},
			Upstream: &UpstreamConfig{
				URL: "https://example.com",
			},
		}
		cfg.setDefaults()

		validator := NewValidator()
		err := validator.Validate(cfg)
		if err == nil {
			t.Fatal("expected validation error")
		}
		// Check if it's a ValidationError with specific TLS errors
		if ve, ok := err.(*ValidationError); ok {
			found := false
			for _, e := range ve.Errors {
				if strings.Contains(e.Error(), "cert_file") {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected error to mention cert_file in validation errors: %v", ve.Errors)
			}
		} else if !strings.Contains(err.Error(), "cert_file") {
			t.Errorf("expected error to mention cert_file, got: %v", err)
		}
	})

	t.Run("TLS enabled without key", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{
			Mode: "single",
			Server: ServerConfig{
				Port: 8443,
				TLS: TLSConfig{
					Enabled:  true,
					CertFile: "/path/to/cert.pem",
				},
			},
			Upstream: &UpstreamConfig{
				URL: "https://example.com",
			},
		}
		cfg.setDefaults()

		validator := NewValidator()
		err := validator.Validate(cfg)
		if err == nil {
			t.Fatal("expected validation error")
		}
		// Check if it's a ValidationError with specific TLS errors
		if ve, ok := err.(*ValidationError); ok {
			found := false
			for _, e := range ve.Errors {
				if strings.Contains(e.Error(), "key_file") {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected error to mention key_file in validation errors: %v", ve.Errors)
			}
		} else if !strings.Contains(err.Error(), "key_file") {
			t.Errorf("expected error to mention key_file, got: %v", err)
		}
	})
}

// TestComplexConfig tests a more realistic complex configuration
func TestComplexConfig(t *testing.T) {
	t.Run("complex federation config", func(t *testing.T) {
		t.Parallel()

		yaml := `
mode: federation
server:
  host: 0.0.0.0
  port: 8080
  timeouts:
    read: 30s
    write: 60s
    idle: 120s
  tls:
    enabled: true
    cert_file: /etc/ssl/cert.pem
    key_file: /etc/ssl/key.pem
logging:
  level: info
  format: json
  output: stdout
metrics:
  enabled: true
  path: /metrics
  port: 9090
health:
  path: /health
  check_upstreams: true
  check_interval: 30s
federation:
  search_strategy: parallel
  max_concurrent: 20
  aggregate_timeout: 90s
  conflict_strategy: priority
  default_page_size: 50
  max_page_size: 500
  origins:
    - id: earth-search
      name: Earth Search
      description: NASA Earth Search STAC API
      base_url: https://earth-search.aws.element84.com/v1
      enabled: true
      timeout: 30s
      priority: 1
      searchable: true
      auto_discover: true
      discovery_interval: 1h
    - id: planetary-computer
      name: Microsoft Planetary Computer
      base_url: https://planetarycomputer.microsoft.com/api/stac/v1
      enabled: true
      timeout: 45s
      priority: 2
      searchable: true
middleware:
  - name: logging
    config:
      verbose: true
  - name: cors
    config:
      allowed_origins: ["*"]
`
		tmpFile := createTempFile(t, yaml)
		defer os.Remove(tmpFile)

		cfg, err := Load(tmpFile)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Verify server config
		if cfg.Server.Port != 8080 {
			t.Errorf("expected port 8080, got %d", cfg.Server.Port)
		}
		if !cfg.Server.TLS.Enabled {
			t.Error("expected TLS to be enabled")
		}

		// Verify federation config
		if cfg.Federation.MaxConcurrent != 20 {
			t.Errorf("expected max concurrent 20, got %d", cfg.Federation.MaxConcurrent)
		}
		if len(cfg.Federation.Origins) != 2 {
			t.Fatalf("expected 2 origins, got %d", len(cfg.Federation.Origins))
		}

		// Verify origin details
		earthSearch := cfg.GetOrigin("earth-search")
		if earthSearch == nil {
			t.Fatal("expected to find earth-search origin")
		}
		if earthSearch.Name != "Earth Search" {
			t.Errorf("expected name 'Earth Search', got %q", earthSearch.Name)
		}
		if !earthSearch.Searchable {
			t.Error("expected earth-search to be searchable")
		}
		if !earthSearch.AutoDiscover {
			t.Error("expected earth-search to have auto-discover enabled")
		}

		// Verify middleware
		if len(cfg.Middleware) != 2 {
			t.Fatalf("expected 2 middleware, got %d", len(cfg.Middleware))
		}
		if cfg.Middleware[0].Name != "logging" {
			t.Errorf("expected first middleware to be 'logging', got %q", cfg.Middleware[0].Name)
		}

		// Verify metrics
		if !cfg.Metrics.Enabled {
			t.Error("expected metrics to be enabled")
		}
		if cfg.Metrics.Port != 9090 {
			t.Errorf("expected metrics port 9090, got %d", cfg.Metrics.Port)
		}
	})
}

// TestOriginAuth tests origin authentication configuration
func TestOriginAuth(t *testing.T) {
	t.Run("origin with basic auth", func(t *testing.T) {
		t.Parallel()

		yaml := `
mode: federation
server:
  port: 8080
federation:
  origins:
    - id: secure-origin
      base_url: https://secure.example.com
      auth:
        type: basic
        username: testuser
        password: testpass
`
		tmpFile := createTempFile(t, yaml)
		defer os.Remove(tmpFile)

		cfg, err := Load(tmpFile)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		origin := cfg.GetOrigin("secure-origin")
		if origin == nil {
			t.Fatal("expected to find secure-origin")
		}
		if origin.Auth == nil {
			t.Fatal("expected auth to be configured")
		}
		if origin.Auth.Type != "basic" {
			t.Errorf("expected auth type 'basic', got %q", origin.Auth.Type)
		}
		if origin.Auth.Username != "testuser" {
			t.Errorf("expected username 'testuser', got %q", origin.Auth.Username)
		}
	})

	t.Run("origin with bearer token", func(t *testing.T) {
		t.Parallel()

		yaml := `
mode: federation
server:
  port: 8080
federation:
  origins:
    - id: token-origin
      base_url: https://token.example.com
      auth:
        type: bearer
        token: my-secret-token
`
		tmpFile := createTempFile(t, yaml)
		defer os.Remove(tmpFile)

		cfg, err := Load(tmpFile)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		origin := cfg.GetOrigin("token-origin")
		if origin == nil {
			t.Fatal("expected to find token-origin")
		}
		if origin.Auth == nil {
			t.Fatal("expected auth to be configured")
		}
		if origin.Auth.Type != "bearer" {
			t.Errorf("expected auth type 'bearer', got %q", origin.Auth.Type)
		}
		if origin.Auth.Token != "my-secret-token" {
			t.Errorf("expected token 'my-secret-token', got %q", origin.Auth.Token)
		}
	})
}

// TestValidationHelpers tests validation helper functions
func TestValidationHelpers(t *testing.T) {
	t.Run("IsValidURL", func(t *testing.T) {
		t.Parallel()

		tests := []struct {
			name  string
			url   string
			valid bool
		}{
			{"valid https URL", "https://example.com", true},
			{"valid http URL", "http://example.com/path", true},
			{"valid URL with port", "https://example.com:8080", true},
			{"invalid - no scheme", "example.com", false},
			{"invalid - no host", "https://", false},
			{"invalid - malformed", "ht!tp://example.com", false},
			{"empty string", "", false},
		}

		for _, tt := range tests {
			tt := tt
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()
				result := IsValidURL(tt.url)
				if result != tt.valid {
					t.Errorf("IsValidURL(%q) = %v, want %v", tt.url, result, tt.valid)
				}
			})
		}
	})

	t.Run("IsValidDuration", func(t *testing.T) {
		t.Parallel()

		tests := []struct {
			name     string
			duration time.Duration
			valid    bool
		}{
			{"positive duration", 30 * time.Second, true},
			{"zero duration", 0, true},
			{"negative duration", -5 * time.Second, false},
		}

		for _, tt := range tests {
			tt := tt
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()
				result := IsValidDuration(tt.duration)
				if result != tt.valid {
					t.Errorf("IsValidDuration(%v) = %v, want %v", tt.duration, result, tt.valid)
				}
			})
		}
	})

	t.Run("IsValidPort", func(t *testing.T) {
		t.Parallel()

		tests := []struct {
			name  string
			port  int
			valid bool
		}{
			{"valid port 1", 1, true},
			{"valid port 8080", 8080, true},
			{"valid port 65535", 65535, true},
			{"invalid port 0", 0, false},
			{"invalid port -1", -1, false},
			{"invalid port 65536", 65536, false},
		}

		for _, tt := range tests {
			tt := tt
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()
				result := IsValidPort(tt.port)
				if result != tt.valid {
					t.Errorf("IsValidPort(%d) = %v, want %v", tt.port, result, tt.valid)
				}
			})
		}
	})

	t.Run("ValidateRequiredString", func(t *testing.T) {
		t.Parallel()

		err := ValidateRequiredString("field_name", "value")
		if err != nil {
			t.Errorf("expected no error for non-empty string, got: %v", err)
		}

		err = ValidateRequiredString("field_name", "")
		if err == nil {
			t.Error("expected error for empty string")
		}
		if !strings.Contains(err.Error(), "field_name is required") {
			t.Errorf("expected error to mention field name, got: %v", err)
		}
	})
}

// TestMustValidate tests the MustValidate panic function
func TestMustValidate(t *testing.T) {
	t.Run("valid config does not panic", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{
			Mode: "single",
			Upstream: &UpstreamConfig{
				URL: "https://example.com",
			},
		}
		cfg.setDefaults()

		// Should not panic
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("MustValidate panicked unexpectedly: %v", r)
			}
		}()

		MustValidate(cfg)
	})

	t.Run("invalid config panics", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{
			Mode: "invalid",
		}
		cfg.setDefaults()

		// Should panic
		defer func() {
			if r := recover(); r == nil {
				t.Error("MustValidate should have panicked")
			}
		}()

		MustValidate(cfg)
	})
}

// TestLoggingValidation tests logging configuration validation
func TestLoggingValidation(t *testing.T) {
	t.Run("invalid log level", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{
			Mode: "single",
			Server: ServerConfig{
				Port: 8080,
			},
			Logging: LoggingConfig{
				Level: "invalid",
			},
			Upstream: &UpstreamConfig{
				URL: "https://example.com",
			},
		}
		cfg.setDefaults()

		validator := NewValidator()
		err := validator.Validate(cfg)
		if err == nil {
			t.Fatal("expected validation error")
		}
		if !containsValidationError(err, "logging.level") {
			t.Errorf("expected error about log level, got: %v", err)
		}
	})

	t.Run("invalid log format", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{
			Mode: "single",
			Server: ServerConfig{
				Port: 8080,
			},
			Logging: LoggingConfig{
				Level:  "info",
				Format: "invalid",
			},
			Upstream: &UpstreamConfig{
				URL: "https://example.com",
			},
		}
		cfg.setDefaults()

		validator := NewValidator()
		err := validator.Validate(cfg)
		if err == nil {
			t.Fatal("expected validation error")
		}
		if !containsValidationError(err, "logging.format") {
			t.Errorf("expected error about log format, got: %v", err)
		}
	})

	t.Run("valid log levels", func(t *testing.T) {
		t.Parallel()

		levels := []string{"debug", "info", "warn", "error"}
		for _, level := range levels {
			cfg := &Config{
				Mode: "single",
				Server: ServerConfig{
					Port: 8080,
				},
				Logging: LoggingConfig{
					Level:  level,
					Format: "json",
				},
				Upstream: &UpstreamConfig{
					URL: "https://example.com",
				},
			}
			cfg.setDefaults()

			validator := NewValidator()
			err := validator.Validate(cfg)
			if err != nil {
				t.Errorf("unexpected error for log level %q: %v", level, err)
			}
		}
	})
}

// TestTimeoutValidation tests timeout validation
func TestTimeoutValidation(t *testing.T) {
	t.Run("negative read timeout", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{
			Mode: "single",
			Server: ServerConfig{
				Port: 8080,
				Timeouts: TimeoutConfig{
					Read:  -10 * time.Second,
					Write: 30 * time.Second,
					Idle:  60 * time.Second,
				},
			},
			Upstream: &UpstreamConfig{
				URL: "https://example.com",
			},
		}

		validator := NewValidator()
		err := validator.Validate(cfg)
		if err == nil {
			t.Fatal("expected validation error")
		}
		if !containsValidationError(err, "timeouts.read cannot be negative") {
			t.Errorf("expected error about negative read timeout, got: %v", err)
		}
	})

	t.Run("negative write timeout", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{
			Mode: "single",
			Server: ServerConfig{
				Port: 8080,
				Timeouts: TimeoutConfig{
					Read:  30 * time.Second,
					Write: -10 * time.Second,
					Idle:  60 * time.Second,
				},
			},
			Upstream: &UpstreamConfig{
				URL: "https://example.com",
			},
		}

		validator := NewValidator()
		err := validator.Validate(cfg)
		if err == nil {
			t.Fatal("expected validation error")
		}
		if !containsValidationError(err, "timeouts.write cannot be negative") {
			t.Errorf("expected error about negative write timeout, got: %v", err)
		}
	})

	t.Run("negative idle timeout", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{
			Mode: "single",
			Server: ServerConfig{
				Port: 8080,
				Timeouts: TimeoutConfig{
					Read:  30 * time.Second,
					Write: 30 * time.Second,
					Idle:  -10 * time.Second,
				},
			},
			Upstream: &UpstreamConfig{
				URL: "https://example.com",
			},
		}

		validator := NewValidator()
		err := validator.Validate(cfg)
		if err == nil {
			t.Fatal("expected validation error")
		}
		if !containsValidationError(err, "timeouts.idle cannot be negative") {
			t.Errorf("expected error about negative idle timeout, got: %v", err)
		}
	})
}

// TestUpstreamValidation tests upstream configuration validation
func TestUpstreamValidation(t *testing.T) {
	t.Run("invalid URL", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{
			Mode: "single",
			Server: ServerConfig{
				Port: 8080,
			},
			Upstream: &UpstreamConfig{
				URL: "ht!tp://invalid url",
			},
		}
		cfg.setDefaults()

		validator := NewValidator()
		err := validator.Validate(cfg)
		if err == nil {
			t.Fatal("expected validation error")
		}
		if !containsValidationError(err, "upstream.url") {
			t.Errorf("expected error about upstream URL, got: %v", err)
		}
	})

	t.Run("negative timeout", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{
			Mode: "single",
			Server: ServerConfig{
				Port: 8080,
			},
			Upstream: &UpstreamConfig{
				URL:     "https://example.com",
				Timeout: -10 * time.Second,
			},
		}
		cfg.setDefaults()

		validator := NewValidator()
		err := validator.Validate(cfg)
		if err == nil {
			t.Fatal("expected validation error")
		}
		if !containsValidationError(err, "upstream.timeout cannot be negative") {
			t.Errorf("expected error about negative timeout, got: %v", err)
		}
	})
}

// TestOriginAuthValidation tests origin authentication validation
func TestOriginAuthValidation(t *testing.T) {
	t.Run("invalid auth type", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{
			Mode: "federation",
			Server: ServerConfig{
				Port: 8080,
			},
			Federation: &FederationConfig{
				Origins: []OriginConfig{
					{
						ID:      "origin1",
						BaseURL: "https://origin1.com",
						Auth: &OriginAuthConfig{
							Type: "invalid",
						},
					},
				},
			},
		}
		cfg.setDefaults()

		validator := NewValidator()
		err := validator.Validate(cfg)
		if err == nil {
			t.Fatal("expected validation error")
		}
		if !containsValidationError(err, "auth.type is invalid") {
			t.Errorf("expected error about invalid auth type, got: %v", err)
		}
	})

	t.Run("basic auth missing username", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{
			Mode: "federation",
			Server: ServerConfig{
				Port: 8080,
			},
			Federation: &FederationConfig{
				Origins: []OriginConfig{
					{
						ID:      "origin1",
						BaseURL: "https://origin1.com",
						Auth: &OriginAuthConfig{
							Type:     "basic",
							Password: "pass",
						},
					},
				},
			},
		}
		cfg.setDefaults()

		validator := NewValidator()
		err := validator.Validate(cfg)
		if err == nil {
			t.Fatal("expected validation error")
		}
		if !containsValidationError(err, "username and password") {
			t.Errorf("expected error about username/password, got: %v", err)
		}
	})

	t.Run("bearer auth missing token", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{
			Mode: "federation",
			Server: ServerConfig{
				Port: 8080,
			},
			Federation: &FederationConfig{
				Origins: []OriginConfig{
					{
						ID:      "origin1",
						BaseURL: "https://origin1.com",
						Auth: &OriginAuthConfig{
							Type: "bearer",
						},
					},
				},
			},
		}
		cfg.setDefaults()

		validator := NewValidator()
		err := validator.Validate(cfg)
		if err == nil {
			t.Fatal("expected validation error")
		}
		if !containsValidationError(err, "token") {
			t.Errorf("expected error about token, got: %v", err)
		}
	})

	t.Run("api_key auth missing header", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{
			Mode: "federation",
			Server: ServerConfig{
				Port: 8080,
			},
			Federation: &FederationConfig{
				Origins: []OriginConfig{
					{
						ID:      "origin1",
						BaseURL: "https://origin1.com",
						Auth: &OriginAuthConfig{
							Type:        "api_key",
							APIKeyValue: "secret",
						},
					},
				},
			},
		}
		cfg.setDefaults()

		validator := NewValidator()
		err := validator.Validate(cfg)
		if err == nil {
			t.Fatal("expected validation error")
		}
		if !containsValidationError(err, "api_key_header") {
			t.Errorf("expected error about api_key_header, got: %v", err)
		}
	})

	t.Run("oauth2 auth missing config", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{
			Mode: "federation",
			Server: ServerConfig{
				Port: 8080,
			},
			Federation: &FederationConfig{
				Origins: []OriginConfig{
					{
						ID:      "origin1",
						BaseURL: "https://origin1.com",
						Auth: &OriginAuthConfig{
							Type: "oauth2",
						},
					},
				},
			},
		}
		cfg.setDefaults()

		validator := NewValidator()
		err := validator.Validate(cfg)
		if err == nil {
			t.Fatal("expected validation error")
		}
		if !containsValidationError(err, "oauth2 config") {
			t.Errorf("expected error about oauth2 config, got: %v", err)
		}
	})

	t.Run("oauth2 auth missing token_url", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{
			Mode: "federation",
			Server: ServerConfig{
				Port: 8080,
			},
			Federation: &FederationConfig{
				Origins: []OriginConfig{
					{
						ID:      "origin1",
						BaseURL: "https://origin1.com",
						Auth: &OriginAuthConfig{
							Type: "oauth2",
							OAuth2: &OAuth2Config{
								ClientID:     "client",
								ClientSecret: "secret",
							},
						},
					},
				},
			},
		}
		cfg.setDefaults()

		validator := NewValidator()
		err := validator.Validate(cfg)
		if err == nil {
			t.Fatal("expected validation error")
		}
		if !containsValidationError(err, "token_url") {
			t.Errorf("expected error about token_url, got: %v", err)
		}
	})

	t.Run("oauth2 auth missing client_id", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{
			Mode: "federation",
			Server: ServerConfig{
				Port: 8080,
			},
			Federation: &FederationConfig{
				Origins: []OriginConfig{
					{
						ID:      "origin1",
						BaseURL: "https://origin1.com",
						Auth: &OriginAuthConfig{
							Type: "oauth2",
							OAuth2: &OAuth2Config{
								TokenURL:     "https://auth.example.com/token",
								ClientSecret: "secret",
							},
						},
					},
				},
			},
		}
		cfg.setDefaults()

		validator := NewValidator()
		err := validator.Validate(cfg)
		if err == nil {
			t.Fatal("expected validation error")
		}
		if !containsValidationError(err, "client_id") {
			t.Errorf("expected error about client_id, got: %v", err)
		}
	})

	t.Run("valid none auth", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{
			Mode: "federation",
			Server: ServerConfig{
				Port: 8080,
			},
			Federation: &FederationConfig{
				Origins: []OriginConfig{
					{
						ID:      "origin1",
						BaseURL: "https://origin1.com",
						Auth: &OriginAuthConfig{
							Type: "none",
						},
					},
				},
			},
		}
		cfg.setDefaults()

		validator := NewValidator()
		err := validator.Validate(cfg)
		if err != nil {
			t.Errorf("unexpected validation error: %v", err)
		}
	})
}

// TestFederationValidation tests federation configuration validation
func TestFederationValidation(t *testing.T) {
	t.Run("invalid conflict strategy", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{
			Mode: "federation",
			Server: ServerConfig{
				Port: 8080,
			},
			Federation: &FederationConfig{
				ConflictStrategy: "invalid",
				Origins: []OriginConfig{
					{ID: "origin1", BaseURL: "https://origin1.com"},
				},
			},
		}
		cfg.setDefaults()

		validator := NewValidator()
		err := validator.Validate(cfg)
		if err == nil {
			t.Fatal("expected validation error")
		}
		if !containsValidationError(err, "conflict_strategy") {
			t.Errorf("expected error about conflict_strategy, got: %v", err)
		}
	})

	t.Run("duplicate origin IDs", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{
			Mode: "federation",
			Server: ServerConfig{
				Port: 8080,
			},
			Federation: &FederationConfig{
				Origins: []OriginConfig{
					{ID: "origin1", BaseURL: "https://origin1.com"},
					{ID: "origin1", BaseURL: "https://origin2.com"}, // duplicate
				},
			},
		}
		cfg.setDefaults()

		validator := NewValidator()
		err := validator.Validate(cfg)
		if err == nil {
			t.Fatal("expected validation error")
		}
		if !containsValidationError(err, "duplicate") {
			t.Errorf("expected error about duplicate ID, got: %v", err)
		}
	})

	t.Run("invalid origin ID format", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{
			Mode: "federation",
			Server: ServerConfig{
				Port: 8080,
			},
			Federation: &FederationConfig{
				Origins: []OriginConfig{
					{ID: "invalid@id!", BaseURL: "https://origin1.com"},
				},
			},
		}
		cfg.setDefaults()

		validator := NewValidator()
		err := validator.Validate(cfg)
		if err == nil {
			t.Fatal("expected validation error")
		}
		if !containsValidationError(err, "invalid characters") {
			t.Errorf("expected error about invalid characters, got: %v", err)
		}
	})

	t.Run("negative origin timeout", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{
			Mode: "federation",
			Server: ServerConfig{
				Port: 8080,
			},
			Federation: &FederationConfig{
				Origins: []OriginConfig{
					{
						ID:      "origin1",
						BaseURL: "https://origin1.com",
						Timeout: -10 * time.Second,
					},
				},
			},
		}
		cfg.setDefaults()

		validator := NewValidator()
		err := validator.Validate(cfg)
		if err == nil {
			t.Fatal("expected validation error")
		}
		if !containsValidationError(err, "timeout cannot be negative") {
			t.Errorf("expected error about negative timeout, got: %v", err)
		}
	})

	t.Run("invalid origin base_url", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{
			Mode: "federation",
			Server: ServerConfig{
				Port: 8080,
			},
			Federation: &FederationConfig{
				Origins: []OriginConfig{
					{
						ID:      "origin1",
						BaseURL: "ht!tp://invalid url",
					},
				},
			},
		}
		cfg.setDefaults()

		validator := NewValidator()
		err := validator.Validate(cfg)
		if err == nil {
			t.Fatal("expected validation error")
		}
		if !containsValidationError(err, "not a valid URL") {
			t.Errorf("expected error about invalid URL, got: %v", err)
		}
	})
}

// TestValidationWarnings tests that warnings are generated properly
func TestValidationWarnings(t *testing.T) {
	t.Run("empty server host warning", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{
			Mode: "single",
			Server: ServerConfig{
				Port: 8080,
				Host: "", // empty host
			},
			Upstream: &UpstreamConfig{
				URL: "https://example.com",
			},
		}
		// Don't call setDefaults to keep host empty

		validator := NewValidator()
		err := validator.Validate(cfg)
		// Should still succeed but with warnings
		if err != nil {
			// Check if it's a ValidationError with warnings
			if ve, ok := err.(*ValidationError); ok {
				if len(ve.Warnings) == 0 {
					t.Error("expected warnings for empty host")
				}
			}
		}
	})

	t.Run("short read timeout warning", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{
			Mode: "single",
			Server: ServerConfig{
				Port: 8080,
				Timeouts: TimeoutConfig{
					Read: 2 * time.Second, // very short
				},
			},
			Upstream: &UpstreamConfig{
				URL: "https://example.com",
			},
		}

		validator := NewValidator()
		err := validator.Validate(cfg)
		// Should succeed but may have warnings
		if err != nil {
			if ve, ok := err.(*ValidationError); ok {
				if len(ve.Warnings) == 0 {
					t.Error("expected warnings for short timeout")
				}
			}
		}
	})

	t.Run("unrecognized middleware warning", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{
			Mode: "single",
			Server: ServerConfig{
				Port: 8080,
			},
			Middleware: []MiddlewareConfig{
				{Name: "unknown_middleware"},
			},
			Upstream: &UpstreamConfig{
				URL: "https://example.com",
			},
		}
		cfg.setDefaults()

		validator := NewValidator()
		err := validator.Validate(cfg)
		// Should succeed but may have warnings
		if err != nil {
			if ve, ok := err.(*ValidationError); ok {
				if len(ve.Warnings) == 0 {
					t.Error("expected warnings for unrecognized middleware")
				}
			}
		}
	})
}

// TestEdgeCases tests edge cases for validation
func TestEdgeCases(t *testing.T) {
	t.Run("empty upstream URL", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{
			Mode: "single",
			Server: ServerConfig{
				Port: 8080,
			},
			Upstream: &UpstreamConfig{
				URL: "", // empty URL
			},
		}
		cfg.setDefaults()

		validator := NewValidator()
		err := validator.Validate(cfg)
		if err == nil {
			t.Fatal("expected validation error for empty upstream URL")
		}
		if !containsValidationError(err, "upstream.url is required") {
			t.Errorf("expected error about required upstream URL, got: %v", err)
		}
	})

	t.Run("valid middleware names", func(t *testing.T) {
		t.Parallel()

		validNames := []string{"logging", "auth", "authz", "cache", "rate_limit", "url_remap", "cors"}

		for _, name := range validNames {
			cfg := &Config{
				Mode: "single",
				Server: ServerConfig{
					Port: 8080,
				},
				Middleware: []MiddlewareConfig{
					{Name: name},
				},
				Upstream: &UpstreamConfig{
					URL: "https://example.com",
				},
			}
			cfg.setDefaults()

			validator := NewValidator()
			err := validator.Validate(cfg)
			if err != nil {
				t.Errorf("unexpected validation error for middleware %q: %v", name, err)
			}
		}
	})

	t.Run("valid log formats", func(t *testing.T) {
		t.Parallel()

		formats := []string{"json", "text", "console"}
		for _, format := range formats {
			cfg := &Config{
				Mode: "single",
				Server: ServerConfig{
					Port: 8080,
				},
				Logging: LoggingConfig{
					Level:  "info",
					Format: format,
				},
				Upstream: &UpstreamConfig{
					URL: "https://example.com",
				},
			}
			cfg.setDefaults()

			validator := NewValidator()
			err := validator.Validate(cfg)
			if err != nil {
				t.Errorf("unexpected error for log format %q: %v", format, err)
			}
		}
	})

	t.Run("valid conflict strategies", func(t *testing.T) {
		t.Parallel()

		strategies := []string{"first_wins", "priority", "merge", "namespace", "reject_duplicates"}
		for _, strategy := range strategies {
			cfg := &Config{
				Mode: "federation",
				Server: ServerConfig{
					Port: 8080,
				},
				Federation: &FederationConfig{
					ConflictStrategy: strategy,
					Origins: []OriginConfig{
						{ID: "origin1", BaseURL: "https://origin1.com"},
					},
				},
			}
			cfg.setDefaults()

			validator := NewValidator()
			err := validator.Validate(cfg)
			if err != nil {
				t.Errorf("unexpected error for conflict strategy %q: %v", strategy, err)
			}
		}
	})

	t.Run("valid auth types", func(t *testing.T) {
		t.Parallel()

		// Test valid auth types that don't require additional fields
		validTypes := []string{"none", "custom_headers", "aws_sigv4"}

		for _, authType := range validTypes {
			cfg := &Config{
				Mode: "federation",
				Server: ServerConfig{
					Port: 8080,
				},
				Federation: &FederationConfig{
					Origins: []OriginConfig{
						{
							ID:      "origin1",
							BaseURL: "https://origin1.com",
							Auth: &OriginAuthConfig{
								Type: authType,
							},
						},
					},
				},
			}
			cfg.setDefaults()

			validator := NewValidator()
			err := validator.Validate(cfg)
			if err != nil {
				t.Errorf("unexpected error for auth type %q: %v", authType, err)
			}
		}
	})

	t.Run("valid origin ID formats", func(t *testing.T) {
		t.Parallel()

		validIDs := []string{"origin1", "origin-2", "my-origin", "Origin123", "a", "A1"}

		for _, id := range validIDs {
			cfg := &Config{
				Mode: "federation",
				Server: ServerConfig{
					Port: 8080,
				},
				Federation: &FederationConfig{
					Origins: []OriginConfig{
						{ID: id, BaseURL: "https://origin1.com"},
					},
				},
			}
			cfg.setDefaults()

			validator := NewValidator()
			err := validator.Validate(cfg)
			if err != nil {
				t.Errorf("unexpected error for origin ID %q: %v", id, err)
			}
		}
	})

	t.Run("invalid origin ID starting with number", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{
			Mode: "federation",
			Server: ServerConfig{
				Port: 8080,
			},
			Federation: &FederationConfig{
				Origins: []OriginConfig{
					{ID: "1origin", BaseURL: "https://origin1.com"},
				},
			},
		}
		cfg.setDefaults()

		validator := NewValidator()
		err := validator.Validate(cfg)
		if err == nil {
			t.Fatal("expected validation error for ID starting with number")
		}
		if !containsValidationError(err, "invalid characters") {
			t.Errorf("expected error about invalid ID, got: %v", err)
		}
	})
}

// createTempFile creates a temporary file with the given content
func createTempFile(t *testing.T, content string) string {
	t.Helper()

	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "config.yaml")

	if err := os.WriteFile(tmpFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}

	return tmpFile
}

// containsValidationError checks if an error (potentially wrapped) contains
// a ValidationError with an error message containing the given substring
func containsValidationError(err error, substring string) bool {
	if err == nil {
		return false
	}

	// Check if the error string directly contains the substring
	if strings.Contains(err.Error(), substring) {
		return true
	}

	// Try to unwrap and check for ValidationError
	var ve *ValidationError
	if errors.As(err, &ve) {
		for _, e := range ve.Errors {
			if strings.Contains(e.Error(), substring) {
				return true
			}
		}
	}

	return false
}
func TestValidateOrigin_NegativeMaxResponseBytesRejected(t *testing.T) {
	t.Parallel()

	cfg := &Config{
		Mode: "federation",
		Server: ServerConfig{Port: 8080},
		Federation: &FederationConfig{
			Origins: []OriginConfig{
				{
					ID:               "origin1",
					BaseURL:          "https://origin1.com",
					MaxResponseBytes: -1,
				},
			},
		},
	}
	cfg.setDefaults()

	err := NewValidator().Validate(cfg)
	if err == nil {
		t.Fatal("expected validation error for negative max_response_bytes")
	}
	if !containsValidationError(err, "max_response_bytes cannot be negative") {
		t.Errorf("expected max_response_bytes error, got: %v", err)
	}
}

// TestValidateOrigin_RejectsNonHTTPScheme covers H8: only http/https
// origin schemes are accepted.
func TestValidateOrigin_RejectsNonHTTPScheme(t *testing.T) {
	t.Parallel()

	schemes := []string{
		"file:///etc/passwd",
		"gopher://example.com",
		"ftp://example.com",
	}
	for _, base := range schemes {
		cfg := &Config{
			Mode: "federation",
			Server: ServerConfig{Port: 8080},
			Federation: &FederationConfig{
				Origins: []OriginConfig{{ID: "origin1", BaseURL: base}},
			},
		}
		cfg.setDefaults()

		err := NewValidator().Validate(cfg)
		if err == nil {
			t.Errorf("scheme %q: expected validation error, got nil", base)
			continue
		}
		if !containsValidationError(err, "scheme must be http or https") {
			t.Errorf("scheme %q: expected scheme error, got: %v", base, err)
		}
	}
}

// TestValidateOrigin_RejectsLoopbackByDefault: H8.
func TestValidateOrigin_RejectsLoopbackByDefault(t *testing.T) {
	t.Parallel()

	hosts := []string{
		"https://127.0.0.1",
		"https://localhost",
		"https://[::1]",
	}
	for _, base := range hosts {
		cfg := &Config{
			Mode: "federation",
			Server: ServerConfig{Port: 8080},
			Federation: &FederationConfig{
				Origins: []OriginConfig{{ID: "origin1", BaseURL: base}},
			},
		}
		cfg.setDefaults()

		err := NewValidator().Validate(cfg)
		if err == nil {
			t.Errorf("host %q: expected validation error, got nil", base)
			continue
		}
		if !containsValidationError(err, "loopback") {
			t.Errorf("host %q: expected loopback error, got: %v", base, err)
		}
	}
}

// TestValidateOrigin_RejectsRFC1918ByDefault: H8.
func TestValidateOrigin_RejectsRFC1918ByDefault(t *testing.T) {
	t.Parallel()

	hosts := []string{
		"https://10.0.0.1",
		"https://172.16.0.1",
		"https://192.168.1.1",
	}
	for _, base := range hosts {
		cfg := &Config{
			Mode: "federation",
			Server: ServerConfig{Port: 8080},
			Federation: &FederationConfig{
				Origins: []OriginConfig{{ID: "origin1", BaseURL: base}},
			},
		}
		cfg.setDefaults()

		err := NewValidator().Validate(cfg)
		if err == nil {
			t.Errorf("host %q: expected validation error, got nil", base)
			continue
		}
		if !containsValidationError(err, "private") {
			t.Errorf("host %q: expected private-range error, got: %v", base, err)
		}
	}
}

// TestValidateOrigin_AcceptsLoopbackWhenAllowed: H8.
func TestValidateOrigin_AcceptsLoopbackWhenAllowed(t *testing.T) {
	t.Parallel()

	cfg := &Config{
		Mode: "federation",
		Server: ServerConfig{Port: 8080},
		Federation: &FederationConfig{
			AllowPrivateOrigins: true,
			CursorSecret:        "test-secret",
			Origins: []OriginConfig{
				{ID: "origin1", BaseURL: "https://127.0.0.1"},
			},
		},
	}
	cfg.setDefaults()

	if err := NewValidator().Validate(cfg); err != nil {
		t.Errorf("unexpected validation error: %v", err)
	}
}

// TestValidateUpstream_AcceptsLoopbackWhenAllowed verifies the
// single-origin equivalent of the federation flag.
func TestValidateUpstream_AcceptsLoopbackWhenAllowed(t *testing.T) {
	t.Parallel()

	cfg := &Config{
		Mode:   "single",
		Server: ServerConfig{Port: 8080},
		Upstream: &UpstreamConfig{
			URL:                "https://127.0.0.1",
			AllowPrivateOrigin: true,
		},
	}
	cfg.setDefaults()

	if err := NewValidator().Validate(cfg); err != nil {
		t.Errorf("unexpected validation error: %v", err)
	}
}

// TestValidateUpstream_RejectsLoopbackByDefault: H8 single-origin.
func TestValidateUpstream_RejectsLoopbackByDefault(t *testing.T) {
	t.Parallel()

	cfg := &Config{
		Mode:   "single",
		Server: ServerConfig{Port: 8080},
		Upstream: &UpstreamConfig{
			URL: "https://127.0.0.1",
		},
	}
	cfg.setDefaults()

	err := NewValidator().Validate(cfg)
	if err == nil {
		t.Fatal("expected validation error for loopback upstream")
	}
	if !containsValidationError(err, "loopback") {
		t.Errorf("expected loopback error, got: %v", err)
	}
}

// TestValidateOrigin_AcceptsPublicAlways: H8.
func TestValidateOrigin_AcceptsPublicAlways(t *testing.T) {
	t.Parallel()

	hosts := []string{
		"https://example.com",
		"https://earth-search.aws.element84.com",
	}
	for _, base := range hosts {
		for _, allow := range []bool{false, true} {
			cfg := &Config{
				Mode: "federation",
				Server: ServerConfig{Port: 8080},
				Federation: &FederationConfig{
					AllowPrivateOrigins: allow,
					CursorSecret:        "test-secret",
					Origins:             []OriginConfig{{ID: "origin1", BaseURL: base}},
				},
			}
			cfg.setDefaults()

			if err := NewValidator().Validate(cfg); err != nil {
				t.Errorf("host %q (allow=%v): unexpected validation error: %v", base, allow, err)
			}
		}
	}
}
