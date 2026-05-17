package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		require.NoError(t, err)

		assert.Equal(t, "single", cfg.Mode)
		assert.Equal(t, "127.0.0.1", cfg.Server.Host)
		assert.Equal(t, 8080, cfg.Server.Port)
		require.NotNil(t, cfg.Upstream, "expected upstream to be set")
		assert.Equal(t, "https://example.com/stac", cfg.Upstream.URL)
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
		require.NoError(t, err)

		assert.Equal(t, "federation", cfg.Mode)
		require.NotNil(t, cfg.Federation, "expected federation to be set")
		require.Len(t, cfg.Federation.Origins, 2)
		assert.Equal(t, "origin1", cfg.Federation.Origins[0].ID)
		assert.Equal(t, "https://origin1.example.com", cfg.Federation.Origins[0].BaseURL)
	})

	t.Run("missing file error", func(t *testing.T) {
		t.Parallel()

		_, err := Load("/nonexistent/path/to/config.yaml")
		require.Error(t, err, "expected error for missing file")
		assert.Contains(t, err.Error(), "failed to read config file")
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
		require.Error(t, err, "expected error for invalid YAML")
		assert.Contains(t, err.Error(), "failed to parse config file")
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
		require.Error(t, err, "expected validation error")
		assert.Contains(t, err.Error(), "config validation failed")
		assert.True(t, containsValidationError(err, "upstream"), "expected error to mention 'upstream', got: %v", err)
	})

	t.Run("validation error - federation mode without origins", func(t *testing.T) {
		t.Parallel()

		yaml := `
mode: federation
server:
  port: 8080
federation: {}
`
		tmpFile := createTempFile(t, yaml)
		defer os.Remove(tmpFile)

		_, err := Load(tmpFile)
		require.Error(t, err, "expected validation error")
		assert.Contains(t, err.Error(), "config validation failed")
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
		require.NoError(t, err)

		assert.Equal(t, 9999, cfg.Server.Port, "expected port 9999 from env var")
		assert.Equal(t, "https://env-var-test.com", cfg.Upstream.URL, "expected URL from env var")
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
		require.Error(t, err, "expected validation error for TLS without cert/key")
		assert.True(t,
			containsValidationError(err, "cert_file") || containsValidationError(err, "key_file"),
			"expected error to mention cert_file or key_file, got: %v", err,
		)
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

		assert.Equal(t, "0.0.0.0", cfg.Server.Host)
		assert.Equal(t, 8080, cfg.Server.Port)
		assert.Equal(t, 30*time.Second, cfg.Server.Timeouts.Read)
		assert.Equal(t, 60*time.Second, cfg.Server.Timeouts.Write)
		assert.Equal(t, 120*time.Second, cfg.Server.Timeouts.Idle)
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

		assert.Equal(t, "info", cfg.Logging.Level)
		assert.Equal(t, "json", cfg.Logging.Format)
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

		assert.Equal(t, "/health", cfg.Health.Path)
	})

	t.Run("mode defaults", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{
			Upstream: &UpstreamConfig{
				URL: "https://example.com",
			},
		}

		cfg.setDefaults()

		assert.Equal(t, "single", cfg.Mode)
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

		assert.Equal(t, 10, cfg.Federation.MaxConcurrent)
		assert.Equal(t, 60*time.Second, cfg.Federation.AggregateTimeout)
		assert.Equal(t, "priority", cfg.Federation.ConflictStrategy)
		assert.Equal(t, 100, cfg.Federation.DefaultPageSize)
		assert.Equal(t, 1000, cfg.Federation.MaxPageSize)
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

		assert.Equal(t, 30*time.Second, cfg.Federation.Origins[0].Timeout, "expected default origin timeout 30s")
		assert.Equal(t, 15*time.Second, cfg.Federation.Origins[1].Timeout, "expected origin timeout to remain 15s")
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

		assert.Equal(t, "192.168.1.1", cfg.Server.Host)
		assert.Equal(t, 3000, cfg.Server.Port)
		assert.Equal(t, 10*time.Second, cfg.Server.Timeouts.Read)
		assert.Equal(t, "debug", cfg.Logging.Level)
		assert.Equal(t, "/healthz", cfg.Health.Path)
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

		assert.NoError(t, cfg.Validate())
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

		assert.NoError(t, cfg.Validate())
	})

	t.Run("invalid mode", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{
			Mode: "invalid",
		}
		cfg.setDefaults()

		err := cfg.Validate()
		require.Error(t, err, "expected validation error")
		assert.True(t, containsValidationError(err, "mode must be"), "expected error about invalid mode, got: %v", err)
	})

	t.Run("single mode requires upstream", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{
			Mode: "single",
		}
		cfg.setDefaults()

		err := cfg.Validate()
		require.Error(t, err, "expected validation error")
		assert.True(t, containsValidationError(err, "upstream"), "expected error about missing upstream, got: %v", err)
	})

	t.Run("federation mode requires federation config", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{
			Mode: "federation",
		}
		cfg.setDefaults()

		err := cfg.Validate()
		require.Error(t, err, "expected validation error")
		assert.True(t, containsValidationError(err, "federation"), "expected error about missing federation config, got: %v", err)
	})

	t.Run("federation requires at least one origin", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{
			Mode: "federation",
			Federation: &FederationConfig{
				CursorSecret: "test-secret",
				Origins:      []OriginConfig{},
			},
		}
		cfg.setDefaults()

		err := cfg.Validate()
		require.Error(t, err, "expected validation error")
		assert.True(t, containsValidationError(err, "origin"), "expected error about missing origins, got: %v", err)
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
		require.Error(t, err, "expected validation error")
		assert.True(t, containsValidationError(err, "id is required"), "expected error about missing ID, got: %v", err)
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
		require.Error(t, err, "expected validation error")
		assert.True(t, containsValidationError(err, "base_url is required"), "expected error about missing base_url, got: %v", err)
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
		require.Error(t, err, "expected validation error")
		assert.True(t, containsValidationError(err, "base_url"), "expected error about missing base_url, got: %v", err)
	})
}

// TestIsFederation tests the IsFederation helper method
func TestIsFederation(t *testing.T) {
	t.Run("single mode", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{Mode: "single"}
		assert.False(t, cfg.IsFederation(), "expected IsFederation to return false for single mode")
	})

	t.Run("federation mode", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{Mode: "federation"}
		assert.True(t, cfg.IsFederation(), "expected IsFederation to return true for federation mode")
	})

	t.Run("default mode", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{}
		assert.False(t, cfg.IsFederation(), "expected IsFederation to return false for empty mode")
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
		require.NotNil(t, origin, "expected to find origin2")
		assert.Equal(t, "origin2", origin.ID)
		assert.Equal(t, "https://origin2.com", origin.BaseURL)
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

		assert.Nil(t, cfg.GetOrigin("nonexistent"), "expected GetOrigin to return nil for nonexistent origin")
	})

	t.Run("no federation config", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{Mode: "single"}

		assert.Nil(t, cfg.GetOrigin("origin1"), "expected GetOrigin to return nil when no federation config")
	})

	t.Run("empty origins list", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{
			Mode: "federation",
			Federation: &FederationConfig{
				CursorSecret: "test-secret", Origins: []OriginConfig{}},
		}

		assert.Nil(t, cfg.GetOrigin("origin1"), "expected GetOrigin to return nil for empty origins list")
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

			if tt.wantErr {
				assert.Error(t, err, "expected validation error but got none")
			} else {
				assert.NoError(t, err)
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

		assert.Equal(t, 8080, cfg.Server.Port, "expected port to be set to default 8080")

		validator := NewValidator()
		assert.NoError(t, validator.Validate(cfg), "unexpected validation error after defaults")
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
		assert.NoError(t, validator.Validate(cfg))
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
		assert.NoError(t, validator.Validate(cfg))
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
		require.Error(t, err, "expected validation error")
		// Check if it's a ValidationError with specific TLS errors
		if ve, ok := err.(*ValidationError); ok {
			found := false
			for _, e := range ve.Errors {
				if strings.Contains(e.Error(), "cert_file") {
					found = true
					break
				}
			}
			assert.True(t, found, "expected error to mention cert_file in validation errors: %v", ve.Errors)
		} else {
			assert.Contains(t, err.Error(), "cert_file")
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
		require.Error(t, err, "expected validation error")
		// Check if it's a ValidationError with specific TLS errors
		if ve, ok := err.(*ValidationError); ok {
			found := false
			for _, e := range ve.Errors {
				if strings.Contains(e.Error(), "key_file") {
					found = true
					break
				}
			}
			assert.True(t, found, "expected error to mention key_file in validation errors: %v", ve.Errors)
		} else {
			assert.Contains(t, err.Error(), "key_file")
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
metrics:
  enabled: true
  path: /metrics
  port: 9090
health:
  path: /health
federation:
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
		require.NoError(t, err)

		// Verify server config
		assert.Equal(t, 8080, cfg.Server.Port)
		assert.True(t, cfg.Server.TLS.Enabled, "expected TLS to be enabled")

		// Verify federation config
		assert.Equal(t, 20, cfg.Federation.MaxConcurrent)
		require.Len(t, cfg.Federation.Origins, 2)

		// Verify origin details
		earthSearch := cfg.GetOrigin("earth-search")
		require.NotNil(t, earthSearch, "expected to find earth-search origin")
		assert.Equal(t, "Earth Search", earthSearch.Name)
		assert.True(t, earthSearch.Searchable, "expected earth-search to be searchable")
		assert.True(t, earthSearch.AutoDiscover, "expected earth-search to have auto-discover enabled")

		// Verify middleware
		require.Len(t, cfg.Middleware, 2)
		assert.Equal(t, "logging", cfg.Middleware[0].Name)

		// Verify metrics
		assert.True(t, cfg.Metrics.Enabled, "expected metrics to be enabled")
		assert.Equal(t, 9090, cfg.Metrics.Port)
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
		require.NoError(t, err)

		origin := cfg.GetOrigin("secure-origin")
		require.NotNil(t, origin, "expected to find secure-origin")
		require.NotNil(t, origin.Auth, "expected auth to be configured")
		assert.Equal(t, "basic", origin.Auth.Type)
		assert.Equal(t, "testuser", origin.Auth.Username)
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
		require.NoError(t, err)

		origin := cfg.GetOrigin("token-origin")
		require.NotNil(t, origin, "expected to find token-origin")
		require.NotNil(t, origin.Auth, "expected auth to be configured")
		assert.Equal(t, "bearer", origin.Auth.Type)
		assert.Equal(t, "my-secret-token", origin.Auth.Token)
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
				assert.Equal(t, tt.valid, IsValidURL(tt.url), "IsValidURL(%q)", tt.url)
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
				assert.Equal(t, tt.valid, IsValidDuration(tt.duration), "IsValidDuration(%v)", tt.duration)
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
				assert.Equal(t, tt.valid, IsValidPort(tt.port), "IsValidPort(%d)", tt.port)
			})
		}
	})

	t.Run("ValidateRequiredString", func(t *testing.T) {
		t.Parallel()

		assert.NoError(t, ValidateRequiredString("field_name", "value"))

		err := ValidateRequiredString("field_name", "")
		require.Error(t, err, "expected error for empty string")
		assert.Contains(t, err.Error(), "field_name is required")
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

		assert.NotPanics(t, func() { MustValidate(cfg) })
	})

	t.Run("invalid config panics", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{
			Mode: "invalid",
		}
		cfg.setDefaults()

		assert.Panics(t, func() { MustValidate(cfg) }, "MustValidate should have panicked")
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
		require.Error(t, err, "expected validation error")
		assert.True(t, containsValidationError(err, "logging.level"), "expected error about log level, got: %v", err)
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
		require.Error(t, err, "expected validation error")
		assert.True(t, containsValidationError(err, "logging.format"), "expected error about log format, got: %v", err)
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
			assert.NoError(t, validator.Validate(cfg), "unexpected error for log level %q", level)
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
		require.Error(t, err, "expected validation error")
		assert.True(t, containsValidationError(err, "timeouts.read cannot be negative"), "expected error about negative read timeout, got: %v", err)
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
		require.Error(t, err, "expected validation error")
		assert.True(t, containsValidationError(err, "timeouts.write cannot be negative"), "expected error about negative write timeout, got: %v", err)
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
		require.Error(t, err, "expected validation error")
		assert.True(t, containsValidationError(err, "timeouts.idle cannot be negative"), "expected error about negative idle timeout, got: %v", err)
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
		require.Error(t, err, "expected validation error")
		assert.True(t, containsValidationError(err, "upstream.url"), "expected error about upstream URL, got: %v", err)
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
		require.Error(t, err, "expected validation error")
		assert.True(t, containsValidationError(err, "upstream.timeout cannot be negative"), "expected error about negative timeout, got: %v", err)
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
		require.Error(t, err, "expected validation error")
		assert.True(t, containsValidationError(err, "auth.type is invalid"), "expected error about invalid auth type, got: %v", err)
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
		require.Error(t, err, "expected validation error")
		assert.True(t, containsValidationError(err, "username and password"), "expected error about username/password, got: %v", err)
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
		require.Error(t, err, "expected validation error")
		assert.True(t, containsValidationError(err, "token"), "expected error about token, got: %v", err)
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
		require.Error(t, err, "expected validation error")
		assert.True(t, containsValidationError(err, "api_key_header"), "expected error about api_key_header, got: %v", err)
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
		require.Error(t, err, "expected validation error")
		assert.True(t, containsValidationError(err, "oauth2 config"), "expected error about oauth2 config, got: %v", err)
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
		require.Error(t, err, "expected validation error")
		assert.True(t, containsValidationError(err, "token_url"), "expected error about token_url, got: %v", err)
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
		require.Error(t, err, "expected validation error")
		assert.True(t, containsValidationError(err, "client_id"), "expected error about client_id, got: %v", err)
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
		assert.NoError(t, validator.Validate(cfg))
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
		require.Error(t, err, "expected validation error")
		assert.True(t, containsValidationError(err, "conflict_strategy"), "expected error about conflict_strategy, got: %v", err)
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
		require.Error(t, err, "expected validation error")
		assert.True(t, containsValidationError(err, "duplicate"), "expected error about duplicate ID, got: %v", err)
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
		require.Error(t, err, "expected validation error")
		assert.True(t, containsValidationError(err, "invalid characters"), "expected error about invalid characters, got: %v", err)
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
		require.Error(t, err, "expected validation error")
		assert.True(t, containsValidationError(err, "timeout cannot be negative"), "expected error about negative timeout, got: %v", err)
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
		require.Error(t, err, "expected validation error")
		assert.True(t, containsValidationError(err, "not a valid URL"), "expected error about invalid URL, got: %v", err)
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
				assert.NotEmpty(t, ve.Warnings, "expected warnings for empty host")
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
				assert.NotEmpty(t, ve.Warnings, "expected warnings for short timeout")
			}
		}
	})

	t.Run("unrecognized middleware fails validation", func(t *testing.T) {
		t.Parallel()

		// A typo'd middleware name (e.g. "rate-limit" vs "rate_limit")
		// previously emitted only a warning, so deployments could ship
		// with authz/ratelimit silently disabled. Validation now hard-
		// fails so the misconfig surfaces at startup.
		cfg := &Config{
			Mode: "single",
			Server: ServerConfig{
				Port: 8080,
			},
			Middleware: []MiddlewareConfig{
				{Name: "rate-limit"},
			},
			Upstream: &UpstreamConfig{
				URL: "https://example.com",
			},
		}
		cfg.setDefaults()

		validator := NewValidator()
		err := validator.Validate(cfg)
		require.Error(t, err, "expected validation error for unrecognized middleware name")
		assert.True(t, containsValidationError(err, "is not a recognized middleware"), "expected unrecognized-middleware error, got: %v", err)
	})

	t.Run("cors with credentials and wildcard origin rejected", func(t *testing.T) {
		t.Parallel()
		cfg := &Config{
			Mode:   "single",
			Server: ServerConfig{Port: 8080},
			Middleware: []MiddlewareConfig{
				{Name: "cors", Config: map[string]interface{}{
					"allowed_origins":   []interface{}{"*"},
					"allow_credentials": true,
				}},
			},
			Upstream: &UpstreamConfig{URL: "https://example.com"},
		}
		cfg.setDefaults()
		err := NewValidator().Validate(cfg)
		require.Error(t, err, "expected error for cors credentials+wildcard")
		assert.True(t, containsValidationError(err, "allow_credentials cannot be true with wildcard"), "unexpected error: %v", err)
	})

	t.Run("cors with non-string origin element rejected", func(t *testing.T) {
		t.Parallel()
		cfg := &Config{
			Mode:   "single",
			Server: ServerConfig{Port: 8080},
			Middleware: []MiddlewareConfig{
				{Name: "cors", Config: map[string]interface{}{
					"allowed_origins": []interface{}{"https://example.org", 42},
				}},
			},
			Upstream: &UpstreamConfig{URL: "https://example.com"},
		}
		cfg.setDefaults()
		err := NewValidator().Validate(cfg)
		require.Error(t, err, "expected error for non-string origin")
		assert.True(t, containsValidationError(err, "must be a string"), "unexpected error: %v", err)
	})

	t.Run("cors with credentials and exact origins is valid", func(t *testing.T) {
		t.Parallel()
		cfg := &Config{
			Mode:   "single",
			Server: ServerConfig{Port: 8080},
			Middleware: []MiddlewareConfig{
				{Name: "cors", Config: map[string]interface{}{
					"allowed_origins":   []interface{}{"https://app.example.org"},
					"allow_credentials": true,
				}},
			},
			Upstream: &UpstreamConfig{URL: "https://example.com"},
		}
		cfg.setDefaults()
		require.NoError(t, NewValidator().Validate(cfg))
	})

	t.Run("cache store redis rejected at validation", func(t *testing.T) {
		t.Parallel()
		cfg := &Config{
			Mode:   "single",
			Server: ServerConfig{Port: 8080},
			Middleware: []MiddlewareConfig{
				{Name: "cache", Config: map[string]interface{}{
					"store": "redis",
				}},
			},
			Upstream: &UpstreamConfig{URL: "https://example.com"},
		}
		cfg.setDefaults()
		err := NewValidator().Validate(cfg)
		require.Error(t, err, "expected error for cache.store=redis")
		assert.True(t, containsValidationError(err, "store \"redis\" is not supported"), "unexpected error: %v", err)
	})

	t.Run("cache store memory accepted", func(t *testing.T) {
		t.Parallel()
		cfg := &Config{
			Mode:   "single",
			Server: ServerConfig{Port: 8080},
			Middleware: []MiddlewareConfig{
				{Name: "cache", Config: map[string]interface{}{
					"store": "memory",
				}},
			},
			Upstream: &UpstreamConfig{URL: "https://example.com"},
		}
		cfg.setDefaults()
		require.NoError(t, NewValidator().Validate(cfg))
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
		require.Error(t, err, "expected validation error for empty upstream URL")
		assert.True(t, containsValidationError(err, "upstream.url is required"), "expected error about required upstream URL, got: %v", err)
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
			assert.NoError(t, validator.Validate(cfg), "unexpected validation error for middleware %q", name)
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
			assert.NoError(t, validator.Validate(cfg), "unexpected error for log format %q", format)
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
			assert.NoError(t, validator.Validate(cfg), "unexpected error for conflict strategy %q", strategy)
		}
	})

	t.Run("valid auth types", func(t *testing.T) {
		t.Parallel()

		// Test valid auth types that don't require additional fields
		validTypes := []string{"none", "custom", "aws_sigv4"}

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
			assert.NoError(t, validator.Validate(cfg), "unexpected error for auth type %q", authType)
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
			assert.NoError(t, validator.Validate(cfg), "unexpected error for origin ID %q", id)
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
		require.Error(t, err, "expected validation error for ID starting with number")
		assert.True(t, containsValidationError(err, "invalid characters"), "expected error about invalid ID, got: %v", err)
	})
}

// TestValidation_RejectsCustomHeadersAsAuthType verifies that the
// previously accepted (but inert) "custom_headers" auth.type is now
// rejected. CustomHeaders is a per-config field, not a provider type;
// the corresponding provider type is "custom".
func TestValidation_RejectsCustomHeadersAsAuthType(t *testing.T) {
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
					BaseURL: "https://origin1.example.com",
					Auth: &OriginAuthConfig{
						Type: "custom_headers",
					},
				},
			},
		},
	}
	cfg.setDefaults()

	err := NewValidator().Validate(cfg)
	require.Error(t, err, "expected validation error for auth.type=custom_headers")
	assert.True(t, containsValidationError(err, "auth.type"), "expected error to mention auth.type, got: %v", err)
}

// TestConfig_ExpandEnv_ErrorsOnUndefined verifies that referencing
// an unset environment variable from YAML now fails Load (HIGH
// H-config-1). Previously os.ExpandEnv silently produced "" and the
// config slipped past validation as "configured".
func TestConfig_ExpandEnv_ErrorsOnUndefined(t *testing.T) {
	// Cannot t.Parallel — uses os.Setenv which races with other env tests.
	const varName = "STAC_PROXY_TEST_UNSET_8E2F1A"
	os.Unsetenv(varName)

	yaml := `
mode: single
upstream:
  url: ${` + varName + `}
`
	tmp := createTempFile(t, yaml)
	defer os.Remove(tmp)

	_, err := Load(tmp)
	require.Error(t, err, "expected error for undefined env var")
	assert.Contains(t, err.Error(), varName, "error should mention the undefined var")
}

// TestConfig_ExpandEnv_DefaultSyntax verifies ${VAR:-default}
// expands to "default" when VAR is unset, matching shell semantics.
func TestConfig_ExpandEnv_DefaultSyntax(t *testing.T) {
	const varName = "STAC_PROXY_TEST_DEFAULT_8E2F1B"
	os.Unsetenv(varName)

	yaml := `
mode: single
upstream:
  url: ${` + varName + `:-https://fallback.example.com}
`
	tmp := createTempFile(t, yaml)
	defer os.Remove(tmp)

	cfg, err := Load(tmp)
	require.NoError(t, err, "expected default to satisfy load")
	require.NotNil(t, cfg.Upstream)
	assert.Equal(t, "https://fallback.example.com", cfg.Upstream.URL, "expected fallback to apply")
}

// TestConfig_ExpandEnv_SetVarTakesPriority verifies that when the
// env var IS set, its value wins over the :-default fallback.
func TestConfig_ExpandEnv_SetVarTakesPriority(t *testing.T) {
	const varName = "STAC_PROXY_TEST_SET_8E2F1C"
	require.NoError(t, os.Setenv(varName, "https://from-env.example.com"))
	defer os.Unsetenv(varName)

	yaml := `
mode: single
upstream:
  url: ${` + varName + `:-https://fallback.example.com}
`
	tmp := createTempFile(t, yaml)
	defer os.Remove(tmp)

	cfg, err := Load(tmp)
	require.NoError(t, err)
	assert.Equal(t, "https://from-env.example.com", cfg.Upstream.URL, "expected env-set value to win")
}

// TestConfig_RejectsUnknownKeys verifies that the YAML decoder runs
// with KnownFields(true) so typos and references to undocumented
// features fail Load instead of silently no-opping. Drift between
// documented YAML and the config struct (e.g. `search_strategy`,
// `check_upstreams`) was previously accepted without error.
func TestConfig_RejectsUnknownKeys(t *testing.T) {
	t.Parallel()

	yaml := `
mode: single
upstream:
  url: https://example.com/stac
not_a_real_key: foo
`
	tmp := createTempFile(t, yaml)
	defer os.Remove(tmp)

	_, err := Load(tmp)
	require.Error(t, err, "expected error for unknown YAML key")
	assert.Contains(t, err.Error(), "not_a_real_key", "error should mention the unknown key")
}

// createTempFile creates a temporary file with the given content
func createTempFile(t *testing.T, content string) string {
	t.Helper()

	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "config.yaml")

	require.NoError(t, os.WriteFile(tmpFile, []byte(content), 0644), "failed to create temp file")

	return tmpFile
}

// containsValidationError checks if an error (potentially wrapped) contains
// a ValidationError with an error message containing the given substring.
// Kept because ValidationError.Error() only includes a summary count; the
// detailed errors live in the Errors slice and need typed inspection.
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
		Mode:   "federation",
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
	require.Error(t, err, "expected validation error for negative max_response_bytes")
	assert.True(t, containsValidationError(err, "max_response_bytes cannot be negative"), "expected max_response_bytes error, got: %v", err)
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
			Mode:   "federation",
			Server: ServerConfig{Port: 8080},
			Federation: &FederationConfig{
				Origins: []OriginConfig{{ID: "origin1", BaseURL: base}},
			},
		}
		cfg.setDefaults()

		err := NewValidator().Validate(cfg)
		if !assert.Error(t, err, "scheme %q: expected validation error", base) {
			continue
		}
		assert.True(t, containsValidationError(err, "scheme must be http or https"), "scheme %q: expected scheme error, got: %v", base, err)
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
			Mode:   "federation",
			Server: ServerConfig{Port: 8080},
			Federation: &FederationConfig{
				Origins: []OriginConfig{{ID: "origin1", BaseURL: base}},
			},
		}
		cfg.setDefaults()

		err := NewValidator().Validate(cfg)
		if !assert.Error(t, err, "host %q: expected validation error", base) {
			continue
		}
		assert.True(t, containsValidationError(err, "loopback"), "host %q: expected loopback error, got: %v", base, err)
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
			Mode:   "federation",
			Server: ServerConfig{Port: 8080},
			Federation: &FederationConfig{
				Origins: []OriginConfig{{ID: "origin1", BaseURL: base}},
			},
		}
		cfg.setDefaults()

		err := NewValidator().Validate(cfg)
		if !assert.Error(t, err, "host %q: expected validation error", base) {
			continue
		}
		assert.True(t, containsValidationError(err, "private"), "host %q: expected private-range error, got: %v", base, err)
	}
}

// TestValidateOrigin_AcceptsLoopbackWhenAllowed: H8.
func TestValidateOrigin_AcceptsLoopbackWhenAllowed(t *testing.T) {
	t.Parallel()

	cfg := &Config{
		Mode:   "federation",
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

	assert.NoError(t, NewValidator().Validate(cfg))
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

	assert.NoError(t, NewValidator().Validate(cfg))
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
	require.Error(t, err, "expected validation error for loopback upstream")
	assert.True(t, containsValidationError(err, "loopback"), "expected loopback error, got: %v", err)
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
				Mode:   "federation",
				Server: ServerConfig{Port: 8080},
				Federation: &FederationConfig{
					AllowPrivateOrigins: allow,
					CursorSecret:        "test-secret",
					Origins:             []OriginConfig{{ID: "origin1", BaseURL: base}},
				},
			}
			cfg.setDefaults()

			assert.NoError(t, NewValidator().Validate(cfg), "host %q (allow=%v)", base, allow)
		}
	}
}
