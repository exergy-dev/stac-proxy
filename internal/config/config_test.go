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
  cursor_secret: test-cursor-secret
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

}

// TestSetDefaults tests that default values are applied correctly
func TestSetDefaults(t *testing.T) {
	t.Run("all defaults applied", func(t *testing.T) {
		t.Parallel()
		cfg := &Config{Upstream: &UpstreamConfig{URL: "https://example.com"}}
		cfg.setDefaults()
		assert.Equal(t, "single", cfg.Mode)
		assert.Equal(t, "0.0.0.0", cfg.Server.Host)
		assert.Equal(t, 8080, cfg.Server.Port)
		assert.Equal(t, 30*time.Second, cfg.Server.Timeouts.Read)
		assert.Equal(t, 60*time.Second, cfg.Server.Timeouts.Write)
		assert.Equal(t, 120*time.Second, cfg.Server.Timeouts.Idle)
		assert.Equal(t, "info", cfg.Logging.Level)
		assert.Equal(t, "json", cfg.Logging.Format)
		assert.Equal(t, "/health", cfg.Health.Path)
		assert.Equal(t, DefaultMaxHeaderBytes, cfg.Server.MaxHeaderBytes)
		assert.Equal(t, 64*1024, cfg.Server.MaxHeaderBytes)
	})

	t.Run("explicit max_header_bytes honored", func(t *testing.T) {
		t.Parallel()
		cfg := &Config{
			Upstream: &UpstreamConfig{URL: "https://example.com"},
			Server:   ServerConfig{MaxHeaderBytes: 8 * 1024},
		}
		cfg.setDefaults()
		assert.Equal(t, 8*1024, cfg.Server.MaxHeaderBytes,
			"explicit max_header_bytes must not be overwritten by the default")
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
				CursorSecret: "test-cursor-secret",
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

}

// TestIsFederation tests the IsFederation helper method
func TestIsFederation(t *testing.T) {
	t.Parallel()
	assert.True(t, (&Config{Mode: "federation"}).IsFederation())
	assert.False(t, (&Config{Mode: "single"}).IsFederation())
}

// TestGetOrigin tests the GetOrigin helper method
func TestGetOrigin(t *testing.T) {
	t.Parallel()

	cfg := &Config{
		Mode: "federation",
		Federation: &FederationConfig{
			Origins: []OriginConfig{
				{ID: "origin1", BaseURL: "https://origin1.com"},
			},
		},
	}
	origin := cfg.GetOrigin("origin1")
	require.NotNil(t, origin)
	assert.Equal(t, "origin1", origin.ID)

	// Not found in non-empty federation (covers post-loop return nil branch).
	assert.Nil(t, cfg.GetOrigin("missing"))
	// No federation config.
	assert.Nil(t, (&Config{Mode: "single"}).GetOrigin("origin1"))
}

// TestServerConfigValidation tests server configuration validation
func TestServerConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		port    int
		wantErr bool
	}{
		{"valid port 8080", 8080, false},
		{"invalid port 65536", 65536, true},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := &Config{
				Mode:     "single",
				Server:   ServerConfig{Port: tt.port},
				Upstream: &UpstreamConfig{URL: "https://example.com"},
			}
			cfg.setDefaults()
			err := NewValidator().Validate(cfg)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestTLSConfigValidation tests TLS configuration validation
func TestTLSConfigValidation(t *testing.T) {
	tests := []struct {
		name      string
		tls       TLSConfig
		errSubstr string
	}{
		{"missing cert", TLSConfig{Enabled: true, KeyFile: "/path/to/key.pem"}, "cert_file"},
		{"missing key", TLSConfig{Enabled: true, CertFile: "/path/to/cert.pem"}, "key_file"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := &Config{
				Mode:     "single",
				Server:   ServerConfig{Port: 8443, TLS: tt.tls},
				Upstream: &UpstreamConfig{URL: "https://example.com"},
			}
			cfg.setDefaults()
			err := NewValidator().Validate(cfg)
			require.Error(t, err)
			assert.True(t, containsValidationError(err, tt.errSubstr), "got: %v", err)
		})
	}
}

// TestValidationHelpers tests validation helper functions
func TestValidationHelpers(t *testing.T) {
	t.Run("IsValidURL", func(t *testing.T) {
		t.Parallel()
		assert.True(t, IsValidURL("https://example.com"))
		assert.False(t, IsValidURL("example.com"))
	})

	t.Run("IsValidDuration", func(t *testing.T) {
		t.Parallel()
		assert.True(t, IsValidDuration(30*time.Second))
		assert.False(t, IsValidDuration(-5*time.Second))
	})

	t.Run("IsValidPort", func(t *testing.T) {
		t.Parallel()
		assert.True(t, IsValidPort(8080))
		assert.False(t, IsValidPort(0))
	})

	t.Run("ValidateRequiredString", func(t *testing.T) {
		t.Parallel()
		assert.NoError(t, ValidateRequiredString("field_name", "value"))
		err := ValidateRequiredString("field_name", "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "field_name is required")
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

	t.Run("valid log level", func(t *testing.T) {
		t.Parallel()
		cfg := &Config{
			Mode:     "single",
			Server:   ServerConfig{Port: 8080},
			Logging:  LoggingConfig{Level: "debug", Format: "json"},
			Upstream: &UpstreamConfig{URL: "https://example.com"},
		}
		cfg.setDefaults()
		assert.NoError(t, NewValidator().Validate(cfg))
	})
}

// TestUpstreamValidation tests upstream URL and timeout validation.
func TestUpstreamValidation(t *testing.T) {
	tests := []struct {
		name      string
		upstream  *UpstreamConfig
		errSubstr string
	}{
		{"invalid URL", &UpstreamConfig{URL: "ht!tp://invalid url"}, "upstream.url"},
		{"negative timeout", &UpstreamConfig{URL: "https://example.com", Timeout: -10 * time.Second}, "upstream.timeout cannot be negative"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := &Config{
				Mode:     "single",
				Server:   ServerConfig{Port: 8080},
				Upstream: tt.upstream,
			}
			cfg.setDefaults()
			err := NewValidator().Validate(cfg)
			require.Error(t, err)
			assert.True(t, containsValidationError(err, tt.errSubstr), "got: %v", err)
		})
	}
}

// TestFederationOriginValidation tests origin-level URL/timeout validation.
func TestFederationOriginValidation(t *testing.T) {
	tests := []struct {
		name      string
		origin    OriginConfig
		errSubstr string
	}{
		{"missing ID", OriginConfig{BaseURL: "https://origin1.com"}, "id is required"},
		{"missing base_url", OriginConfig{ID: "origin1"}, "base_url is required"},
		{"negative timeout", OriginConfig{ID: "origin1", BaseURL: "https://origin1.com", Timeout: -10 * time.Second}, "timeout cannot be negative"},
		{"invalid base_url", OriginConfig{ID: "origin1", BaseURL: "ht!tp://invalid url"}, "not a valid URL"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := &Config{
				Mode:   "federation",
				Server: ServerConfig{Port: 8080},
				Federation: &FederationConfig{
					Origins: []OriginConfig{tt.origin},
				},
			}
			cfg.setDefaults()
			err := NewValidator().Validate(cfg)
			require.Error(t, err)
			assert.True(t, containsValidationError(err, tt.errSubstr), "got: %v", err)
		})
	}
}

// TestFederation_EmptyOriginsRejected covers the early-return branch of
// validateFederation, separately from the per-origin paths above.
func TestFederation_EmptyOriginsRejected(t *testing.T) {
	t.Parallel()
	cfg := &Config{
		Mode:       "federation",
		Server:     ServerConfig{Port: 8080},
		Federation: &FederationConfig{Origins: []OriginConfig{}},
	}
	cfg.setDefaults()
	err := NewValidator().Validate(cfg)
	require.Error(t, err)
	assert.True(t, containsValidationError(err, "origins"), "got: %v", err)
}

// TestMiddleware_NilConfigShortCircuits exercises the cfg==nil short-
// circuits in validateCorsMiddleware and validateCacheMiddleware.
func TestMiddleware_NilConfigShortCircuits(t *testing.T) {
	t.Parallel()
	cfg := &Config{
		Mode:   "single",
		Server: ServerConfig{Port: 8080},
		Middleware: []MiddlewareConfig{
			{Name: "cors"},
			{Name: "cache"},
		},
		Upstream: &UpstreamConfig{URL: "https://example.com"},
	}
	cfg.setDefaults()
	assert.NoError(t, NewValidator().Validate(cfg))
}

// TestLoad_InvalidYAML covers the YAML parse error branch of Load.
func TestLoad_InvalidYAML(t *testing.T) {
	t.Parallel()
	tmpFile := createTempFile(t, "mode: single\nserver:\n  port: \"not closed\n")
	defer os.Remove(tmpFile)
	_, err := Load(tmpFile)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse config file")
}

// TestLoad_ValidationFailure covers the post-parse Validate() error
// branch of Load (parses cleanly, fails validation).
func TestLoad_ValidationFailure(t *testing.T) {
	t.Parallel()
	tmpFile := createTempFile(t, "mode: single\nserver:\n  port: 8080\n")
	defer os.Remove(tmpFile)
	_, err := Load(tmpFile)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "config validation failed")
}

// TestServer_ShortReadTimeoutWarning covers the "very short" warning
// branch in validateServer.
func TestServer_ShortReadTimeoutWarning(t *testing.T) {
	t.Parallel()
	cfg := &Config{
		Mode:     "single",
		Server:   ServerConfig{Port: 8080, Timeouts: TimeoutConfig{Read: 2 * time.Second}},
		Upstream: &UpstreamConfig{URL: "https://example.com"},
	}
	// Don't call setDefaults — would overwrite Read with 30s.
	// Validation should still succeed; we just want the warning branch run.
	_ = NewValidator().Validate(cfg)
}

// TestTimeoutValidation tests timeout validation
func TestTimeoutValidation(t *testing.T) {
	tests := []struct {
		name      string
		timeouts  TimeoutConfig
		errSubstr string
	}{
		{"negative read", TimeoutConfig{Read: -10 * time.Second, Write: 30 * time.Second, Idle: 60 * time.Second}, "timeouts.read cannot be negative"},
		{"negative write", TimeoutConfig{Read: 30 * time.Second, Write: -10 * time.Second, Idle: 60 * time.Second}, "timeouts.write cannot be negative"},
		{"negative idle", TimeoutConfig{Read: 30 * time.Second, Write: 30 * time.Second, Idle: -10 * time.Second}, "timeouts.idle cannot be negative"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := &Config{
				Mode:     "single",
				Server:   ServerConfig{Port: 8080, Timeouts: tt.timeouts},
				Upstream: &UpstreamConfig{URL: "https://example.com"},
			}
			err := NewValidator().Validate(cfg)
			require.Error(t, err)
			assert.True(t, containsValidationError(err, tt.errSubstr), "got: %v", err)
		})
	}
}

// TestOriginAuthValidation tests origin authentication validation
func TestOriginAuthValidation(t *testing.T) {
	tests := []struct {
		name      string
		auth      *OriginAuthConfig
		wantErr   bool
		errSubstr string
	}{
		{"invalid auth type", &OriginAuthConfig{Type: "invalid"}, true, "auth.type is invalid"},
		{"basic missing username", &OriginAuthConfig{Type: "basic", Password: "pass"}, true, "username and password"},
		{"bearer missing token", &OriginAuthConfig{Type: "bearer"}, true, "token"},
		{"api_key missing header", &OriginAuthConfig{Type: "api_key", APIKeyValue: "secret"}, true, "api_key_header"},
		{"oauth2 missing config", &OriginAuthConfig{Type: "oauth2"}, true, "oauth2 config"},
		{"oauth2 missing token_url", &OriginAuthConfig{Type: "oauth2", OAuth2: &OAuth2Config{ClientID: "c", ClientSecret: "s"}}, true, "token_url"},
		{"oauth2 missing client_id", &OriginAuthConfig{Type: "oauth2", OAuth2: &OAuth2Config{TokenURL: "https://auth.example.com/token", ClientSecret: "s"}}, true, "client_id"},
		{"valid none auth", &OriginAuthConfig{Type: "none"}, false, ""},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := &Config{
				Mode:   "federation",
				Server: ServerConfig{Port: 8080},
				Federation: &FederationConfig{
					CursorSecret: "test-cursor-secret",
					Origins: []OriginConfig{{
						ID:      "origin1",
						BaseURL: "https://origin1.com",
						Auth:    tt.auth,
					}},
				},
			}
			cfg.setDefaults()
			err := NewValidator().Validate(cfg)
			if tt.wantErr {
				require.Error(t, err)
				assert.True(t, containsValidationError(err, tt.errSubstr), "got: %v", err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestFederationValidation tests federation configuration validation
func TestFederationValidation(t *testing.T) {
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

}

// TestValidationWarnings tests that warnings are generated properly
func TestValidationWarnings(t *testing.T) {
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

	t.Run("cache store redis without redis block rejected", func(t *testing.T) {
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
		require.Error(t, err, "expected error for cache.store=redis without redis block")
		assert.True(t, containsValidationError(err, "requires the top-level redis block"), "unexpected error: %v", err)
	})

	t.Run("cache store redis with redis block accepted", func(t *testing.T) {
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
			Redis:    &RedisConfig{Addr: "redis:6379"},
		}
		cfg.setDefaults()
		require.NoError(t, NewValidator().Validate(cfg))
	})

	t.Run("cache store bogus rejected", func(t *testing.T) {
		t.Parallel()
		cfg := &Config{
			Mode:   "single",
			Server: ServerConfig{Port: 8080},
			Middleware: []MiddlewareConfig{
				{Name: "cache", Config: map[string]interface{}{
					"store": "memcached",
				}},
			},
			Upstream: &UpstreamConfig{URL: "https://example.com"},
		}
		cfg.setDefaults()
		err := NewValidator().Validate(cfg)
		require.Error(t, err, "expected error for cache.store=memcached")
		assert.True(t, containsValidationError(err, "is not supported"), "unexpected error: %v", err)
	})

	t.Run("page_cache store redis without redis block rejected", func(t *testing.T) {
		t.Parallel()
		cfg := &Config{
			Mode:   "federation",
			Server: ServerConfig{Port: 8080},
			Federation: &FederationConfig{
				Origins:      []OriginConfig{{ID: "a", BaseURL: "https://stac.example.com", Enabled: true}},
				CursorSecret: "s3cret",
				PageCache:    &PageCacheConfig{Store: "redis"},
			},
		}
		cfg.setDefaults()
		err := NewValidator().Validate(cfg)
		require.Error(t, err, "expected error for page_cache.store=redis without redis block")
		assert.True(t, containsValidationError(err, "requires the top-level redis block"), "unexpected error: %v", err)
	})

	t.Run("page_cache store redis with redis block accepted", func(t *testing.T) {
		t.Parallel()
		cfg := &Config{
			Mode:   "federation",
			Server: ServerConfig{Port: 8080},
			Federation: &FederationConfig{
				Origins:      []OriginConfig{{ID: "a", BaseURL: "https://stac.example.com", Enabled: true}},
				CursorSecret: "s3cret",
				PageCache:    &PageCacheConfig{Store: "redis"},
			},
			Redis: &RedisConfig{Addr: "redis:6379"},
		}
		cfg.setDefaults()
		require.NoError(t, NewValidator().Validate(cfg))
	})

	t.Run("page_cache store bogus rejected", func(t *testing.T) {
		t.Parallel()
		cfg := &Config{
			Mode:   "federation",
			Server: ServerConfig{Port: 8080},
			Federation: &FederationConfig{
				Origins:      []OriginConfig{{ID: "a", BaseURL: "https://stac.example.com", Enabled: true}},
				CursorSecret: "s3cret",
				PageCache:    &PageCacheConfig{Store: "sqlite"},
			},
		}
		cfg.setDefaults()
		err := NewValidator().Validate(cfg)
		require.Error(t, err, "expected error for page_cache.store=sqlite")
		assert.True(t, containsValidationError(err, "page_cache.store \"sqlite\" is not supported"), "unexpected error: %v", err)
	})

	t.Run("rate_limit store redis without redis block rejected", func(t *testing.T) {
		t.Parallel()
		cfg := &Config{
			Mode:   "single",
			Server: ServerConfig{Port: 8080},
			Middleware: []MiddlewareConfig{
				{Name: "rate_limit", Config: map[string]interface{}{
					"store": "redis",
				}},
			},
			Upstream: &UpstreamConfig{URL: "https://example.com"},
		}
		cfg.setDefaults()
		err := NewValidator().Validate(cfg)
		require.Error(t, err, "expected error for rate_limit.store=redis without redis block")
		assert.True(t, containsValidationError(err, "requires the top-level redis block"), "unexpected error: %v", err)
	})

	t.Run("rate_limit failure_mode enum enforced", func(t *testing.T) {
		t.Parallel()
		cfg := &Config{
			Mode:   "single",
			Server: ServerConfig{Port: 8080},
			Middleware: []MiddlewareConfig{
				{Name: "rate_limit", Config: map[string]interface{}{
					"store":        "redis",
					"failure_mode": "explode",
				}},
			},
			Upstream: &UpstreamConfig{URL: "https://example.com"},
			Redis:    &RedisConfig{Addr: "redis:6379"},
		}
		cfg.setDefaults()
		err := NewValidator().Validate(cfg)
		require.Error(t, err, "expected error for failure_mode=explode")
		assert.True(t, containsValidationError(err, "failure_mode"), "unexpected error: %v", err)
	})

	t.Run("rate_limit redis with failure_mode closed accepted", func(t *testing.T) {
		t.Parallel()
		cfg := &Config{
			Mode:   "single",
			Server: ServerConfig{Port: 8080},
			Middleware: []MiddlewareConfig{
				{Name: "rate_limit", Config: map[string]interface{}{
					"store":        "redis",
					"failure_mode": "closed",
				}},
			},
			Upstream: &UpstreamConfig{URL: "https://example.com"},
			Redis:    &RedisConfig{Addr: "redis:6379"},
		}
		cfg.setDefaults()
		require.NoError(t, NewValidator().Validate(cfg))
	})

	t.Run("redis block requires addr", func(t *testing.T) {
		t.Parallel()
		cfg := &Config{
			Mode:     "single",
			Server:   ServerConfig{Port: 8080},
			Upstream: &UpstreamConfig{URL: "https://example.com"},
			Redis:    &RedisConfig{},
		}
		cfg.setDefaults()
		err := NewValidator().Validate(cfg)
		require.Error(t, err, "expected error for redis block without addr")
		assert.True(t, containsValidationError(err, "redis.addr is required"), "unexpected error: %v", err)
	})

	t.Run("redis tls cert without key rejected", func(t *testing.T) {
		t.Parallel()
		cfg := &Config{
			Mode:     "single",
			Server:   ServerConfig{Port: 8080},
			Upstream: &UpstreamConfig{URL: "https://example.com"},
			Redis: &RedisConfig{
				Addr: "redis:6379",
				TLS:  RedisTLSConfig{Enabled: true, CertFile: "/etc/tls/cert.pem"},
			},
		}
		cfg.setDefaults()
		err := NewValidator().Validate(cfg)
		require.Error(t, err, "expected error for cert_file without key_file")
		assert.True(t, containsValidationError(err, "must be set together"), "unexpected error: %v", err)
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

	t.Run("valid middleware name", func(t *testing.T) {
		t.Parallel()
		cfg := &Config{
			Mode:       "single",
			Server:     ServerConfig{Port: 8080},
			Middleware: []MiddlewareConfig{{Name: "logging"}},
			Upstream:   &UpstreamConfig{URL: "https://example.com"},
		}
		cfg.setDefaults()
		assert.NoError(t, NewValidator().Validate(cfg))
	})

	t.Run("valid log format", func(t *testing.T) {
		t.Parallel()
		cfg := &Config{
			Mode:     "single",
			Server:   ServerConfig{Port: 8080},
			Logging:  LoggingConfig{Level: "info", Format: "text"},
			Upstream: &UpstreamConfig{URL: "https://example.com"},
		}
		cfg.setDefaults()
		assert.NoError(t, NewValidator().Validate(cfg))
	})

	t.Run("valid auth type", func(t *testing.T) {
		t.Parallel()
		cfg := &Config{
			Mode:   "federation",
			Server: ServerConfig{Port: 8080},
			Federation: &FederationConfig{
				CursorSecret: "test-cursor-secret",
				Origins: []OriginConfig{{
					ID:      "origin1",
					BaseURL: "https://origin1.com",
					Auth:    &OriginAuthConfig{Type: "none"},
				}},
			},
		}
		cfg.setDefaults()
		assert.NoError(t, NewValidator().Validate(cfg))
	})

	t.Run("valid origin ID format", func(t *testing.T) {
		t.Parallel()
		cfg := &Config{
			Mode:   "federation",
			Server: ServerConfig{Port: 8080},
			Federation: &FederationConfig{
				CursorSecret: "test-cursor-secret",
				Origins:      []OriginConfig{{ID: "my-origin", BaseURL: "https://origin1.com"}},
			},
		}
		cfg.setDefaults()
		assert.NoError(t, NewValidator().Validate(cfg))
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

// TestConfig_FederationRequiresCursorSecret verifies that federation
// mode now hard-fails validation when cursor_secret is empty (paginated
// search cannot sign cursors without it).
func TestConfig_FederationRequiresCursorSecret(t *testing.T) {
	t.Parallel()
	cfg := &Config{
		Mode:   "federation",
		Server: ServerConfig{Port: 8080},
		Federation: &FederationConfig{
			Origins: []OriginConfig{{ID: "origin1", BaseURL: "https://origin1.com"}},
		},
	}
	cfg.setDefaults()
	err := NewValidator().Validate(cfg)
	require.Error(t, err, "expected error for missing cursor_secret in federation mode")
	assert.True(t, containsValidationError(err, "cursor_secret is required"), "got: %v", err)

	// Whitespace-only is also rejected.
	cfg.Federation.CursorSecret = "   "
	err = NewValidator().Validate(cfg)
	require.Error(t, err)
	assert.True(t, containsValidationError(err, "cursor_secret is required"), "got: %v", err)
}

// TestConfig_ExpandEnv_IgnoresCommentsAndRegexReplace is the key
// regression for Phase 2: expansion runs over parsed scalar values
// only, so (a) a ${DOES_NOT_EXIST} reference inside a YAML comment does
// NOT fail the load, and (b) a url_remap replace value containing a
// regex capture group `$1` survives verbatim (bare $NAME is never
// treated as a variable).
func TestConfig_ExpandEnv_IgnoresCommentsAndRegexReplace(t *testing.T) {
	t.Parallel()

	yaml := `
mode: single
# this comment references ${DOES_NOT_EXIST} and must be ignored
upstream:
  url: https://example.com/stac
middleware:
  - name: url_remap
    config:
      rules:
        - match: "^https://internal/(.*)$"
          replace: "https://cdn.example.com/$1"
`
	tmp := createTempFile(t, yaml)
	defer os.Remove(tmp)

	cfg, err := Load(tmp)
	require.NoError(t, err, "comment ${...} and regex $1 must not fail load")
	require.Len(t, cfg.Middleware, 1)

	rules, ok := cfg.Middleware[0].Config["rules"].([]interface{})
	require.True(t, ok, "expected rules list, got %T", cfg.Middleware[0].Config["rules"])
	require.Len(t, rules, 1)
	rule, ok := rules[0].(map[string]interface{})
	require.True(t, ok, "expected rule map, got %T", rules[0])
	assert.Equal(t, "https://cdn.example.com/$1", rule["replace"], "regex capture group $1 must survive literally")
}

// TestConfig_ExpandEnv_DollarEscape verifies $$ collapses to a single
// literal '$'.
func TestConfig_ExpandEnv_DollarEscape(t *testing.T) {
	t.Parallel()

	yaml := `
mode: single
upstream:
  url: https://example.com/stac
middleware:
  - name: url_remap
    config:
      literal: "a$$b"
`
	tmp := createTempFile(t, yaml)
	defer os.Remove(tmp)

	cfg, err := Load(tmp)
	require.NoError(t, err)
	assert.Equal(t, "a$b", cfg.Middleware[0].Config["literal"])
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

// TestValidateOrigin_RejectsRFC1918ByDefault: H8.
func TestValidateOrigin_RejectsRFC1918ByDefault(t *testing.T) {
	t.Parallel()
	cfg := &Config{
		Mode:   "federation",
		Server: ServerConfig{Port: 8080},
		Federation: &FederationConfig{
			Origins: []OriginConfig{{ID: "origin1", BaseURL: "https://10.0.0.1"}},
		},
	}
	cfg.setDefaults()
	err := NewValidator().Validate(cfg)
	require.Error(t, err)
	assert.True(t, containsValidationError(err, "private"), "got: %v", err)
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

	cfg := &Config{
		Mode:   "federation",
		Server: ServerConfig{Port: 8080},
		Federation: &FederationConfig{
			CursorSecret: "test-secret",
			Origins:      []OriginConfig{{ID: "origin1", BaseURL: "https://example.com"}},
		},
	}
	cfg.setDefaults()

	assert.NoError(t, NewValidator().Validate(cfg))
}
