// Package config provides configuration management.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"time"
)

// Validator validates configuration.
type Validator struct {
	errors   []error
	warnings []string
}

// NewValidator creates a new configuration validator.
func NewValidator() *Validator {
	return &Validator{}
}

// Validate validates the complete configuration.
func (v *Validator) Validate(cfg *Config) error {
	v.errors = nil
	v.warnings = nil

	// Validate server config
	v.validateServer(cfg.Server)

	// Validate logging
	v.validateLogging(cfg.Logging)

	// Validate mode-specific config
	switch cfg.Mode {
	case "single":
		if cfg.Upstream == nil {
			v.addError("upstream configuration required in single mode")
		} else {
			v.validateUpstream(*cfg.Upstream)
		}
	case "federation":
		if cfg.Federation == nil {
			v.addError("federation configuration required in federation mode")
		} else {
			v.validateFederation(*cfg.Federation)
		}
	default:
		v.addError("mode must be 'single' or 'federation', got '%s'", cfg.Mode)
	}

	// Validate middleware
	v.validateMiddleware(cfg.Middleware)

	// Return combined errors
	if len(v.errors) > 0 {
		return &ValidationError{Errors: v.errors, Warnings: v.warnings}
	}

	return nil
}

// ValidationError contains validation errors.
type ValidationError struct {
	Errors   []error
	Warnings []string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("configuration validation failed: %d errors", len(e.Errors))
}

func (v *Validator) addError(format string, args ...interface{}) {
	v.errors = append(v.errors, fmt.Errorf(format, args...))
}

func (v *Validator) addWarning(format string, args ...interface{}) {
	v.warnings = append(v.warnings, fmt.Sprintf(format, args...))
}

func (v *Validator) validateServer(cfg ServerConfig) {
	if cfg.Port < 1 || cfg.Port > 65535 {
		v.addError("server.port must be between 1 and 65535")
	}

	if cfg.Host == "" {
		v.addWarning("server.host is empty, defaulting to 0.0.0.0")
	}

	// Validate timeouts
	if cfg.Timeouts.Read < 0 {
		v.addError("server.timeouts.read cannot be negative")
	}
	if cfg.Timeouts.Write < 0 {
		v.addError("server.timeouts.write cannot be negative")
	}
	if cfg.Timeouts.Idle < 0 {
		v.addError("server.timeouts.idle cannot be negative")
	}

	// Warn about very short timeouts
	if cfg.Timeouts.Read > 0 && cfg.Timeouts.Read < 5*time.Second {
		v.addWarning("server.timeouts.read is very short (%v)", cfg.Timeouts.Read)
	}

	// Validate TLS if enabled
	if cfg.TLS.Enabled {
		v.validateTLS(cfg.TLS)
	}
}

func (v *Validator) validateTLS(cfg TLSConfig) {
	if cfg.CertFile == "" {
		v.addError("server.tls.cert_file is required when TLS is enabled")
	}
	if cfg.KeyFile == "" {
		v.addError("server.tls.key_file is required when TLS is enabled")
	}
}

func (v *Validator) validateLogging(cfg LoggingConfig) {
	validLevels := map[string]bool{
		"debug": true, "info": true, "warn": true, "error": true,
	}
	if cfg.Level != "" && !validLevels[cfg.Level] {
		v.addError("logging.level must be one of: debug, info, warn, error")
	}

	validFormats := map[string]bool{
		"json": true, "text": true, "console": true,
	}
	if cfg.Format != "" && !validFormats[cfg.Format] {
		v.addError("logging.format must be one of: json, text, console")
	}
}

func (v *Validator) validateUpstream(cfg UpstreamConfig) {
	if cfg.URL == "" {
		v.addError("upstream.url is required in single mode")
		return
	}

	if _, err := url.Parse(cfg.URL); err != nil {
		v.addError("upstream.url is not a valid URL: %v", err)
	}

	if cfg.Timeout < 0 {
		v.addError("upstream.timeout cannot be negative")
	}
}

func (v *Validator) validateFederation(cfg FederationConfig) {
	if len(cfg.Origins) == 0 {
		v.addError("federation.origins cannot be empty in federation mode")
		return
	}

	seenIDs := make(map[string]bool)
	for i, origin := range cfg.Origins {
		v.validateOrigin(i, origin, seenIDs)
	}

	// Validate search strategy
	validStrategies := map[string]bool{
		"parallel": true, "sequential": true, "priority": true,
	}
	if cfg.SearchStrategy != "" && !validStrategies[cfg.SearchStrategy] {
		v.addError("federation.search_strategy must be one of: parallel, sequential, priority")
	}

	// Validate conflict strategy
	validConflict := map[string]bool{
		"first_wins": true, "priority": true, "merge": true,
		"namespace": true, "reject_duplicates": true,
	}
	if cfg.ConflictStrategy != "" && !validConflict[cfg.ConflictStrategy] {
		v.addError("federation.conflict_strategy must be one of: first_wins, priority, merge, namespace, reject_duplicates")
	}
}

func (v *Validator) validateOrigin(index int, origin OriginConfig, seenIDs map[string]bool) {
	prefix := fmt.Sprintf("federation.origins[%d]", index)

	if origin.ID == "" {
		v.addError("%s.id is required", prefix)
	} else if seenIDs[origin.ID] {
		v.addError("%s.id '%s' is duplicate", prefix, origin.ID)
	} else {
		seenIDs[origin.ID] = true
	}

	// Validate ID format
	if origin.ID != "" && !isValidID(origin.ID) {
		v.addError("%s.id '%s' contains invalid characters (must be alphanumeric with hyphens)", prefix, origin.ID)
	}

	if origin.BaseURL == "" {
		v.addError("%s.base_url is required", prefix)
	} else if _, err := url.Parse(origin.BaseURL); err != nil {
		v.addError("%s.base_url is not a valid URL: %v", prefix, err)
	}

	if origin.Timeout < 0 {
		v.addError("%s.timeout cannot be negative", prefix)
	}

	// Validate auth if present
	if origin.Auth != nil {
		v.validateOriginAuth(prefix, origin.Auth)
	}
}

func (v *Validator) validateOriginAuth(prefix string, auth *OriginAuthConfig) {
	validTypes := map[string]bool{
		"none": true, "basic": true, "bearer": true, "api_key": true,
		"oauth2": true, "aws_sigv4": true, "custom_headers": true,
	}

	if !validTypes[auth.Type] {
		v.addError("%s.auth.type is invalid: %s", prefix, auth.Type)
		return
	}

	switch auth.Type {
	case "basic":
		if auth.Username == "" || auth.Password == "" {
			v.addError("%s.auth requires username and password for basic auth", prefix)
		}
	case "bearer":
		if auth.Token == "" {
			v.addError("%s.auth requires token for bearer auth", prefix)
		}
	case "api_key":
		if auth.APIKeyHeader == "" || auth.APIKeyValue == "" {
			v.addError("%s.auth requires api_key_header and api_key_value", prefix)
		}
	case "oauth2":
		if auth.OAuth2 == nil {
			v.addError("%s.auth requires oauth2 config for oauth2 auth", prefix)
		} else {
			if auth.OAuth2.TokenURL == "" {
				v.addError("%s.auth.oauth2.token_url is required", prefix)
			}
			if auth.OAuth2.ClientID == "" {
				v.addError("%s.auth.oauth2.client_id is required", prefix)
			}
		}
	}
}

func (v *Validator) validateMiddleware(configs []MiddlewareConfig) {
	validMiddleware := map[string]bool{
		"logging": true, "auth": true, "authz": true, "cache": true,
		"rate_limit": true, "url_remap": true, "cors": true,
	}

	for i, mw := range configs {
		if !validMiddleware[mw.Name] {
			v.addWarning("middleware[%d].name '%s' is not a recognized middleware", i, mw.Name)
		}
	}
}

// isValidID checks if an ID is valid (alphanumeric with hyphens).
var validIDRegex = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9-]*$`)

func isValidID(id string) bool {
	return validIDRegex.MatchString(id)
}

// ValidateConfig validates a configuration and returns errors.
func ValidateConfig(cfg *Config) error {
	v := NewValidator()
	return v.Validate(cfg)
}

// MustValidate validates and panics on error.
func MustValidate(cfg *Config) {
	if err := ValidateConfig(cfg); err != nil {
		panic(err)
	}
}

// Quick validation helpers

// IsValidURL checks if a string is a valid URL.
func IsValidURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme != "" && u.Host != ""
}

// IsValidDuration checks if a duration is valid (non-negative).
func IsValidDuration(d time.Duration) bool {
	return d >= 0
}

// IsValidPort checks if a port number is valid.
func IsValidPort(port int) bool {
	return port >= 1 && port <= 65535
}

// ValidateRequiredString checks if a required string is present.
func ValidateRequiredString(name, value string) error {
	if value == "" {
		return errors.New(name + " is required")
	}
	return nil
}
