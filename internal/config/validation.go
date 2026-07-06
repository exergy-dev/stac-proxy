// Package config provides configuration management.
package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
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

	if cfg.PublicBaseURL != "" {
		v.validatePublicBaseURL(cfg.PublicBaseURL)
	}
}

func (v *Validator) validatePublicBaseURL(raw string) {
	u, err := url.Parse(raw)
	if err != nil {
		v.addError("server.public_base_url is not a valid URL: %v", err)
		return
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		v.addError("server.public_base_url scheme must be http or https, got %q", u.Scheme)
	}
	if u.Host == "" {
		v.addError("server.public_base_url must include a host")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		v.addError("server.public_base_url must not include a query or fragment")
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

	if u, err := url.Parse(cfg.URL); err != nil {
		v.addError("upstream.url is not a valid URL: %v", err)
	} else {
		v.validateOriginURL("upstream", u, cfg.AllowPrivateOrigin)
	}

	if cfg.Timeout < 0 {
		v.addError("upstream.timeout cannot be negative")
	}

	if cfg.MaxResponseBytes < 0 {
		v.addError("upstream.max_response_bytes cannot be negative")
	} else if cfg.MaxResponseBytes > 1<<30 {
		v.addWarning("upstream.max_response_bytes is very large (%d bytes; over 1 GiB)", cfg.MaxResponseBytes)
	}
}

func (v *Validator) validateFederation(cfg FederationConfig) {
	if len(cfg.Origins) == 0 {
		v.addError("federation.origins cannot be empty in federation mode")
		return
	}

	seenIDs := make(map[string]bool)
	for i, origin := range cfg.Origins {
		v.validateOrigin(i, origin, seenIDs, cfg.AllowPrivateOrigins)
	}

	// Federated pagination cursors are HMAC-signed. In federation mode
	// the paginated searcher is always wired (NewPaginatedSearcher
	// rejects an empty key), so a missing secret means paginated search
	// silently fails at request time. Hard-fail at load instead. Single
	// mode does not engage the cursor path (buildSingleOriginAsFederation
	// passes no CursorSecret), so this is only required here.
	if strings.TrimSpace(cfg.CursorSecret) == "" {
		v.addError("federation.cursor_secret is required in federation mode; paginated search cannot sign cursors without it. Generate one with `openssl rand -hex 32` and inject it from your secrets manager (identical across all replicas).")
	}

	if cfg.PageCache != nil {
		if cfg.PageCache.MaxEntries < 0 {
			v.addError("federation.page_cache.max_entries cannot be negative")
		}
		if cfg.PageCache.TTL < 0 {
			v.addError("federation.page_cache.ttl cannot be negative")
		}
		if cfg.PageCache.Enabled != nil && *cfg.PageCache.Enabled && cfg.CursorSecret == "" {
			v.addError("federation.page_cache.enabled is true but federation.cursor_secret is empty; the cache has no cursors to key by")
		}
	}
}

func (v *Validator) validateOrigin(index int, origin OriginConfig, seenIDs map[string]bool, allowPrivate bool) {
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
	} else if u, err := url.Parse(origin.BaseURL); err != nil {
		v.addError("%s.base_url is not a valid URL: %v", prefix, err)
	} else {
		v.validateOriginURL(prefix+".base_url", u, allowPrivate)
	}

	if origin.Timeout < 0 {
		v.addError("%s.timeout cannot be negative", prefix)
	}

	if origin.MaxResponseBytes < 0 {
		v.addError("%s.max_response_bytes cannot be negative", prefix)
	} else if origin.MaxResponseBytes > 1<<30 {
		v.addWarning("%s.max_response_bytes is very large (%d bytes; over 1 GiB)", prefix, origin.MaxResponseBytes)
	}

	// Validate rewrite_assets enum. The empty string is treated as
	// "never" (default) and accepted; everything else must match one
	// of the three modes documented on OriginConfig.RewriteAssets.
	switch origin.RewriteAssets {
	case "", "never", "sign", "proxy":
	default:
		v.addError("%s.rewrite_assets %q is not one of: never, sign, proxy",
			prefix, origin.RewriteAssets)
	}
	if origin.AssetSignTTL < 0 {
		v.addError("%s.asset_sign_ttl cannot be negative", prefix)
	}

	// Validate pagination adapter enum (empty = "auto" default).
	if origin.Pagination != nil {
		switch origin.Pagination.Adapter {
		case "", "auto", "token", "next_url", "offset", "link_header":
		default:
			v.addError("%s.pagination.adapter %q is not one of: auto, token, next_url, offset, link_header",
				prefix, origin.Pagination.Adapter)
		}
	}

	// Validate auth if present
	if origin.Auth != nil {
		v.validateOriginAuth(prefix, origin.Auth)
	}
}

// validateOriginURL enforces scheme (http/https only) and rejects
// loopback / RFC 1918 / link-local hosts unless allowPrivate is true.
// Hostnames that are not literal IPs (e.g. example.com) are accepted
// as-is; operators are trusted to manage their DNS.
func (v *Validator) validateOriginURL(field string, u *url.URL, allowPrivate bool) {
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		v.addError("%s scheme must be http or https, got %q", field, u.Scheme)
		return
	}

	host := u.Hostname()
	if host == "" {
		return
	}

	if !allowPrivate {
		lowerHost := strings.ToLower(host)
		if lowerHost == "localhost" {
			v.addError("%s host %q is loopback; set allow_private_origin(s) = true for dev/test", field, host)
			return
		}

		if ip := net.ParseIP(host); ip != nil {
			switch {
			case ip.IsLoopback():
				v.addError("%s host %q is loopback; set allow_private_origin(s) = true for dev/test", field, host)
			case ip.IsPrivate():
				v.addError("%s host %q is in a private RFC 1918 range; set allow_private_origin(s) = true for dev/test", field, host)
			case ip.IsLinkLocalUnicast():
				v.addError("%s host %q is link-local; set allow_private_origin(s) = true for dev/test", field, host)
			}
		}
	}
}

func (v *Validator) validateOriginAuth(prefix string, auth *OriginAuthConfig) {
	// `custom_headers` is intentionally NOT a `type` value — it's a
	// per-origin field (`OriginAuthConfig.CustomHeaders`) consumed by
	// the `custom` provider. Listing it here let invalid configs pass
	// validation and then silently no-op at the federation layer.
	validTypes := map[string]bool{
		"none": true, "basic": true, "bearer": true, "api_key": true,
		"oauth2": true, "aws_sigv4": true, "custom": true,
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
			// Promoted from warning to error: a typo'd middleware name
			// silently no-ops, which historically meant authz/ratelimit
			// could be disabled in production by a hyphen-vs-underscore
			// slip. Hard-fail validation so misconfigs surface at boot.
			v.addError("middleware[%d].name '%s' is not a recognized middleware (valid: auth, authz, cache, cors, logging, rate_limit, url_remap)", i, mw.Name)
			continue
		}
		switch mw.Name {
		case "cors":
			v.validateCorsMiddleware(i, mw.Config)
		case "cache":
			v.validateCacheMiddleware(i, mw.Config)
		}
	}
}

// validateCorsMiddleware enforces CORS-specific rules that would
// otherwise only surface at request time (or be silently misconfigured).
// The spec forbids the combination of credentials + wildcard origin —
// rejecting at validation time means a bad config fails at boot rather
// than producing a "looks fine" deployment that browsers silently
// refuse.
func (v *Validator) validateCorsMiddleware(idx int, cfg map[string]interface{}) {
	if cfg == nil {
		return
	}
	allowCreds := false
	if b, ok := cfg["allow_credentials"].(bool); ok {
		allowCreds = b
	}
	origins, ok := cfg["allowed_origins"]
	if !ok || origins == nil {
		return
	}
	list, ok := origins.([]interface{})
	if !ok {
		// Allow []string too (some YAML decoders produce it directly).
		if _, ok := origins.([]string); ok {
			return
		}
		v.addError("middleware[%d] cors: allowed_origins must be a list", idx)
		return
	}
	hasWildcard := false
	for j, item := range list {
		s, ok := item.(string)
		if !ok {
			v.addError("middleware[%d] cors: allowed_origins[%d] must be a string", idx, j)
			continue
		}
		if s == "*" {
			hasWildcard = true
		}
	}
	if allowCreds && hasWildcard {
		v.addError("middleware[%d] cors: allow_credentials cannot be true with wildcard allowed_origins '*'", idx)
	}
}

// validateCacheMiddleware rejects unsupported cache stores at config
// load time. Without this, a config with `store: redis` parses fine and
// the proxy boots, then errors on the first request — a much worse
// failure mode than a clean startup error.
func (v *Validator) validateCacheMiddleware(idx int, cfg map[string]interface{}) {
	if cfg == nil {
		return
	}
	store, ok := cfg["store"].(string)
	if !ok || store == "" {
		return
	}
	if store != "memory" {
		v.addError("middleware[%d] cache: store %q is not supported; only \"memory\" is available", idx, store)
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
