// Package config provides configuration management.
package config

import (
	"fmt"
	"net"
	"net/netip"
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
	v.validateMiddleware(cfg)

	// Validate the shared Redis block (and its cross-references from
	// components that select `store: redis`).
	v.validateRedis(cfg)

	// Cross-check: signed asset rewriting needs a signing secret.
	v.validateAssetSigning(cfg)

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

	// A negative header cap is meaningless: net/http treats
	// MaxHeaderBytes <= 0 as its 1 MiB default, silently undoing the
	// tighter limit the operator intended. Reject it at load.
	if cfg.MaxHeaderBytes < 0 {
		v.addError("server.max_header_bytes cannot be negative")
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

	v.validateClientIP(cfg.ClientIP)
}

// validateClientIP checks the client-IP trust model. Invalid CIDRs are
// a boot error here rather than a router-construction panic (chi's
// ClientIPFromXFF panics on bad prefixes).
func (v *Validator) validateClientIP(cfg ClientIPConfig) {
	switch cfg.Source {
	case "", "remote_addr":
		if cfg.Header != "" {
			v.addWarning("server.client_ip.header is set but source is remote_addr; it will be ignored")
		}
		if len(cfg.TrustedProxies) > 0 {
			v.addWarning("server.client_ip.trusted_proxies is set but source is remote_addr; it will be ignored")
		}
	case "header":
		if cfg.Header == "" {
			v.addError("server.client_ip.header is required when source is 'header' (e.g. CF-Connecting-IP behind Cloudflare, X-Real-IP behind nginx realip)")
		}
	case "xff":
		for _, p := range cfg.TrustedProxies {
			if _, err := netip.ParsePrefix(p); err != nil {
				v.addError("server.client_ip.trusted_proxies entry %q is not a valid CIDR prefix: %v", p, err)
			}
		}
		if len(cfg.TrustedProxies) == 0 {
			v.addWarning("server.client_ip source 'xff' with no trusted_proxies uses the rightmost X-Forwarded-For entry; only safe with exactly one trusted hop directly in front")
		}
	case "xff_trusted_count":
		if cfg.TrustedCount < 1 {
			v.addError("server.client_ip.trusted_count must be >= 1 when source is 'xff_trusted_count'")
		}
	default:
		v.addError("server.client_ip.source must be one of: remote_addr, header, xff, xff_trusted_count; got %q", cfg.Source)
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

// minCursorSecretLen is the minimum accepted cursor_secret length.
// 16 characters is a floor against outright-guessable keys, not a
// strength guarantee — the docs steer operators to 64 hex chars.
const minCursorSecretLen = 16

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
	if secret := strings.TrimSpace(cfg.CursorSecret); secret == "" {
		v.addError("federation.cursor_secret is required in federation mode; paginated search cannot sign cursors without it. Generate one with `openssl rand -hex 32` and inject it from your secrets manager (identical across all replicas).")
	} else if len(secret) < minCursorSecretLen {
		// An HMAC key this short is guessable — a forged cursor means
		// forged pagination state. Refuse at boot rather than sign
		// with it.
		v.addError("federation.cursor_secret is too short (%d chars, need >= %d); generate one with `openssl rand -hex 32`", len(secret), minCursorSecretLen)
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
		switch cfg.PageCache.Store {
		case "", "memory", "redis":
			// "redis" additionally requires the top-level redis block —
			// checked in validateRedis, which sees the whole Config.
		default:
			v.addError("federation.page_cache.store %q is not supported; valid stores: memory, redis", cfg.PageCache.Store)
		}
	}
}

func (v *Validator) validateOrigin(index int, origin OriginConfig, seenIDs map[string]bool, allowPrivate bool) {
	prefix := fmt.Sprintf("federation.origins[%d]", index)

	if cb := origin.CircuitBreaker; cb != nil {
		if cb.FailureThreshold < 0 {
			v.addError("%s.circuit_breaker.failure_threshold cannot be negative", prefix)
		}
		if cb.HalfOpenProbes < 0 {
			v.addError("%s.circuit_breaker.half_open_probes cannot be negative", prefix)
		}
		if cb.OpenDuration < 0 || cb.MaxOpenDuration < 0 {
			v.addError("%s.circuit_breaker durations cannot be negative", prefix)
		}
		if cb.OpenDuration > 0 && cb.MaxOpenDuration > 0 && cb.MaxOpenDuration < cb.OpenDuration {
			v.addError("%s.circuit_breaker.max_open_duration cannot be smaller than open_duration", prefix)
		}
	}

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

func (v *Validator) validateMiddleware(cfg *Config) {
	validMiddleware := map[string]bool{
		"logging": true, "auth": true, "authz": true, "cache": true,
		"rate_limit": true, "url_remap": true, "cors": true,
	}

	for i, mw := range cfg.Middleware {
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
			v.validateStoreSelector("cache", i, mw.Config, cfg)
		case "rate_limit":
			v.validateRateLimitMiddleware(i, mw.Config, cfg)
		}
	}
}

// validateRateLimitMiddleware checks the store selector (see
// validateStoreSelector) and the failure_mode knob (open/closed; only
// meaningful with redis, since the in-memory limiter cannot fail).
func (v *Validator) validateRateLimitMiddleware(idx int, mwCfg map[string]interface{}, cfg *Config) {
	store := v.validateStoreSelector("rate_limit", idx, mwCfg, cfg)
	if mwCfg == nil {
		return
	}
	if fm, ok := mwCfg["failure_mode"]; ok {
		s, _ := fm.(string)
		switch s {
		case "open", "closed":
			if store != "redis" {
				v.addWarning("middleware[%d] rate_limit: failure_mode has no effect without store: redis (the in-memory limiter cannot fail)", idx)
			}
		default:
			v.addError("middleware[%d] rate_limit: failure_mode %q is not supported; valid modes: open, closed", idx, fm)
		}
	}
}

// StoreSelection reads the `store` key of a middleware config block.
// Returns "" when absent (meaning the component default, memory).
// Exported because main.go's builders make the same read when wiring
// the shared Redis client — one accessor owns the key name and the
// empty-means-memory defaulting.
func StoreSelection(cfg map[string]interface{}) string {
	if cfg == nil {
		return ""
	}
	s, _ := cfg["store"].(string)
	return s
}

// validateRedis checks the shared `redis:` block and warns when it is
// configured but no component selects `store: redis` (dead config is a
// likely operator mistake — they meant to flip a component over).
// Component-side "store: redis without a redis block" errors live with
// each component's validator so messages carry the middleware index.
func (v *Validator) validateRedis(cfg *Config) {
	if cfg.Redis == nil {
		// The cache middleware's equivalent cross-check lives in
		// validateStoreSelector (it has the middleware index for the
		// message); the page cache's lives here because
		// validateFederation only sees the federation subtree.
		if cfg.Federation != nil && cfg.Federation.PageCache != nil &&
			cfg.Federation.PageCache.Store == "redis" {
			v.addError("federation.page_cache.store \"redis\" requires the top-level redis block")
		}
		return
	}
	r := cfg.Redis
	if strings.TrimSpace(r.Addr) == "" {
		v.addError("redis.addr is required when the redis block is present")
	}
	if r.DB < 0 {
		v.addError("redis.db must be >= 0")
	}
	if r.PoolSize < 0 || r.MinIdleConns < 0 {
		v.addError("redis pool_size and min_idle_conns must be >= 0")
	}
	if r.DialTimeout < 0 || r.ReadTimeout < 0 || r.WriteTimeout < 0 {
		v.addError("redis timeouts must be >= 0")
	}
	if r.TLS.Enabled && (r.TLS.CertFile == "") != (r.TLS.KeyFile == "") {
		v.addError("redis.tls cert_file and key_file must be set together")
	}
	if !cfg.SelectsRedis() {
		v.addWarning("redis block is configured but no component selects store: redis — the connection will not be used")
	}
}

// validateAssetSigning hard-fails when any origin opts into
// `rewrite_assets: sign` but no url_remap signing secret exists.
// Previously this silently fell back to unsigned passthrough at
// request time (main.go's buildAssetSigner returns nil) — a config
// that promises gated asset URLs and quietly doesn't deliver them.
func (v *Validator) validateAssetSigning(cfg *Config) {
	if cfg.Federation == nil {
		return
	}
	var signers []string
	for _, o := range cfg.Federation.Origins {
		if o.RewriteAssets == "sign" {
			signers = append(signers, o.ID)
		}
	}
	if len(signers) == 0 {
		return
	}
	for _, mw := range cfg.Middleware {
		if mw.Name == "url_remap" {
			if s, _ := mw.Config["secret"].(string); strings.TrimSpace(s) != "" {
				return
			}
		}
	}
	v.addError("origins %s set rewrite_assets: sign, but no url_remap middleware with a non-empty `secret` is configured — asset URLs would silently be emitted unsigned. Add the url_remap secret or switch the origins to rewrite_assets: proxy/none.", strings.Join(signers, ", "))
}

// SelectsRedis reports whether any component opted into the shared
// Redis backend (cache / rate_limit middleware `store: redis`, or
// federation.page_cache.store). Single source of truth for the
// consumer list — used by validation (unused-block warning) and by
// main.go to decide whether to build the shared client; a new Redis
// consumer must only be added here.
func (c *Config) SelectsRedis() bool {
	for _, mw := range c.Middleware {
		if mw.Name == "cache" || mw.Name == "rate_limit" {
			if StoreSelection(mw.Config) == "redis" {
				return true
			}
		}
	}
	return c.Federation != nil && c.Federation.PageCache != nil &&
		c.Federation.PageCache.Store == "redis"
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

// validateStoreSelector rejects unsupported `store:` selections at
// config load time. Without this, a bogus store parses fine and the
// proxy boots, then errors on the first request — a much worse
// failure mode than a clean startup error. `store: redis`
// additionally requires the top-level `redis:` block. Returns the
// selected store so callers can layer component-specific checks.
func (v *Validator) validateStoreSelector(component string, idx int, mwCfg map[string]interface{}, cfg *Config) string {
	store := StoreSelection(mwCfg)
	switch store {
	case "", "memory":
	case "redis":
		if cfg.Redis == nil {
			v.addError("middleware[%d] %s: store \"redis\" requires the top-level redis block", idx, component)
		}
	default:
		v.addError("middleware[%d] %s: store %q is not supported; valid stores: memory, redis", idx, component, store)
	}
	return store
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
