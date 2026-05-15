// Package config provides configuration loading and management.
package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the root configuration structure.
type Config struct {
	Server     ServerConfig       `yaml:"server"`
	Logging    LoggingConfig      `yaml:"logging"`
	Metrics    MetricsConfig      `yaml:"metrics"`
	Middleware []MiddlewareConfig `yaml:"middleware"`
	Mode       string             `yaml:"mode"` // "single" or "federation"
	Upstream   *UpstreamConfig    `yaml:"upstream"`
	Federation *FederationConfig  `yaml:"federation"`
	Health     HealthConfig       `yaml:"health"`
	Authz      *AuthzConfig       `yaml:"authz"`
}

// ServerConfig contains HTTP server settings.
type ServerConfig struct {
	Host     string        `yaml:"host"`
	Port     int           `yaml:"port"`
	TLS      TLSConfig     `yaml:"tls"`
	Timeouts TimeoutConfig `yaml:"timeouts"`
	// MaxBodyBytes caps inbound request body size. 0 → default
	// (1 MiB); negative disables the cap. Set higher when expecting
	// large GeoJSON intersects polygons on /search.
	MaxBodyBytes int64 `yaml:"max_body_bytes"`
	// TrustedProxies lists the CIDRs from which the proxy will honor
	// X-Forwarded-For when deriving the client IP for rate limiting,
	// logging, etc. The default empty list means XFF is ignored and
	// client IPs come from the TCP RemoteAddr — the safe default for
	// an internet-exposed listener. Deployments behind a load
	// balancer / CDN must list the immediate-upstream CIDRs here.
	TrustedProxies []string `yaml:"trusted_proxies"`
}

// TLSConfig contains TLS settings.
type TLSConfig struct {
	Enabled  bool   `yaml:"enabled"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// TimeoutConfig contains HTTP timeout settings.
type TimeoutConfig struct {
	Read  time.Duration `yaml:"read"`
	Write time.Duration `yaml:"write"`
	Idle  time.Duration `yaml:"idle"`
}

// LoggingConfig contains logging settings.
type LoggingConfig struct {
	Level  string `yaml:"level"`  // debug, info, warn, error
	Format string `yaml:"format"` // json, console
}

// MetricsConfig contains Prometheus metrics settings.
type MetricsConfig struct {
	Enabled bool   `yaml:"enabled"`
	Path    string `yaml:"path"`
	// BindAddr is the host:port the metrics server listens on. The
	// default `127.0.0.1:9090` keeps metrics on the loopback interface
	// so they aren't reachable from the public network. Operators
	// wanting LAN-wide scrape must set it explicitly (e.g.
	// `0.0.0.0:9090`) — typically only safe when the proxy runs in a
	// private subnet behind a firewall, or when paired with an
	// `auth_token` below.
	BindAddr string `yaml:"bind_addr"`
	// Port is retained for backward-compat config shape but is only
	// consulted when BindAddr is empty.
	Port int `yaml:"port"`
	// AuthToken, when set, is required as a Bearer token on /metrics
	// requests. Combined with a non-loopback BindAddr this gives a
	// minimum gate for cross-host scrape.
	AuthToken string `yaml:"auth_token"`
}

// HealthConfig contains health check settings.
type HealthConfig struct {
	Path string `yaml:"path"`
	// Verbose controls whether per-check `message` and `details`
	// fields are included in the JSON response. The default false
	// keeps `/health` responses generic so upstream URLs and error
	// strings don't leak topology to whoever can reach the endpoint.
	Verbose bool `yaml:"verbose"`
}

// MiddlewareConfig contains configuration for a single middleware.
type MiddlewareConfig struct {
	Name   string                 `yaml:"name"`
	Config map[string]interface{} `yaml:"config"`
}

// UpstreamConfig contains single-origin proxy settings.
type UpstreamConfig struct {
	URL     string        `yaml:"url"`
	Timeout time.Duration `yaml:"timeout"`

	// SupportsFilterExtension indicates whether the upstream STAC API
	// supports the Filter Extension (cql2-text / cql2-json). When true,
	// authz CQL2 filters and geofence S_INTERSECTS predicates are pushed
	// down to the upstream rather than enforced via response post-filter.
	SupportsFilterExtension bool `yaml:"supports_filter_extension"`

	// MaxResponseBytes caps the size in bytes of an upstream response
	// body consumed by the proxy. <= 0 means the default 32 MiB.
	MaxResponseBytes int64 `yaml:"max_response_bytes"`

	// AllowPrivateOrigin must be true to use a loopback / RFC 1918 /
	// link-local host in URL. Default false — required for dev/test
	// setups using httptest on 127.0.0.1; production deployments
	// should leave this unset to prevent SSRF-style misconfigurations.
	AllowPrivateOrigin bool `yaml:"allow_private_origin"`
}

// FederationConfig contains multi-origin federation settings.
type FederationConfig struct {
	Origins          []OriginConfig `yaml:"origins"`
	MaxConcurrent    int            `yaml:"max_concurrent"`
	AggregateTimeout time.Duration  `yaml:"aggregate_timeout"`
	ConflictStrategy string         `yaml:"conflict_strategy"` // first_wins, priority, merge, namespace
	DefaultPageSize  int            `yaml:"default_page_size"`
	MaxPageSize      int            `yaml:"max_page_size"`

	// AllowPrivateOrigins must be true to register origins whose
	// BaseURL hosts resolve to loopback / RFC 1918 / link-local
	// addresses. Default false. Required for dev/test deployments
	// with httptest origins; production deployments should leave
	// this unset to prevent SSRF-style misconfigurations.
	AllowPrivateOrigins bool `yaml:"allow_private_origins"`

	// CursorSecret is the HMAC key used to sign federation cursors.
	// Required in federation mode — minted cursors are unsigned (and
	// therefore tamperable) without it. Inject from a secrets manager
	// rather than checking in the YAML.
	CursorSecret string `yaml:"cursor_secret"`
}

// OriginConfig contains configuration for a single upstream STAC server.
type OriginConfig struct {
	// Identity
	ID          string `yaml:"id"`
	Name        string `yaml:"name"`
	Description string `yaml:"description"`

	// Connection
	BaseURL string        `yaml:"base_url"`
	Enabled bool          `yaml:"enabled"`
	Timeout time.Duration `yaml:"timeout"`
	Retry   *RetryConfig  `yaml:"retry"`

	// Authentication for this downstream server
	Auth *OriginAuthConfig `yaml:"auth"`

	// Collection routing
	Collections        []string `yaml:"collections"`
	ExcludeCollections []string `yaml:"exclude_collections"`

	// Behavior
	Priority   int  `yaml:"priority"`
	ReadOnly   bool `yaml:"read_only"`
	Searchable bool `yaml:"searchable"`

	// Collection discovery
	AutoDiscover      bool          `yaml:"auto_discover"`
	DiscoveryInterval time.Duration `yaml:"discovery_interval"`

	// Transformations
	CollectionPrefix  string            `yaml:"collection_prefix"`
	CollectionMapping map[string]string `yaml:"collection_mapping"`
	StripPathPrefix   string            `yaml:"strip_path_prefix"`

	// SupportsFilterExtension indicates whether this origin's STAC API
	// supports the Filter Extension. When true, the authz middleware
	// pushes CQL2 predicates (including geofence S_INTERSECTS) into the
	// search request; when false, the post-filter path stays responsible
	// for enforcement.
	SupportsFilterExtension bool `yaml:"supports_filter_extension"`

	// MaxResponseBytes caps the size in bytes of an upstream response
	// body consumed by the federation origin client. <= 0 means the
	// default 32 MiB.
	MaxResponseBytes int64 `yaml:"max_response_bytes"`

	// ForwardUserIdentity controls whether the inbound client's
	// Authorization / Cookie / X-API-Key headers are forwarded to
	// this origin. Default false (strip). Set to true ONLY for
	// origins that specifically expect OIDC-token-pass-through, and
	// only when the confused-deputy risk is understood.
	ForwardUserIdentity bool `yaml:"forward_user_identity"`

	// RewriteAssets controls how `assets[*].href` is rewritten in
	// responses from this origin. One of:
	//   ""      — same as "never" (default; current behavior).
	//   "never" — asset hrefs pass through unchanged.
	//   "sign"  — the asset href is HMAC-signed via the remap signer
	//             so direct fetches must carry a valid signature.
	//   "proxy" — the asset href is replaced with a proxy URL of the
	//             form {proxy_base_url}/assets/{origin_id}/{base64url-href}
	//             that streams the asset bytes through the proxy with
	//             the same auth/authz/ratelimit chain as STAC requests.
	RewriteAssets string `yaml:"rewrite_assets"`

	// AssetSignTTL is the TTL applied when RewriteAssets == "sign".
	// Defaults to 15 minutes when zero.
	AssetSignTTL time.Duration `yaml:"asset_sign_ttl"`
}

// RetryConfig contains retry policy settings.
type RetryConfig struct {
	MaxRetries     int           `yaml:"max_retries"`
	InitialBackoff time.Duration `yaml:"initial_backoff"`
	MaxBackoff     time.Duration `yaml:"max_backoff"`
	RetryOn        []int         `yaml:"retry_on"` // HTTP status codes to retry
}

// OriginAuthConfig contains authentication config for an upstream origin.
type OriginAuthConfig struct {
	Type string `yaml:"type"` // none, basic, bearer, api_key, oauth2, aws_sigv4, custom

	// Basic Auth
	Username string `yaml:"username"`
	Password string `yaml:"password"`

	// Bearer Token (static)
	Token string `yaml:"token"`

	// API Key
	APIKeyHeader  string `yaml:"api_key_header"`
	APIKeyValue   string `yaml:"api_key_value"`
	APIKeyInQuery bool   `yaml:"api_key_in_query"`

	// OAuth2 Client Credentials Flow
	OAuth2 *OAuth2Config `yaml:"oauth2"`

	// AWS Signature V4
	AWSSigV4 *AWSSigV4Config `yaml:"aws_sig_v4"`

	// Custom header injection
	CustomHeaders map[string]string `yaml:"custom_headers"`

	// mTLS client certificate
	ClientCert *ClientCertConfig `yaml:"client_cert"`
}

// OAuth2Config contains OAuth2 client credentials settings.
type OAuth2Config struct {
	TokenURL     string   `yaml:"token_url"`
	ClientID     string   `yaml:"client_id"`
	ClientSecret string   `yaml:"client_secret"`
	Scopes       []string `yaml:"scopes"`
	Audience     string   `yaml:"audience"`
}

// AWSSigV4Config contains AWS Signature V4 settings.
type AWSSigV4Config struct {
	Region     string `yaml:"region"`
	Service    string `yaml:"service"`
	AccessKey  string `yaml:"access_key"`
	SecretKey  string `yaml:"secret_key"`
	UseIAMRole bool   `yaml:"use_iam_role"`
}

// ClientCertConfig contains mTLS client certificate settings.
type ClientCertConfig struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	CAFile   string `yaml:"ca_file"`
}

// AuthConfig contains client-facing authentication settings.
type AuthConfig struct {
	AllowAnonymous bool                 `yaml:"allow_anonymous"`
	Providers      []AuthProviderConfig `yaml:"providers"`
}

// AuthProviderConfig contains settings for an auth provider.
type AuthProviderConfig struct {
	Type string `yaml:"type"` // bearer, api_key, oauth2, oidc, basic, mtls

	// Bearer/JWT
	JWKSUrl  string `yaml:"jwks_url"`
	Issuer   string `yaml:"issuer"`
	Audience string `yaml:"audience"`

	// API Key
	Header   string `yaml:"header"`
	KeysFile string `yaml:"keys_file"`

	// OIDC
	DiscoveryURL string `yaml:"discovery_url"`
}

// AuthzConfig contains authorization settings.
type AuthzConfig struct {
	OPA           *OPAConfig           `yaml:"opa"`
	CQL2Injection *CQL2InjectionConfig `yaml:"cql2_injection"`
}

// CQL2InjectionConfig controls the CQL2 filter-injection middleware
// behaviour. When enabled, CQL2 expressions emitted by the policy
// engine (and geofence push-down predicates) are AND-combined with any
// client-supplied filter and forwarded to the upstream STAC API.
type CQL2InjectionConfig struct {
	// Enabled gates the whole feature; default false.
	Enabled bool `yaml:"enabled"`

	// Combine controls how policy and client filters are combined.
	// Only "and" is supported today; the field is reserved for future
	// strategies (e.g. "or", "replace").
	Combine string `yaml:"combine"`
}

// OPAConfig contains Open Policy Agent settings.
type OPAConfig struct {
	// External OPA server mode
	URL        string `yaml:"url"`
	PolicyPath string `yaml:"policy_path"`

	// Embedded OPA mode
	Embedded           bool          `yaml:"embedded"`
	BundleURL          string        `yaml:"bundle_url"`
	BundlePollInterval time.Duration `yaml:"bundle_poll_interval"`
	RegoFiles          []string      `yaml:"rego_files"`
	DataFiles          []string      `yaml:"data_files"`

	// Performance
	Timeout        time.Duration `yaml:"timeout"`
	CacheDecisions bool          `yaml:"cache_decisions"`
	CacheTTL       time.Duration `yaml:"cache_ttl"`
}

// CacheConfig contains caching settings.
type CacheConfig struct {
	Store         string        `yaml:"store"` // memory, redis
	RedisURL      string        `yaml:"redis_url"`
	CollectionTTL time.Duration `yaml:"collection_ttl"`
	ItemTTL       time.Duration `yaml:"item_ttl"`
	SearchTTL     time.Duration `yaml:"search_ttl"`
	MaxSize       int           `yaml:"max_size"` // For memory cache
}

// RateLimitConfig contains rate limiting settings.
type RateLimitConfig struct {
	DefaultQuota QuotaConfig            `yaml:"default_quota"`
	QuotasByRole map[string]QuotaConfig `yaml:"quotas_by_role"`
	Burst        int                    `yaml:"burst"`
}

// QuotaConfig contains quota settings.
type QuotaConfig struct {
	Requests int           `yaml:"requests"`
	Window   time.Duration `yaml:"window"`
}

// RemapConfig contains URL remapping settings.
type RemapConfig struct {
	Rules []RemapRuleConfig `yaml:"rules"`
}

// RemapRuleConfig contains a single remap rule.
type RemapRuleConfig struct {
	Match   string        `yaml:"match"`
	Replace string        `yaml:"replace"`
	Sign    bool          `yaml:"sign"`
	SignTTL time.Duration `yaml:"sign_ttl"`
}

// Load reads configuration from a file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Expand environment variables. Unlike os.ExpandEnv, we treat
	// undefined references as a configuration error rather than
	// silently expanding to "" — a YAML containing ${MISSING_SECRET}
	// otherwise reads as "configured" with an empty value and slips
	// past validation. Shell-style ${VAR:-default} provides an
	// explicit opt-out for genuinely optional fields.
	expanded, err := expandEnvStrict(string(data))
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	data = []byte(expanded)

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Set defaults
	cfg.setDefaults()

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return &cfg, nil
}

// expandEnvStrict performs ${VAR} / $VAR substitution like
// os.ExpandEnv, with two semantic differences:
//
//   - References to unset environment variables produce an error
//     rather than expanding to "". This catches configs where a
//     required secret was forgotten — without the strict check, the
//     YAML would parse as if the field were set to "" and downstream
//     validation would happily accept the empty string as
//     "configured".
//
//   - Shell-style ${VAR:-default} returns "default" when VAR is
//     unset (or set to ""), giving operators an explicit way to
//     declare a fallback for genuinely optional fields.
//
// All undefined references are collected before returning so the
// operator gets a single error listing every missing variable, not
// one-error-per-load-attempt.
func expandEnvStrict(s string) (string, error) {
	var missing []string
	out := os.Expand(s, func(name string) string {
		// ${VAR:-default}: name == "VAR:-default"
		if idx := strings.Index(name, ":-"); idx >= 0 {
			varName := name[:idx]
			fallback := name[idx+2:]
			if v, ok := os.LookupEnv(varName); ok && v != "" {
				return v
			}
			return fallback
		}
		if v, ok := os.LookupEnv(name); ok {
			return v
		}
		missing = append(missing, name)
		return ""
	})
	if len(missing) > 0 {
		return "", fmt.Errorf("undefined environment variable(s) referenced in config: %s (use ${VAR:-default} to provide a fallback)",
			strings.Join(missing, ", "))
	}
	return out, nil
}

// setDefaults sets default values for optional fields.
func (c *Config) setDefaults() {
	if c.Server.Host == "" {
		c.Server.Host = "0.0.0.0"
	}
	if c.Server.Port == 0 {
		c.Server.Port = 8080
	}
	if c.Server.Timeouts.Read == 0 {
		c.Server.Timeouts.Read = 30 * time.Second
	}
	if c.Server.Timeouts.Write == 0 {
		c.Server.Timeouts.Write = 60 * time.Second
	}
	if c.Server.Timeouts.Idle == 0 {
		c.Server.Timeouts.Idle = 120 * time.Second
	}
	if c.Logging.Level == "" {
		c.Logging.Level = "info"
	}
	if c.Logging.Format == "" {
		c.Logging.Format = "json"
	}
	if c.Health.Path == "" {
		c.Health.Path = "/health"
	}
	if c.Mode == "" {
		c.Mode = "single"
	}
	if c.Federation != nil {
		if c.Federation.MaxConcurrent == 0 {
			c.Federation.MaxConcurrent = 10
		}
		if c.Federation.AggregateTimeout == 0 {
			c.Federation.AggregateTimeout = 60 * time.Second
		}
		if c.Federation.ConflictStrategy == "" {
			c.Federation.ConflictStrategy = "priority"
		}
		if c.Federation.DefaultPageSize == 0 {
			c.Federation.DefaultPageSize = 100
		}
		if c.Federation.MaxPageSize == 0 {
			c.Federation.MaxPageSize = 1000
		}
		for i := range c.Federation.Origins {
			if c.Federation.Origins[i].Timeout == 0 {
				c.Federation.Origins[i].Timeout = 30 * time.Second
			}
		}
	}
}

// Validate checks the configuration for errors.
func (c *Config) Validate() error {
	// Use the comprehensive validator for thorough validation
	return ValidateConfig(c)
}

// IsFederation returns true if running in federation mode.
func (c *Config) IsFederation() bool {
	return c.Mode == "federation"
}

// GetOrigin returns an origin config by ID.
func (c *Config) GetOrigin(id string) *OriginConfig {
	if c.Federation == nil {
		return nil
	}
	for i := range c.Federation.Origins {
		if c.Federation.Origins[i].ID == id {
			return &c.Federation.Origins[i]
		}
	}
	return nil
}
