// Package main is the entry point for stac-proxy.
package main

import (
	"context"
	"crypto/x509"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/yourorg/stac-proxy/internal/config"
	"github.com/yourorg/stac-proxy/internal/federation"
	"github.com/yourorg/stac-proxy/internal/federation/pagecache"
	"github.com/yourorg/stac-proxy/internal/middleware"
	"github.com/yourorg/stac-proxy/internal/middleware/auth"
	"github.com/yourorg/stac-proxy/internal/middleware/authz"
	"github.com/yourorg/stac-proxy/internal/middleware/cache"
	"github.com/yourorg/stac-proxy/internal/middleware/cors"
	"github.com/yourorg/stac-proxy/internal/middleware/logging"
	"github.com/yourorg/stac-proxy/internal/middleware/ratelimit"
	"github.com/yourorg/stac-proxy/internal/middleware/remap"
	"github.com/yourorg/stac-proxy/internal/observability"
	"github.com/yourorg/stac-proxy/internal/server"
	"github.com/yourorg/stac-proxy/internal/stac"
	redisstore "github.com/yourorg/stac-proxy/internal/store/redis"

	"github.com/redis/go-redis/v9"
)

// Build-time identity. Overridden via -ldflags "-X main.version=...
// -X main.commit=... -X main.date=...". See Makefile / Dockerfile.
var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	// Parse command line flags
	configPath := flag.String("config", "config.yaml", "Path to configuration file")
	showVersion := flag.Bool("version", false, "Show version and exit")
	validateOnly := flag.Bool("validate", false, "Validate configuration and exit")
	healthcheck := flag.Bool("healthcheck", false, "Probe local /health and exit 0/1 (for container HEALTHCHECK)")
	healthAddr := flag.String("healthcheck-addr", "http://127.0.0.1:8080/health", "URL the --healthcheck probe hits")
	flag.Parse()

	if *showVersion {
		fmt.Printf("stac-proxy %s (commit=%s built=%s)\n", version, commit, date)
		os.Exit(0)
	}

	if *healthcheck {
		// If the operator left --healthcheck-addr at its default and
		// --config points at a real file, derive the URL from
		// cfg.Server.Port so the probe hits the right port without
		// needing the flag to be repeated. Failure to load the
		// config is non-fatal here: fall back to the default URL.
		addr := *healthAddr
		if isFlagDefault(addr, "http://127.0.0.1:8080/health") && *configPath != "" {
			if cfg, err := config.Load(*configPath); err == nil && cfg.Server.Port != 0 {
				addr = fmt.Sprintf("http://127.0.0.1:%d/health", cfg.Server.Port)
			}
		}
		os.Exit(runHealthcheck(addr))
	}

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	// Validate configuration
	if err := config.ValidateConfig(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Configuration validation failed: %v\n", err)
		os.Exit(1)
	}

	if *validateOnly {
		fmt.Println("Configuration is valid")
		os.Exit(0)
	}

	// Initialize logger based on config
	logger := initLogger(cfg.Logging)

	// Publish the configured logger as the slog default so package-level
	// code (federation per-origin loggers, etc.) can call slog.Info /
	// slog.Error without requiring DI.
	slog.SetDefault(logger)

	logger.Info("Starting stac-proxy",
		"version", version,
		"commit", commit,
		"mode", cfg.Mode,
	)

	// Parent context, cancelled by SIGINT/SIGTERM. run() observes
	// cancellation and calls the HTTP server's Shutdown so in-flight
	// requests drain within ShutdownTimeout.
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := run(ctx, cfg, logger); err != nil && err != http.ErrServerClosed {
		logger.Error("Server error", "error", err)
		os.Exit(1)
	}
	logger.Info("Shutdown complete")
}

// shutdownTimeout is how long run() will wait for in-flight requests
// to complete before forcing the HTTP server closed.
const shutdownTimeout = 30 * time.Second

// run starts the proxy server.
func run(ctx context.Context, cfg *config.Config, logger *slog.Logger) error {
	// Initialize health checker. Checks are appended as origins are
	// built; the underlying alexliesenfeld/health.Checker is lazily
	// constructed on first request to /health.
	healthChecker := observability.NewHealthChecker()

	// Shared Redis client — built only when some component selects
	// `store: redis`. main owns the client lifecycle; the per-store
	// wrappers' Close() are no-ops.
	redisClient, err := buildRedisClient(ctx, cfg, logger)
	if err != nil {
		return fmt.Errorf("failed to build redis client: %w", err)
	}
	if redisClient != nil {
		defer func() {
			if err := redisClient.Close(); err != nil {
				logger.Warn("redis client close error", "error", err)
			}
		}()
	}

	// Build the federation handler. Single-origin mode is modeled as a
	// federation-of-1 — the single-origin code path collapses into
	// reverseProxyOnce against the synthetic "primary" origin.
	handler, err := buildFederationHandler(ctx, cfg, logger, healthChecker, redisClient)
	if err != nil {
		return fmt.Errorf("failed to build handler: %w", err)
	}

	// Create router. Stateless middlewares are wired at the chi
	// router level rather than inside the buffered Chain so they sit
	// at the request boundary without per-iteration overhead.
	//
	// Order matters:
	//   logging → cors → auth → ratelimit → authz → cache → remap
	//
	// cors before auth so preflight (OPTIONS + AC-Request-Method) short-
	// circuits with 204 without consuming auth/ratelimit budget; browsers
	// send preflights unauthenticated by spec.
	// auth before ratelimit so the rate-limit key can include the
	// authenticated principal. authz BEFORE cache so the cache key
	// can be informed by the authz decision — specifically, when the
	// decision attaches a row-level constraint (CQL2 filter, geofence,
	// narrowed collection allow-list, etc.), the cache layer bypasses
	// itself entirely, since the same URL legitimately produces
	// different responses for different principals.
	httpMiddlewares := []func(http.Handler) http.Handler{
		logging.NewHTTPMiddleware(logging.Config{Logger: logger}),
	}
	if corsMW, err := buildCorsHTTPMiddleware(cfg); err != nil {
		return fmt.Errorf("failed to build cors middleware: %w", err)
	} else if corsMW != nil {
		httpMiddlewares = append(httpMiddlewares, corsMW)
	}
	if authMW, err := buildAuthHTTPMiddleware(ctx, cfg, logger); err != nil {
		return fmt.Errorf("failed to build auth middleware: %w", err)
	} else if authMW != nil {
		httpMiddlewares = append(httpMiddlewares, authMW)
	}
	if rlMW := buildRateLimitHTTPMiddleware(cfg, redisClient, logger); rlMW != nil {
		httpMiddlewares = append(httpMiddlewares, rlMW)
	}
	if azMW, err := buildAuthzHTTPMiddleware(ctx, cfg, logger); err != nil {
		return fmt.Errorf("failed to build authz middleware: %w", err)
	} else if azMW != nil {
		httpMiddlewares = append(httpMiddlewares, azMW)
	}
	if cMW, err := buildCacheHTTPMiddleware(cfg, redisClient, logger); err != nil {
		return fmt.Errorf("failed to build cache middleware: %w", err)
	} else if cMW != nil {
		httpMiddlewares = append(httpMiddlewares, cMW)
	}
	if rmMW, err := buildRemapHTTPMiddleware(cfg); err != nil {
		return fmt.Errorf("failed to build remap middleware: %w", err)
	} else if rmMW != nil {
		httpMiddlewares = append(httpMiddlewares, rmMW)
	}
	router := server.NewRouter(server.RouterConfig{
		Handler:         handler,
		HealthChecker:   healthChecker,
		MaxBodyBytes:    cfg.Server.MaxBodyBytes,
		HTTPMiddlewares: httpMiddlewares,
		// The federation handler implements both http.Handler (catalog
		// routes) and server.AssetHandler (the streaming proxy
		// endpoint). Mounting the asset endpoint is gated on the
		// router seeing a non-nil AssetHandler — single-origin
		// pass-through deployments leave it nil.
		AssetHandler: handler,
	})

	// Create and start HTTP server
	srv, err := server.New(server.Config{
		ServerConfig: &cfg.Server,
		Handler:      router,
		Logger:       logger,
	})
	if err != nil {
		return fmt.Errorf("failed to create server: %w", err)
	}

	// Start health checks
	healthChecker.Start()
	defer healthChecker.Stop()

	// Loud warning when the middleware chain does not reject anonymous
	// traffic — an easy-to-miss misconfiguration for a public deployment.
	if serverIsUnauthenticated(cfg) {
		logger.Warn("SERVER IS OPEN: it will accept UNAUTHENTICATED requests; no auth provider is configured to reject anonymous clients",
			"remedy", "add a `middleware` entry named `auth` with `allow_anonymous: false` and at least one provider, and/or configure `authz.opa` to gate requests",
		)
	}

	logger.Info("Server starting",
		"address", fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		"tls", cfg.Server.TLS.Enabled,
	)

	// Watch for parent-context cancellation (signal received) and
	// trigger graceful shutdown. srv.Start() will then return
	// http.ErrServerClosed and main can exit cleanly.
	go func() {
		<-ctx.Done()
		logger.Info("Shutdown signal received; draining", "timeout", shutdownTimeout)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			logger.Error("Server shutdown error", "error", err)
		}
	}()

	// Start server (blocks until Shutdown is called)
	return srv.Start()
}

// buildAuthzMiddleware wires the authz middleware (including CQL2
// injection) from the top-level authz config. Returns (nil, nil) when
// authz is not configured.
func buildAuthzHTTPMiddleware(ctx context.Context, cfg *config.Config, logger *slog.Logger) (func(http.Handler) http.Handler, error) {
	az := cfg.Authz
	if az == nil || az.OPA == nil {
		return nil, nil
	}

	if !az.OPA.Embedded {
		return nil, fmt.Errorf("authz.opa.embedded must be true; only embedded OPA is supported")
	}
	enf, err := authz.NewEmbeddedOPAEnforcer(ctx, authz.EmbeddedOPAConfig{
		Name:        "embedded-opa",
		PolicyPaths: az.OPA.RegoFiles,
	})
	if err != nil {
		return nil, err
	}
	var enforcer authz.Enforcer = enf

	cql2Enabled := false
	if az.CQL2Injection != nil {
		cql2Enabled = az.CQL2Injection.Enabled
	}

	// Single-origin: gate push-down on cfg.Upstream.SupportsFilterExtension.
	// Federation: conservative AND across configured origins.
	var filterCheck func(*http.Request, *middleware.STACInfo) bool
	if cfg.IsFederation() {
		allSupport := true
		any := false
		for _, o := range cfg.Federation.Origins {
			if !o.Enabled {
				continue
			}
			any = true
			if !o.SupportsFilterExtension {
				allSupport = false
				break
			}
		}
		supports := any && allSupport
		filterCheck = func(_ *http.Request, _ *middleware.STACInfo) bool { return supports }
	} else if cfg.Upstream != nil {
		supports := cfg.Upstream.SupportsFilterExtension
		filterCheck = func(_ *http.Request, _ *middleware.STACInfo) bool { return supports }
	}

	logger.Info("authz middleware configured",
		"cql2_injection", cql2Enabled,
		"filter_extension_check", filterCheck != nil,
	)

	return authz.NewHTTPMiddleware(authz.HTTPConfig{
		Enforcer:             enforcer,
		AllowAnonymous:       true,
		CQL2InjectionEnabled: cql2Enabled,
		FilterExtensionCheck: filterCheck,
	}), nil
}

// serverIsUnauthenticated reports whether the configured middleware
// chain will accept anonymous (unauthenticated) requests — i.e. nothing
// in the chain is configured to reject a client that presents no
// credentials. It returns true (server is open) when:
//
//   - there is no `auth` middleware block whose `allow_anonymous` is
//     false, AND
//   - there is no authz (embedded OPA) enforcer, which — with its
//     fail-closed default policy — gates every request including
//     anonymous ones.
//
// Note that `allow_anonymous` defaults to true, matching
// buildAuthHTTPMiddleware, so an `auth` block that omits it is still
// considered open.
func serverIsUnauthenticated(cfg *config.Config) bool {
	// An authz (OPA) enforcer evaluates every request, so a configured
	// enforcer means anonymous clients are gated by policy.
	if cfg.Authz != nil && cfg.Authz.OPA != nil {
		return false
	}
	for _, mw := range cfg.Middleware {
		if mw.Name != "auth" {
			continue
		}
		allowAnon := true
		if v, ok := mw.Config["allow_anonymous"].(bool); ok {
			allowAnon = v
		}
		// `allow_anonymous: false` makes the auth chain reject
		// unauthenticated requests → the server is not open.
		return allowAnon
	}
	// No auth block configured at all → open.
	return true
}

// buildAuthHTTPMiddleware builds the chi-style auth middleware from
// the `auth` block of the middleware config list. Returns
// (nil, nil) when no `auth` block is configured — the router skips
// a nil entry.
//
// Supported provider types: bearer/jwt, api_key, oidc, basic, mtls.
// Unknown types now return an error (HIGH H-config-3) — previously
// they were silently ignored, which meant a misspelled type made a
// production deployment look authenticated when it was actually
// running fully open.
func buildAuthHTTPMiddleware(ctx context.Context, cfg *config.Config, logger *slog.Logger) (func(http.Handler) http.Handler, error) {
	var rawCfg map[string]interface{}
	for _, mw := range cfg.Middleware {
		if mw.Name == "auth" {
			rawCfg = mw.Config
			break
		}
	}
	if rawCfg == nil {
		return nil, nil
	}

	allowAnonymous := true
	if v, ok := rawCfg["allow_anonymous"].(bool); ok {
		allowAnonymous = v
	}

	var providers []auth.Provider
	if providersCfg, ok := rawCfg["providers"].([]interface{}); ok {
		for i, pCfg := range providersCfg {
			pMap, ok := pCfg.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("auth.providers[%d]: expected map, got %T", i, pCfg)
			}
			provider, err := buildAuthProvider(ctx, pMap, logger)
			if err != nil {
				return nil, fmt.Errorf("auth.providers[%d]: %w", i, err)
			}
			if provider != nil {
				providers = append(providers, provider)
			}
		}
	}

	return auth.NewHTTPMiddleware(auth.Config{
		Providers:      providers,
		AllowAnonymous: allowAnonymous,
	}), nil
}

// buildAuthProvider materializes a single auth.Provider from a YAML
// map. Returns (nil, nil) only when the constructor is best-effort
// soft-failed (e.g. JWKS unreachable at boot) — currently no
// branches do that, but the signature leaves the door open.
func buildAuthProvider(ctx context.Context, pMap map[string]interface{}, _ *slog.Logger) (auth.Provider, error) {
	pType, _ := pMap["type"].(string)
	switch pType {
	case "bearer", "jwt":
		bearerCfg := auth.BearerConfig{
			Name:        "bearer",
			Issuer:      getStringConfig(pMap, "issuer"),
			Audience:    getStringConfig(pMap, "audience"),
			JWKSURL:     getStringConfig(pMap, "jwks_url"),
			LifetimeCtx: ctx,
		}
		if s := getStringConfig(pMap, "secret"); s != "" {
			bearerCfg.Secret = []byte(s)
		}
		return auth.NewBearerProvider(bearerCfg)
	case "api_key":
		return auth.NewAPIKeyProvider(auth.APIKeyConfig{
			Name:       "api_key",
			Header:     getStringConfig(pMap, "header_name"),
			QueryParam: getStringConfig(pMap, "query_param"),
		})
	case "oidc":
		return auth.NewOIDCProvider(auth.OIDCConfig{
			Name:              "oidc",
			IssuerURL:         getStringConfig(pMap, "issuer_url"),
			Audience:          getStringConfig(pMap, "audience"),
			AllowInsecureHTTP: getBoolConfig(pMap, "allow_insecure_http"),
		})
	case "basic":
		users, err := parseBasicUsers(pMap["users"])
		if err != nil {
			return nil, fmt.Errorf("basic users: %w", err)
		}
		return auth.NewBasicAuthProvider(auth.BasicAuthConfig{
			Name:  "basic",
			Realm: getStringConfig(pMap, "realm"),
			Users: users,
		})
	case "mtls":
		mtlsCfg := auth.MTLSConfig{
			Name:            "mtls",
			RequireClientCA: getBoolConfig(pMap, "require_client_ca"),
		}
		if caFile := getStringConfig(pMap, "trusted_ca_file"); caFile != "" {
			pool, err := loadCAPool(caFile)
			if err != nil {
				return nil, fmt.Errorf("mtls trusted_ca_file %q: %w", caFile, err)
			}
			mtlsCfg.TrustedCAs = pool
		}
		return auth.NewMTLSProvider(mtlsCfg)
	case "":
		return nil, fmt.Errorf("missing required field 'type'")
	default:
		return nil, fmt.Errorf("unknown auth provider type %q (supported: bearer, jwt, api_key, oidc, basic, mtls)", pType)
	}
}

// parseBasicUsers decodes the `users` array of a basic auth config.
// Each entry should be a map with username, password_hash, and
// optional roles/attributes.
func parseBasicUsers(raw interface{}) ([]auth.BasicUser, error) {
	list, ok := raw.([]interface{})
	if !ok {
		if raw == nil {
			return nil, nil
		}
		return nil, fmt.Errorf("expected list, got %T", raw)
	}
	out := make([]auth.BasicUser, 0, len(list))
	for i, item := range list {
		m, ok := item.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("users[%d]: expected map, got %T", i, item)
		}
		u := auth.BasicUser{
			Username:     getStringConfig(m, "username"),
			PasswordHash: getStringConfig(m, "password_hash"),
			Roles:        getStringSliceConfig(m, "roles"),
		}
		if attrs, ok := m["attributes"].(map[string]interface{}); ok {
			u.Attributes = attrs
		}
		out = append(out, u)
	}
	return out, nil
}

// loadCAPool loads PEM-encoded CA certificates from path into a
// fresh x509.CertPool.
func loadCAPool(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("no PEM certificates found")
	}
	return pool, nil
}

// getBoolConfig returns m[key] as a bool, or false if missing/wrong type.
func getBoolConfig(m map[string]interface{}, key string) bool {
	if v, ok := m[key].(bool); ok {
		return v
	}
	return false
}

// buildCacheHTTPMiddleware builds the chi-style cache middleware from
// the `cache` block of the middleware config list. Returns (nil, nil)
// when no block is configured. When the block selects `store: redis`,
// the store is built on the shared client (validation guarantees the
// client exists; the double-check here turns a wiring regression into
// a boot error instead of a nil deref).
func buildCacheHTTPMiddleware(cfg *config.Config, rdb redis.UniversalClient, logger *slog.Logger) (func(http.Handler) http.Handler, error) {
	var rawCfg map[string]interface{}
	for _, mw := range cfg.Middleware {
		if mw.Name == "cache" {
			rawCfg = mw.Config
			break
		}
	}
	if rawCfg == nil {
		return nil, nil
	}
	var store cache.Store
	if s, _ := rawCfg["store"].(string); s == "redis" {
		if rdb == nil {
			return nil, fmt.Errorf("cache store is redis but no redis client was built")
		}
		store = redisstore.NewKV(rdb, redisKeyPrefix(cfg)+"rc:", logger)
	}
	return cache.NewFromConfigWithStore(rawCfg, store)
}

// redisKeyPrefix returns the operator key prefix (default "stacproxy:").
func redisKeyPrefix(cfg *config.Config) string {
	if cfg.Redis != nil && cfg.Redis.KeyPrefix != "" {
		return cfg.Redis.KeyPrefix
	}
	return "stacproxy:"
}

// buildRedisClient constructs the shared Redis client when any
// component selects `store: redis`. A present-but-unused redis block
// is skipped (config validation already warns). Reachability is probed
// once for the boot log — failure is a warning, not an error: every
// consumer fails open, and a proxy booting during a Redis outage must
// still serve.
//
// Deliberately NOT registered with the readiness checker: the health
// library aggregates all checks into one up/down, so a Redis check
// would have load balancers pull replicas during a Redis outage —
// turning a soft degradation (cold cache, per-replica rate limiting)
// into a hard one. Redis state is surfaced via throttled warn logs
// from the stores instead.
func buildRedisClient(ctx context.Context, cfg *config.Config, logger *slog.Logger) (redis.UniversalClient, error) {
	if cfg.Redis == nil || !configSelectsRedis(cfg) {
		return nil, nil
	}
	client, err := redisstore.New(redisstore.Config{
		Addr:         cfg.Redis.Addr,
		Username:     cfg.Redis.Username,
		Password:     cfg.Redis.Password,
		DB:           cfg.Redis.DB,
		PoolSize:     cfg.Redis.PoolSize,
		MinIdleConns: cfg.Redis.MinIdleConns,
		DialTimeout:  cfg.Redis.DialTimeout,
		ReadTimeout:  cfg.Redis.ReadTimeout,
		WriteTimeout: cfg.Redis.WriteTimeout,
		TLS: redisstore.TLSConfig{
			Enabled:            cfg.Redis.TLS.Enabled,
			CAFile:             cfg.Redis.TLS.CAFile,
			CertFile:           cfg.Redis.TLS.CertFile,
			KeyFile:            cfg.Redis.TLS.KeyFile,
			InsecureSkipVerify: cfg.Redis.TLS.InsecureSkipVerify,
		},
	})
	if err != nil {
		return nil, err
	}

	pingCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := client.Ping(pingCtx).Err(); err != nil {
		logger.Warn("redis unreachable at boot; consumers will fail open until it recovers",
			"addr", cfg.Redis.Addr, "error", err)
	} else {
		logger.Info("Redis connected", "addr", cfg.Redis.Addr)
	}
	return client, nil
}

// configSelectsRedis reports whether any component opted into the
// shared Redis backend.
func configSelectsRedis(cfg *config.Config) bool {
	for _, mw := range cfg.Middleware {
		if mw.Name != "cache" && mw.Name != "rate_limit" {
			continue
		}
		if s, _ := mw.Config["store"].(string); s == "redis" {
			return true
		}
	}
	return cfg.Federation != nil && cfg.Federation.PageCache != nil &&
		cfg.Federation.PageCache.Store == "redis"
}

// buildCorsHTTPMiddleware builds the chi-style CORS middleware from the
// `cors` block of the middleware config list. Returns (nil, nil) when no
// block is configured.
func buildCorsHTTPMiddleware(cfg *config.Config) (func(http.Handler) http.Handler, error) {
	var rawCfg map[string]interface{}
	for _, mw := range cfg.Middleware {
		if mw.Name == "cors" {
			rawCfg = mw.Config
			break
		}
	}
	if rawCfg == nil {
		return nil, nil
	}
	return cors.NewFromConfig(rawCfg)
}

// buildRemapHTTPMiddleware builds the chi-style URL-remap middleware
// from the `url_remap` block of the middleware config list. Returns
// (nil, nil) when no block is configured.
func buildRemapHTTPMiddleware(cfg *config.Config) (func(http.Handler) http.Handler, error) {
	var rawCfg map[string]interface{}
	for _, mw := range cfg.Middleware {
		if mw.Name == "url_remap" {
			rawCfg = mw.Config
			break
		}
	}
	if rawCfg == nil {
		return nil, nil
	}
	return remap.NewFromConfig(rawCfg)
}

// buildAssetSigner returns the HMAC signer used to sign asset hrefs
// when an origin has `rewrite_assets: sign`. Reuses the secret from
// the `url_remap` middleware config so deployments don't have to
// configure two secrets to do the same thing. Returns nil when no
// origin opts into "sign" and no signing secret is configured —
// federation.rewriteAssetHref falls back to passthrough in that case.
func buildAssetSigner(cfg *config.Config) federation.AssetSigner {
	// Only build a signer when at least one origin asks for signing,
	// to avoid materializing keys we won't use.
	needsSigner := false
	if cfg.Federation != nil {
		for _, o := range cfg.Federation.Origins {
			if o.RewriteAssets == "sign" {
				needsSigner = true
				break
			}
		}
	}
	if !needsSigner {
		return nil
	}
	for _, mw := range cfg.Middleware {
		if mw.Name == "url_remap" {
			if secret, ok := mw.Config["secret"].(string); ok && secret != "" {
				return remap.NewHMACSigner(secret)
			}
		}
	}
	return nil
}

// buildRateLimitHTTPMiddleware builds the chi-style rate-limit middleware
// from the `rate_limit` block of the middleware config list. Returns nil
// when no `rate_limit` block is configured. With `store: redis`, buckets
// live in the shared Redis so quotas hold globally across replicas;
// `failure_mode` (open, the default, or closed) picks the behavior when
// Redis is unreachable.
func buildRateLimitHTTPMiddleware(cfg *config.Config, rdb redis.UniversalClient, logger *slog.Logger) func(http.Handler) http.Handler {
	var rawCfg map[string]interface{}
	for _, mw := range cfg.Middleware {
		if mw.Name == "rate_limit" {
			rawCfg = mw.Config
			break
		}
	}
	if rawCfg == nil {
		return nil
	}

	// YAML scalars decode as int OR float64 depending on whether the
	// value has a decimal point; accept either shape.
	requests := 1000
	if v, ok := intFromAny(rawCfg["requests"]); ok {
		requests = v
	}
	window := 1 * time.Hour
	if v, ok := rawCfg["window"].(string); ok {
		if d, err := time.ParseDuration(v); err == nil {
			window = d
		}
	}
	burst := 50
	if v, ok := intFromAny(rawCfg["burst"]); ok {
		burst = v
	}
	// Burst must be > 0; the underlying token-bucket limiter treats
	// 0/negative as "block everything", which is almost certainly not
	// what an operator intended when omitting the field. Fall back to
	// the default rather than silently bricking.
	if burst <= 0 {
		burst = 50
	}

	mwCfg := ratelimit.Config{
		DefaultQuota: ratelimit.Quota{
			Requests: requests,
			Window:   window,
			Burst:    burst,
		},
	}
	if s, _ := rawCfg["store"].(string); s == "redis" {
		if rdb == nil {
			// Validation guarantees the redis block; degrade loudly to
			// the in-memory limiter rather than boot without limiting.
			logger.Warn("rate_limit store is redis but no redis client was built; using in-memory limiter")
		} else {
			mwCfg.Limiter = ratelimit.NewRedisLimiter(rdb, redisKeyPrefix(cfg)+"rl:", logger)
			mwCfg.FailClosed = rawCfg["failure_mode"] == "closed"
		}
	}
	return ratelimit.NewHTTPMiddleware(mwCfg)
}

// intFromAny accepts the int / float64 shapes that YAML scalar
// numbers can decode into and returns them as int. Returns ok=false
// for any other kind (including nil).
func intFromAny(v interface{}) (int, bool) {
	switch x := v.(type) {
	case int:
		return x, true
	case int64:
		return int(x), true
	case float64:
		// Reject NaN/Inf and obvious non-integers.
		if x != x || x < float64(int64(-1<<62)) || x > float64(int64(1<<62)) {
			return 0, false
		}
		return int(x), true
	default:
		return 0, false
	}
}

// buildFederationHandler creates the federation handler. In
// single-origin mode (cfg.Mode != "federation") it synthesizes a
// single-element Origins list from cfg.Upstream, so the same code
// path handles both deployment shapes.
func buildFederationHandler(ctx context.Context, cfg *config.Config, logger *slog.Logger, health *observability.HealthChecker, rdb redis.UniversalClient) (*federation.Handler, error) {
	// Single-origin → federation-of-1 translation. The page cache (the
	// only redis consumer below) is federation-only, so the client is
	// not threaded through.
	if !cfg.IsFederation() {
		return buildSingleOriginAsFederation(ctx, cfg, logger, health)
	}

	var origins []*federation.Origin

	for _, originCfg := range cfg.Federation.Origins {
		if !originCfg.Enabled {
			continue
		}

		timeout := originCfg.Timeout
		if timeout == 0 {
			timeout = 30 * time.Second
		}

		supportsFilter := originCfg.SupportsFilterExtension
		if !supportsFilter {
			supportsFilter = probeFilterExtension(logger, originCfg.ID, originCfg.BaseURL)
		}

		origin := &federation.Origin{
			ID:                      originCfg.ID,
			Name:                    originCfg.Name,
			Description:             originCfg.Description,
			BaseURL:                 originCfg.BaseURL,
			Enabled:                 originCfg.Enabled,
			Timeout:                 timeout,
			Retry:                   originRetryPolicy(originCfg.Retry),
			CircuitBreaker:          originBreakerPolicy(originCfg.CircuitBreaker),
			MaxIdleConnsPerHost:     originCfg.MaxIdleConnsPerHost,
			Collections:             originCfg.Collections,
			ExcludeCollections:      originCfg.ExcludeCollections,
			Priority:                originCfg.Priority,
			ReadOnly:                originCfg.ReadOnly,
			Searchable:              originCfg.Searchable,
			AutoDiscover:            originCfg.AutoDiscover,
			DiscoveryInterval:       originCfg.DiscoveryInterval,
			CollectionPrefix:        originCfg.CollectionPrefix,
			CollectionMapping:       originCfg.CollectionMapping,
			StripPathPrefix:         originCfg.StripPathPrefix,
			SupportsFilterExtension: supportsFilter,
			RewriteAssets:           originCfg.RewriteAssets,
			AssetSignTTL:            originCfg.AssetSignTTL,
			ForwardUserIdentity:     originCfg.ForwardUserIdentity,
			MaxResponseBytes:        originCfg.MaxResponseBytes,
			Pagination:              originPaginationSpec(originCfg.Pagination),
			Auth:                    originAuthConfig(originCfg.Auth),
		}
		origins = append(origins, origin)

		logger.Info("Configured origin",
			"id", originCfg.ID,
			"url", originCfg.BaseURL,
			"priority", originCfg.Priority,
			"filter_extension", supportsFilter,
		)
	}

	caps := computeConformanceCaps(cfg, origins)

	handler, err := federation.NewHandler(federation.HandlerConfig{
		Origins:          origins,
		MaxConcurrent:    cfg.Federation.MaxConcurrent,
		AggregateTimeout: cfg.Federation.AggregateTimeout,
		ProxyBaseURL:     cfg.Server.PublicBaseURL,
		DefaultPageSize:  cfg.Federation.DefaultPageSize,
		MaxPageSize:      cfg.Federation.MaxPageSize,
		ConformanceCaps:  caps,
		LifetimeCtx:      ctx,
		Logger:           logger,
		AssetSigner:      buildAssetSigner(cfg),
		CursorSecret:     []byte(cfg.Federation.CursorSecret),
		PageCache:        buildPageCache(cfg, rdb, logger),
	})
	if err != nil {
		return nil, err
	}

	// Register origin health checks against the same *http.Client the
	// federation fan-out uses, so probes share the project's
	// instrumented transport (retry, custom CA pool, per-origin auth)
	// rather than constructing a parallel client (M-observability-2).
	for _, o := range origins {
		var client *http.Client
		if oc := handler.OriginClient(o.ID); oc != nil {
			client = oc.HTTPClient()
		}
		baseURL := o.BaseURL
		health.AddCheck(observability.NewOriginCheck(o.ID, baseURL, client))
	}

	return handler, nil
}

// computeConformanceCaps derives the proxy's runtime conformance
// capabilities from the loaded config and the origin list. In
// particular, the filter extension is only advertised when CQL2
// injection is enabled AND every routed origin supports it.
func computeConformanceCaps(cfg *config.Config, origins []*federation.Origin) stac.ConformanceCaps {
	cql2Enabled := false
	if cfg.Authz != nil && cfg.Authz.CQL2Injection != nil {
		cql2Enabled = cfg.Authz.CQL2Injection.Enabled
	}
	allFilter := false
	if len(origins) > 0 {
		allFilter = true
		for _, o := range origins {
			if !o.SupportsFilterExtension {
				allFilter = false
				break
			}
		}
	}
	return stac.ConformanceCaps{
		CQL2InjectionEnabled:    cql2Enabled,
		AllOriginsSupportFilter: allFilter,
	}
}

// originRetryPolicy converts the YAML-bound retry config to the
// federation.RetryPolicy value used by federation.Origin. Returns nil
// when the YAML block is absent so the origin client falls back to its
// per-package default.
func originRetryPolicy(c *config.RetryConfig) *federation.RetryPolicy {
	if c == nil {
		return nil
	}
	return &federation.RetryPolicy{
		MaxRetries:     c.MaxRetries,
		InitialBackoff: c.InitialBackoff,
		MaxBackoff:     c.MaxBackoff,
		RetryOn:        c.RetryOn,
	}
}

// originBreakerPolicy mirrors the YAML circuit_breaker block into the
// federation type. nil in → nil out, which federation treats as
// "enabled with defaults" (the breaker is opt-out).
func originBreakerPolicy(c *config.CircuitBreakerConfig) *federation.BreakerPolicy {
	if c == nil {
		return nil
	}
	return &federation.BreakerPolicy{
		Disabled:         c.Enabled != nil && !*c.Enabled,
		FailureThreshold: c.FailureThreshold,
		OpenDuration:     c.OpenDuration,
		MaxOpenDuration:  c.MaxOpenDuration,
	}
}

// buildPageCache constructs the federated-search page cache from
// YAML config. Returns nil — meaning "feature disabled" — when:
//
//   - there is no cursor secret (no cursors to key by; the paginator
//     wouldn't run anyway), OR
//   - the operator set `page_cache.enabled: false` explicitly.
//
// The default when `page_cache` is absent or `enabled` is unset is
// ON, matching the user-stated preference: backwards navigation works
// out of the box wherever federated pagination is already configured.
//
// With `store: redis` the pages live in the shared Redis, so rel:prev
// / rel:first navigation works across replicas without sticky routing.
func buildPageCache(cfg *config.Config, rdb redis.UniversalClient, logger *slog.Logger) *pagecache.Cache {
	fc := cfg.Federation
	if fc == nil || fc.CursorSecret == "" {
		return nil
	}

	// Resolve the enabled toggle: nil means default-on; explicit
	// false means off.
	enabled := true
	if fc.PageCache != nil && fc.PageCache.Enabled != nil {
		enabled = *fc.PageCache.Enabled
	}
	if !enabled {
		return nil
	}

	maxEntries := 1024
	ttl := time.Hour
	if fc.PageCache != nil {
		if fc.PageCache.MaxEntries > 0 {
			maxEntries = fc.PageCache.MaxEntries
		}
		if fc.PageCache.TTL > 0 {
			ttl = fc.PageCache.TTL
		}
	}

	var store pagecache.Store
	storeKind := "memory"
	if fc.PageCache != nil && fc.PageCache.Store == "redis" {
		if rdb == nil {
			// Validation guarantees the redis block exists; a nil client
			// here is a wiring regression. Degrade to memory rather than
			// panic — the page cache is an optimization.
			logger.Warn("federation page cache: store is redis but no redis client was built; falling back to memory")
		} else {
			store = redisstore.NewKV(rdb, redisKeyPrefix(cfg)+"pg:", logger)
			storeKind = "redis"
		}
	}
	if store == nil {
		store = cache.NewMemoryStore(cache.MemoryConfig{MaxSize: maxEntries})
	}
	c, err := pagecache.New(store, ttl, []byte(fc.CursorSecret))
	if err != nil {
		logger.Warn("federation page cache disabled (construction failed)", "err", err)
		return nil
	}
	logger.Info("Federation page cache enabled",
		"store", storeKind,
		"max_entries", maxEntries,
		"ttl", ttl,
	)
	return c
}

// originPaginationSpec converts the YAML-bound pagination config to
// the federation.PaginationSpec value used by federation.Origin.
// Returns the zero value (i.e. "auto" adapter behavior) when the
// YAML block is absent.
func originPaginationSpec(c *config.PaginationConfig) federation.PaginationSpec {
	if c == nil {
		return federation.PaginationSpec{}
	}
	return federation.PaginationSpec{
		Adapter:     c.Adapter,
		OffsetParam: c.OffsetParam,
		TokenParam:  c.TokenParam,
	}
}

// originAuthConfig converts the YAML-bound config to the
// federation.AuthConfig value used by federation.Origin.
func originAuthConfig(c *config.OriginAuthConfig) federation.AuthConfig {
	if c == nil {
		return federation.AuthConfig{Type: "none"}
	}
	auth := federation.AuthConfig{
		Type:          c.Type,
		Username:      c.Username,
		Password:      c.Password,
		Token:         c.Token,
		APIKeyHeader:  c.APIKeyHeader,
		APIKeyValue:   c.APIKeyValue,
		APIKeyInQuery: c.APIKeyInQuery,
		CustomHeaders: c.CustomHeaders,
	}
	if c.OAuth2 != nil {
		auth.OAuth2 = &federation.OAuth2Config{
			TokenURL:     c.OAuth2.TokenURL,
			ClientID:     c.OAuth2.ClientID,
			ClientSecret: c.OAuth2.ClientSecret,
			Scopes:       c.OAuth2.Scopes,
			Audience:     c.OAuth2.Audience,
		}
	}
	if c.AWSSigV4 != nil {
		auth.AWSSigV4 = &federation.AWSSigV4Config{
			Region:    c.AWSSigV4.Region,
			Service:   c.AWSSigV4.Service,
			AccessKey: c.AWSSigV4.AccessKey,
			SecretKey: c.AWSSigV4.SecretKey,
		}
	}
	return auth
}

// buildSingleOriginAsFederation builds a federation handler from a
// single-origin cfg.Upstream — i.e. the "single" mode collapses to a
// federation-of-1 so we only carry one request pipeline.
func buildSingleOriginAsFederation(ctx context.Context, cfg *config.Config, logger *slog.Logger, health *observability.HealthChecker) (*federation.Handler, error) {
	if cfg.Upstream == nil {
		return nil, fmt.Errorf("single mode requires upstream config")
	}

	timeout := cfg.Upstream.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	supportsFilter := cfg.Upstream.SupportsFilterExtension
	if !supportsFilter {
		supportsFilter = probeFilterExtension(logger, "upstream", cfg.Upstream.URL)
	}

	origin := &federation.Origin{
		ID:                      "primary",
		BaseURL:                 cfg.Upstream.URL,
		Enabled:                 true,
		Timeout:                 timeout,
		Priority:                100,
		Searchable:              true,
		SupportsFilterExtension: supportsFilter,
		// No auth, no collection prefix, no collection list — the
		// router treats this as the catch-all origin for everything.
	}

	logger.Info("Configured single-origin upstream as federation-of-1",
		"url", cfg.Upstream.URL,
		"filter_extension", supportsFilter,
	)

	caps := computeConformanceCaps(cfg, []*federation.Origin{origin})

	handler, err := federation.NewHandler(federation.HandlerConfig{
		Origins:         []*federation.Origin{origin},
		ProxyBaseURL:    cfg.Server.PublicBaseURL,
		ConformanceCaps: caps,
		LifetimeCtx:     ctx,
		Logger:          logger,
	})
	if err != nil {
		return nil, err
	}

	// Register upstream health check against the same instrumented
	// HTTP client used for fan-out (M-observability-2).
	var hc *http.Client
	if oc := handler.OriginClient(origin.ID); oc != nil {
		hc = oc.HTTPClient()
	}
	health.AddCheck(observability.NewOriginCheck("upstream", cfg.Upstream.URL, hc))

	return handler, nil
}

// initLogger builds a structured slog.Logger from config. Format
// selects JSON (default) or text output; Level maps debug/info/warn/error.
func initLogger(cfg config.LoggingConfig) *slog.Logger {
	level := slog.LevelInfo
	switch cfg.Level {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	opts := &slog.HandlerOptions{Level: level}
	var handler slog.Handler
	switch cfg.Format {
	case "console", "text":
		handler = slog.NewTextHandler(os.Stdout, opts)
	default:
		handler = slog.NewJSONHandler(os.Stdout, opts)
	}
	return slog.New(handler)
}

// Helper functions for config extraction
func getStringConfig(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func getStringSliceConfig(m map[string]interface{}, key string) []string {
	if v, ok := m[key].([]interface{}); ok {
		result := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}
	return nil
}

// probeFilterExtension probes baseURL/conformance once at boot and
// returns whether the upstream advertises the STAC Filter Extension.
// Logs the result against the supplied id (origin ID, or "upstream"
// for single-origin mode). Network failures yield false so the
// post-filter path remains responsible for enforcement.
func probeFilterExtension(logger *slog.Logger, id, baseURL string) bool {
	probeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ok, err := stac.ProbeFilterExtension(probeCtx, nil, baseURL)
	switch {
	case err != nil:
		logger.Warn("conformance probe failed; assuming no Filter Extension",
			"origin", id, "error", err)
		return false
	case ok:
		logger.Info("conformance probe: Filter Extension supported",
			"origin", id)
		return true
	default:
		logger.Info("conformance probe: Filter Extension not advertised",
			"origin", id)
		return false
	}
}

// isFlagDefault reports whether got matches the documented default.
// Used by --healthcheck so we can detect "operator did not override
// the addr flag" and substitute the configured port.
func isFlagDefault(got, def string) bool {
	return got == def
}

// runHealthcheck makes a single GET against the supplied URL and
// returns a process exit code: 0 on 2xx, 1 otherwise. Used by the
// container HEALTHCHECK directive so the runtime image doesn't need
// to ship curl/wget.
func runHealthcheck(url string) int {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "healthcheck: %v\n", err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		fmt.Fprintf(os.Stderr, "healthcheck: status %d\n", resp.StatusCode)
		return 1
	}
	return 0
}

