// Package main is the entry point for stac-proxy.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/yourorg/stac-proxy/internal/config"
	"github.com/yourorg/stac-proxy/internal/federation"
	"github.com/yourorg/stac-proxy/internal/middleware"
	"github.com/yourorg/stac-proxy/internal/middleware/auth"
	"github.com/yourorg/stac-proxy/internal/middleware/authz"
	"github.com/yourorg/stac-proxy/internal/middleware/cache"
	"github.com/yourorg/stac-proxy/internal/middleware/logging"
	"github.com/yourorg/stac-proxy/internal/middleware/ratelimit"
	"github.com/yourorg/stac-proxy/internal/middleware/remap"
	"github.com/yourorg/stac-proxy/internal/observability"
	"github.com/yourorg/stac-proxy/internal/server"
	"github.com/yourorg/stac-proxy/internal/stac"
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
		os.Exit(runHealthcheck(*healthAddr))
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
	logger, err := initLogger(cfg.Logging)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync()

	// Publish the configured logger globally so package-level code
	// (federation per-origin loggers, etc.) can call zap.L() without
	// requiring DI.
	zap.ReplaceGlobals(logger)

	logger.Info("Starting stac-proxy",
		zap.String("version", version),
		zap.String("commit", commit),
		zap.String("mode", cfg.Mode),
	)

	// Parent context, cancelled by SIGINT/SIGTERM. run() observes
	// cancellation and calls the HTTP server's Shutdown so in-flight
	// requests drain within ShutdownTimeout.
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := run(ctx, cfg, logger); err != nil && err != http.ErrServerClosed {
		logger.Fatal("Server error", zap.Error(err))
	}
	logger.Info("Shutdown complete")
}

// shutdownTimeout is how long run() will wait for in-flight requests
// to complete before forcing the HTTP server closed.
const shutdownTimeout = 30 * time.Second

// run starts the proxy server.
func run(ctx context.Context, cfg *config.Config, logger *zap.Logger) error {
	// Initialize metrics and publish them as the process-wide
	// default so middleware/handlers can emit without us threading
	// the Metrics pointer through every constructor.
	metrics := observability.NewMetrics("stac_proxy")
	observability.SetDefault(metrics)

	// Initialize health checker
	healthChecker := observability.NewHealthChecker()

	// Build middleware chain
	chain, err := buildMiddlewareChain(cfg, logger, metrics)
	if err != nil {
		return fmt.Errorf("failed to build middleware chain: %w", err)
	}

	// Build the federation handler. Single-origin mode is modeled as a
	// federation-of-1 — the single-origin code path collapses into
	// reverseProxyOnce against the synthetic "primary" origin.
	var handler middleware.Handler
	handler, err = buildFederationHandler(cfg, logger, healthChecker, metrics)
	if err != nil {
		return fmt.Errorf("failed to build handler: %w", err)
	}

	// Create router. Stateless middlewares (logging, auth, ratelimit)
	// are wired at the chi router level rather than inside the buffered
	// Chain so they sit at the request boundary without per-iteration
	// overhead. Order matters: logging → auth → ratelimit so that
	// rate-limit decisions can key off the authenticated principal.
	httpMiddlewares := []func(http.Handler) http.Handler{
		logging.NewHTTPMiddleware(logging.Config{Logger: logger}),
	}
	if authMW := buildAuthHTTPMiddleware(cfg, logger); authMW != nil {
		httpMiddlewares = append(httpMiddlewares, authMW)
	}
	if rlMW := buildRateLimitHTTPMiddleware(cfg); rlMW != nil {
		httpMiddlewares = append(httpMiddlewares, rlMW)
	}
	router := server.NewRouter(server.RouterConfig{
		Handler:         handler,
		Chain:           chain,
		HealthChecker:   healthChecker,
		Metrics:         metrics,
		MaxBodyBytes:    cfg.Server.MaxBodyBytes,
		HTTPMiddlewares: httpMiddlewares,
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

	// Start metrics server if enabled
	if cfg.Metrics.Enabled {
		go startMetricsServer(cfg.Metrics, metrics, logger)
	}

	// Start health checks
	healthChecker.Start()
	defer healthChecker.Stop()

	logger.Info("Server starting",
		zap.String("address", fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)),
		zap.Bool("tls", cfg.Server.TLS.Enabled),
	)

	// Watch for parent-context cancellation (signal received) and
	// trigger graceful shutdown. srv.Start() will then return
	// http.ErrServerClosed and main can exit cleanly.
	go func() {
		<-ctx.Done()
		logger.Info("Shutdown signal received; draining",
			zap.Duration("timeout", shutdownTimeout))
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			logger.Error("Server shutdown error", zap.Error(err))
		}
	}()

	// Start server (blocks until Shutdown is called)
	return srv.Start()
}

// buildMiddlewareChain creates the middleware chain from configuration.
func buildMiddlewareChain(cfg *config.Config, logger *zap.Logger, metrics *observability.Metrics) (*middleware.Chain, error) {
	var middlewares []middleware.Middleware

	for _, mwCfg := range cfg.Middleware {
		mw, err := createMiddleware(mwCfg, logger, metrics)
		if err != nil {
			return nil, fmt.Errorf("failed to create middleware %s: %w", mwCfg.Name, err)
		}
		if mw != nil {
			middlewares = append(middlewares, mw)
		}
	}

	// Authz lives under its own top-level `authz:` config rather than
	// the middleware list. Build it after the list so its CQL2
	// injection sees any earlier mutations.
	if mw, err := buildAuthzMiddleware(cfg, logger); err != nil {
		return nil, fmt.Errorf("failed to create authz middleware: %w", err)
	} else if mw != nil {
		middlewares = append(middlewares, mw)
	}

	return middleware.NewChain(middlewares...), nil
}

// buildAuthzMiddleware wires the authz middleware (including CQL2
// injection) from the top-level authz config. Returns (nil, nil) when
// authz is not configured.
func buildAuthzMiddleware(cfg *config.Config, logger *zap.Logger) (middleware.Middleware, error) {
	az := cfg.Authz
	if az == nil {
		return nil, nil
	}
	if az.OPA == nil {
		return nil, nil
	}

	var enforcer authz.Enforcer
	if az.OPA.Embedded {
		opaCfg := authz.EmbeddedOPAConfig{
			Name:        "embedded-opa",
			PolicyPaths: az.OPA.RegoFiles,
		}
		enf, err := authz.NewEmbeddedOPAEnforcer(opaCfg)
		if err != nil {
			return nil, err
		}
		enforcer = enf
	} else {
		return nil, fmt.Errorf("only embedded OPA is wired today; external OPA URL=%q", az.OPA.URL)
	}

	cql2Enabled := false
	if az.CQL2Injection != nil {
		cql2Enabled = az.CQL2Injection.Enabled
	}

	// Single-origin: gate push-down on cfg.Upstream.SupportsFilterExtension.
	// Federation: conservative AND across configured origins (only push
	// down when every enabled origin advertises Filter Extension
	// support). Per-request origin-routing is a future refinement.
	var filterCheck func(_ *middleware.STACRequest) bool
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
		if any && allSupport {
			filterCheck = func(_ *middleware.STACRequest) bool { return true }
		} else {
			filterCheck = func(_ *middleware.STACRequest) bool { return false }
		}
	} else if cfg.Upstream != nil {
		supports := cfg.Upstream.SupportsFilterExtension
		filterCheck = func(_ *middleware.STACRequest) bool { return supports }
	}

	logger.Info("authz middleware configured",
		zap.Bool("cql2_injection", cql2Enabled),
		zap.Bool("filter_extension_check", filterCheck != nil),
	)

	return authz.NewAuthzMiddleware(authz.AuthzMiddlewareConfig{
		Enforcer:             enforcer,
		AllowAnonymous:       true,
		CQL2InjectionEnabled: cql2Enabled,
		FilterExtensionCheck: filterCheck,
	}), nil
}

// createMiddleware creates a middleware from configuration.
func createMiddleware(cfg config.MiddlewareConfig, logger *zap.Logger, metrics *observability.Metrics) (middleware.Middleware, error) {
	switch cfg.Name {
	case "logging":
		// Logging is wired as chi middleware at the router level, not
		// in the buffered chain. Silently skip the config entry so old
		// YAMLs that listed it continue to load without error.
		return nil, nil

	case "auth":
		// Auth is wired as chi middleware at the router level (see
		// buildAuthHTTPMiddleware). Silently skip the legacy chain entry.
		return nil, nil

	case "cache":
		return buildCacheMiddleware(cfg.Config)

	case "rate_limit":
		// Rate limit is wired as chi middleware at the router level.
		return nil, nil

	case "url_remap":
		return buildRemapMiddleware(cfg.Config)

	default:
		logger.Warn("Unknown middleware, skipping", zap.String("name", cfg.Name))
		return nil, nil
	}
}

// buildAuthHTTPMiddleware builds the chi-style auth middleware from the
// `auth` block of the middleware config list. Returns nil when no
// `auth` block is configured — the router skips a nil entry.
func buildAuthHTTPMiddleware(cfg *config.Config, logger *zap.Logger) func(http.Handler) http.Handler {
	var rawCfg map[string]interface{}
	for _, mw := range cfg.Middleware {
		if mw.Name == "auth" {
			rawCfg = mw.Config
			break
		}
	}
	if rawCfg == nil {
		return nil
	}

	allowAnonymous := true
	if v, ok := rawCfg["allow_anonymous"].(bool); ok {
		allowAnonymous = v
	}

	var providers []auth.Provider
	if providersCfg, ok := rawCfg["providers"].([]interface{}); ok {
		for _, pCfg := range providersCfg {
			pMap, ok := pCfg.(map[string]interface{})
			if !ok {
				continue
			}
			switch pMap["type"] {
			case "bearer", "jwt":
				bearerCfg := auth.BearerConfig{
					Name:     "bearer",
					Issuer:   getStringConfig(pMap, "issuer"),
					Audience: getStringConfig(pMap, "audience"),
					JWKSURL:  getStringConfig(pMap, "jwks_url"),
				}
				if s := getStringConfig(pMap, "secret"); s != "" {
					bearerCfg.Secret = []byte(s)
				}
				provider, err := auth.NewBearerProvider(bearerCfg)
				if err != nil {
					logger.Warn("Failed to create bearer provider", zap.Error(err))
					continue
				}
				providers = append(providers, provider)
			case "api_key":
				provider, err := auth.NewAPIKeyProvider(auth.APIKeyConfig{
					Name:       "api_key",
					Header:     getStringConfig(pMap, "header_name"),
					QueryParam: getStringConfig(pMap, "query_param"),
				})
				if err != nil {
					logger.Warn("Failed to create API key provider", zap.Error(err))
					continue
				}
				providers = append(providers, provider)
			}
		}
	}

	return auth.NewHTTPMiddleware(auth.Config{
		Providers:      providers,
		AllowAnonymous: allowAnonymous,
	})
}

// buildCacheMiddleware creates caching middleware.
func buildCacheMiddleware(cfg map[string]interface{}) (middleware.Middleware, error) {
	storeType := "memory"
	if v, ok := cfg["store"].(string); ok {
		storeType = v
	}

	var store cache.Store
	switch storeType {
	case "memory":
		maxSize := 10000
		if v, ok := cfg["max_size"].(int); ok {
			maxSize = v
		}
		store = cache.NewMemoryStore(cache.MemoryConfig{MaxSize: maxSize})

	default:
		return nil, fmt.Errorf("unknown cache store type: %s", storeType)
	}

	return cache.NewMiddleware(cache.Config{
		Store:    store,
		Strategy: nil, // use BasicStrategy default
	}), nil
}

// buildRateLimitHTTPMiddleware builds the chi-style rate-limit middleware
// from the `rate_limit` block of the middleware config list. Returns nil
// when no `rate_limit` block is configured.
func buildRateLimitHTTPMiddleware(cfg *config.Config) func(http.Handler) http.Handler {
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

	requests := 1000
	if v, ok := rawCfg["requests"].(int); ok {
		requests = v
	}
	window := 1 * time.Hour
	if v, ok := rawCfg["window"].(string); ok {
		if d, err := time.ParseDuration(v); err == nil {
			window = d
		}
	}
	burst := 50
	if v, ok := rawCfg["burst"].(int); ok {
		burst = v
	}

	return ratelimit.NewHTTPMiddleware(ratelimit.Config{
		DefaultQuota: ratelimit.Quota{
			Requests: requests,
			Window:   window,
			Burst:    burst,
		},
	})
}

// buildRemapMiddleware creates URL remapping middleware.
func buildRemapMiddleware(cfg map[string]interface{}) (middleware.Middleware, error) {
	var rules []remap.RuleConfig

	if rulesCfg, ok := cfg["rules"].([]interface{}); ok {
		for _, rCfg := range rulesCfg {
			rMap, ok := rCfg.(map[string]interface{})
			if !ok {
				continue
			}
			rules = append(rules, remap.RuleConfig{
				Match:   getStringConfig(rMap, "match"),
				Replace: getStringConfig(rMap, "replace"),
			})
		}
	}

	return remap.NewMiddleware(remap.Config{Rules: rules})
}

// buildFederationHandler creates the federation handler. In
// single-origin mode (cfg.Mode != "federation") it synthesizes a
// single-element Origins list from cfg.Upstream, so the same code
// path handles both deployment shapes.
func buildFederationHandler(cfg *config.Config, logger *zap.Logger, health *observability.HealthChecker, metrics *observability.Metrics) (middleware.Handler, error) {
	// Single-origin → federation-of-1 translation.
	if !cfg.IsFederation() {
		return buildSingleOriginAsFederation(cfg, logger, health)
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
			Auth:                    originAuthConfig(originCfg.Auth),
		}
		origins = append(origins, origin)

		// Add to health checker — bind the URL into a local Check so we
		// don't capture the loop variable.
		baseURL := originCfg.BaseURL
		health.AddCheck(observability.NewOriginCheck(originCfg.ID, baseURL))

		logger.Info("Configured origin",
			zap.String("id", originCfg.ID),
			zap.String("url", originCfg.BaseURL),
			zap.Int("priority", originCfg.Priority),
			zap.Bool("filter_extension", supportsFilter),
		)
	}

	// Create handler
	conflictStrategy := federation.ConflictPriorityWins
	switch cfg.Federation.ConflictStrategy {
	case "first_wins":
		conflictStrategy = federation.ConflictFirstWins
	case "merge":
		conflictStrategy = federation.ConflictMerge
	case "namespace":
		conflictStrategy = federation.ConflictNamespace
	}

	return federation.NewHandler(federation.HandlerConfig{
		Origins:          origins,
		ConflictStrategy: conflictStrategy,
		MaxConcurrent:    cfg.Federation.MaxConcurrent,
		AggregateTimeout: cfg.Federation.AggregateTimeout,
		DefaultPageSize:  cfg.Federation.DefaultPageSize,
		MaxPageSize:      cfg.Federation.MaxPageSize,
	})
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
		}
	}
	return auth
}

// buildSingleOriginAsFederation builds a federation handler from a
// single-origin cfg.Upstream — i.e. the "single" mode collapses to a
// federation-of-1 so we only carry one request pipeline.
func buildSingleOriginAsFederation(cfg *config.Config, logger *zap.Logger, health *observability.HealthChecker) (middleware.Handler, error) {
	if cfg.Upstream == nil {
		return nil, fmt.Errorf("single mode requires upstream config")
	}

	timeout := cfg.Upstream.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	// Add upstream health check
	health.AddCheck(observability.NewOriginCheck("upstream", cfg.Upstream.URL))

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
		zap.String("url", cfg.Upstream.URL),
		zap.Bool("filter_extension", supportsFilter),
	)

	return federation.NewHandler(federation.HandlerConfig{
		Origins:          []*federation.Origin{origin},
		ConflictStrategy: federation.ConflictPriorityWins,
		ProxyBaseURL:     "",
	})
}

// startMetricsServer starts the Prometheus metrics server.
func startMetricsServer(cfg config.MetricsConfig, metrics *observability.Metrics, logger *zap.Logger) {
	addr := fmt.Sprintf(":%d", cfg.Port)
	logger.Info("Starting metrics server", zap.String("address", addr))

	mux := http.NewServeMux()
	mux.Handle(cfg.Path, metrics.Handler())

	server := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("Metrics server error", zap.Error(err))
	}
}

// initLogger creates a configured zap logger.
func initLogger(cfg config.LoggingConfig) (*zap.Logger, error) {
	level := zapcore.InfoLevel
	switch cfg.Level {
	case "debug":
		level = zapcore.DebugLevel
	case "info":
		level = zapcore.InfoLevel
	case "warn":
		level = zapcore.WarnLevel
	case "error":
		level = zapcore.ErrorLevel
	}

	var encoder zapcore.Encoder
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.TimeKey = "timestamp"
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	switch cfg.Format {
	case "json":
		encoder = zapcore.NewJSONEncoder(encoderConfig)
	case "console", "text":
		encoder = zapcore.NewConsoleEncoder(encoderConfig)
	default:
		encoder = zapcore.NewJSONEncoder(encoderConfig)
	}

	core := zapcore.NewCore(
		encoder,
		zapcore.AddSync(os.Stdout),
		level,
	)

	return zap.New(core, zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel)), nil
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
func probeFilterExtension(logger *zap.Logger, id, baseURL string) bool {
	probeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ok, err := stac.ProbeFilterExtension(probeCtx, nil, baseURL)
	switch {
	case err != nil:
		logger.Warn("conformance probe failed; assuming no Filter Extension",
			zap.String("origin", id), zap.Error(err))
		return false
	case ok:
		logger.Info("conformance probe: Filter Extension supported",
			zap.String("origin", id))
		return true
	default:
		logger.Info("conformance probe: Filter Extension not advertised",
			zap.String("origin", id))
		return false
	}
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
