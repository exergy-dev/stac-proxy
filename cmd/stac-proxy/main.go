// Package main is the entry point for stac-proxy.
package main

import (
	"context"
	"crypto/subtle"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

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
	// Initialize metrics and publish them as the process-wide
	// default so middleware/handlers can emit without us threading
	// the Metrics pointer through every constructor.
	metrics := observability.NewMetrics("stac_proxy")
	observability.SetDefault(metrics)

	// Initialize health checker
	healthChecker := observability.NewHealthChecker()
	healthChecker.Verbose = cfg.Health.Verbose

	// Build the federation handler. Single-origin mode is modeled as a
	// federation-of-1 — the single-origin code path collapses into
	// reverseProxyOnce against the synthetic "primary" origin.
	handler, err := buildFederationHandler(ctx, cfg, logger, healthChecker, metrics)
	if err != nil {
		return fmt.Errorf("failed to build handler: %w", err)
	}

	// Create router. Stateless middlewares are wired at the chi
	// router level rather than inside the buffered Chain so they sit
	// at the request boundary without per-iteration overhead.
	//
	// Order matters:
	//   logging → auth → ratelimit → authz → cache → remap
	//
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
	if authMW := buildAuthHTTPMiddleware(cfg, logger); authMW != nil {
		httpMiddlewares = append(httpMiddlewares, authMW)
	}
	if rlMW := buildRateLimitHTTPMiddleware(cfg); rlMW != nil {
		httpMiddlewares = append(httpMiddlewares, rlMW)
	}
	if azMW, err := buildAuthzHTTPMiddleware(cfg, logger); err != nil {
		return fmt.Errorf("failed to build authz middleware: %w", err)
	} else if azMW != nil {
		httpMiddlewares = append(httpMiddlewares, azMW)
	}
	if cMW, err := buildCacheHTTPMiddleware(cfg); err != nil {
		return fmt.Errorf("failed to build cache middleware: %w", err)
	} else if cMW != nil {
		httpMiddlewares = append(httpMiddlewares, cMW)
	}
	if rmMW, err := buildRemapHTTPMiddleware(cfg); err != nil {
		return fmt.Errorf("failed to build remap middleware: %w", err)
	} else if rmMW != nil {
		httpMiddlewares = append(httpMiddlewares, rmMW)
	}
	if len(cfg.Server.TrustedProxies) == 0 && !isLoopbackAddr(cfg.Server.Host) {
		logger.Info("XFF will be ignored; set Server.TrustedProxies if behind a load balancer",
			"host", cfg.Server.Host,
		)
	}
	router := server.NewRouter(server.RouterConfig{
		Handler:         handler,
		HealthChecker:   healthChecker,
		Metrics:         metrics,
		MaxBodyBytes:    cfg.Server.MaxBodyBytes,
		HTTPMiddlewares: httpMiddlewares,
		TrustedProxies:  cfg.Server.TrustedProxies,
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

	// Start metrics server if enabled
	if cfg.Metrics.Enabled {
		go startMetricsServer(cfg.Metrics, metrics, logger)
	}

	// Start health checks
	healthChecker.Start()
	defer healthChecker.Stop()

	logger.Info("Server starting",
		"address", fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		"tls", cfg.Server.TLS.Enabled,
	)

	// Watch for parent-context cancellation (signal received) and
	// trigger graceful shutdown. srv.Start() will then return
	// http.ErrServerClosed and main can exit cleanly.
	go func() {
		<-ctx.Done()
		logger.Info("Shutdown signal received; draining",
			"timeout", shutdownTimeout)
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
func buildAuthzHTTPMiddleware(cfg *config.Config, logger *slog.Logger) (func(http.Handler) http.Handler, error) {
	az := cfg.Authz
	if az == nil || az.OPA == nil {
		return nil, nil
	}

	var enforcer authz.Enforcer
	if az.OPA.Embedded {
		enf, err := authz.NewEmbeddedOPAEnforcer(authz.EmbeddedOPAConfig{
			Name:        "embedded-opa",
			PolicyPaths: az.OPA.RegoFiles,
		})
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

// buildAuthHTTPMiddleware builds the chi-style auth middleware from the
// `auth` block of the middleware config list. Returns nil when no
// `auth` block is configured — the router skips a nil entry.
func buildAuthHTTPMiddleware(cfg *config.Config, logger *slog.Logger) func(http.Handler) http.Handler {
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
					logger.Warn("Failed to create bearer provider", "error", err)
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
					logger.Warn("Failed to create API key provider", "error", err)
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

// buildCacheHTTPMiddleware builds the chi-style cache middleware from
// the `cache` block of the middleware config list. Returns (nil, nil)
// when no block is configured.
func buildCacheHTTPMiddleware(cfg *config.Config) (func(http.Handler) http.Handler, error) {
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
	return cache.NewFromConfig(rawCfg)
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

// buildFederationHandler creates the federation handler. In
// single-origin mode (cfg.Mode != "federation") it synthesizes a
// single-element Origins list from cfg.Upstream, so the same code
// path handles both deployment shapes.
func buildFederationHandler(ctx context.Context, cfg *config.Config, logger *slog.Logger, health *observability.HealthChecker, metrics *observability.Metrics) (*federation.Handler, error) {
	// Single-origin → federation-of-1 translation.
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
			Auth:                    originAuthConfig(originCfg.Auth),
		}
		origins = append(origins, origin)

		// Add to health checker — bind the URL into a local Check so we
		// don't capture the loop variable.
		baseURL := originCfg.BaseURL
		health.AddCheck(observability.NewOriginCheck(originCfg.ID, baseURL))

		logger.Info("Configured origin",
			"id", originCfg.ID,
			"url", originCfg.BaseURL,
			"priority", originCfg.Priority,
			"filter_extension", supportsFilter,
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

	caps := computeConformanceCaps(cfg, origins)

	return federation.NewHandler(federation.HandlerConfig{
		Origins:          origins,
		ConflictStrategy: conflictStrategy,
		MaxConcurrent:    cfg.Federation.MaxConcurrent,
		AggregateTimeout: cfg.Federation.AggregateTimeout,
		DefaultPageSize:  cfg.Federation.DefaultPageSize,
		MaxPageSize:      cfg.Federation.MaxPageSize,
		ConformanceCaps:  caps,
		LifetimeCtx:      ctx,
		Logger:           logger,
		AssetSigner:      buildAssetSigner(cfg),
		CursorSecret:     []byte(cfg.Federation.CursorSecret),
	})
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
func buildSingleOriginAsFederation(ctx context.Context, cfg *config.Config, logger *slog.Logger, health *observability.HealthChecker) (*federation.Handler, error) {
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
		"url", cfg.Upstream.URL,
		"filter_extension", supportsFilter,
	)

	caps := computeConformanceCaps(cfg, []*federation.Origin{origin})

	return federation.NewHandler(federation.HandlerConfig{
		Origins:          []*federation.Origin{origin},
		ConflictStrategy: federation.ConflictPriorityWins,
		ProxyBaseURL:     "",
		ConformanceCaps:  caps,
		LifetimeCtx:      ctx,
		Logger:           logger,
	})
}

// startMetricsServer starts the Prometheus metrics server. The metrics
// listener defaults to 127.0.0.1:9090 so /metrics is not reachable
// from the public network; operators wanting cross-host scrape must
// explicitly set Metrics.BindAddr (and ideally Metrics.AuthToken).
func startMetricsServer(cfg config.MetricsConfig, metrics *observability.Metrics, logger *slog.Logger) {
	addr := cfg.BindAddr
	if addr == "" {
		port := cfg.Port
		if port == 0 {
			port = 9090
		}
		addr = fmt.Sprintf("127.0.0.1:%d", port)
	}
	logger.Info("Starting metrics server",
		"address", addr,
		"auth_required", cfg.AuthToken != "",
	)

	path := cfg.Path
	if path == "" {
		path = "/metrics"
	}

	handler := metrics.Handler()
	if cfg.AuthToken != "" {
		token := "Bearer " + cfg.AuthToken
		inner := handler
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte(token)) != 1 {
				w.Header().Set("WWW-Authenticate", `Bearer realm="metrics"`)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			inner.ServeHTTP(w, r)
		})
	}

	mux := http.NewServeMux()
	mux.Handle(path, handler)

	server := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("Metrics server error", "error", err)
	}
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

// isLoopbackAddr reports whether host is loopback (empty string,
// "localhost", 127.0.0.0/8, ::1). Used to decide whether to nag the
// operator about missing TrustedProxies — silent for dev binds.
func isLoopbackAddr(host string) bool {
	if host == "" || host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}
