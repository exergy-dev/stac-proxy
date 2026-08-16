// Package server provides HTTP routing.
package server

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"

	"github.com/exergy-dev/stac-proxy/internal/config"
	"github.com/exergy-dev/stac-proxy/internal/observability"
)

// DefaultMaxBodyBytes is the body-size limit used when RouterConfig
// leaves MaxBodyBytes at zero. Sized for a generous STAC search body
// (large GeoJSON intersects polygons are the worst case).
const DefaultMaxBodyBytes int64 = 1 << 20 // 1 MiB

// AssetHandler is the optional interface a federation.Handler can
// implement to serve /assets/{originId}/{ref} requests, used when one
// or more origins has `rewrite_assets: proxy` configured. Decoupled
// from federation.Handler via an interface so the server package
// stays consumable in test fixtures without pulling the federation
// transitive deps.
type AssetHandler interface {
	ServeAssetHTTP(w http.ResponseWriter, r *http.Request, originID, ref string)
}

// Router wraps chi router with STAC-specific functionality.
type Router struct {
	*chi.Mux
	handler       http.Handler
	healthChecker *observability.HealthChecker
	assetHandler  AssetHandler
}

// RouterConfig contains router configuration.
type RouterConfig struct {
	// Handler is the inner http.Handler (typically *federation.Handler)
	// that the chi-style middleware chain wraps. It reads STACInfo from
	// the request context.
	Handler       http.Handler
	HealthChecker *observability.HealthChecker
	ProxyBaseURL  string
	// MaxBodyBytes caps the size of any inbound request body. 0 uses
	// DefaultMaxBodyBytes; negative disables the cap.
	MaxBodyBytes int64
	// HTTPMiddlewares are chi-style middlewares registered via r.Use
	// before the inner handler runs.
	HTTPMiddlewares []func(http.Handler) http.Handler
	// AssetHandler, when set, exposes GET /assets/{originId}/{ref} for
	// origins configured with `rewrite_assets: proxy`. Typically the
	// same *federation.Handler that fronts Handler.
	AssetHandler AssetHandler
	// ClientIP selects how the client IP is derived (see
	// config.ClientIPConfig). The zero value means remote_addr.
	ClientIP config.ClientIPConfig
}

// clientIPMiddleware maps the validated client_ip config onto chi's
// ClientIPFrom* middlewares. config validation guarantees the CIDRs
// parse and the enum is closed, so the default arm is defensive only.
func clientIPMiddleware(cfg config.ClientIPConfig) func(http.Handler) http.Handler {
	switch cfg.Source {
	case "header":
		return chimiddleware.ClientIPFromHeader(cfg.Header)
	case "xff":
		return chimiddleware.ClientIPFromXFF(cfg.TrustedProxies...)
	case "xff_trusted_count":
		return chimiddleware.ClientIPFromXFFTrustedProxies(cfg.TrustedCount)
	default: // "", "remote_addr"
		return chimiddleware.ClientIPFromRemoteAddr
	}
}

// NewRouter creates a new router with STAC API endpoints.
func NewRouter(cfg RouterConfig) *Router {
	r := &Router{
		Mux:           chi.NewRouter(),
		handler:       cfg.Handler,
		healthChecker: cfg.HealthChecker,
		assetHandler:  cfg.AssetHandler,
	}

	// Standard middleware. The client-IP middleware (selected by
	// server.client_ip config) stores the derived client IP in the
	// request context; downstream consumers (ratelimit, authz,
	// logging) read it via middleware.ClientIP, which falls back to
	// the TCP peer when the configured source yields nothing.
	// r.RemoteAddr is never mutated (chi's deprecated RealIP was:
	// GO-2026-5777 — it trusted forgeable headers unconditionally).
	r.Use(chimiddleware.RequestID)
	r.Use(clientIPMiddleware(cfg.ClientIP))
	r.Use(chimiddleware.Recoverer)

	// Health endpoints mount OUTSIDE the STAC group below, so probes
	// never pass through the operator chain: liveness/readiness must
	// not require credentials (auth with allow_anonymous: false would
	// 401 the container HEALTHCHECK and every K8s probe), consume
	// rate-limit budget, or hit the cache. Probe requests also skip
	// the access log — by design; they fired every 30s.
	if cfg.HealthChecker != nil {
		r.Get("/health", cfg.HealthChecker.HealthHandler())
		r.Get("/health/live", cfg.HealthChecker.LivenessHandler())
		r.Get("/health/ready", cfg.HealthChecker.ReadinessHandler())
	}

	// Everything else — the STAC surface — lives in a group carrying
	// the body cap, classifier, search parser, and the operator chain.
	r.Group(func(g chi.Router) {
		// Cap inbound bodies before any handler reads them. Must run
		// before searchParser (which reads POST /search bodies) and
		// before any operator-supplied middleware that might consume
		// the body.
		limit := cfg.MaxBodyBytes
		if limit == 0 {
			limit = DefaultMaxBodyBytes
		}
		if limit > 0 {
			g.Use(bodyLimitMiddleware(limit))
		}

		// Classify the route and attach STACInfo BEFORE the search
		// parser and operator middlewares — both read it from the
		// context, and context values attached later (in the route
		// handler) are invisible to them. See stacInfoClassifier.
		// (Group routes register on the shared r.Mux tree, so the
		// classifier's matcher sees them.)
		g.Use(stacInfoClassifier(r.Mux))

		// Parse search bodies/queries before authz so authz constraint
		// enforcement (AllowedCollections, DeniedCollections,
		// RequiredFilters) can mutate the parsed SearchRequest. Must
		// run before cfg.HTTPMiddlewares so authz lives in.
		g.Use(searchParserMiddleware())

		// Operator-supplied chi middlewares (logging, authz, ratelimit,
		// cache, remap).
		for _, mw := range cfg.HTTPMiddlewares {
			g.Use(mw)
		}

		// STAC API routes
		// Every catalog route delegates to the same inner handler; the
		// request's STAC shape was already attached by stacInfoClassifier
		// (route patterns and types live in classifier.go's
		// routePatternTypes — one map, guarded by a chi.Walk test).
		g.Get("/", r.serve)
		g.Get("/conformance", r.serve)
		g.Get("/collections", r.serve)
		g.Get("/collections/{collectionId}", r.serve)
		g.Get("/collections/{collectionId}/items", r.serve)
		g.Get("/collections/{collectionId}/items/{itemId}", r.serve)
		g.Get("/search", r.serve)
		g.Post("/search", r.serve)
		g.Get("/queryables", r.serve)
		g.Get("/collections/{collectionId}/queryables", r.serve)

		// Asset streaming endpoint — only mounted when the deployment
		// actually has an asset handler. Kept off the chi tree otherwise
		// so the surface stays minimal in single-origin / pass-through
		// deployments.
		if r.assetHandler != nil {
			g.Get("/assets/{originId}/{ref}", r.handleAsset)
			g.Head("/assets/{originId}/{ref}", r.handleAsset)
		}
	})

	return r
}

// handleAsset proxies an asset request through to the configured
// AssetHandler. STACInfo carries RequestType=Asset and the origin ID
// in Collection so authz/ratelimit middleware can gate access using
// the same policy keys as STAC endpoints.
func (r *Router) handleAsset(w http.ResponseWriter, req *http.Request) {
	originID := chi.URLParam(req, "originId")
	ref := chi.URLParam(req, "ref")

	// STACInfo (RequestType=Asset, Collection=originID) was attached
	// by stacInfoClassifier before the middleware chain ran.

	// Delegate to the asset handler so it can stream bytes; we do NOT
	// buffer the response (asset bytes can be GB-scale and must
	// stream).
	r.assetHandler.ServeAssetHTTP(w, req, originID, ref)
}

// serve delegates to the inner handler. STACInfo was attached by
// stacInfoClassifier before the middleware chain ran; the handler
// must see THAT instance — the search parser and authz middlewares
// mutate it (SearchReq, injected constraints). If classifier coverage
// ever drifts from the route table, the inner handler rejects the
// nil-info request loudly (500) and the chi.Walk guard test fails —
// a silent per-route authz/cache bypass is not a failure mode here.
func (r *Router) serve(w http.ResponseWriter, req *http.Request) {
	r.handler.ServeHTTP(w, req)
}

// bodyLimitMiddleware wraps every request body in http.MaxBytesReader
// so reads beyond the configured cap return an error rather than
// allowing arbitrarily large payloads to be buffered into memory.
// The cap is enforced lazily — handlers that don't read the body pay
// nothing, handlers that do see an io.EOF-like error past the limit.
func bodyLimitMiddleware(limit int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Body != nil {
				r.Body = http.MaxBytesReader(w, r.Body, limit)
			}
			next.ServeHTTP(w, r)
		})
	}
}
