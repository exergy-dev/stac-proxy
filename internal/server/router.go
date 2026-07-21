// Package server provides HTTP routing.
package server

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"

	"github.com/yourorg/stac-proxy/internal/observability"
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
}

// NewRouter creates a new router with STAC API endpoints.
func NewRouter(cfg RouterConfig) *Router {
	r := &Router{
		Mux:           chi.NewRouter(),
		handler:       cfg.Handler,
		healthChecker: cfg.HealthChecker,
		assetHandler:  cfg.AssetHandler,
	}

	// Standard middleware. RealIP overwrites r.RemoteAddr from
	// True-Client-IP / X-Real-IP / X-Forwarded-For when present so
	// downstream middleware (ratelimit, authz, logging) sees the
	// claimed client IP. NOTE: this trusts these headers
	// unconditionally — deploy behind a reverse proxy that strips or
	// overwrites them; do NOT expose this listener directly.
	r.Use(chimiddleware.RequestID)
	r.Use(chimiddleware.RealIP)
	r.Use(chimiddleware.Recoverer)

	// Cap inbound bodies before any handler reads them. Must run
	// before searchParser (which reads POST /search bodies) and
	// before any operator-supplied middleware that might consume
	// the body.
	limit := cfg.MaxBodyBytes
	if limit == 0 {
		limit = DefaultMaxBodyBytes
	}
	if limit > 0 {
		r.Use(bodyLimitMiddleware(limit))
	}

	// Classify the route and attach STACInfo BEFORE the search parser
	// and operator middlewares — both read it from the context, and
	// context values attached later (in the route handler) are
	// invisible to them. See stacInfoClassifier.
	r.Use(stacInfoClassifier(r.Mux))

	// Parse search bodies/queries before authz so authz constraint
	// enforcement (AllowedCollections, DeniedCollections,
	// RequiredFilters) can mutate the parsed SearchRequest. Must
	// run before cfg.HTTPMiddlewares so authz lives in.
	r.Use(searchParserMiddleware())

	// Operator-supplied chi middlewares (logging, authz, ratelimit,
	// cache, remap).
	for _, mw := range cfg.HTTPMiddlewares {
		r.Use(mw)
	}

	// Mount health endpoints
	if cfg.HealthChecker != nil {
		r.Get("/health", cfg.HealthChecker.HealthHandler())
		r.Get("/health/live", cfg.HealthChecker.LivenessHandler())
		r.Get("/health/ready", cfg.HealthChecker.ReadinessHandler())
	}

	// STAC API routes
	// Every catalog route delegates to the same inner handler; the
	// request's STAC shape was already attached by stacInfoClassifier
	// (route patterns and types live in classifier.go's
	// routePatternTypes — one map, guarded by a chi.Walk test).
	r.Get("/", r.serve)
	r.Get("/conformance", r.serve)
	r.Get("/collections", r.serve)
	r.Get("/collections/{collectionId}", r.serve)
	r.Get("/collections/{collectionId}/items", r.serve)
	r.Get("/collections/{collectionId}/items/{itemId}", r.serve)
	r.Get("/search", r.serve)
	r.Post("/search", r.serve)
	r.Get("/queryables", r.serve)
	r.Get("/collections/{collectionId}/queryables", r.serve)

	// Asset streaming endpoint — only mounted when the deployment
	// actually has an asset handler. Kept off the chi tree otherwise
	// so the surface stays minimal in single-origin / pass-through
	// deployments.
	if r.assetHandler != nil {
		r.Get("/assets/{originId}/{ref}", r.handleAsset)
		r.Head("/assets/{originId}/{ref}", r.handleAsset)
	}

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
