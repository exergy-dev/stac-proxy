// Package server provides HTTP routing.
package server

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"

	"github.com/yourorg/stac-proxy/internal/middleware"
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
	r.Get("/", r.handleLanding)
	r.Get("/conformance", r.handleConformance)
	r.Get("/collections", r.handleCollections)
	r.Get("/collections/{collectionId}", r.handleCollection)
	r.Get("/collections/{collectionId}/items", r.handleItems)
	r.Get("/collections/{collectionId}/items/{itemId}", r.handleItem)
	r.Get("/search", r.handleSearch)
	r.Post("/search", r.handleSearch)
	r.Get("/queryables", r.handleQueryables)
	r.Get("/collections/{collectionId}/queryables", r.handleCollectionQueryables)

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

// handleLanding handles GET /
func (r *Router) handleLanding(w http.ResponseWriter, req *http.Request) {
	r.dispatch(w, req, middleware.RequestTypeLanding, "", "")
}

// handleConformance handles GET /conformance
func (r *Router) handleConformance(w http.ResponseWriter, req *http.Request) {
	r.dispatch(w, req, middleware.RequestTypeConformance, "", "")
}

// handleCollections handles GET /collections
func (r *Router) handleCollections(w http.ResponseWriter, req *http.Request) {
	r.dispatch(w, req, middleware.RequestTypeCollections, "", "")
}

// handleCollection handles GET /collections/{collectionId}
func (r *Router) handleCollection(w http.ResponseWriter, req *http.Request) {
	r.dispatch(w, req, middleware.RequestTypeCollection, chi.URLParam(req, "collectionId"), "")
}

// handleItems handles GET /collections/{collectionId}/items
func (r *Router) handleItems(w http.ResponseWriter, req *http.Request) {
	r.dispatch(w, req, middleware.RequestTypeItems, chi.URLParam(req, "collectionId"), "")
}

// handleItem handles GET /collections/{collectionId}/items/{itemId}
func (r *Router) handleItem(w http.ResponseWriter, req *http.Request) {
	r.dispatch(w, req, middleware.RequestTypeItem, chi.URLParam(req, "collectionId"), chi.URLParam(req, "itemId"))
}

// handleSearch handles GET/POST /search
func (r *Router) handleSearch(w http.ResponseWriter, req *http.Request) {
	r.dispatch(w, req, middleware.RequestTypeSearch, "", "")
}

// handleQueryables handles GET /queryables
func (r *Router) handleQueryables(w http.ResponseWriter, req *http.Request) {
	r.dispatch(w, req, middleware.RequestTypeQueryables, "", "")
}

// handleCollectionQueryables handles GET /collections/{collectionId}/queryables
func (r *Router) handleCollectionQueryables(w http.ResponseWriter, req *http.Request) {
	r.dispatch(w, req, middleware.RequestTypeCollectionQueryables, chi.URLParam(req, "collectionId"), "")
}

// handleAsset proxies an asset request through to the configured
// AssetHandler. STACInfo carries RequestType=Asset and the origin ID
// in Collection so authz/ratelimit middleware can gate access using
// the same policy keys as STAC endpoints.
func (r *Router) handleAsset(w http.ResponseWriter, req *http.Request) {
	originID := chi.URLParam(req, "originId")
	ref := chi.URLParam(req, "ref")

	// Attach STACInfo so the middleware chain (authz, cache opt-out,
	// metrics) sees this as an Asset request keyed by origin.
	info := &middleware.STACInfo{
		RequestType: middleware.RequestTypeAsset,
		Collection:  originID, // reuse the Collection slot for the origin/route key
	}
	req = req.WithContext(middleware.WithSTACInfo(req.Context(), info))

	// Delegate to the asset handler so it can stream bytes; we do NOT
	// route through dispatch() because that path buffers the
	// response into memory.
	r.assetHandler.ServeAssetHTTP(w, req, originID, ref)
}

// dispatch attaches STACInfo to req.Context() so chi-layer middlewares
// can read the parsed STAC shape, then delegates to the inner handler.
func (r *Router) dispatch(w http.ResponseWriter, req *http.Request, rt middleware.RequestType, collection, itemID string) {
	info := &middleware.STACInfo{RequestType: rt, Collection: collection, ItemID: itemID}
	ctx := middleware.WithSTACInfo(req.Context(), info)
	r.handler.ServeHTTP(w, req.WithContext(ctx))
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
