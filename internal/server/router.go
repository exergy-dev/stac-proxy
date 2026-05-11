// Package server provides HTTP routing.
package server

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"

	"github.com/yourorg/stac-proxy/internal/middleware"
	"github.com/yourorg/stac-proxy/internal/observability"
)

// Router wraps chi router with STAC-specific functionality.
type Router struct {
	*chi.Mux
	handler       middleware.Handler
	chain         *middleware.Chain
	healthChecker *observability.HealthChecker
	metrics       *observability.Metrics
}

// RouterConfig contains router configuration.
type RouterConfig struct {
	Handler       middleware.Handler
	Chain         *middleware.Chain
	HealthChecker *observability.HealthChecker
	Metrics       *observability.Metrics
	ProxyBaseURL  string
}

// NewRouter creates a new router with STAC API endpoints.
func NewRouter(cfg RouterConfig) *Router {
	r := &Router{
		Mux:           chi.NewRouter(),
		handler:       cfg.Handler,
		chain:         cfg.Chain,
		healthChecker: cfg.HealthChecker,
		metrics:       cfg.Metrics,
	}

	// Standard middleware
	r.Use(chimiddleware.RequestID)
	r.Use(chimiddleware.RealIP)
	r.Use(chimiddleware.Recoverer)

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

	// Admin endpoints
	r.Route("/_admin", func(admin chi.Router) {
		admin.Get("/config", r.handleAdminConfig)
		admin.Get("/origins", r.handleAdminOrigins)
		admin.Post("/cache/clear", r.handleAdminCacheClear)
	})

	return r
}

// handleLanding handles GET /
func (r *Router) handleLanding(w http.ResponseWriter, req *http.Request) {
	stacReq := r.buildSTACRequest(req, middleware.RequestTypeLanding)
	r.executeHandler(w, stacReq)
}

// handleConformance handles GET /conformance
func (r *Router) handleConformance(w http.ResponseWriter, req *http.Request) {
	stacReq := r.buildSTACRequest(req, middleware.RequestTypeConformance)
	r.executeHandler(w, stacReq)
}

// handleCollections handles GET /collections
func (r *Router) handleCollections(w http.ResponseWriter, req *http.Request) {
	stacReq := r.buildSTACRequest(req, middleware.RequestTypeCollections)
	r.executeHandler(w, stacReq)
}

// handleCollection handles GET /collections/{collectionId}
func (r *Router) handleCollection(w http.ResponseWriter, req *http.Request) {
	stacReq := r.buildSTACRequest(req, middleware.RequestTypeCollection)
	stacReq.Collection = chi.URLParam(req, "collectionId")
	r.executeHandler(w, stacReq)
}

// handleItems handles GET /collections/{collectionId}/items
func (r *Router) handleItems(w http.ResponseWriter, req *http.Request) {
	stacReq := r.buildSTACRequest(req, middleware.RequestTypeItems)
	stacReq.Collection = chi.URLParam(req, "collectionId")
	r.executeHandler(w, stacReq)
}

// handleItem handles GET /collections/{collectionId}/items/{itemId}
func (r *Router) handleItem(w http.ResponseWriter, req *http.Request) {
	stacReq := r.buildSTACRequest(req, middleware.RequestTypeItem)
	stacReq.Collection = chi.URLParam(req, "collectionId")
	stacReq.ItemID = chi.URLParam(req, "itemId")
	r.executeHandler(w, stacReq)
}

// handleSearch handles GET/POST /search
func (r *Router) handleSearch(w http.ResponseWriter, req *http.Request) {
	stacReq := r.buildSTACRequest(req, middleware.RequestTypeSearch)
	r.executeHandler(w, stacReq)
}

// handleQueryables handles GET /queryables
func (r *Router) handleQueryables(w http.ResponseWriter, req *http.Request) {
	stacReq := r.buildSTACRequest(req, middleware.RequestTypeQueryables)
	r.executeHandler(w, stacReq)
}

// handleCollectionQueryables handles GET /collections/{collectionId}/queryables
func (r *Router) handleCollectionQueryables(w http.ResponseWriter, req *http.Request) {
	stacReq := r.buildSTACRequest(req, middleware.RequestTypeCollectionQueryables)
	stacReq.Collection = chi.URLParam(req, "collectionId")
	r.executeHandler(w, stacReq)
}

// handleAdminConfig handles GET /_admin/config
func (r *Router) handleAdminConfig(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status": "ok"}`))
}

// handleAdminOrigins handles GET /_admin/origins
func (r *Router) handleAdminOrigins(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"origins": []}`))
}

// handleAdminCacheClear handles POST /_admin/cache/clear
func (r *Router) handleAdminCacheClear(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"cleared": true}`))
}

// buildSTACRequest creates a STACRequest from an HTTP request.
func (r *Router) buildSTACRequest(req *http.Request, requestType middleware.RequestType) *middleware.STACRequest {
	return &middleware.STACRequest{
		Request:     req,
		Context:     req.Context(),
		RequestType: requestType,
		Params:      make(map[string]interface{}),
	}
}

// executeHandler runs the request through the middleware chain and handler.
func (r *Router) executeHandler(w http.ResponseWriter, stacReq *middleware.STACRequest) {
	var resp *middleware.STACResponse
	var err error

	if r.chain != nil {
		// Execute through middleware chain
		wrappedHandler := r.chain.Wrap(r.handler)
		resp, err = wrappedHandler.Handle(stacReq.Context, stacReq)
	} else {
		// Execute handler directly
		resp, err = r.handler.Handle(stacReq.Context, stacReq)
	}

	if err != nil {
		r.handleError(w, err)
		return
	}

	r.writeResponse(w, resp)
}

// handleError writes an error response.
func (r *Router) handleError(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json")

	switch e := err.(type) {
	case *middleware.AuthError:
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"code": "Unauthorized", "description": "` + e.Message + `"}`))
	case *middleware.ForbiddenError:
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"code": "Forbidden", "description": "` + e.Reason + `"}`))
	case *middleware.RateLimitError:
		w.Header().Set("Retry-After", string(rune(e.RetryAfter)))
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte(`{"code": "RateLimitExceeded", "description": "Rate limit exceeded"}`))
	default:
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"code": "InternalError", "description": "` + err.Error() + `"}`))
	}
}

// writeResponse writes a STAC response.
func (r *Router) writeResponse(w http.ResponseWriter, resp *middleware.STACResponse) {
	// Copy headers
	for key, values := range resp.Headers {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// Set content type if not set
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "application/json")
	}

	w.WriteHeader(resp.StatusCode)
	w.Write(resp.Body)
}
