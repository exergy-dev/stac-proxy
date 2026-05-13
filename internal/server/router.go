// Package server provides HTTP routing.
package server

import (
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"

	"github.com/yourorg/stac-proxy/internal/middleware"
	"github.com/yourorg/stac-proxy/internal/observability"
)

// DefaultMaxBodyBytes is the body-size limit used when RouterConfig
// leaves MaxBodyBytes at zero. Sized for a generous STAC search body
// (large GeoJSON intersects polygons are the worst case).
const DefaultMaxBodyBytes int64 = 1 << 20 // 1 MiB

// Router wraps chi router with STAC-specific functionality.
type Router struct {
	*chi.Mux
	handler       http.Handler
	healthChecker *observability.HealthChecker
	metrics       *observability.Metrics
}

// RouterConfig contains router configuration.
type RouterConfig struct {
	// Handler is the inner http.Handler (typically *federation.Handler)
	// that the chi-style middleware chain wraps. It reads STACInfo from
	// the request context.
	Handler       http.Handler
	HealthChecker *observability.HealthChecker
	Metrics       *observability.Metrics
	ProxyBaseURL  string
	// MaxBodyBytes caps the size of any inbound request body. 0 uses
	// DefaultMaxBodyBytes; negative disables the cap.
	MaxBodyBytes int64
	// HTTPMiddlewares are chi-style middlewares registered via r.Use
	// before the inner handler runs.
	HTTPMiddlewares []func(http.Handler) http.Handler
}

// NewRouter creates a new router with STAC API endpoints.
func NewRouter(cfg RouterConfig) *Router {
	r := &Router{
		Mux:           chi.NewRouter(),
		handler:       cfg.Handler,
		healthChecker: cfg.HealthChecker,
		metrics:       cfg.Metrics,
	}

	// Standard middleware
	r.Use(chimiddleware.RequestID)
	r.Use(chimiddleware.RealIP)
	r.Use(chimiddleware.Recoverer)

	// Operator-supplied chi middlewares (logging, etc.).
	for _, mw := range cfg.HTTPMiddlewares {
		r.Use(mw)
	}

	// Cap inbound bodies before any handler reads them.
	limit := cfg.MaxBodyBytes
	if limit == 0 {
		limit = DefaultMaxBodyBytes
	}
	if limit > 0 {
		r.Use(bodyLimitMiddleware(limit))
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

// dispatch attaches STACInfo to req.Context() so chi-layer middlewares
// can read the parsed STAC shape, then delegates to the inner handler.
// Request-level metrics are recorded after the handler returns.
func (r *Router) dispatch(w http.ResponseWriter, req *http.Request, rt middleware.RequestType, collection, itemID string) {
	start := time.Now()
	info := &middleware.STACInfo{RequestType: rt, Collection: collection, ItemID: itemID}
	ctx := middleware.WithSTACInfo(req.Context(), info)
	req = req.WithContext(ctx)

	sw := &statusWriter{ResponseWriter: w}
	r.handler.ServeHTTP(sw, req)
	r.observeRequest(req, sw.status, start)
}

// statusWriter captures the response status code for the metrics path.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (s *statusWriter) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

// observeRequest records end-to-end request duration and a status-coded
// counter. Status 0 means the handler returned an error before producing
// a response; the handler's structured error mapping picks the final
// status code.
func (r *Router) observeRequest(req *http.Request, status int, start time.Time) {
	if r.metrics == nil {
		return
	}
	path := req.URL.Path
	r.metrics.RequestDuration.WithLabelValues(req.Method, path).Observe(time.Since(start).Seconds())
	if status != 0 {
		r.metrics.RequestsTotal.WithLabelValues(req.Method, path, strconv.Itoa(status)).Inc()
	}
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
