// Package server provides HTTP routing.
package server

import (
	"encoding/json"
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
	// MaxBodyBytes caps the size of any inbound request body. 0 uses
	// DefaultMaxBodyBytes; negative disables the cap.
	MaxBodyBytes int64
	// HTTPMiddlewares are chi-style middlewares registered via r.Use
	// BEFORE the buffered middleware Chain runs. Used for cross-cutting
	// concerns that don't need the parsed STACResponse (logging,
	// request-ID forwarding, etc.).
	HTTPMiddlewares []func(http.Handler) http.Handler
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
	r.executeHandler(w, r.buildSTACRequest(req, middleware.RequestTypeLanding, "", ""))
}

// handleConformance handles GET /conformance
func (r *Router) handleConformance(w http.ResponseWriter, req *http.Request) {
	r.executeHandler(w, r.buildSTACRequest(req, middleware.RequestTypeConformance, "", ""))
}

// handleCollections handles GET /collections
func (r *Router) handleCollections(w http.ResponseWriter, req *http.Request) {
	r.executeHandler(w, r.buildSTACRequest(req, middleware.RequestTypeCollections, "", ""))
}

// handleCollection handles GET /collections/{collectionId}
func (r *Router) handleCollection(w http.ResponseWriter, req *http.Request) {
	r.executeHandler(w, r.buildSTACRequest(req, middleware.RequestTypeCollection, chi.URLParam(req, "collectionId"), ""))
}

// handleItems handles GET /collections/{collectionId}/items
func (r *Router) handleItems(w http.ResponseWriter, req *http.Request) {
	r.executeHandler(w, r.buildSTACRequest(req, middleware.RequestTypeItems, chi.URLParam(req, "collectionId"), ""))
}

// handleItem handles GET /collections/{collectionId}/items/{itemId}
func (r *Router) handleItem(w http.ResponseWriter, req *http.Request) {
	r.executeHandler(w, r.buildSTACRequest(req, middleware.RequestTypeItem, chi.URLParam(req, "collectionId"), chi.URLParam(req, "itemId")))
}

// handleSearch handles GET/POST /search
func (r *Router) handleSearch(w http.ResponseWriter, req *http.Request) {
	r.executeHandler(w, r.buildSTACRequest(req, middleware.RequestTypeSearch, "", ""))
}

// handleQueryables handles GET /queryables
func (r *Router) handleQueryables(w http.ResponseWriter, req *http.Request) {
	r.executeHandler(w, r.buildSTACRequest(req, middleware.RequestTypeQueryables, "", ""))
}

// handleCollectionQueryables handles GET /collections/{collectionId}/queryables
func (r *Router) handleCollectionQueryables(w http.ResponseWriter, req *http.Request) {
	r.executeHandler(w, r.buildSTACRequest(req, middleware.RequestTypeCollectionQueryables, chi.URLParam(req, "collectionId"), ""))
}

// buildSTACRequest creates a STACRequest from an HTTP request AND
// attaches the matching STACInfo to the request's context so chi-style
// middlewares can read the parsed STAC shape via STACInfoFromContext.
func (r *Router) buildSTACRequest(req *http.Request, rt middleware.RequestType, collection, itemID string) *middleware.STACRequest {
	info := &middleware.STACInfo{RequestType: rt, Collection: collection, ItemID: itemID}
	ctx := middleware.WithSTACInfo(req.Context(), info)
	req = req.WithContext(ctx)
	return &middleware.STACRequest{
		Request:     req,
		Context:     ctx,
		Collection:  collection,
		ItemID:      itemID,
		RequestType: rt,
	}
}

// executeHandler runs the request through the middleware chain and handler.
func (r *Router) executeHandler(w http.ResponseWriter, stacReq *middleware.STACRequest) {
	start := time.Now()
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
		r.observeRequest(stacReq.Request, 0, start)
		r.handleError(w, stacReq.Request, err)
		return
	}

	r.observeRequest(stacReq.Request, resp.StatusCode, start)
	r.writeResponse(w, resp)
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

// errorBody is the wire shape for STAC-style error responses.
type errorBody struct {
	Code        string `json:"code"`
	Description string `json:"description"`
	RequestID   string `json:"request_id,omitempty"`
}

// writeErrorJSON encodes a structured error response via encoding/json so
// caller-controlled strings cannot break out of the JSON document.
func writeErrorJSON(w http.ResponseWriter, status int, body errorBody) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// handleError writes a structured error response. Internal error details
// are never leaked to the client; clients receive a generic message plus
// the request ID so support can correlate against logs.
func (r *Router) handleError(w http.ResponseWriter, req *http.Request, err error) {
	rid := chimiddleware.GetReqID(req.Context())

	switch e := err.(type) {
	case *middleware.AuthError:
		writeErrorJSON(w, http.StatusUnauthorized, errorBody{
			Code:        "Unauthorized",
			Description: e.Message,
			RequestID:   rid,
		})
	case *middleware.ForbiddenError:
		writeErrorJSON(w, http.StatusForbidden, errorBody{
			Code:        "Forbidden",
			Description: e.Reason,
			RequestID:   rid,
		})
	case *middleware.RateLimitError:
		w.Header().Set("Retry-After", strconv.Itoa(e.RetryAfter))
		writeErrorJSON(w, http.StatusTooManyRequests, errorBody{
			Code:        "RateLimitExceeded",
			Description: "Rate limit exceeded",
			RequestID:   rid,
		})
	default:
		// Never leak internal error text to the client.
		writeErrorJSON(w, http.StatusInternalServerError, errorBody{
			Code:        "InternalError",
			Description: "internal error",
			RequestID:   rid,
		})
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
