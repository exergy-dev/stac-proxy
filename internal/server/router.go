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

// buildSTACRequest creates a STACRequest from an HTTP request.
func (r *Router) buildSTACRequest(req *http.Request, requestType middleware.RequestType) *middleware.STACRequest {
	return &middleware.STACRequest{
		Request:     req,
		Context:     req.Context(),
		RequestType: requestType,
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
