// Package server provides HTTP routing.
package server

import (
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/felixge/httpsnoop"
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
	metrics       *observability.Metrics
	assetHandler  AssetHandler
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
	// AssetHandler, when set, exposes GET /assets/{originId}/{ref} for
	// origins configured with `rewrite_assets: proxy`. Typically the
	// same *federation.Handler that fronts Handler.
	AssetHandler AssetHandler
	// TrustedProxies is the list of CIDRs from which the proxy will
	// honor X-Forwarded-For when deriving the client IP. When empty
	// (the default), XFF is ignored and the client IP is taken from
	// the TCP RemoteAddr — the safe default for an internet-exposed
	// listener. Deployments behind a load balancer or CDN must list
	// the immediate-upstream CIDR(s) here to get accurate rate
	// limiting per real client.
	TrustedProxies []string
}

// NewRouter creates a new router with STAC API endpoints.
func NewRouter(cfg RouterConfig) *Router {
	r := &Router{
		Mux:           chi.NewRouter(),
		handler:       cfg.Handler,
		healthChecker: cfg.HealthChecker,
		metrics:       cfg.Metrics,
		assetHandler:  cfg.AssetHandler,
	}

	// Standard middleware. Note: chi's RealIP middleware is
	// deliberately NOT used — it parses X-Forwarded-For
	// unconditionally and is spoofable when the proxy is exposed
	// directly. clientIPMiddleware below honors XFF only when the
	// TCP peer is in TrustedProxies.
	r.Use(chimiddleware.RequestID)
	r.Use(clientIPMiddleware(cfg.TrustedProxies))
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
	m := httpsnoop.CaptureMetrics(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.assetHandler.ServeAssetHTTP(w, req, originID, ref)
	}), w, req)
	if r.metrics != nil {
		pattern := routePattern(req)
		r.metrics.RequestDuration.WithLabelValues(req.Method, pattern).Observe(m.Duration.Seconds())
		if m.Code != 0 {
			r.metrics.RequestsTotal.WithLabelValues(req.Method, pattern, strconv.Itoa(m.Code)).Inc()
		}
	}
}

// dispatch attaches STACInfo to req.Context() so chi-layer middlewares
// can read the parsed STAC shape, then delegates to the inner handler.
// Request-level metrics are recorded after the handler returns.
//
// Metrics labels use the chi route pattern (e.g. "/collections/{collectionId}/items/{itemId}")
// rather than the raw request path so cardinality stays bounded by the
// number of registered routes regardless of how many distinct collection
// IDs or item IDs the proxy sees.
func (r *Router) dispatch(w http.ResponseWriter, req *http.Request, rt middleware.RequestType, collection, itemID string) {
	info := &middleware.STACInfo{RequestType: rt, Collection: collection, ItemID: itemID}
	ctx := middleware.WithSTACInfo(req.Context(), info)
	req = req.WithContext(ctx)

	m := httpsnoop.CaptureMetrics(r.handler, w, req)
	if r.metrics != nil {
		pattern := routePattern(req)
		r.metrics.RequestDuration.WithLabelValues(req.Method, pattern).Observe(m.Duration.Seconds())
		if m.Code != 0 {
			r.metrics.RequestsTotal.WithLabelValues(req.Method, pattern, strconv.Itoa(m.Code)).Inc()
		}
	}
}

// routePattern returns the chi route pattern for req (e.g. "/collections/{collectionId}/items/{itemId}"),
// or "unknown" when no chi context is attached. Used to keep Prometheus
// label cardinality bounded by the number of registered routes.
func routePattern(req *http.Request) string {
	if rctx := chi.RouteContext(req.Context()); rctx != nil {
		if p := rctx.RoutePattern(); p != "" {
			return p
		}
	}
	return "unknown"
}

// clientIPMiddleware derives the client IP from either the TCP
// RemoteAddr (default) or the right-most untrusted entry of
// X-Forwarded-For (when the immediate connection came from a
// configured trusted-proxy CIDR). The derived IP is attached to the
// request context via middleware.ClientIPKey for downstream consumers
// (rate limiter, logger, etc.).
//
// When trustedCIDRs is empty, X-Forwarded-For is always ignored.
// This is the safe default for an internet-exposed listener — an
// untrusted client cannot inflate or partition its rate-limit bucket
// by spoofing the header.
//
// Malformed entries (unparseable CIDRs / IPs) are silently skipped;
// startup-time validation of cfg.Server.TrustedProxies catches them.
func clientIPMiddleware(trustedCIDRs []string) func(http.Handler) http.Handler {
	nets := parseTrustedCIDRs(trustedCIDRs)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := deriveClientIP(r, nets)
			ctx := middleware.WithClientIP(r.Context(), ip)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func parseTrustedCIDRs(cidrs []string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, s := range cidrs {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		// Accept bare IPs by promoting to /32 or /128.
		if !strings.Contains(s, "/") {
			if ip := net.ParseIP(s); ip != nil {
				if ip.To4() != nil {
					s += "/32"
				} else {
					s += "/128"
				}
			}
		}
		if _, n, err := net.ParseCIDR(s); err == nil {
			out = append(out, n)
		}
	}
	return out
}

// deriveClientIP returns the trusted client IP for r. When the peer
// (r.RemoteAddr) is in one of the trusted CIDRs, the right-most
// untrusted entry of X-Forwarded-For (or X-Real-IP as a fallback) is
// honored; otherwise the peer's own IP is returned.
func deriveClientIP(r *http.Request, trusted []*net.IPNet) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if len(trusted) == 0 {
		return host
	}
	peerIP := net.ParseIP(host)
	if peerIP == nil || !ipInAny(peerIP, trusted) {
		return host
	}
	// Peer is trusted — walk XFF right-to-left, returning the first
	// entry that is NOT itself in a trusted CIDR.
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		entries := strings.Split(xff, ",")
		for i := len(entries) - 1; i >= 0; i-- {
			candidate := strings.TrimSpace(entries[i])
			ip := net.ParseIP(candidate)
			if ip == nil {
				continue
			}
			if !ipInAny(ip, trusted) {
				return candidate
			}
		}
	}
	if xrip := strings.TrimSpace(r.Header.Get("X-Real-IP")); xrip != "" {
		return xrip
	}
	return host
}

func ipInAny(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
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
