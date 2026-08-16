// Package federation provides the federation handler for multi-origin queries.
package federation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/exergy-dev/stac-proxy/internal/federation/pagecache"
	"github.com/exergy-dev/stac-proxy/internal/logx"
	"github.com/exergy-dev/stac-proxy/internal/middleware"
	"github.com/exergy-dev/stac-proxy/internal/stac"
)

// Handler orchestrates queries across all configured origins.
type Handler struct {
	origins          map[string]*OriginClient
	router           *CollectionRouter
	merger           *ResultMerger
	maxConcurrent    int
	aggregateTimeout time.Duration
	proxyBaseURL     string
	defaultPageSize  int
	maxPageSize      int
	conformanceCaps  stac.ConformanceCaps
	// searcher is the federated paginated searcher. It is non-nil only
	// when a CursorSecret was configured; otherwise handleSearch falls
	// back to a single-page fan-out (validation warns on this so the
	// operator gets a startup-time signal).
	searcher *PaginatedSearcher
	// assetSigner is used by rewriteAssetHref when an origin has
	// `rewrite_assets: sign` configured. When nil and an origin asks
	// for "sign", the rewrite falls back to passthrough (we never
	// silently emit unsigned URLs while pretending they are gated).
	assetSigner AssetSigner

	logger *slog.Logger
	// partialWarn throttles the partial-result warning: during an
	// origin outage every response is partial, and logs-only
	// observability means a per-response Warn would bury the signal.
	partialWarn *logx.LogThrottle
}

// AssetSigner is the minimal contract rewriteAssetHref needs from a
// URL signer when an origin opts into `rewrite_assets: sign`. The
// concrete implementation today is remap.HMACSigner; the interface
// keeps federation from depending on internal/middleware/remap.
type AssetSigner interface {
	Sign(ctx context.Context, rawURL string, ttl time.Duration) string
}

// HandlerConfig contains configuration for the federation handler.
type HandlerConfig struct {
	Origins          []*Origin
	MaxConcurrent    int
	AggregateTimeout time.Duration
	ProxyBaseURL     string
	DefaultPageSize  int
	MaxPageSize      int
	// ConformanceCaps controls which conformance classes the proxy is
	// willing to advertise on /conformance and the landing page. The
	// actual response is the intersection of these caps with what every
	// routed origin advertises (see internal/stac.Intersect).
	ConformanceCaps stac.ConformanceCaps
	// LifetimeCtx (optional) is used to tie background goroutines
	// (auto-discovery) to the proxy's lifetime so a shutdown signal
	// aborts in-flight upstream calls. Defaults to context.Background()
	// when nil, preserving previous behavior.
	LifetimeCtx context.Context
	// Logger (optional) receives structured logs from background work
	// like auto-discovery. Defaults to slog.Default() when nil.
	Logger *slog.Logger
	// AssetSigner is invoked when an origin has rewrite_assets: sign.
	// Optional — when nil and `sign` is configured, the rewriter falls
	// back to passthrough rather than emit unsigned URLs.
	AssetSigner AssetSigner
	// CursorSecret is the HMAC key used to sign federated pagination
	// cursors. When empty the proxy still serves single-page federated
	// searches but cannot issue "next" links — config validation emits
	// a warning in that case.
	CursorSecret []byte

	// PageCache, when non-nil, stores rendered pages keyed by cursor
	// signature so the paginator can serve `rel: prev` / `rel: first`
	// navigation without re-fanning-out to origins. Construction is
	// in main; nil disables the feature.
	PageCache *pagecache.Cache
}

// NewHandler creates a new federation handler.
func NewHandler(cfg HandlerConfig) (*Handler, error) {
	handler := &Handler{
		origins:          make(map[string]*OriginClient),
		router:           NewCollectionRouter(),
		merger:           NewResultMerger(),
		maxConcurrent:    cfg.MaxConcurrent,
		aggregateTimeout: cfg.AggregateTimeout,
		proxyBaseURL:     cfg.ProxyBaseURL,
		defaultPageSize:  cfg.DefaultPageSize,
		maxPageSize:      cfg.MaxPageSize,
		conformanceCaps:  cfg.ConformanceCaps,
		assetSigner:      cfg.AssetSigner,
		partialWarn:      logx.NewLogThrottle(30 * time.Second),
	}

	// Constructor invariant for direct construction (tests, embedders);
	// values mirror config.setDefaults, which fills them on the YAML path.
	if handler.maxConcurrent <= 0 {
		handler.maxConcurrent = 10
	}
	if handler.aggregateTimeout <= 0 {
		handler.aggregateTimeout = 60 * time.Second
	}
	if handler.defaultPageSize <= 0 {
		handler.defaultPageSize = 100
	}
	if handler.maxPageSize <= 0 {
		handler.maxPageSize = 1000
	}

	parentCtx := cfg.LifetimeCtx
	if parentCtx == nil {
		parentCtx = context.Background()
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	handler.logger = logger

	// Initialize origin clients
	for _, origin := range cfg.Origins {
		if !origin.Enabled {
			continue
		}

		client, err := NewOriginClientWithContext(parentCtx, logger, origin)
		if err != nil {
			return nil, fmt.Errorf("failed to init origin %s: %w", origin.ID, err)
		}

		handler.origins[origin.ID] = client
		handler.router.Register(origin)
	}

	// Build the paginated searcher when a cursor secret is configured.
	// Without a secret, handleSearch falls back to a single-page
	// fan-out — federated multi-page pagination requires signed
	// cursors (NewPaginatedSearcher rejects an empty key).
	if len(cfg.CursorSecret) > 0 && len(handler.origins) > 0 {
		origins := make(map[string]Searcher, len(handler.origins))
		for id, c := range handler.origins {
			s, err := NewOriginClientSearcher(c, c.Origin().Pagination.ToAdapterConfig())
			if err != nil {
				return nil, fmt.Errorf("origin %q pagination adapter: %w", id, err)
			}
			origins[id] = s
		}
		searcher, err := NewPaginatedSearcher(PaginatedSearchConfig{
			Origins:         origins,
			Merger:          handler.merger,
			DefaultPageSize: handler.defaultPageSize,
			MaxPageSize:     handler.maxPageSize,
			CursorSecret:    cfg.CursorSecret,
			PageCache:       cfg.PageCache,
		})
		if err != nil {
			return nil, fmt.Errorf("paginated searcher: %w", err)
		}
		handler.searcher = searcher
	}

	return handler, nil
}

// Handle processes a STAC request by routing to appropriate origins.
func (h *Handler) Handle(ctx context.Context, req *request) (*response, error) {
	switch req.RequestType {
	case middleware.RequestTypeSearch:
		return h.handleSearch(ctx, req)
	case middleware.RequestTypeItems:
		return h.handleItems(ctx, req)
	case middleware.RequestTypeQueryables, middleware.RequestTypeCollectionQueryables:
		return h.handleQueryables(ctx, req)
	case middleware.RequestTypeCollections:
		return h.handleGetCollections(ctx, req)
	case middleware.RequestTypeCollection:
		return h.handleGetCollection(ctx, req)
	case middleware.RequestTypeItem:
		return h.handleGetItem(ctx, req)
	case middleware.RequestTypeConformance:
		return h.handleConformance(ctx, req)
	case middleware.RequestTypeLanding:
		return h.handleLanding(ctx, req)
	case middleware.RequestTypeAsset:
		// The asset endpoint streams response bytes directly; the
		// federation `*response` shape buffers them, so we cannot
		// handle this path via Handle(). The router calls
		// ServeAssetHTTP directly for /assets/.
		return nil, fmt.Errorf("asset requests must be served via ServeAssetHTTP")
	default:
		// For other request types, try to proxy to the first available origin
		return h.handleGenericProxy(ctx, req)
	}
}

// ServeHTTP makes Handler implement http.Handler. It reads STACInfo from
// the request context (populated by the router), reconstructs a
// request, delegates to Handle, then writes the
// STACResponse out to w. This is the integration point that lets
// federation be the inner handler in a chi-style middleware chain.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	info := middleware.STACInfoFromContext(r.Context())
	if info == nil {
		http.Error(w, "missing STAC info", http.StatusInternalServerError)
		return
	}
	sreq := &request{
		Request:     r,
		Context:     r.Context(),
		Collection:  info.Collection,
		ItemID:      info.ItemID,
		RequestType: info.RequestType,
		SearchReq:   info.SearchReq,
	}
	resp, err := h.Handle(r.Context(), sreq)
	if err != nil {
		writeFederationError(w, r, err)
		return
	}
	for k, vs := range resp.Headers {
		// The upstream's Content-Length is stale whenever
		// transformResponse re-marshaled the body (link/asset
		// rewriting changes its length); forwarding it makes real
		// HTTP/1.1 clients fail with a truncated/overlong transfer.
		// net/http recomputes it from the buffered body we write.
		if http.CanonicalHeaderKey(k) == "Content-Length" {
			continue
		}
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "application/json")
	}
	if resp.StatusCode == 0 {
		resp.StatusCode = http.StatusOK
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(resp.Body)
}

// writeFederationError translates a federation/middleware-tier error
// into a STAC-shaped JSON response. Mirrors the router's handleError
// for the cases reachable from federation.Handle.
func writeFederationError(w http.ResponseWriter, _ *http.Request, err error) {
	var ie *middleware.InternalError
	if errors.As(err, &ie) {
		middleware.WriteJSONError(w, http.StatusBadGateway, "BadGateway", ie.Message)
		return
	}
	middleware.WriteJSONError(w, http.StatusInternalServerError, "InternalError", "internal error")
}

// errorResponse builds a STAC-shaped JSON error envelope as an
// internal *response, for handler paths that return responses rather
// than writing directly. Same {"code","description"} shape as
// middleware.WriteJSONError.
func errorResponse(status int, code, description string) *response {
	body, _ := json.Marshal(map[string]string{"code": code, "description": description})
	return &response{
		StatusCode: status,
		Headers:    http.Header{"Content-Type": []string{"application/json"}},
		Body:       body,
	}
}

// primaryOrigin returns the highest-priority enabled origin (or nil
// when no enabled origins are configured). Used by handleGenericProxy
// and the federation-of-1 translation in cmd/stac-proxy.
func (h *Handler) primaryOrigin() *Origin {
	origins := h.router.EnabledOrigins()
	if len(origins) == 0 {
		return nil
	}
	best := origins[0]
	for _, o := range origins[1:] {
		if o.Priority > best.Priority {
			best = o
		}
	}
	return best
}

// parseSearchRequest parses a search request from the STAC request.
//
// Defensive fallback only: the server-level searchParserMiddleware
// populates req.SearchReq before federation runs, so this code path is
// only exercised by tests / alternate routings that bypass the
// middleware. We delegate to stac.Parser so the parsing rules
// (collections split on `,`, bbox/limit strict parse, ids, filter,
// intersects, fields, sortby, etc.) match the inbound parser exactly
// instead of re-implementing a subset that drops most parameters.
func (h *Handler) parseSearchRequest(req *request) (*stac.SearchRequest, error) {
	return stac.NewParser().ParseSearchRequestFromHTTP(req.Request)
}

// OriginCount returns the number of configured origins.
func (h *Handler) OriginCount() int {
	return len(h.origins)
}

// OriginIDs returns the IDs of all configured origins.
func (h *Handler) OriginIDs() []string {
	ids := make([]string, 0, len(h.origins))
	for id := range h.origins {
		ids = append(ids, id)
	}
	return ids
}

// OriginClient returns the *OriginClient for the given origin ID, or
// nil if no such origin is registered. Exposed so external collaborators
// (e.g. cmd/stac-proxy wiring observability.OriginCheck) can reuse the
// same instrumented HTTP client/transport that fan-out uses, instead
// of constructing a parallel client that bypasses retry, custom CA
// pools, etc.
func (h *Handler) OriginClient(id string) *OriginClient {
	return h.origins[id]
}

// ProxyBaseURL returns the configured external base URL the handler
// uses when rewriting links (empty when unset → relative links). Exposed
// for tests that need to verify config-to-handler wiring.
func (h *Handler) ProxyBaseURL() string {
	return h.proxyBaseURL
}
