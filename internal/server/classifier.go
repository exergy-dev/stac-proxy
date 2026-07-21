package server

import (
	"net/http"
	"sync"

	"github.com/go-chi/chi/v5"

	"github.com/yourorg/stac-proxy/internal/middleware"
)

// routeCtxPool recycles the throwaway RouteContexts the classifier
// matches against — chi pools its own contexts the same way; without
// this the classifier would be the only per-request allocation on the
// routing path.
var routeCtxPool = sync.Pool{
	New: func() any { return chi.NewRouteContext() },
}

// routePatternTypes maps the chi route patterns registered in NewRouter
// to their STAC request types. Health endpoints are intentionally
// absent — they carry no STACInfo.
var routePatternTypes = map[string]middleware.RequestType{
	"/":                                 middleware.RequestTypeLanding,
	"/conformance":                      middleware.RequestTypeConformance,
	"/collections":                      middleware.RequestTypeCollections,
	"/collections/{collectionId}":       middleware.RequestTypeCollection,
	"/collections/{collectionId}/items": middleware.RequestTypeItems,
	"/collections/{collectionId}/items/{itemId}": middleware.RequestTypeItem,
	"/search":                                middleware.RequestTypeSearch,
	"/queryables":                            middleware.RequestTypeQueryables,
	"/collections/{collectionId}/queryables": middleware.RequestTypeCollectionQueryables,
	"/assets/{originId}/{ref}":               middleware.RequestTypeAsset,
}

// stacInfoClassifier attaches STACInfo to the request context BEFORE
// the rest of the middleware chain runs.
//
// This must be a router-level middleware, not part of the route
// handler: chi runs `r.Use` middlewares before the matched handler, so
// anything attached to the context inside the handler (the historical
// `dispatch` behavior) is invisible to every middleware. That ordering
// bug meant the search-body parser, the authz constraint/CQL2
// injection path, and the response cache all saw a nil STACInfo on the
// real router — while passing their unit tests, which inject STACInfo
// into the context by hand. (Found by black-box e2e: no X-Cache-Status
// on live /search responses.)
//
// chi cannot tell us the matched route before dispatch, so the
// classifier runs the router's own matcher against a throwaway
// RouteContext: same patterns, same precedence, no handler execution.
// Requests that match no route (or a health route) pass through with
// no STACInfo, exactly as before.
func stacInfoClassifier(mux *chi.Mux) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Mirror chi's own path selection (RawPath when the URL
			// contains encoded characters) so the pre-match can never
			// diverge from the real routing decision.
			routePath := r.URL.RawPath
			if routePath == "" {
				routePath = r.URL.Path
			}
			tctx := routeCtxPool.Get().(*chi.Context)
			defer func() {
				tctx.Reset()
				routeCtxPool.Put(tctx)
			}()
			if mux.Match(tctx, r.Method, routePath) {
				if rt, ok := routePatternTypes[tctx.RoutePattern()]; ok {
					info := &middleware.STACInfo{
						RequestType: rt,
						ItemID:      tctx.URLParam("itemId"),
					}
					// The asset route reuses Collection to carry the
					// origin ID so authz/ratelimit can key on it — see
					// handleAsset.
					if rt == middleware.RequestTypeAsset {
						info.Collection = tctx.URLParam("originId")
					} else {
						info.Collection = tctx.URLParam("collectionId")
					}
					r = r.WithContext(middleware.WithSTACInfo(r.Context(), info))
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}
