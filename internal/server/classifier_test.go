package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/exergy-dev/stac-proxy/internal/middleware"
	"github.com/exergy-dev/stac-proxy/internal/middleware/cache"
	"github.com/exergy-dev/stac-proxy/internal/observability"
	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// infoRecorder captures what STACInfo (and SearchReq) an operator
// middleware observes at middleware time — the contract the cache,
// authz, and remap middlewares all depend on.
type infoObservation struct {
	info      *middleware.STACInfo
	hasSearch bool
}

func recordingMiddleware(out *infoObservation) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			out.info = middleware.STACInfoFromContext(r.Context())
			out.hasSearch = out.info != nil && out.info.SearchReq != nil
			next.ServeHTTP(w, r)
		})
	}
}

// TestRouter_STACInfoVisibleToMiddlewares is the regression test for
// the classifier-ordering bug: STACInfo used to be attached inside the
// route handler (dispatch), AFTER every r.Use middleware had already
// run, so the search parser, authz constraint injection, and response
// cache all saw nil on the real router — while their unit tests
// passed by injecting STACInfo manually. This test goes through
// server.NewRouter end to end.
func TestRouter_STACInfoVisibleToMiddlewares(t *testing.T) {
	t.Parallel()

	tests := []struct {
		method         string
		path           string
		wantType       middleware.RequestType
		wantCollection string
		wantItemID     string
		wantSearchReq  bool
	}{
		{http.MethodGet, "/", middleware.RequestTypeLanding, "", "", false},
		{http.MethodGet, "/conformance", middleware.RequestTypeConformance, "", "", false},
		{http.MethodGet, "/collections", middleware.RequestTypeCollections, "", "", false},
		{http.MethodGet, "/collections/c1", middleware.RequestTypeCollection, "c1", "", false},
		{http.MethodGet, "/collections/c1/items", middleware.RequestTypeItems, "c1", "", true},
		{http.MethodGet, "/collections/c1/items/i1", middleware.RequestTypeItem, "c1", "i1", false},
		{http.MethodGet, "/search?collections=c1", middleware.RequestTypeSearch, "", "", true},
		{http.MethodPost, "/search", middleware.RequestTypeSearch, "", "", true},
		{http.MethodGet, "/queryables", middleware.RequestTypeQueryables, "", "", false},
		{http.MethodGet, "/collections/c1/queryables", middleware.RequestTypeCollectionQueryables, "c1", "", false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			t.Parallel()
			var seen infoObservation
			router := NewRouter(RouterConfig{
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
				}),
				HTTPMiddlewares: []func(http.Handler) http.Handler{recordingMiddleware(&seen)},
			})

			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, httptest.NewRequest(tt.method, tt.path, nil))
			require.Equal(t, http.StatusOK, rr.Code)

			require.NotNil(t, seen.info,
				"operator middleware must see STACInfo at middleware time")
			assert.Equal(t, tt.wantType, seen.info.RequestType, "request type")
			assert.Equal(t, tt.wantCollection, seen.info.Collection, "collection")
			assert.Equal(t, tt.wantItemID, seen.info.ItemID, "item id")
			assert.Equal(t, tt.wantSearchReq, seen.hasSearch,
				"SearchReq population at middleware time (search parser contract)")
		})
	}

	t.Run("health routes carry no STACInfo", func(t *testing.T) {
		t.Parallel()
		var seen infoObservation
		seen.info = &middleware.STACInfo{} // sentinel; must be overwritten with nil
		router := NewRouter(RouterConfig{
			Handler:         http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
			HTTPMiddlewares: []func(http.Handler) http.Handler{recordingMiddleware(&seen)},
		})
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/unknown-route", nil))
		assert.Nil(t, seen.info, "unmatched routes must not carry STACInfo")
	})
}

// TestClassifier_CoversEveryRegisteredRoute walks the real chi route
// table and requires a routePatternTypes entry for every non-health
// pattern. This is the drift guard: a route added to NewRouter
// without a classifier entry would silently hand its requests to the
// middlewares with nil STACInfo — the exact authz/cache bypass the
// classifier exists to prevent — and hand-enumerated path tests would
// never notice.
func TestClassifier_CoversEveryRegisteredRoute(t *testing.T) {
	t.Parallel()

	router := NewRouter(RouterConfig{
		Handler:       http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
		HealthChecker: observability.NewHealthChecker(),
		AssetHandler: assetHandlerFunc(func(http.ResponseWriter, *http.Request, string, string) {
		}),
	})

	// Health endpoints are deliberately outside the STAC surface.
	exempt := map[string]bool{
		"/health":       true,
		"/health/live":  true,
		"/health/ready": true,
	}

	err := chi.Walk(router.Mux, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		if exempt[route] {
			return nil
		}
		if _, ok := routePatternTypes[route]; !ok {
			t.Errorf("route %s %s has no routePatternTypes entry — its requests would reach authz/cache with nil STACInfo", method, route)
		}
		return nil
	})
	require.NoError(t, err)
}

// assetHandlerFunc adapts a func to AssetHandler for tests.
type assetHandlerFunc func(http.ResponseWriter, *http.Request, string, string)

func (f assetHandlerFunc) ServeAssetHTTP(w http.ResponseWriter, r *http.Request, originID, ref string) {
	f(w, r, originID, ref)
}

// TestRouter_ResponseCacheEngages proves the cache middleware works
// through the real router — MISS on first request, HIT on second —
// which is exactly the observable that exposed the ordering bug in
// the live e2e (no X-Cache-Status header at all).
func TestRouter_ResponseCacheEngages(t *testing.T) {
	t.Parallel()

	cacheMW, err := cache.NewFromConfig(map[string]interface{}{"store": "memory"})
	require.NoError(t, err)

	router := NewRouter(RouterConfig{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"collections":[]}`))
		}),
		HTTPMiddlewares: []func(http.Handler) http.Handler{cacheMW},
	})

	rr1 := httptest.NewRecorder()
	router.ServeHTTP(rr1, httptest.NewRequest(http.MethodGet, "/collections", nil))
	require.Equal(t, http.StatusOK, rr1.Code)
	assert.Equal(t, "MISS", rr1.Header().Get("X-Cache-Status"),
		"first request through the real router must be a cache MISS (not blank)")

	rr2 := httptest.NewRecorder()
	router.ServeHTTP(rr2, httptest.NewRequest(http.MethodGet, "/collections", nil))
	require.Equal(t, http.StatusOK, rr2.Code)
	assert.Equal(t, "HIT", rr2.Header().Get("X-Cache-Status"),
		"second request must be served from cache")
}
