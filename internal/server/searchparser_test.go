package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yourorg/stac-proxy/internal/middleware"
	"github.com/yourorg/stac-proxy/internal/stac"
)

// runWithInfo wires the searchParser around an inner handler that
// records the captured info.SearchReq and the body bytes the inner
// reads. Returns the recorded values.
func runWithInfo(t *testing.T, info *middleware.STACInfo, r *http.Request) (*stac.SearchRequest, []byte) {
	t.Helper()
	var capturedSR *stac.SearchRequest
	var capturedBody []byte
	r = r.WithContext(middleware.WithSTACInfo(r.Context(), info))
	mw := searchParserMiddleware()
	mw(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		capturedSR = info.SearchReq
		if req.Body != nil {
			capturedBody, _ = io.ReadAll(req.Body)
		}
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(httptest.NewRecorder(), r)
	return capturedSR, capturedBody
}

func TestSearchParser_POSTSearch_PopulatesSearchReq(t *testing.T) {
	body := `{"collections":["a","b"],"limit":50}`
	r := httptest.NewRequest("POST", "/search", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	info := &middleware.STACInfo{RequestType: middleware.RequestTypeSearch}
	sr, downstream := runWithInfo(t, info, r)
	require.NotNil(t, sr, "SearchReq nil; parser did not run")
	assert.Equal(t, []string{"a", "b"}, sr.Collections, "collections")
	assert.Equal(t, 50, sr.Limit, "limit")
	assert.Equal(t, body, string(downstream), "body not restored for downstream")
}

func TestSearchParser_GETSearch_PopulatesFromQuery(t *testing.T) {
	r := httptest.NewRequest("GET", "/search?collections=a,b&limit=25", nil)
	info := &middleware.STACInfo{RequestType: middleware.RequestTypeSearch}
	sr, _ := runWithInfo(t, info, r)
	require.NotNil(t, sr, "SearchReq nil")
	assert.NotEmpty(t, sr.Collections, "collections empty")
	assert.Equal(t, 25, sr.Limit, "limit")
}

func TestSearchParser_GETItems_InjectsCollectionFromRoute(t *testing.T) {
	r := httptest.NewRequest("GET", "/collections/foo/items?limit=10", nil)
	// Simulate chi route binding for collectionId.
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("collectionId", "foo")
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
	info := &middleware.STACInfo{RequestType: middleware.RequestTypeItems, Collection: "foo"}
	sr, _ := runWithInfo(t, info, r)
	require.NotNil(t, sr, "SearchReq nil")
	assert.Equal(t, []string{"foo"}, sr.Collections, "collection-from-route")
	assert.Equal(t, 10, sr.Limit, "limit")
}

func TestSearchParser_NonSearchRoute_NoOp(t *testing.T) {
	r := httptest.NewRequest("GET", "/collections/foo", nil)
	info := &middleware.STACInfo{RequestType: middleware.RequestTypeCollection, Collection: "foo"}
	sr, _ := runWithInfo(t, info, r)
	require.Nil(t, sr, "non-search route should not populate SearchReq; got %+v", sr)
}

func TestSearchParser_AlreadyParsed_DoesNotOverwrite(t *testing.T) {
	pre := &stac.SearchRequest{Collections: []string{"pre-set"}}
	r := httptest.NewRequest("POST", "/search", strings.NewReader(`{"collections":["other"]}`))
	r.Header.Set("Content-Type", "application/json")
	info := &middleware.STACInfo{RequestType: middleware.RequestTypeSearch, SearchReq: pre}
	sr, _ := runWithInfo(t, info, r)
	require.NotNil(t, sr, "pre-set SearchReq must not be overwritten")
	require.Equal(t, []string{"pre-set"}, sr.Collections, "pre-set SearchReq must not be overwritten")
}
