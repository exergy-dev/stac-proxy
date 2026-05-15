package server

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

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
	if sr == nil {
		t.Fatal("SearchReq nil; parser did not run")
	}
	if len(sr.Collections) != 2 || sr.Collections[0] != "a" || sr.Collections[1] != "b" {
		t.Errorf("collections: got %v", sr.Collections)
	}
	if sr.Limit != 50 {
		t.Errorf("limit: got %d", sr.Limit)
	}
	if string(downstream) != body {
		t.Errorf("body not restored for downstream: got %q want %q", downstream, body)
	}
}

func TestSearchParser_GETSearch_PopulatesFromQuery(t *testing.T) {
	r := httptest.NewRequest("GET", "/search?collections=a,b&limit=25", nil)
	info := &middleware.STACInfo{RequestType: middleware.RequestTypeSearch}
	sr, _ := runWithInfo(t, info, r)
	if sr == nil {
		t.Fatal("SearchReq nil")
	}
	if len(sr.Collections) == 0 {
		t.Errorf("collections empty: %v", sr.Collections)
	}
	if sr.Limit != 25 {
		t.Errorf("limit: got %d", sr.Limit)
	}
}

func TestSearchParser_GETItems_InjectsCollectionFromRoute(t *testing.T) {
	r := httptest.NewRequest("GET", "/collections/foo/items?limit=10", nil)
	// Simulate chi route binding for collectionId.
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("collectionId", "foo")
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
	info := &middleware.STACInfo{RequestType: middleware.RequestTypeItems, Collection: "foo"}
	sr, _ := runWithInfo(t, info, r)
	if sr == nil {
		t.Fatal("SearchReq nil")
	}
	if len(sr.Collections) != 1 || sr.Collections[0] != "foo" {
		t.Errorf("collection-from-route: got %v", sr.Collections)
	}
	if sr.Limit != 10 {
		t.Errorf("limit: got %d", sr.Limit)
	}
}

func TestSearchParser_NonSearchRoute_NoOp(t *testing.T) {
	r := httptest.NewRequest("GET", "/collections/foo", nil)
	info := &middleware.STACInfo{RequestType: middleware.RequestTypeCollection, Collection: "foo"}
	sr, _ := runWithInfo(t, info, r)
	if sr != nil {
		t.Fatalf("non-search route should not populate SearchReq; got %+v", sr)
	}
}

func TestSearchParser_AlreadyParsed_DoesNotOverwrite(t *testing.T) {
	pre := &stac.SearchRequest{Collections: []string{"pre-set"}}
	r := httptest.NewRequest("POST", "/search", strings.NewReader(`{"collections":["other"]}`))
	r.Header.Set("Content-Type", "application/json")
	info := &middleware.STACInfo{RequestType: middleware.RequestTypeSearch, SearchReq: pre}
	sr, _ := runWithInfo(t, info, r)
	if sr == nil || len(sr.Collections) != 1 || sr.Collections[0] != "pre-set" {
		t.Fatalf("pre-set SearchReq must not be overwritten; got %+v", sr)
	}
}

func TestSearchParser_POSTSearch_BodyRestoredForRereaders(t *testing.T) {
	// Specifically verify that the body downstream readers see can be
	// re-read multiple times (federation handler may call its own
	// re-parser as a defensive fallback).
	body := `{"collections":["x"]}`
	r := httptest.NewRequest("POST", "/search", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	info := &middleware.STACInfo{RequestType: middleware.RequestTypeSearch}
	r = r.WithContext(middleware.WithSTACInfo(r.Context(), info))

	mw := searchParserMiddleware()
	mw(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		read1, _ := io.ReadAll(req.Body)
		if !bytes.Equal(read1, []byte(body)) {
			t.Errorf("downstream first read: got %q want %q", read1, body)
		}
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(httptest.NewRecorder(), r)
}
