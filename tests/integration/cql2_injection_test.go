// Package integration contains end-to-end tests that exercise the
// proxy middleware chain against an httptest upstream. These are not
// included in the default `go test ./internal/...` run; invoke them
// via `go test ./tests/integration/...`.
package integration

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/stac-proxy/internal/federation"
	"github.com/yourorg/stac-proxy/internal/middleware"
	"github.com/yourorg/stac-proxy/internal/middleware/auth"
	"github.com/yourorg/stac-proxy/internal/middleware/authz"
	"github.com/yourorg/stac-proxy/internal/stac"
)

// withChain wires the chi-style authz middleware around the federation
// handler, populates STACInfo + an anonymous principal in the request
// context, and serves a single request.
func withChain(t *testing.T, mw func(http.Handler) http.Handler, h *federation.Handler, req *http.Request, info *middleware.STACInfo) *httptest.ResponseRecorder {
	t.Helper()
	ctx := middleware.WithSTACInfo(req.Context(), info)
	ctx = context.WithValue(ctx, middleware.PrincipalKey, &auth.Principal{ID: "anon", Type: "anonymous"})
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()
	mw(h).ServeHTTP(rr, req)
	return rr
}

// newSingleOriginFederation wires a federation-of-1 against srv.URL for
// integration tests that previously used proxy.NewHandler. The fast-path
// in federation.Handler.Handle forwards every request to the synthetic
// "primary" origin via ReverseProxy — the same wire-level pass-through
// the old single-origin handler provided.
func newSingleOriginFederation(t *testing.T, upstreamURL string) *federation.Handler {
	t.Helper()
	h, err := federation.NewHandler(federation.HandlerConfig{
		Origins: []*federation.Origin{{
			ID:                      "primary",
			BaseURL:                 upstreamURL,
			Enabled:                 true,
			Priority:                100,
			Searchable:              true,
			SupportsFilterExtension: true,
			Timeout:                 5 * time.Second,
		}},
	})
	require.NoError(t, err, "federation.NewHandler")
	return h
}

type capturedUpstream struct {
	method string
	path   string
	body   []byte
}

func newUpstream(t *testing.T) (*httptest.Server, *capturedUpstream) {
	t.Helper()
	c := &capturedUpstream{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.method = r.Method
		c.path = r.URL.Path
		c.body, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(`{"type":"FeatureCollection","features":[]}`))
	}))
	t.Cleanup(srv.Close)
	return srv, c
}

// fixedEnforcer always returns the same decision; used to simulate an
// OPA policy that emits a CQL2 filter constraint.
type fixedEnforcer struct{ d *authz.AuthzDecision }

func (e *fixedEnforcer) Name() string { return "fixed" }
func (e *fixedEnforcer) Authorize(_ context.Context, _ *authz.AuthzInput) (*authz.AuthzDecision, error) {
	return e.d, nil
}

func TestIntegration_PolicyCQL2FlowsToUpstreamSingleOrigin(t *testing.T) {
	srv, cap := newUpstream(t)

	mw := authz.NewHTTPMiddleware(authz.HTTPConfig{
		Enforcer: &fixedEnforcer{d: &authz.AuthzDecision{
			Allowed: true,
			Constraints: &authz.AuthzConstraints{
				CQL2Filter: "eo:cloud_cover < 20",
			},
		}},
		AllowAnonymous:       true,
		CQL2InjectionEnabled: true,
	})

	handler := newSingleOriginFederation(t, srv.URL)

	sr := &stac.SearchRequest{
		Filter:     "datetime > '2025-01-01'",
		FilterLang: "cql2-text",
		Limit:      10,
	}
	httpReq := httptest.NewRequest("GET", "/search?limit=10", nil)
	withChain(t, mw, handler, httpReq, &middleware.STACInfo{
		RequestType: middleware.RequestTypeSearch,
		SearchReq:   sr,
	})

	require.Equal(t, http.MethodPost, cap.method, "upstream method")
	require.Equal(t, "/search", cap.path, "upstream path")

	// The upstream body should contain BOTH predicates AND-combined.
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(cap.body, &body), "upstream body not JSON: %s", cap.body)
	filter, ok := body["filter"].(string)
	require.True(t, ok, "upstream filter not a string: %T %v", body["filter"], body["filter"])
	assert.Contains(t, filter, "eo:cloud_cover", "upstream missing policy predicate")
	assert.Contains(t, filter, "datetime", "upstream missing client predicate")
	assert.Contains(t, filter, "AND", "upstream filter not AND-combined")
	lang, _ := body["filter-lang"].(string)
	assert.Equal(t, "cql2-text", lang, "upstream filter-lang")
}

