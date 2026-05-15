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
	"strings"
	"testing"
	"time"

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
		ConflictStrategy: federation.ConflictPriorityWins,
	})
	if err != nil {
		t.Fatalf("federation.NewHandler: %v", err)
	}
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

	if cap.method != http.MethodPost {
		t.Fatalf("upstream method = %q, want POST", cap.method)
	}
	if cap.path != "/search" {
		t.Fatalf("upstream path = %q, want /search", cap.path)
	}

	// The upstream body should contain BOTH predicates AND-combined.
	var body map[string]interface{}
	if err := json.Unmarshal(cap.body, &body); err != nil {
		t.Fatalf("upstream body not JSON: %v\n%s", err, cap.body)
	}
	filter, ok := body["filter"].(string)
	if !ok {
		t.Fatalf("upstream filter not a string: %T %v", body["filter"], body["filter"])
	}
	if !strings.Contains(filter, "eo:cloud_cover") {
		t.Errorf("upstream missing policy predicate, got %q", filter)
	}
	if !strings.Contains(filter, "datetime") {
		t.Errorf("upstream missing client predicate, got %q", filter)
	}
	if !strings.Contains(filter, "AND") {
		t.Errorf("upstream filter not AND-combined: %q", filter)
	}
	if lang, _ := body["filter-lang"].(string); lang != "cql2-text" {
		t.Errorf("upstream filter-lang = %q, want cql2-text", lang)
	}
}

func TestIntegration_GeofencePushdownThroughProxy(t *testing.T) {
	srv, cap := newUpstream(t)

	polygon := map[string]interface{}{
		"type": "Polygon",
		"coordinates": []interface{}{
			[]interface{}{
				[]interface{}{-10.0, -10.0},
				[]interface{}{10.0, -10.0},
				[]interface{}{10.0, 10.0},
				[]interface{}{-10.0, 10.0},
				[]interface{}{-10.0, -10.0},
			},
		},
	}

	mw := authz.NewHTTPMiddleware(authz.HTTPConfig{
		Enforcer: &fixedEnforcer{d: &authz.AuthzDecision{
			Allowed: true,
			Constraints: &authz.AuthzConstraints{
				Geofence: &authz.GeofenceConstraint{
					AllowedArea: polygon,
					FilterMode:  true,
				},
			},
		}},
		AllowAnonymous:       true,
		CQL2InjectionEnabled: true,
	})

	handler := newSingleOriginFederation(t, srv.URL)

	httpReq := httptest.NewRequest("GET", "/search", nil)
	withChain(t, mw, handler, httpReq, &middleware.STACInfo{
		RequestType: middleware.RequestTypeSearch,
		SearchReq:   &stac.SearchRequest{Limit: 5},
	})

	var body map[string]interface{}
	if err := json.Unmarshal(cap.body, &body); err != nil {
		t.Fatalf("upstream body not JSON: %v\n%s", err, cap.body)
	}
	filter, _ := body["filter"].(string)
	if !strings.Contains(strings.ToUpper(filter), "S_INTERSECTS") {
		t.Errorf("upstream filter missing S_INTERSECTS, got %q", filter)
	}
}

func TestIntegration_DisabledByDefault(t *testing.T) {
	srv, cap := newUpstream(t)

	// CQL2InjectionEnabled NOT set => default off, no injection.
	mw := authz.NewHTTPMiddleware(authz.HTTPConfig{
		Enforcer: &fixedEnforcer{d: &authz.AuthzDecision{
			Allowed: true,
			Constraints: &authz.AuthzConstraints{
				CQL2Filter: "eo:cloud_cover < 20",
			},
		}},
		AllowAnonymous: true,
	})

	handler := newSingleOriginFederation(t, srv.URL)

	httpReq := httptest.NewRequest("GET", "/search", nil)
	withChain(t, mw, handler, httpReq, &middleware.STACInfo{
		RequestType: middleware.RequestTypeSearch,
		SearchReq:   &stac.SearchRequest{},
	})

	// Body should not contain the policy filter — injection was off.
	if strings.Contains(string(cap.body), "eo:cloud_cover") {
		t.Errorf("policy filter leaked despite injection disabled: %s", cap.body)
	}
}
