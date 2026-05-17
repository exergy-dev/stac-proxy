package integration

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/stac-proxy/internal/federation"
	"github.com/yourorg/stac-proxy/internal/middleware"
	"github.com/yourorg/stac-proxy/internal/middleware/auth"
	"github.com/yourorg/stac-proxy/internal/middleware/authz"
	"github.com/yourorg/stac-proxy/internal/stac"
)

// originCapture stands up an httptest server simulating one
// federation origin and records the search body it received.
type originCapture struct {
	mu   sync.Mutex
	body []byte
}

func (o *originCapture) snapshot() []byte {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := make([]byte, len(o.body))
	copy(out, o.body)
	return out
}

func newOriginServer(t *testing.T) (*httptest.Server, *originCapture) {
	t.Helper()
	cap := &originCapture{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		cap.mu.Lock()
		cap.body = b
		cap.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(`{"type":"FeatureCollection","features":[]}`))
	}))
	t.Cleanup(srv.Close)
	return srv, cap
}

// TestIntegration_FederationFilterRidesAlong asserts that when the
// authz middleware injects a CQL2 filter into req.SearchReq, both
// federation origins receive the merged filter in their per-origin
// POST body — since each OriginClient re-marshals SearchReq in Search().
func TestIntegration_FederationFilterRidesAlong(t *testing.T) {
	srvA, capA := newOriginServer(t)
	srvB, capB := newOriginServer(t)

	originA, err := federation.NewOriginClient(&federation.Origin{
		ID:      "origin-a",
		Name:    "Origin A",
		BaseURL: srvA.URL,
		Enabled: true,
		Auth:    federation.AuthConfig{Type: "none"},
	})
	require.NoError(t, err, "NewOriginClient A")
	originB, err := federation.NewOriginClient(&federation.Origin{
		ID:      "origin-b",
		Name:    "Origin B",
		BaseURL: srvB.URL,
		Enabled: true,
		Auth:    federation.AuthConfig{Type: "none"},
	})
	require.NoError(t, err, "NewOriginClient B")

	mw := authz.NewHTTPMiddleware(authz.HTTPConfig{
		Enforcer: &fixedEnforcer{d: &authz.AuthzDecision{
			Allowed: true,
			Constraints: &authz.AuthzConstraints{
				CQL2Filter: "eo:cloud_cover < 25",
			},
		}},
		AllowAnonymous:       true,
		CQL2InjectionEnabled: true,
	})

	sr := &stac.SearchRequest{
		Filter:     "datetime > '2025-01-01'",
		FilterLang: "cql2-text",
		Limit:      10,
	}
	info := &middleware.STACInfo{RequestType: middleware.RequestTypeSearch, SearchReq: sr}
	httpReq := httptest.NewRequest("GET", "/search", nil)
	ctx := middleware.WithSTACInfo(httpReq.Context(), info)
	ctx = context.WithValue(ctx, middleware.PrincipalKey, &auth.Principal{ID: "anon", Type: "anonymous"})
	httpReq = httpReq.WithContext(ctx)

	// Run authz chi middleware over a no-op inner handler so it
	// mutates sr.Filter pre-fanout, then dispatch directly to each
	// origin client (simulating federation fan-out).
	mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {})).ServeHTTP(httptest.NewRecorder(), httpReq)

	_, _, err = originA.Search(context.Background(), sr)
	require.NoError(t, err, "originA Search")
	_, _, err = originB.Search(context.Background(), sr)
	require.NoError(t, err, "originB Search")

	for name, body := range map[string][]byte{
		"origin-a": capA.snapshot(),
		"origin-b": capB.snapshot(),
	} {
		var got map[string]interface{}
		require.NoError(t, json.Unmarshal(body, &got), "%s: body not JSON: %s", name, body)
		filter, ok := got["filter"].(string)
		require.True(t, ok, "%s: filter not a string: %T %v", name, got["filter"], got["filter"])
		assert.Contains(t, filter, "eo:cloud_cover", "%s: missing policy predicate", name)
		assert.Contains(t, filter, "datetime", "%s: missing client predicate", name)
		assert.Contains(t, filter, "AND", "%s: not AND-combined", name)
	}
}
