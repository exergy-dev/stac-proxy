package integration

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/yourorg/stac-proxy/internal/federation"
	"github.com/yourorg/stac-proxy/internal/middleware"
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
	if err != nil {
		t.Fatalf("NewOriginClient A: %v", err)
	}
	originB, err := federation.NewOriginClient(&federation.Origin{
		ID:      "origin-b",
		Name:    "Origin B",
		BaseURL: srvB.URL,
		Enabled: true,
		Auth:    federation.AuthConfig{Type: "none"},
	})
	if err != nil {
		t.Fatalf("NewOriginClient B: %v", err)
	}

	mw := authz.NewAuthzMiddleware(authz.AuthzMiddlewareConfig{
		Enforcer: &fixedEnforcer{d: &authz.AuthzDecision{
			Allowed: true,
			Constraints: &authz.AuthzConstraints{
				CQL2Filter: "eo:cloud_cover < 25",
			},
		}},
		AllowAnonymous:       true,
		CQL2InjectionEnabled: true,
	})

	httpReq := httptest.NewRequest("GET", "/search", nil)
	req := &middleware.STACRequest{
		Request:     httpReq,
		Context:     httpReq.Context(),
		RequestType: middleware.RequestTypeSearch,
		SearchReq: &stac.SearchRequest{
			Filter:     "datetime > '2025-01-01'",
			FilterLang: "cql2-text",
			Limit:      10,
		},
	}

	if _, err := mw.ProcessRequest(req.Context, req); err != nil {
		t.Fatalf("authz ProcessRequest: %v", err)
	}

	// Simulate the federation fan-out: each origin client serializes
	// the same SearchReq independently. This is what
	// federation.Handler does internally.
	ctx := context.Background()
	if _, err := originA.Search(ctx, req.SearchReq); err != nil {
		t.Fatalf("originA Search: %v", err)
	}
	if _, err := originB.Search(ctx, req.SearchReq); err != nil {
		t.Fatalf("originB Search: %v", err)
	}

	for name, body := range map[string][]byte{
		"origin-a": capA.snapshot(),
		"origin-b": capB.snapshot(),
	} {
		var got map[string]interface{}
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatalf("%s: body not JSON: %v\n%s", name, err, body)
		}
		filter, ok := got["filter"].(string)
		if !ok {
			t.Fatalf("%s: filter not a string: %T %v", name, got["filter"], got["filter"])
		}
		if !strings.Contains(filter, "eo:cloud_cover") {
			t.Errorf("%s: missing policy predicate: %q", name, filter)
		}
		if !strings.Contains(filter, "datetime") {
			t.Errorf("%s: missing client predicate: %q", name, filter)
		}
		if !strings.Contains(filter, "AND") {
			t.Errorf("%s: not AND-combined: %q", name, filter)
		}
	}
}
