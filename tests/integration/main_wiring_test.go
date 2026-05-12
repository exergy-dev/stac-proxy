package integration

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yourorg/stac-proxy/internal/middleware"
	"github.com/yourorg/stac-proxy/internal/middleware/authz"
	"github.com/yourorg/stac-proxy/internal/proxy"
	"github.com/yourorg/stac-proxy/internal/stac"
)

// TestIntegration_EndToEndConfigDrivenInjection wires the same
// pieces main.go's buildAuthzMiddleware wires (embedded OPA + CQL2
// injection + per-upstream gate), against an httptest upstream that
// captures the forwarded request. Verifies that a Rego policy
// emitting cql2_filter actually ends up in the upstream body.
func TestIntegration_EndToEndConfigDrivenInjection(t *testing.T) {
	// Build a temporary Rego policy that emits a cql2_filter constraint.
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.rego")
	policy := `package stac.authz

default allow := true

result := {
    "allow": allow,
    "reasons": [],
    "constraints": {
        "cql2_filter": "eo:cloud_cover < 30"
    }
}
`
	if err := os.WriteFile(policyPath, []byte(policy), 0644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	enf, err := authz.NewEmbeddedOPAEnforcer(authz.EmbeddedOPAConfig{
		Name:        "e2e",
		PolicyPaths: []string{policyPath},
	})
	if err != nil {
		t.Fatalf("NewEmbeddedOPAEnforcer: %v", err)
	}

	// Upstream that records the body.
	cap := &capturedUpstream{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cap.method = r.Method
		cap.path = r.URL.Path
		cap.body, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"type":"FeatureCollection","features":[]}`))
	}))
	defer srv.Close()

	// Build the authz middleware as buildAuthzMiddleware would, with
	// SupportsFilterExtension=true on the upstream gate.
	mw := authz.NewAuthzMiddleware(authz.AuthzMiddlewareConfig{
		Enforcer:             enf,
		AllowAnonymous:       true,
		CQL2InjectionEnabled: true,
		FilterExtensionCheck: func(_ *middleware.STACRequest) bool { return true },
	})

	handler, err := proxy.NewHandler(proxy.Config{
		UpstreamURL:             srv.URL,
		Timeout:                 5,
		SupportsFilterExtension: true,
	})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	httpReq := httptest.NewRequest("GET", "/search", nil)
	req := &middleware.STACRequest{
		Request:     httpReq,
		Context:     httpReq.Context(),
		RequestType: middleware.RequestTypeSearch,
		SearchReq:   &stac.SearchRequest{Limit: 10},
	}

	if _, err := mw.ProcessRequest(req.Context, req); err != nil {
		t.Fatalf("authz ProcessRequest: %v", err)
	}
	if _, err := handler.Handle(context.Background(), req); err != nil {
		t.Fatalf("Handle: %v", err)
	}

	var body map[string]interface{}
	if err := json.Unmarshal(cap.body, &body); err != nil {
		t.Fatalf("upstream body not JSON: %v\n%s", err, cap.body)
	}
	filter, ok := body["filter"].(string)
	if !ok {
		t.Fatalf("upstream filter not a string: %T %v", body["filter"], body["filter"])
	}
	if !strings.Contains(filter, "eo:cloud_cover") {
		t.Errorf("policy filter did not reach upstream: got %q", filter)
	}
}
