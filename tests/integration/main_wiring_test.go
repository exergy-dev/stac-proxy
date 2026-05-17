package integration

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/stac-proxy/internal/federation"
	"github.com/yourorg/stac-proxy/internal/middleware"
	"github.com/yourorg/stac-proxy/internal/middleware/authz"
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
	require.NoError(t, os.WriteFile(policyPath, []byte(policy), 0644), "write policy")

	enf, err := authz.NewEmbeddedOPAEnforcer(authz.EmbeddedOPAConfig{
		Name:        "e2e",
		PolicyPaths: []string{policyPath},
	})
	require.NoError(t, err, "NewEmbeddedOPAEnforcer")

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

	mw := authz.NewHTTPMiddleware(authz.HTTPConfig{
		Enforcer:             enf,
		AllowAnonymous:       true,
		CQL2InjectionEnabled: true,
		FilterExtensionCheck: func(_ *http.Request, _ *middleware.STACInfo) bool { return true },
	})

	handler, err := federation.NewHandler(federation.HandlerConfig{
		Origins: []*federation.Origin{{
			ID:                      "primary",
			BaseURL:                 srv.URL,
			Enabled:                 true,
			Priority:                100,
			Searchable:              true,
			SupportsFilterExtension: true,
			Timeout:                 5 * time.Second,
		}},
		ConflictStrategy: federation.ConflictPriorityWins,
	})
	require.NoError(t, err, "NewHandler")

	httpReq := httptest.NewRequest("GET", "/search", nil)
	withChain(t, mw, handler, httpReq, &middleware.STACInfo{
		RequestType: middleware.RequestTypeSearch,
		SearchReq:   &stac.SearchRequest{Limit: 10},
	})

	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(cap.body, &body), "upstream body not JSON: %s", cap.body)
	filter, ok := body["filter"].(string)
	require.True(t, ok, "upstream filter not a string: %T %v", body["filter"], body["filter"])
	assert.Contains(t, filter, "eo:cloud_cover", "policy filter did not reach upstream")
}
