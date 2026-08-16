package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/exergy-dev/stac-proxy/internal/config"
	"github.com/exergy-dev/stac-proxy/internal/observability"
	"github.com/exergy-dev/stac-proxy/internal/server"
)

// chainUpstream is a mock STAC upstream that records the last /search
// body it received and returns a FeatureCollection with one in-area
// and one out-of-area feature (relative to the test policy's fence).
type chainUpstream struct {
	srv *httptest.Server

	mu         sync.Mutex
	lastSearch []byte
}

func newChainUpstream(t *testing.T, conformsTo []string) *chainUpstream {
	t.Helper()
	u := &chainUpstream{}
	mux := http.NewServeMux()
	mux.HandleFunc("/conformance", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"conformsTo": conformsTo})
	})
	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		u.mu.Lock()
		u.lastSearch = body
		u.mu.Unlock()
		w.Header().Set("Content-Type", "application/geo+json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"type": "FeatureCollection",
			"features": []map[string]any{
				{"type": "Feature", "id": "in-area", "collection": "c1",
					"geometry":   map[string]any{"type": "Point", "coordinates": []float64{1, 1}},
					"properties": map[string]any{}},
				{"type": "Feature", "id": "out-of-area", "collection": "c1",
					"geometry":   map[string]any{"type": "Point", "coordinates": []float64{50, 50}},
					"properties": map[string]any{}},
			},
		})
	})
	u.srv = httptest.NewServer(mux)
	t.Cleanup(u.srv.Close)
	return u
}

func (u *chainUpstream) searchBody(t *testing.T) map[string]any {
	t.Helper()
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.lastSearch) == 0 {
		return nil
	}
	var m map[string]any
	require.NoError(t, json.Unmarshal(u.lastSearch, &m))
	return m
}

// chainPolicy denies anonymous, denies the "secret" collection with a
// distinct reason, emits a cloud-cover CQL2 filter for everyone, and a
// geofence for principals holding the "fenced" role.
const chainPolicy = `package stac.authz

import future.keywords.contains
import future.keywords.if
import future.keywords.in

default allow := false

result := {"allow": allow, "reasons": reasons, "constraints": constraints}

reasons contains "authentication required" if {
	not allow
	not input.principal
}

reasons contains "collection off-limits" if {
	not allow
	input.principal
}

reasons contains "ok" if allow

allow if {
	input.principal
	not input.resource.collection == "secret"
}

constraints := c if {
	allow
	c := object.union_n([{"cql2_filter": "eo:cloud_cover < 42"}, geofence_part])
} else := {}

default geofence_part := {}

geofence_part := {"geofence": {
	"allowed_area": {
		"type": "Polygon",
		"coordinates": [[[-10, -10], [10, -10], [10, 10], [-10, 10], [-10, -10]]],
	},
	"filter_mode": true,
}} if {
	"fenced" in input.principal.roles
}
`

// buildSecurityChain goes YAML file -> config.Load -> ValidateConfig ->
// the same build functions run() uses -> server.NewRouter, returning
// the composed handler exactly as production would serve it.
func buildSecurityChain(t *testing.T, upstreamURL string) http.Handler {
	t.Helper()
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.rego")
	require.NoError(t, os.WriteFile(policyPath, []byte(chainPolicy), 0o600))

	yaml := fmt.Sprintf(`
mode: single
server:
  host: "127.0.0.1"
  port: 8080
upstream:
  url: %q
  allow_private_origin: true
logging:
  level: "error"
  format: "json"
middleware:
  - name: auth
    config:
      allow_anonymous: false
      providers:
        - type: api_key
          header_name: "X-API-Key"
          hmac_secret: "chain-test-secret"
          keys:
            - key: "sk-plain"
              name: "svc-plain"
              roles: ["user"]
            - key: "sk-fenced"
              name: "svc-fenced"
              roles: ["user", "fenced"]
authz:
  opa:
    embedded: true
    policy_path: %q
  cql2_injection:
    enabled: true
`, upstreamURL, policyPath)
	cfgPath := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(yaml), 0o600))

	cfg, err := config.Load(cfgPath)
	require.NoError(t, err, "config.Load")
	require.NoError(t, config.ValidateConfig(cfg), "ValidateConfig")

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	health := observability.NewHealthChecker()
	handler, err := buildFederationHandler(context.Background(), cfg, logger, health, nil)
	require.NoError(t, err, "buildFederationHandler")

	authMW, err := buildAuthHTTPMiddleware(context.Background(), cfg, logger)
	require.NoError(t, err, "buildAuthHTTPMiddleware")
	require.NotNil(t, authMW)
	azMW, err := buildAuthzHTTPMiddleware(context.Background(), cfg, logger, handler)
	require.NoError(t, err, "buildAuthzHTTPMiddleware")
	require.NotNil(t, azMW)

	return server.NewRouter(server.RouterConfig{
		Handler:         handler,
		HealthChecker:   health,
		HTTPMiddlewares: []func(http.Handler) http.Handler{authMW, azMW},
		ClientIP:        cfg.Server.ClientIP,
	})
}

func doJSON(t *testing.T, h http.Handler, method, path, apiKey, body string) *httptest.ResponseRecorder {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rd)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

// TestSecurityChain_ConfigFileToEnforcement drives a YAML config
// through the real build functions and asserts the composed chain's
// security behavior end to end — the first test anywhere to do so.
func TestSecurityChain_ConfigFileToEnforcement(t *testing.T) {
	t.Parallel()

	filterOnly := []string{
		"http://www.opengis.net/spec/cql2/1.0/conf/cql2-text",
	}
	filterAndSpatial := append(filterOnly,
		"http://www.opengis.net/spec/cql2/1.0/conf/basic-spatial-functions")

	t.Run("authn: anonymous and bad credentials get 401 envelopes", func(t *testing.T) {
		t.Parallel()
		up := newChainUpstream(t, filterOnly)
		chain := buildSecurityChain(t, up.srv.URL)

		rr := doJSON(t, chain, http.MethodPost, "/search", "", `{}`)
		require.Equal(t, http.StatusUnauthorized, rr.Code, "anonymous: %s", rr.Body.String())
		assert.Contains(t, rr.Body.String(), "Unauthorized")

		rr = doJSON(t, chain, http.MethodPost, "/search", "sk-wrong", `{}`)
		require.Equal(t, http.StatusUnauthorized, rr.Code, "bad key must hard-401, not fall through")
	})

	t.Run("authz: policy-denied collection gets 403 with the policy reason", func(t *testing.T) {
		t.Parallel()
		up := newChainUpstream(t, filterOnly)
		chain := buildSecurityChain(t, up.srv.URL)

		rr := doJSON(t, chain, http.MethodGet, "/collections/secret", "sk-plain", "")
		require.Equal(t, http.StatusForbidden, rr.Code, "body: %s", rr.Body.String())
		assert.Contains(t, rr.Body.String(), "collection off-limits")
	})

	t.Run("policy CQL2 reaches the upstream AND-combined with the client filter", func(t *testing.T) {
		t.Parallel()
		up := newChainUpstream(t, filterOnly)
		chain := buildSecurityChain(t, up.srv.URL)

		rr := doJSON(t, chain, http.MethodPost, "/search", "sk-plain",
			`{"filter":"datetime > '2025-01-01'","filter-lang":"cql2-text"}`)
		require.Equal(t, http.StatusOK, rr.Code, "body: %s", rr.Body.String())

		body := up.searchBody(t)
		require.NotNil(t, body, "upstream must have been reached")
		filter, _ := body["filter"].(string)
		assert.Contains(t, filter, "eo:cloud_cover", "policy predicate missing upstream")
		assert.Contains(t, filter, "datetime", "client predicate missing upstream")
		assert.Contains(t, filter, "AND")
	})

	t.Run("leak gate: no spatial conformance -> geofence stays post-filtered", func(t *testing.T) {
		t.Parallel()
		up := newChainUpstream(t, filterOnly)
		chain := buildSecurityChain(t, up.srv.URL)

		rr := doJSON(t, chain, http.MethodPost, "/search", "sk-fenced", `{}`)
		require.Equal(t, http.StatusOK, rr.Code, "body: %s", rr.Body.String())

		filter, _ := up.searchBody(t)["filter"].(string)
		assert.NotContains(t, filter, "S_INTERSECTS",
			"geofence must NOT push down without spatial conformance")

		var fc map[string]any
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &fc))
		var ids []string
		for _, f := range fc["features"].([]any) {
			ids = append(ids, f.(map[string]any)["id"].(string))
		}
		assert.Equal(t, []string{"in-area"}, ids,
			"post-filter must drop the out-of-area feature (the leak-gate regression)")
	})

	t.Run("spatial conformance -> geofence pushes down as S_INTERSECTS", func(t *testing.T) {
		t.Parallel()
		up := newChainUpstream(t, filterAndSpatial)
		chain := buildSecurityChain(t, up.srv.URL)

		rr := doJSON(t, chain, http.MethodPost, "/search", "sk-fenced", `{}`)
		require.Equal(t, http.StatusOK, rr.Code, "body: %s", rr.Body.String())

		filter, _ := up.searchBody(t)["filter"].(string)
		assert.Contains(t, filter, "S_INTERSECTS",
			"spatial conformance must enable geofence push-down")
		assert.Contains(t, filter, "eo:cloud_cover")
	})
}
