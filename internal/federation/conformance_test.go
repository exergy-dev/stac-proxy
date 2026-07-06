package federation

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/stac-proxy/internal/middleware"
	"github.com/yourorg/stac-proxy/internal/stac"
)

// TestHandleConformance_IntersectsProxyAndOrigins verifies that
// GET /conformance returns proxy_caps ∩ ⋂(origins) rather than
// passing through whichever origin the priority router picked first.
func TestHandleConformance_IntersectsProxyAndOrigins(t *testing.T) {
	t.Parallel()

	// Origin A advertises core + an extra class; Origin B advertises
	// core only. Intersection should be core only.
	srvA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"conformsTo": []string{
				"https://api.stacspec.org/v1.0.0/core",
				"https://api.stacspec.org/v1.0.0/item-search",
				"https://example.com/origin-a-only",
			},
		})
	}))
	defer srvA.Close()

	srvB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"conformsTo": []string{
				"https://api.stacspec.org/v1.0.0/core",
			},
		})
	}))
	defer srvB.Close()

	handler, err := NewHandler(HandlerConfig{
		Origins: []*Origin{
			{ID: "a", BaseURL: srvA.URL, Enabled: true, Timeout: 5 * time.Second, Priority: 10},
			{ID: "b", BaseURL: srvB.URL, Enabled: true, Timeout: 5 * time.Second, Priority: 1},
		},
		AggregateTimeout: 5 * time.Second,
		ConformanceCaps: stac.ConformanceCaps{
			CQL2InjectionEnabled:    false,
			AllOriginsSupportFilter: false,
		},
	})
	require.NoError(t, err, "NewHandler")

	req := &request{
		Request:     httptest.NewRequest(http.MethodGet, "/conformance", nil),
		Context:     context.Background(),
		RequestType: middleware.RequestTypeConformance,
	}
	resp, err := handler.Handle(req.Context, req)
	require.NoError(t, err, "Handle")
	require.Equal(t, http.StatusOK, resp.StatusCode, "status")

	var body struct {
		ConformsTo []string `json:"conformsTo"`
	}
	require.NoError(t, json.Unmarshal(resp.Body, &body), "unmarshal")

	seen := make(map[string]bool, len(body.ConformsTo))
	for _, c := range body.ConformsTo {
		seen[c] = true
	}
	// Origin A's exclusive class must NOT appear: B doesn't advertise it.
	assert.False(t, seen["https://example.com/origin-a-only"], "origin-a-only class leaked through intersection")
	// Core IS advertised — both origins and the proxy support it.
	assert.True(t, seen["https://api.stacspec.org/v1.0.0/core"], "core conformance dropped despite all sides supporting it")
}

// TestHandleConformance_NoOriginsFallsBackToProxyCaps verifies that
// when no origins respond, the proxy still serves an honest set of
// its own capabilities rather than 503-ing.
func TestHandleConformance_NoOriginsFallsBackToProxyCaps(t *testing.T) {
	t.Parallel()

	// Origin returning errors — should be treated as advertising nothing.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	handler, err := NewHandler(HandlerConfig{
		Origins: []*Origin{
			{ID: "a", BaseURL: srv.URL, Enabled: true, Timeout: time.Second},
		},
		AggregateTimeout: time.Second,
	})
	require.NoError(t, err, "NewHandler")

	req := &request{
		Request:     httptest.NewRequest(http.MethodGet, "/conformance", nil),
		Context:     context.Background(),
		RequestType: middleware.RequestTypeConformance,
	}
	resp, err := handler.Handle(req.Context, req)
	require.NoError(t, err, "Handle")
	require.Equal(t, http.StatusOK, resp.StatusCode, "status")

	var body struct {
		ConformsTo []string `json:"conformsTo"`
	}
	require.NoError(t, json.Unmarshal(resp.Body, &body), "unmarshal")
	// Should fall back to proxy core classes.
	assert.Containsf(t, body.ConformsTo, "https://api.stacspec.org/v1.0.0/core", "expected proxy core class in fallback, got %v", body.ConformsTo)
}

// TestHandleLanding_EmitsIntersectedConformance verifies the landing
// page reports the same conformance set as /conformance.
func TestHandleLanding_EmitsIntersectedConformance(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"conformsTo": []string{"https://api.stacspec.org/v1.0.0/core"},
		})
	}))
	defer srv.Close()

	handler, err := NewHandler(HandlerConfig{
		Origins: []*Origin{
			{ID: "a", BaseURL: srv.URL, Enabled: true, Timeout: time.Second},
		},
	})
	require.NoError(t, err, "NewHandler")

	req := &request{
		Request:     httptest.NewRequest(http.MethodGet, "/", nil),
		Context:     context.Background(),
		RequestType: middleware.RequestTypeLanding,
	}
	resp, err := handler.Handle(req.Context, req)
	require.NoError(t, err, "Handle")
	var body struct {
		Type       string   `json:"type"`
		ConformsTo []string `json:"conformsTo"`
	}
	require.NoError(t, json.Unmarshal(resp.Body, &body), "unmarshal")
	assert.Equal(t, "Catalog", body.Type, "type")
	assert.Containsf(t, body.ConformsTo, "https://api.stacspec.org/v1.0.0/core", "landing conformsTo missing core: %v", body.ConformsTo)
}
