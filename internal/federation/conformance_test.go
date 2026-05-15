package federation

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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
		ConflictStrategy: ConflictPriorityWins,
		AggregateTimeout: 5 * time.Second,
		ConformanceCaps: stac.ConformanceCaps{
			CQL2InjectionEnabled:    false,
			AllOriginsSupportFilter: false,
		},
	})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	req := &request{
		Request:     httptest.NewRequest(http.MethodGet, "/conformance", nil),
		Context:     context.Background(),
		RequestType: middleware.RequestTypeConformance,
	}
	resp, err := handler.Handle(req.Context, req)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}

	var body struct {
		ConformsTo []string `json:"conformsTo"`
	}
	if err := json.Unmarshal(resp.Body, &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	seen := make(map[string]bool, len(body.ConformsTo))
	for _, c := range body.ConformsTo {
		seen[c] = true
	}
	// Origin A's exclusive class must NOT appear: B doesn't advertise it.
	if seen["https://example.com/origin-a-only"] {
		t.Error("origin-a-only class leaked through intersection")
	}
	// Core IS advertised — both origins and the proxy support it.
	if !seen["https://api.stacspec.org/v1.0.0/core"] {
		t.Error("core conformance dropped despite all sides supporting it")
	}
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
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	req := &request{
		Request:     httptest.NewRequest(http.MethodGet, "/conformance", nil),
		Context:     context.Background(),
		RequestType: middleware.RequestTypeConformance,
	}
	resp, err := handler.Handle(req.Context, req)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}

	var body struct {
		ConformsTo []string `json:"conformsTo"`
	}
	if err := json.Unmarshal(resp.Body, &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// Should fall back to proxy core classes.
	found := false
	for _, c := range body.ConformsTo {
		if c == "https://api.stacspec.org/v1.0.0/core" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected proxy core class in fallback, got %v", body.ConformsTo)
	}
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
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	req := &request{
		Request:     httptest.NewRequest(http.MethodGet, "/", nil),
		Context:     context.Background(),
		RequestType: middleware.RequestTypeLanding,
	}
	resp, err := handler.Handle(req.Context, req)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	var body struct {
		Type       string   `json:"type"`
		ConformsTo []string `json:"conformsTo"`
	}
	if err := json.Unmarshal(resp.Body, &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body.Type != "Catalog" {
		t.Errorf("type = %q, want Catalog", body.Type)
	}
	found := false
	for _, c := range body.ConformsTo {
		if c == "https://api.stacspec.org/v1.0.0/core" {
			found = true
		}
	}
	if !found {
		t.Errorf("landing conformsTo missing core: %v", body.ConformsTo)
	}
}
