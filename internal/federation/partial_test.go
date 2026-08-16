package federation

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/exergy-dev/stac-proxy/internal/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// twoOriginHandler builds a two-origin federation handler where
// origin "up" serves one item and origin "down" behaves per downFn.
func twoOriginHandler(t *testing.T, downFn http.HandlerFunc) *Handler {
	t.Helper()
	upFC := SampleFeatureCollection(SampleItem("item1", WithCollection("collection1")))
	upServer := NewTestServerWithJSONResponse(upFC)
	t.Cleanup(upServer.Close)
	downServer := httptest.NewServer(downFn)
	t.Cleanup(downServer.Close)

	handler, err := NewHandler(HandlerConfig{
		Origins: []*Origin{
			{
				ID: "up", BaseURL: upServer.URL, Enabled: true, Searchable: true,
				Collections: []string{"collection1"}, Timeout: 5 * time.Second, Priority: 1,
			},
			{
				ID: "down", BaseURL: downServer.URL, Enabled: true, Searchable: true,
				Collections: []string{"collection1"}, Timeout: 5 * time.Second, Priority: 2,
			},
		},
		MaxConcurrent:    10,
		AggregateTimeout: 10 * time.Second,
	})
	require.NoError(t, err)
	return handler
}

func searchVia(t *testing.T, h *Handler) *response {
	t.Helper()
	req := &request{
		Request:     httptest.NewRequest(http.MethodPost, "/search", nil),
		Context:     context.Background(),
		RequestType: middleware.RequestTypeSearch,
		SearchReq:   SampleSearchRequest(WithCollections("collection1"), WithLimit(10)),
	}
	resp, err := h.Handle(req.Context, req)
	require.NoError(t, err, "Handle()")
	return resp
}

func TestPartialResults_OneOriginDown(t *testing.T) {
	t.Parallel()
	h := twoOriginHandler(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})

	resp := searchVia(t, h)
	require.Equal(t, http.StatusOK, resp.StatusCode, "one healthy origin → 200")
	assert.Equal(t, "true", resp.Headers.Get(HeaderFederationPartial))
	assert.Equal(t, "down", resp.Headers.Get(HeaderFederationFailedOrigins))

	// The context block carries machine-readable per-origin status.
	var fc struct {
		Features []json.RawMessage `json:"features"`
		Context  struct {
			Origins []OriginStatus `json:"stac_proxy:origins"`
		} `json:"context"`
	}
	require.NoError(t, json.Unmarshal(resp.Body, &fc))
	assert.Len(t, fc.Features, 1, "healthy origin's item must be served")
	require.Len(t, fc.Context.Origins, 2)
	byID := map[string]OriginStatus{}
	for _, s := range fc.Context.Origins {
		byID[s.ID] = s
	}
	assert.Equal(t, "fetch_failed", byID["down"].Error)
	assert.Empty(t, byID["up"].Error)
	assert.Equal(t, 1, byID["up"].Returned)
}

func TestPartialResults_AllOriginsDown502(t *testing.T) {
	t.Parallel()
	down := func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}
	downServerA := httptest.NewServer(http.HandlerFunc(down))
	t.Cleanup(downServerA.Close)
	downServerB := httptest.NewServer(http.HandlerFunc(down))
	t.Cleanup(downServerB.Close)

	h, err := NewHandler(HandlerConfig{
		Origins: []*Origin{
			{ID: "a", BaseURL: downServerA.URL, Enabled: true, Searchable: true,
				Collections: []string{"collection1"}, Timeout: 5 * time.Second},
			{ID: "b", BaseURL: downServerB.URL, Enabled: true, Searchable: true,
				Collections: []string{"collection1"}, Timeout: 5 * time.Second},
		},
		MaxConcurrent:    10,
		AggregateTimeout: 10 * time.Second,
	})
	require.NoError(t, err)

	resp := searchVia(t, h)
	require.Equal(t, http.StatusBadGateway, resp.StatusCode,
		"all origins down must be a 502, not an empty 200")
	var body map[string]string
	require.NoError(t, json.Unmarshal(resp.Body, &body))
	assert.Equal(t, "UpstreamFederationFailure", body["code"])
	assert.Equal(t, "a,b", resp.Headers.Get(HeaderFederationFailedOrigins))
}

func TestPartialResults_Collections(t *testing.T) {
	t.Parallel()
	h := twoOriginHandler(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})

	req := &request{
		Request:     httptest.NewRequest(http.MethodGet, "/collections", nil),
		Context:     context.Background(),
		RequestType: middleware.RequestTypeCollections,
	}
	resp, err := h.Handle(req.Context, req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "true", resp.Headers.Get(HeaderFederationPartial))
	assert.Equal(t, "down", resp.Headers.Get(HeaderFederationFailedOrigins))
}

func TestPartialResults_HealthyIsUnmarked(t *testing.T) {
	t.Parallel()
	okFC := SampleFeatureCollection(SampleItem("item2", WithCollection("collection1")))
	h := twoOriginHandler(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(okFC)
	})

	resp := searchVia(t, h)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Empty(t, resp.Headers.Get(HeaderFederationPartial),
		"healthy fan-out must not carry the partial marker")
	var fc struct {
		Context struct {
			Origins []OriginStatus `json:"stac_proxy:origins"`
		} `json:"context"`
	}
	require.NoError(t, json.Unmarshal(resp.Body, &fc))
	require.Len(t, fc.Context.Origins, 2, "status block present on healthy responses too")
	for _, s := range fc.Context.Origins {
		assert.Empty(t, s.Error)
	}
}
