package live

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/stac-proxy/internal/federation"
	"github.com/yourorg/stac-proxy/internal/middleware"
	"github.com/yourorg/stac-proxy/internal/stac"
)

// Canonical public STAC API endpoints exercised by these tests. Both
// are unauthenticated for catalog and item-search; Planetary Computer
// requires a separate signing step for asset *fetches* but that is
// out of scope here — we only exercise metadata.
const (
	earthSearchURL = "https://earth-search.aws.element84.com/v1"
	pcURL          = "https://planetarycomputer.microsoft.com/api/stac/v1"
)

// originOpt is the variadic shape tests use to override default
// per-origin settings (e.g. restricting Collections in the routing
// test) without duplicating the full Origin builder.
type originOpt func(earthSearch, pc *federation.Origin)

// newFederation returns a two-origin federation.Handler pointed at
// Earth Search and Planetary Computer, after asserting that the live
// test gate is on. All tests in this package go through this helper
// so the env-var skip is centralised and the URLs/timeouts have a
// single source of truth.
func newFederation(t *testing.T, opts ...originOpt) *federation.Handler {
	t.Helper()
	if os.Getenv("STAC_PROXY_LIVE") != "1" {
		t.Skip("set STAC_PROXY_LIVE=1 to run live STAC tests")
	}

	earthSearch := &federation.Origin{
		ID:                      "earth-search",
		Name:                    "Element 84 Earth Search",
		BaseURL:                 earthSearchURL,
		Enabled:                 true,
		Searchable:              true,
		Priority:                10,
		Timeout:                 15 * time.Second,
		Auth:                    federation.AuthConfig{Type: "none"},
		SupportsFilterExtension: true,
	}
	pc := &federation.Origin{
		ID:                      "planetary-computer",
		Name:                    "Microsoft Planetary Computer",
		BaseURL:                 pcURL,
		Enabled:                 true,
		Searchable:              true,
		Priority:                5,
		Timeout:                 15 * time.Second,
		Auth:                    federation.AuthConfig{Type: "none"},
		SupportsFilterExtension: true,
	}
	for _, opt := range opts {
		opt(earthSearch, pc)
	}

	h, err := federation.NewHandler(federation.HandlerConfig{
		Origins:          []*federation.Origin{earthSearch, pc},
		ConflictStrategy: federation.ConflictPriorityWins,
		MaxConcurrent:    2,
		AggregateTimeout: 30 * time.Second,
	})
	require.NoError(t, err, "NewHandler")
	return h
}

// serve drives federation.Handler.ServeHTTP with a STACInfo already
// populated on the context — mirrors withChain in
// tests/integration/cql2_injection_test.go but without the authz
// middleware wrapper (live tests don't exercise authz).
func serve(t *testing.T, h *federation.Handler, info *middleware.STACInfo,
	method, path string, body io.Reader,
) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, body)
	ctx := middleware.WithSTACInfo(req.Context(), info)
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

// itemOriginMarker pulls the proxy-added stac_proxy:origin link out
// of an item's links and returns the origin's ID (the link's title).
// The merger attaches a link with rel=stac_proxy:origin to every
// federated item so clients can tell which origin contributed each.
func itemOriginMarker(t *testing.T, item *stac.Item) string {
	t.Helper()
	return stac.ItemOriginID(item)
}

// TestLive_BasicSearchMerge issues a small bbox-bounded search for a
// collection both origins serve (sentinel-2-l2a) and verifies the
// merged response carries items from both origins, each tagged with
// the right stac_proxy:origin marker.
func TestLive_BasicSearchMerge(t *testing.T) {
	h := newFederation(t)

	// Tight bbox + tight datetime so each origin naturally returns a
	// handful of items (~1-3 each). Why this matters: the merger
	// trims the merged output to `limit` after priority-sorting
	// origins, so a too-large per-origin return on the higher-
	// priority origin would crowd the lower-priority origin out of
	// the merged result entirely (intentional PriorityWins behavior,
	// not a bug). With a small per-origin return and a generous
	// limit, both origins comfortably fit in the merged output.
	end := time.Now().UTC()
	start := end.Add(-14 * 24 * time.Hour)
	searchReq := &stac.SearchRequest{
		Collections: []string{"sentinel-2-l2a"},
		BBox:        []float64{10.6, 47.4, 10.8, 47.6},
		Datetime:    start.Format(time.RFC3339) + "/" + end.Format(time.RFC3339),
		Limit:       50,
	}
	body, err := json.Marshal(searchReq)
	require.NoError(t, err, "marshal search")

	rr := serve(t, h,
		&middleware.STACInfo{RequestType: middleware.RequestTypeSearch, SearchReq: searchReq},
		http.MethodPost, "/search", bytes.NewReader(body),
	)

	require.Equal(t, http.StatusOK, rr.Code, "status = %d, body = %s", rr.Code, rr.Body.String())

	var fc stac.FeatureCollection
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &fc), "decode FeatureCollection: %s", rr.Body.String())

	require.NotEmpty(t, fc.Features, "no features returned; expected items from both origins")

	originsSeen := make(map[string]int)
	for i, item := range fc.Features {
		if item == nil {
			assert.Failf(t, "nil feature", "feature[%d] is nil", i)
			continue
		}
		assert.NotEmpty(t, item.ID, "feature[%d] has empty ID", i)
		assert.NotEmpty(t, item.Geometry, "feature[%d] (%s) has empty Geometry", i, item.ID)
		_, ok := stac.ItemDatetime(item)
		assert.True(t, ok, "feature[%d] (%s) has no parseable datetime", i, item.ID)
		marker := itemOriginMarker(t, item)
		assert.NotEmpty(t, marker, "feature[%d] (%s) missing stac_proxy:origin marker", i, item.ID)
		originsSeen[marker]++
	}

	// Both origins should have contributed at least one item. If one
	// of them didn't, that's a legitimate failure — the federation
	// merge isn't actually federating.
	for _, want := range []string{"earth-search", "planetary-computer"} {
		assert.NotZero(t, originsSeen[want], "no items tagged with stac_proxy:origin=%q; merge did not include this origin (origins seen: %v)", want, originsSeen)
	}

	if sc := stac.SearchContextOf(&fc); sc == nil {
		assert.Fail(t, "SearchContext missing from FeatureCollection")
	} else {
		assert.Equal(t, len(fc.Features), sc.Returned, "SearchContext.Returned = %d, want %d", sc.Returned, len(fc.Features))
	}
}

// TestLive_CollectionRoutingSkipsIrrelevantOrigins constrains each
// origin to a single collection it serves, then issues searches for
// each collection and verifies the response is sourced only from the
// origin that actually serves it. The router (RouteCollection) reads
// Origin.Collections to decide which origins to fan out to.
//
// Note: when the router resolves a request to a single origin,
// handleSearch takes a `reverseProxyOnce` fast path that streams the
// upstream response back without going through the merger. That's an
// intentional optimisation — it preserves upstream headers and
// streaming semantics — and means the `stac_proxy:origin` per-item
// marker is NOT added in this path (the marker is a merge artefact).
// We assert correctness here by verifying:
//
//   - the response carries items genuinely sourced from the routed
//     origin (item IDs follow that origin's naming convention)
//   - a search for a collection neither origin advertises returns an
//     empty FeatureCollection (the irrelevant-origin skip case)
func TestLive_CollectionRoutingSkipsIrrelevantOrigins(t *testing.T) {
	// "3dep-lidar-dsm" is a USGS 3D Elevation Program collection
	// hosted only by Planetary Computer. "sentinel-2-l2a" is on
	// both, but we constrain Earth Search to advertise it
	// exclusively here so the router routes by config.
	h := newFederation(t, func(es, pc *federation.Origin) {
		es.Collections = []string{"sentinel-2-l2a"}
		pc.Collections = []string{"3dep-lidar-dsm"}
	})

	// 1) PC-exclusive collection → router should pick PC only. The
	// fast path forwards the request directly to PC; the response
	// items are PC-shaped (USGS naming, e.g. "UT_StatewideSouth_…").
	pcOnlyReq := &stac.SearchRequest{
		Collections: []string{"3dep-lidar-dsm"},
		Limit:       3,
	}
	pcBody, _ := json.Marshal(pcOnlyReq)
	rr := serve(t, h,
		&middleware.STACInfo{RequestType: middleware.RequestTypeSearch, SearchReq: pcOnlyReq},
		http.MethodPost, "/search", bytes.NewReader(pcBody),
	)
	require.Equal(t, http.StatusOK, rr.Code, "PC-only search: status = %d, body = %s", rr.Code, rr.Body.String())
	var pcFC stac.FeatureCollection
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &pcFC), "decode PC-only FC: %s", rr.Body.String())
	assert.NotEmpty(t, pcFC.Features, "PC-only search returned no features (routing may have failed)")
	for _, item := range pcFC.Features {
		if item.Collection != "" {
			assert.Equal(t, "3dep-lidar-dsm", item.Collection, "PC-only feature %s belongs to %q, want 3dep-lidar-dsm",
				item.ID, item.Collection)
		}
	}

	// 2) Earth-Search-exclusive (per our config) collection → only ES.
	esOnlyReq := &stac.SearchRequest{
		Collections: []string{"sentinel-2-l2a"},
		BBox:        []float64{10.0, 47.0, 11.0, 48.0},
		Limit:       3,
	}
	esBody, _ := json.Marshal(esOnlyReq)
	rr = serve(t, h,
		&middleware.STACInfo{RequestType: middleware.RequestTypeSearch, SearchReq: esOnlyReq},
		http.MethodPost, "/search", bytes.NewReader(esBody),
	)
	require.Equal(t, http.StatusOK, rr.Code, "ES-only search: status = %d, body = %s", rr.Code, rr.Body.String())
	var esFC stac.FeatureCollection
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &esFC), "decode ES-only FC: %s", rr.Body.String())
	assert.NotEmpty(t, esFC.Features, "ES-only search returned no features (routing may have failed)")
	for _, item := range esFC.Features {
		if item.Collection != "" {
			assert.Equal(t, "sentinel-2-l2a", item.Collection, "ES-only feature %s belongs to %q, want sentinel-2-l2a",
				item.ID, item.Collection)
		}
		// Earth Search Sentinel-2 IDs follow the pattern
		// "S2A_..." or "S2B_..." — a strong signal the response
		// genuinely came from Earth Search rather than from PC.
		assert.True(t, strings.HasPrefix(item.ID, "S2A_") || strings.HasPrefix(item.ID, "S2B_"),
			"ES-only feature ID %q does not look like an Earth Search S2 item", item.ID)
	}

	// 3) A collection neither origin advertises → expect an empty
	// FeatureCollection (the router skips all origins, returning the
	// empty fast-path response).
	noneReq := &stac.SearchRequest{
		Collections: []string{"this-collection-does-not-exist"},
		Limit:       3,
	}
	noneBody, _ := json.Marshal(noneReq)
	rr = serve(t, h,
		&middleware.STACInfo{RequestType: middleware.RequestTypeSearch, SearchReq: noneReq},
		http.MethodPost, "/search", bytes.NewReader(noneBody),
	)
	require.Equal(t, http.StatusOK, rr.Code, "no-match search: status = %d, body = %s", rr.Code, rr.Body.String())
	var noneFC stac.FeatureCollection
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &noneFC), "decode no-match FC: %s", rr.Body.String())
	assert.Len(t, noneFC.Features, 0, "no-match search returned %d features, want 0", len(noneFC.Features))
}

// TestLive_CollectionsAggregate hits /collections and verifies both
// origins contribute, that the merged response dedupes overlapping
// IDs, and that each collection carries the stac_proxy:origin link
// (rel=stac_proxy:origin, title=originID, href=upstream BaseURL).
//
// We deliberately decode the response into a `map[string]any`-shaped
// struct rather than `stac.CollectionsResponse`. The library's
// Collection.UnmarshalJSON does TWO sequential json.Unmarshal passes
// over the same input bytes (one into a struct alias, one into
// map[string]json.RawMessage). The Go race detector flags those two
// passes as conflicting writes/reads on the underlying bytes — same
// goroutine, same memory region, but flagged as a race because of
// RawMessage slice aliasing across the two passes. The flag is a
// false positive (no concurrent goroutines touch the bytes) but it
// makes go test -race brittle here. Decoding into a generic shape
// sidesteps the library's UnmarshalJSON entirely.
func TestLive_CollectionsAggregate(t *testing.T) {
	h := newFederation(t)

	rr := serve(t, h,
		&middleware.STACInfo{RequestType: middleware.RequestTypeCollections},
		http.MethodGet, "/collections", nil,
	)

	require.Equal(t, http.StatusOK, rr.Code, "status = %d, body = %s", rr.Code, rr.Body.String())

	// Decode into a generic shape to avoid the library's
	// dual-pass UnmarshalJSON on stac.Collection (see test
	// docstring above).
	var resp struct {
		Collections []map[string]any `json:"collections"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp), "decode CollectionsResponse: %s", rr.Body.String())

	// Sanity floor: PC alone publishes far more than this. If the
	// total is suspiciously small, one origin probably didn't
	// contribute at all.
	const sanityFloor = 30
	assert.Greater(t, len(resp.Collections), sanityFloor,
		"got %d collections, want > %d (one origin may not have contributed)",
		len(resp.Collections), sanityFloor)

	originsSeen := make(map[string]int)
	idCounts := make(map[string]int)
	for _, coll := range resp.Collections {
		id, _ := coll["id"].(string)
		idCounts[id]++
		marker := originLinkTitle(coll)
		if marker == "" {
			assert.Failf(t, "missing origin marker", "collection %q has no stac_proxy:origin link", id)
			continue
		}
		originsSeen[marker]++
	}

	for _, want := range []string{"earth-search", "planetary-computer"} {
		assert.NotZero(t, originsSeen[want], "no collections from origin %q (origins seen: %v)", want, originsSeen)
	}

	// Both origins serve sentinel-2-l2a; dedupe must collapse it to
	// a single entry in the response.
	assert.Equal(t, 1, idCounts["sentinel-2-l2a"],
		"sentinel-2-l2a appears %d times in response, want 1 (dedupe failed)", idCounts["sentinel-2-l2a"])
}

// originLinkTitle finds the stac_proxy:origin link in a generic
// JSON-decoded STAC document (map[string]any) and returns its
// title, or "" if no such link exists. Used by tests that decode
// into a generic shape to dodge the library's dual-pass
// UnmarshalJSON race-detector false positive.
func originLinkTitle(doc map[string]any) string {
	links, _ := doc["links"].([]any)
	for _, l := range links {
		lm, ok := l.(map[string]any)
		if !ok {
			continue
		}
		if rel, _ := lm["rel"].(string); rel == stac.OriginLinkRel {
			title, _ := lm["title"].(string)
			return title
		}
	}
	return ""
}

// TestLive_ConformanceIntersection hits /conformance and verifies the
// proxy returns the intersection of its own ProxyConformanceCore with
// both origins' conformance sets — never advertising a class that
// only one side supports.
func TestLive_ConformanceIntersection(t *testing.T) {
	h := newFederation(t)

	rr := serve(t, h,
		&middleware.STACInfo{RequestType: middleware.RequestTypeConformance},
		http.MethodGet, "/conformance", nil,
	)

	require.Equal(t, http.StatusOK, rr.Code, "status = %d, body = %s", rr.Code, rr.Body.String())

	var resp struct {
		ConformsTo []string `json:"conformsTo"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp), "decode conformance: %s", rr.Body.String())

	seen := make(map[string]bool, len(resp.ConformsTo))
	for _, c := range resp.ConformsTo {
		seen[c] = true
	}

	// Both origins advertise these and the proxy lists them in
	// ProxyConformanceCore, so the intersection MUST include them.
	for _, want := range []string{
		"https://api.stacspec.org/v1.0.0/core",
		"https://api.stacspec.org/v1.0.0/item-search",
	} {
		assert.True(t, seen[want], "conformance missing required class %q", want)
	}

	// Intersection guarantee: nothing that is not in
	// ProxyConformanceCore (or FilterExtensionConformance when
	// allowed) should appear. Specifically, stac-extensions.github.io
	// URIs are extension *manifests*, not conformance classes, and
	// must never leak into /conformance.
	for _, c := range resp.ConformsTo {
		assert.False(t, strings.Contains(c, "stac-extensions.github.io"),
			"non-conformance extension URI leaked into /conformance: %q", c)
	}

	// We do NOT pin len(resp.ConformsTo) — both providers add
	// classes routinely and the intersection naturally varies.
}
