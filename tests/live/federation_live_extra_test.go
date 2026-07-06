package live

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/stac-proxy/internal/federation"
	"github.com/yourorg/stac-proxy/internal/federation/pagecache"
	"github.com/yourorg/stac-proxy/internal/middleware"
	"github.com/yourorg/stac-proxy/internal/middleware/cache"
	"github.com/yourorg/stac-proxy/internal/stac"
)

// This file extends federation_live_test.go with coverage for the
// non-search request types, the pagination/cursor path, link
// rewriting, and the alternate conflict strategy. All tests share the
// STAC_PROXY_LIVE=1 gate via newFederation/newPaginatedFederation.

const (
	// proxyPublicBase is what the proxy advertises as its externally
	// reachable URL when we want to assert that response links route
	// back through the proxy rather than directly to the upstream.
	proxyPublicBase = "https://stac-proxy.test.example.com"

	// cursorSecret is the HMAC key used to sign pagination cursors in
	// the live tests. Real deployments load this from config; tests
	// use a fixed value so cursors round-trip within a single test
	// run. Length is past the 32-byte recommendation; HMAC accepts
	// any length.
	cursorSecret = "live-test-cursor-secret-must-be-long-enough-for-hmac-sha256"
)

// newPaginatedFederation builds a handler with CursorSecret and
// ProxyBaseURL set so the `next` link path and the federated
// PaginatedSearcher fire. opts can override Origin fields the same
// way newFederation's opts do.
func newPaginatedFederation(t *testing.T, opts ...originOpt) *federation.Handler {
	t.Helper()
	// newFederation enforces the STAC_PROXY_LIVE=1 gate; reuse it,
	// then rebuild with the extra config bits.
	_ = newFederation(t)

	earthSearch := &federation.Origin{
		ID:                      "earth-search",
		Name:                    "Element 84 Earth Search",
		BaseURL:                 earthSearchURL,
		Enabled:                 true,
		Searchable:              true,
		Priority:                10,
		Timeout:                 30 * time.Second,
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
		Timeout:                 30 * time.Second,
		Auth:                    federation.AuthConfig{Type: "none"},
		SupportsFilterExtension: true,
	}
	for _, opt := range opts {
		opt(earthSearch, pc)
	}

	pc_cache, err := pagecache.New(
		cache.NewMemoryStore(cache.MemoryConfig{MaxSize: 256}),
		time.Hour,
		[]byte(cursorSecret),
	)
	require.NoError(t, err, "pagecache.New")

	h, err := federation.NewHandler(federation.HandlerConfig{
		Origins:          []*federation.Origin{earthSearch, pc},
		MaxConcurrent:    2,
		AggregateTimeout: 60 * time.Second,
		CursorSecret:     []byte(cursorSecret),
		ProxyBaseURL:     proxyPublicBase,
		PageCache:        pc_cache,
	})
	require.NoError(t, err, "NewHandler (paginated)")
	return h
}

// TestLive_GETSearchMerges issues the GET form of /search (rather
// than POST). The proxy must accept query-param-encoded searches and
// merge results the same way it does for POST, since federation
// clients pick one form or the other.
func TestLive_GETSearchMerges(t *testing.T) {
	h := newFederation(t)

	end := time.Now().UTC()
	start := end.Add(-14 * 24 * time.Hour)
	q := fmt.Sprintf(
		"/search?collections=sentinel-2-l2a&bbox=10.6,47.4,10.8,47.6&datetime=%s/%s&limit=50",
		start.Format(time.RFC3339), end.Format(time.RFC3339),
	)

	rr := serve(t, h,
		&middleware.STACInfo{
			RequestType: middleware.RequestTypeSearch,
			SearchReq: &stac.SearchRequest{
				Collections: []string{"sentinel-2-l2a"},
				BBox:        []float64{10.6, 47.4, 10.8, 47.6},
				Datetime:    start.Format(time.RFC3339) + "/" + end.Format(time.RFC3339),
				Limit:       50,
			},
		},
		http.MethodGet, q, nil,
	)

	require.Equal(t, http.StatusOK, rr.Code, "status = %d, body = %s", rr.Code, rr.Body.String())

	var fc stac.FeatureCollection
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &fc), "decode FC")
	require.NotEmpty(t, fc.Features, "GET /search returned no features")
}

// TestLive_PaginatedNextLink configures a federated paginator
// with a CursorSecret + ProxyBaseURL, issues a tight-limit POST
// /search across both origins, and verifies the response carries a
// `rel: next` link that:
//
//   - is rooted at proxyPublicBase (so the client comes back via the
//     proxy, not the upstream),
//   - carries method=POST + body.token=<cursor> as the additional
//     fields the spec recommends for cursor-based pagination, and
//   - resolves to a fresh page that doesn't repeat the first page's
//     IDs (cursor dedup actually works across origins).
//
// # Both origins
//
// This test exercises the full federation: Planetary Computer uses
// POST body.token (STAC spec), Earth Search uses ?next=<id> (non-spec).
// The pagination adapter layer normalizes both — the `auto` adapter
// locks PC's response to "token" and ES's to "next_url", and on page 2
// each origin is advanced via its own captured next-state. If either
// upstream's cursor doesn't actually advance, page 2 will repeat
// page 1's items and this test will catch it.
func TestLive_PaginatedNextLink(t *testing.T) {
	h := newPaginatedFederation(t)

	end := time.Now().UTC()
	start := end.Add(-30 * 24 * time.Hour)
	searchReq := &stac.SearchRequest{
		Collections: []string{"sentinel-2-l2a"},
		BBox:        []float64{10.0, 47.0, 11.0, 48.0},
		Datetime:    start.Format(time.RFC3339) + "/" + end.Format(time.RFC3339),
		Limit:       5,
	}
	body, _ := json.Marshal(searchReq)
	rr := serve(t, h,
		&middleware.STACInfo{RequestType: middleware.RequestTypeSearch, SearchReq: searchReq},
		http.MethodPost, "/search", bytes.NewReader(body),
	)
	require.Equal(t, http.StatusOK, rr.Code, "page 1 status = %d, body = %s", rr.Code, rr.Body.String())

	var page1 stac.FeatureCollection
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &page1), "decode page 1")
	require.NotEmpty(t, page1.Features, "page 1 returned no features; can't exercise pagination")

	nextLink := findLink(page1.Links, "next")
	require.NotNil(t, nextLink, "page 1 has no rel=next link; pagination wasn't engaged")
	assert.True(t, strings.HasPrefix(nextLink.Href, proxyPublicBase),
		"next.href = %q, want prefix %q (proxy base URL not applied)",
		nextLink.Href, proxyPublicBase)
	method, _ := nextLink.AdditionalFields["method"].(string)
	assert.Equal(t, http.MethodPost, method, "next link method = %q, want POST", method)
	nextBody, _ := nextLink.AdditionalFields["body"].(map[string]any)
	cursor, _ := nextBody["token"].(string)
	require.NotEmpty(t, cursor, "next link body has no token; nothing to follow")

	// Page 1 IDs — page 2 must not repeat them. The dedup state is
	// encoded in the cursor itself, so this is the integration check
	// that the cursor round-trip preserves it.
	page1IDs := make(map[string]bool, len(page1.Features))
	for _, item := range page1.Features {
		page1IDs[item.ID] = true
	}

	// Follow the cursor.
	page2Req := *searchReq
	page2Req.Token = cursor
	page2Body, _ := json.Marshal(page2Req)
	rr2 := serve(t, h,
		&middleware.STACInfo{RequestType: middleware.RequestTypeSearch, SearchReq: &page2Req},
		http.MethodPost, "/search", bytes.NewReader(page2Body),
	)
	require.Equal(t, http.StatusOK, rr2.Code, "page 2 status = %d, body = %s", rr2.Code, rr2.Body.String())
	var page2 stac.FeatureCollection
	require.NoError(t, json.Unmarshal(rr2.Body.Bytes(), &page2), "decode page 2")
	if len(page2.Features) == 0 {
		// Acceptable for a sparsely-populated bbox: the cursor exists
		// but the second window was empty. Log and continue.
		t.Logf("page 2 was empty; cursor existed but no remaining items")
		return
	}
	for _, item := range page2.Features {
		assert.False(t, page1IDs[item.ID],
			"page 2 repeats page 1 item %q (cursor dedup broke across the round-trip)", item.ID)
	}
}

// TestLive_PaginatedMultiPage_NoRepeatsNoSkips walks several pages of
// a federated search and verifies two integrity properties of the
// paginated path against a real two-origin federation:
//
//  1. No repeats: across N pages of size L, every returned item ID is
//     unique. A cursor that fails to advance an upstream would surface
//     here as the same item showing up on two consecutive pages.
//
//  2. No skips: a single-call fetch with limit=N*L (no cursor) over
//     the same query must be a subset of the union of items seen
//     across the page walk. A cursor that loses items between pages
//     (e.g. a tiebreaker bug at a page boundary) would put items in
//     the single-call response that the walk never sees.
//
// Two bugs this test originally surfaced (now fixed):
//
//   - Buffer-drop: pagination.go used to fetch limit*2 items per
//     origin and advance each cursor past all of them, so the
//     un-emitted items were lost. Fixed by per-origin Stash on
//     OriginCursor (see cursor.go) which the next page consumes
//     before re-fetching from upstream.
//
//   - Earth Search adapter mismatch: ES emits rel=next with method=POST
//     and a non-spec `body.next` field; the original token adapter
//     only looked at body.token, so `auto` fell back to next_url
//     which captured the bare /search href. Fixed by a new post_body
//     adapter (pageadapter/post_body.go) that captures method=POST
//     links' bodies verbatim and replays them on the next page.
//
// Uses a fixed historical datetime window over a small Alpine bbox
// where both Earth Search and Planetary Computer have sentinel-2-l2a
// coverage. Past windows are stable — archived items don't disappear,
// so the test is not flaky against ingest activity.
func TestLive_PaginatedMultiPage_NoRepeatsNoSkips(t *testing.T) {
	h := newPaginatedFederation(t)

	const (
		pageSize  = 4
		maxPages  = 6
		bboxMinX  = 10.6
		bboxMinY  = 47.4
		bboxMaxX  = 10.8
		bboxMaxY  = 47.6
		dtWindow  = "2024-06-01T00:00:00Z/2024-06-30T23:59:59Z"
		queryColl = "sentinel-2-l2a"
	)

	mkReq := func(limit int, token string) *stac.SearchRequest {
		return &stac.SearchRequest{
			Collections: []string{queryColl},
			BBox:        []float64{bboxMinX, bboxMinY, bboxMaxX, bboxMaxY},
			Datetime:    dtWindow,
			Limit:       limit,
			Token:       token,
		}
	}

	// Phase 1: walk pages of size pageSize up to maxPages, collecting
	// every ID and recording its multiplicity so duplicates surface.
	seen := map[string]int{}
	pages := 0
	token := ""
	for i := 0; i < maxPages; i++ {
		req := mkReq(pageSize, token)
		body, _ := json.Marshal(req)
		rr := serve(t, h,
			&middleware.STACInfo{RequestType: middleware.RequestTypeSearch, SearchReq: req},
			http.MethodPost, "/search", bytes.NewReader(body),
		)
		require.Equalf(t, http.StatusOK, rr.Code, "page %d status = %d, body = %s", i, rr.Code, rr.Body.String())

		var fc stac.FeatureCollection
		require.NoErrorf(t, json.Unmarshal(rr.Body.Bytes(), &fc), "page %d decode", i)
		if len(fc.Features) == 0 {
			break
		}
		pages++
		for _, item := range fc.Features {
			seen[item.ID]++
		}

		next := findLink(fc.Links, "next")
		if next == nil {
			break
		}
		nextBody, _ := next.AdditionalFields["body"].(map[string]any)
		nextToken, _ := nextBody["token"].(string)
		if nextToken == "" {
			break
		}
		token = nextToken
	}
	require.GreaterOrEqualf(t, pages, 2, "walked %d pages; need >=2 to exercise cross-page state", pages)

	// (1) No repeats: every ID appeared exactly once across the walk.
	var dupes []string
	for id, n := range seen {
		if n > 1 {
			dupes = append(dupes, fmt.Sprintf("%s×%d", id, n))
		}
	}
	require.Emptyf(t, dupes, "cursor failed to advance: %d duplicate IDs across %d pages: %v",
		len(dupes), pages, dupes)
	t.Logf("walked %d pages, %d unique items", pages, len(seen))

	// Phase 2: single-call fetch over the same query with limit
	// equal to the walk's emitted item count. If the merger and
	// paginator agree, this set should be a subset of `seen`.
	baseReq := mkReq(len(seen), "")
	baseBody, _ := json.Marshal(baseReq)
	rr := serve(t, h,
		&middleware.STACInfo{RequestType: middleware.RequestTypeSearch, SearchReq: baseReq},
		http.MethodPost, "/search", bytes.NewReader(baseBody),
	)
	require.Equalf(t, http.StatusOK, rr.Code, "baseline status = %d, body = %s", rr.Code, rr.Body.String())

	var base stac.FeatureCollection
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &base), "decode baseline")
	require.NotEmpty(t, base.Features, "baseline returned no features")

	// (2) No skips: every baseline ID must appear somewhere in the walk.
	// We allow the walk to be a superset (it can see slightly more if
	// upstream advanced past the baseline's window into a buffer page),
	// but anything in the baseline that the walk lost is a real skip.
	var missing []string
	for _, item := range base.Features {
		if seen[item.ID] == 0 {
			missing = append(missing, item.ID)
		}
	}
	assert.Emptyf(t, missing, "paginated walk skipped %d items that the single-call baseline returned: %v",
		len(missing), missing)
}

// TestLive_LandingPageLinkRels asserts the landing page emits the
// STAC API §1.4 required link rels and that — with ProxyBaseURL set —
// hrefs are absolute and rooted at the proxy, not at any upstream.
func TestLive_LandingPageLinkRels(t *testing.T) {
	h := newPaginatedFederation(t)

	rr := serve(t, h,
		&middleware.STACInfo{RequestType: middleware.RequestTypeLanding},
		http.MethodGet, "/", nil,
	)
	require.Equal(t, http.StatusOK, rr.Code, "status = %d, body = %s", rr.Code, rr.Body.String())

	// Decode generically; the landing page schema is loose enough
	// that a strict type pulls in fields we don't care to assert on.
	var doc map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &doc), "decode landing")
	links, _ := doc["links"].([]any)
	require.NotEmpty(t, links, "landing has no links")

	// Track required rels. §1.4 mandates self, root, data,
	// conformance, and search (both GET and POST forms).
	required := map[string]int{
		"self":        0,
		"root":        0,
		"data":        0,
		"conformance": 0,
		"search":      0,
	}
	searchMethods := map[string]bool{}
	for _, l := range links {
		lm, _ := l.(map[string]any)
		rel, _ := lm["rel"].(string)
		href, _ := lm["href"].(string)
		if _, want := required[rel]; want {
			required[rel]++
			assert.True(t, strings.HasPrefix(href, proxyPublicBase),
				"link rel=%q href=%q does not start with proxy base %q",
				rel, href, proxyPublicBase)
		}
		if rel == "search" {
			m, _ := lm["method"].(string)
			if m == "" {
				m = http.MethodGet
			}
			searchMethods[m] = true
		}
	}
	for rel, count := range required {
		assert.NotZero(t, count, "required link rel %q missing from landing page", rel)
	}
	for _, m := range []string{http.MethodGet, http.MethodPost} {
		assert.True(t, searchMethods[m], "landing page does not advertise a %s search link", m)
	}
}

// TestLive_GetSingleItem does a search to pull a known-good item ID
// off Earth Search, then GETs that exact item via the proxy. This
// covers handleSingleResource for items, including the per-record
// CQL2 validation path when no policy is in play (it should pass
// through cleanly).
//
// Pulling the item ID from a live search is the only stable way to
// avoid hard-coding IDs that age out of the upstream catalogue.
func TestLive_GetSingleItem(t *testing.T) {
	h := newFederation(t, func(es, pc *federation.Origin) {
		// Restrict to ES so the search response and the GET both
		// resolve to the same origin (PC's STAC IDs follow a
		// different convention and we want the GET path deterministic).
		es.Collections = []string{"sentinel-2-l2a"}
		pc.Collections = []string{"3dep-lidar-dsm"} // PC unique; won't match below
	})

	end := time.Now().UTC()
	start := end.Add(-30 * 24 * time.Hour)
	searchReq := &stac.SearchRequest{
		Collections: []string{"sentinel-2-l2a"},
		BBox:        []float64{10.6, 47.4, 10.8, 47.6},
		Datetime:    start.Format(time.RFC3339) + "/" + end.Format(time.RFC3339),
		Limit:       1,
	}
	body, _ := json.Marshal(searchReq)
	rr := serve(t, h,
		&middleware.STACInfo{RequestType: middleware.RequestTypeSearch, SearchReq: searchReq},
		http.MethodPost, "/search", bytes.NewReader(body),
	)
	require.Equal(t, http.StatusOK, rr.Code, "seed search status = %d, body = %s", rr.Code, rr.Body.String())
	var seedFC stac.FeatureCollection
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &seedFC), "decode seed FC")
	if len(seedFC.Features) == 0 {
		t.Skip("seed search returned no items; cannot exercise GET /items/{id}")
	}
	itemID := seedFC.Features[0].ID
	require.NotEmpty(t, itemID, "seed item has no ID")

	// Now GET that exact item by ID.
	itemPath := "/collections/sentinel-2-l2a/items/" + itemID
	rr = serve(t, h,
		&middleware.STACInfo{
			RequestType: middleware.RequestTypeItem,
			Collection:  "sentinel-2-l2a",
			ItemID:      itemID,
		},
		http.MethodGet, itemPath, nil,
	)
	require.Equal(t, http.StatusOK, rr.Code, "item GET status = %d, body = %s", rr.Code, rr.Body.String())

	var item map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &item), "decode item")
	gotID, _ := item["id"].(string)
	assert.Equal(t, itemID, gotID, "item.id = %q, want %q", gotID, itemID)
	t_, _ := item["type"].(string)
	assert.Equal(t, "Feature", t_, "item.type = %q, want Feature", t_)
}

// TestLive_CQL2JSONFilterPushdown_PCOnly exercises the Filter
// Extension via the proxy with a cql2-json predicate (eo:cloud_cover
// below a threshold). PC honours cql2-json server-side; the test
// asserts the filter was actually forwarded by checking that every
// returned item satisfies the predicate.
//
// # Why PC only
//
// Both origins advertise SupportsFilterExtension=true and both accept
// cql2-json without an HTTP error. PC actually evaluates the filter
// and only returns items that match. Earth Search accepts cql2-json
// without rejecting the request but does not appear to enforce
// property predicates server-side (returns items with cloud_cover well
// above the cap). That is an upstream evaluation gap, not a proxy
// gap — but it makes a federation-wide assertion noisy. We scope the
// strict assertion to PC so this test cleanly catches the regression
// it is meant to catch: the proxy dropping the filter on the floor.
//
// This is the live counterpart to
// tests/integration/cql2_injection_test.go, which exercises the
// authz CQL2-injection path against an in-memory upstream.
func TestLive_CQL2JSONFilterPushdown_PCOnly(t *testing.T) {
	h := newFederation(t, func(es, pc *federation.Origin) {
		es.Enabled = false // see "Why PC only" in the docstring
	})

	end := time.Now().UTC()
	start := end.Add(-30 * 24 * time.Hour)
	const cloudCap = 10.0

	// CQL2 JSON form: {"op": "<", "args": [{"property": "..."}, N]}.
	// Encode as json.RawMessage so it survives marshal round-trip.
	filterJSON := json.RawMessage(fmt.Sprintf(
		`{"op":"<","args":[{"property":"eo:cloud_cover"},%g]}`, cloudCap,
	))
	searchReq := &stac.SearchRequest{
		Collections: []string{"sentinel-2-l2a"},
		BBox:        []float64{-10.0, 40.0, 5.0, 50.0}, // Iberian peninsula — plenty of cloud-free S2
		Datetime:    start.Format(time.RFC3339) + "/" + end.Format(time.RFC3339),
		Limit:       20,
		Filter:      filterJSON,
		FilterLang:  "cql2-json",
	}
	body, _ := json.Marshal(searchReq)
	rr := serve(t, h,
		&middleware.STACInfo{RequestType: middleware.RequestTypeSearch, SearchReq: searchReq},
		http.MethodPost, "/search", bytes.NewReader(body),
	)
	require.Equal(t, http.StatusOK, rr.Code, "status = %d, body = %s", rr.Code, rr.Body.String())
	var fc stac.FeatureCollection
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &fc), "decode FC")
	if len(fc.Features) == 0 {
		t.Skip("PC returned no items for the cloud-free Iberian Peninsula query; nothing to assert on (upstream variance)")
	}

	// PC honours the predicate; every returned item with the property
	// present must satisfy it. Items lacking eo:cloud_cover entirely
	// are skipped — CQL2 NULL semantics admit them under `<`.
	var violations int
	for _, item := range fc.Features {
		if item == nil || item.Properties == nil {
			continue
		}
		cloudRaw, ok := item.Properties["eo:cloud_cover"]
		if !ok {
			continue
		}
		cloud, ok := cloudRaw.(float64)
		if !ok {
			continue
		}
		if cloud >= cloudCap {
			violations++
			t.Logf("item %s has eo:cloud_cover=%v (>= %g)", item.ID, cloud, cloudCap)
		}
	}
	assert.Zero(t, violations,
		"filter eo:cloud_cover < %g returned %d violating items out of %d (proxy may have dropped the filter)",
		cloudCap, violations, len(fc.Features))
}

// findLink returns the first link with the given rel, or nil.
func findLink(links []*stac.Link, rel string) *stac.Link {
	for _, l := range links {
		if l != nil && l.Rel == rel {
			return l
		}
	}
	return nil
}

// TestLive_BackwardsNavigation paginates forward two pages, then
// follows the `rel: prev` link from page 2 and asserts the returned
// items match page 1's items exactly. The page cache (configured by
// newPaginatedFederation) is what makes this work — the prev follow
// hits the cache instead of re-executing the upstream fan-out.
//
// Both Earth Search and Planetary Computer participate. The cache
// keys by cursor signature, so the prev follow returns whatever was
// stored at page-1-render time — deterministic regardless of
// upstream variance between calls.
func TestLive_BackwardsNavigation(t *testing.T) {
	h := newPaginatedFederation(t)

	end := time.Now().UTC()
	start := end.Add(-30 * 24 * time.Hour)
	searchReq := &stac.SearchRequest{
		Collections: []string{"sentinel-2-l2a"},
		BBox:        []float64{10.0, 47.0, 11.0, 48.0},
		Datetime:    start.Format(time.RFC3339) + "/" + end.Format(time.RFC3339),
		Limit:       5,
	}

	// Page 1 (the first page after the initial; "page 0" in cursor
	// terms is the request with no incoming cursor).
	body, _ := json.Marshal(searchReq)
	rr := serve(t, h,
		&middleware.STACInfo{RequestType: middleware.RequestTypeSearch, SearchReq: searchReq},
		http.MethodPost, "/search", bytes.NewReader(body),
	)
	require.Equal(t, http.StatusOK, rr.Code, "page 0 status = %d, body = %s", rr.Code, rr.Body.String())
	var page0 stac.FeatureCollection
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &page0), "decode page 0")
	require.NotEmpty(t, page0.Features, "page 0 returned no features; cannot exercise backwards nav")
	page0Next := findLink(page0.Links, "next")
	require.NotNil(t, page0Next, "page 0 has no rel=next; cannot advance to page 1")
	page0Token := cursorTokenOf(page0Next)
	require.NotEmpty(t, page0Token, "page 0 next-link token is empty")

	// Page 1: follow page 0's next; must carry self/prev/next link rels.
	page1Req := *searchReq
	page1Req.Token = page0Token
	body, _ = json.Marshal(&page1Req)
	rr = serve(t, h,
		&middleware.STACInfo{RequestType: middleware.RequestTypeSearch, SearchReq: &page1Req},
		http.MethodPost, "/search", bytes.NewReader(body),
	)
	require.Equal(t, http.StatusOK, rr.Code, "page 1 status = %d, body = %s", rr.Code, rr.Body.String())
	var page1 stac.FeatureCollection
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &page1), "decode page 1")
	require.NotEmpty(t, page1.Features, "page 1 returned no features; cannot exercise backwards nav")

	assert.NotNil(t, findLink(page1.Links, "self"), "page 1 missing rel=self")
	assert.NotNil(t, findLink(page1.Links, "next"), "page 1 missing rel=next")
	// Page 1's prev IS page 0's cursor — but page 0 had no
	// incoming cursor, so the chain emits an empty PrevCursor and
	// the proxy omits the prev link on page 1 (no prev to follow).
	// Only from page 2 onwards do we get a real prev.

	// Page 2: follow page 1's next.
	page2Token := cursorTokenOf(findLink(page1.Links, "next"))
	page2Req := *searchReq
	page2Req.Token = page2Token
	body, _ = json.Marshal(&page2Req)
	rr = serve(t, h,
		&middleware.STACInfo{RequestType: middleware.RequestTypeSearch, SearchReq: &page2Req},
		http.MethodPost, "/search", bytes.NewReader(body),
	)
	require.Equal(t, http.StatusOK, rr.Code, "page 2 status = %d, body = %s", rr.Code, rr.Body.String())
	var page2 stac.FeatureCollection
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &page2), "decode page 2")
	prevLink := findLink(page2.Links, "prev")
	require.NotNil(t, prevLink, "page 2 missing rel=prev; backwards navigation not advertised")

	// Follow prev: must return page 1's items verbatim.
	prevToken := cursorTokenOf(prevLink)
	require.NotEmpty(t, prevToken, "page 2's prev-link has no token")
	prevReq := *searchReq
	prevReq.Token = prevToken
	body, _ = json.Marshal(&prevReq)
	rr = serve(t, h,
		&middleware.STACInfo{RequestType: middleware.RequestTypeSearch, SearchReq: &prevReq},
		http.MethodPost, "/search", bytes.NewReader(body),
	)
	require.Equal(t, http.StatusOK, rr.Code, "prev follow status = %d, body = %s", rr.Code, rr.Body.String())
	var prevPage stac.FeatureCollection
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &prevPage), "decode prev page")

	assert.Equal(t, len(page1.Features), len(prevPage.Features),
		"prev page has %d items; want %d (page 1's count)",
		len(prevPage.Features), len(page1.Features))
	page1IDs := make(map[string]bool, len(page1.Features))
	for _, it := range page1.Features {
		page1IDs[it.ID] = true
	}
	for _, it := range prevPage.Features {
		assert.True(t, page1IDs[it.ID], "prev page item %q not in page 1 (cache served wrong page)", it.ID)
	}
}

// cursorTokenOf extracts the cursor token from a STAC pagination
// link. POST-style links carry it as body.token; GET-style links
// carry it as ?token= in the href. Returns "" when the link doesn't
// look like a proxy-issued pagination link.
func cursorTokenOf(l *stac.Link) string {
	if l == nil {
		return ""
	}
	if l.AdditionalFields != nil {
		if body, ok := l.AdditionalFields["body"].(map[string]any); ok {
			if tok, ok := body["token"].(string); ok && tok != "" {
				return tok
			}
		}
	}
	if l.Href == "" {
		return ""
	}
	// GET-style: parse ?token=
	idx := strings.Index(l.Href, "?")
	if idx < 0 {
		return ""
	}
	for _, kv := range strings.Split(l.Href[idx+1:], "&") {
		if eq := strings.Index(kv, "="); eq >= 0 && kv[:eq] == "token" {
			return kv[eq+1:]
		}
	}
	return ""
}

// Ensure httptest is still imported even when only a subset of tests
// use it (some helpers may evolve to construct local servers later).
var _ = httptest.NewRecorder
