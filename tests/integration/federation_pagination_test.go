package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/exergy-dev/stac-proxy/internal/federation"
	"github.com/exergy-dev/stac-proxy/internal/middleware"
	"github.com/exergy-dev/stac-proxy/internal/middleware/auth"
	"github.com/exergy-dev/stac-proxy/internal/stac"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// paginatingUpstream is a tiny stub STAC search backend honoring
// `?token=off-<N>` for cursor-style pagination. Each call appends a
// "next" link when more items remain.
type paginatingUpstream struct {
	srv   *httptest.Server
	items []*stac.Item
	mu    sync.Mutex
	calls int
}

func newPaginatingUpstream(t *testing.T, items []*stac.Item) *paginatingUpstream {
	t.Helper()
	u := &paginatingUpstream{items: items}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		u.calls++
		u.mu.Unlock()

		var body struct {
			Token string `json:"token"`
			Limit int    `json:"limit"`
		}
		if r.Body != nil {
			defer r.Body.Close()
			_ = json.NewDecoder(r.Body).Decode(&body)
		}
		offset := 0
		if body.Token != "" {
			_, _ = fmt.Sscanf(body.Token, "off-%d", &offset)
		}
		limit := body.Limit
		if limit <= 0 {
			limit = len(items)
		}
		end := offset + limit
		if end > len(items) {
			end = len(items)
		}
		fc := &stac.FeatureCollection{
			Type:     "FeatureCollection",
			Features: items[offset:end],
		}
		if end < len(items) {
			fc.Links = append(fc.Links, &stac.Link{
				Rel:  "next",
				Href: fmt.Sprintf("%s/search?token=off-%d", u.srv.URL, end),
				Type: "application/geo+json",
			})
		}
		w.Header().Set("Content-Type", "application/geo+json")
		_ = json.NewEncoder(w).Encode(fc)
	}))
	t.Cleanup(u.srv.Close)
	return u
}

func makeItem(id string, day int) *stac.Item {
	now := time.Date(2024, 1, day, 0, 0, 0, 0, time.UTC)
	return &stac.Item{
		Version:    "1.0.0",
		ID:         id,
		Collection: "shared",
		Geometry:   json.RawMessage(`{"type":"Point","coordinates":[0,0]}`),
		Properties: map[string]any{
			"datetime": now.Format(time.RFC3339),
		},
	}
}

// TestIntegration_FederatedPaginationWalk exercises the full federation
// handler against two paginating httptest upstreams via the ServeHTTP
// surface (the same path the chi router uses). The test walks the
// proxy's `rel: next` link cursor across pages and asserts the wiring
// invariants the B1 plan called out.
func TestIntegration_FederatedPaginationWalk(t *testing.T) {
	upA := newPaginatingUpstream(t, []*stac.Item{
		makeItem("a-1", 30), makeItem("a-2", 28), makeItem("a-3", 26),
		makeItem("a-4", 24), makeItem("a-5", 22), makeItem("a-6", 20),
		makeItem("a-7", 18), makeItem("a-8", 16),
	})
	upB := newPaginatingUpstream(t, []*stac.Item{
		makeItem("b-1", 29), makeItem("b-2", 27), makeItem("b-3", 25),
		makeItem("b-4", 23), makeItem("b-5", 21), makeItem("b-6", 19),
	})

	handler, err := federation.NewHandler(federation.HandlerConfig{
		Origins: []*federation.Origin{
			{ID: "a", BaseURL: upA.srv.URL, Enabled: true, Searchable: true, Collections: []string{"shared"}, Timeout: 5 * time.Second, Priority: 1},
			{ID: "b", BaseURL: upB.srv.URL, Enabled: true, Searchable: true, Collections: []string{"shared"}, Timeout: 5 * time.Second, Priority: 1},
		},
		MaxConcurrent:    4,
		AggregateTimeout: 10 * time.Second,
		DefaultPageSize:  3,
		MaxPageSize:      100,
		CursorSecret:     []byte("integration-test-secret"),
		ProxyBaseURL:     "https://proxy.test",
	})
	require.NoError(t, err, "NewHandler")

	walk := func(t *testing.T, urlPath string, info *middleware.STACInfo) (seen map[string]int, pages int) {
		seen = map[string]int{}
		token := ""
		for i := 0; i < 10; i++ {
			full := urlPath
			if token != "" {
				sep := "?"
				if strings.Contains(full, "?") {
					sep = "&"
				}
				full = full + sep + "token=" + url.QueryEscape(token)
			}
			req := httptest.NewRequest(http.MethodGet, full, nil)
			info.SearchReq = &stac.SearchRequest{Collections: []string{"shared"}, Limit: 3, Token: token}
			ctx := middleware.WithSTACInfo(req.Context(), info)
			ctx = context.WithValue(ctx, middleware.PrincipalKey, &auth.Principal{ID: "anon", Type: "anonymous"})
			req = req.WithContext(ctx)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			require.Equal(t, http.StatusOK, rr.Code, "page %d: body=%s", i, rr.Body.String())
			var fc stac.FeatureCollection
			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &fc), "page %d: unmarshal", i)
			pages++
			for _, it := range fc.Features {
				seen[it.ID]++
			}
			next := stac.ExtractNextLink(fc.Links)
			if next == nil {
				return seen, pages
			}
			assert.True(t, strings.HasPrefix(next.Href, "https://proxy.test"), "next link not proxy-rooted: %q", next.Href)
			u, err := url.Parse(next.Href)
			require.NoError(t, err, "page %d: parse next", i)
			token = u.Query().Get("token")
			require.NotEmpty(t, token, "page %d: empty token on next link", i)
		}
		return seen, pages
	}

	t.Run("search endpoint walks multiple pages", func(t *testing.T) {
		seen, pages := walk(t, "/search?limit=3", &middleware.STACInfo{RequestType: middleware.RequestTypeSearch})
		assert.GreaterOrEqual(t, pages, 2, "expected at least 2 pages")
		for id, n := range seen {
			assert.Equal(t, 1, n, "item %q seen %d times across pages", id, n)
		}
		assert.GreaterOrEqual(t, len(seen), 4, "expected at least 4 unique items")
	})

	t.Run("items endpoint walks multiple pages", func(t *testing.T) {
		seen, pages := walk(t, "/collections/shared/items?limit=3", &middleware.STACInfo{
			RequestType: middleware.RequestTypeItems,
			Collection:  "shared",
		})
		assert.GreaterOrEqual(t, pages, 2, "expected at least 2 pages")
		for id, n := range seen {
			assert.Equal(t, 1, n, "item %q seen %d times across pages", id, n)
		}
	})
}

// TestIntegration_PostNextLinkMergeContract locks in the POST
// pagination contract for non-empty queries. The proxy's POST-style
// `next` link must carry `"merge": true` — per STAC API Item Search a
// body WITHOUT merge REPLACES the client's request, so a compliant
// client would POST the token alone, the re-hashed empty query would
// no longer match the cursor's bound QueryHash, and every follow-up of
// our own next link would fail (this was live-repro'd against three
// public STAC APIs). A token-only POST must come back 400, not 500.
func TestIntegration_PostNextLinkMergeContract(t *testing.T) {
	upA := newPaginatingUpstream(t, []*stac.Item{
		makeItem("pa-1", 30), makeItem("pa-2", 28), makeItem("pa-3", 26), makeItem("pa-4", 24),
	})
	upB := newPaginatingUpstream(t, []*stac.Item{
		makeItem("pb-1", 29), makeItem("pb-2", 27), makeItem("pb-3", 25), makeItem("pb-4", 23),
	})
	handler, err := federation.NewHandler(federation.HandlerConfig{
		Origins: []*federation.Origin{
			{ID: "a", BaseURL: upA.srv.URL, Enabled: true, Searchable: true, Collections: []string{"shared"}, Timeout: 5 * time.Second, Priority: 1},
			{ID: "b", BaseURL: upB.srv.URL, Enabled: true, Searchable: true, Collections: []string{"shared"}, Timeout: 5 * time.Second, Priority: 1},
		},
		MaxConcurrent:    4,
		AggregateTimeout: 10 * time.Second,
		DefaultPageSize:  3,
		MaxPageSize:      100,
		CursorSecret:     []byte("integration-test-secret"),
		ProxyBaseURL:     "https://proxy.test",
	})
	require.NoError(t, err, "NewHandler")

	post := func(sr *stac.SearchRequest) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/search", strings.NewReader("{}"))
		info := &middleware.STACInfo{RequestType: middleware.RequestTypeSearch, SearchReq: sr}
		ctx := middleware.WithSTACInfo(req.Context(), info)
		ctx = context.WithValue(ctx, middleware.PrincipalKey, &auth.Principal{ID: "anon", Type: "anonymous"})
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req.WithContext(ctx))
		return rr
	}

	// Page 1: a real (non-empty) query.
	rr := post(&stac.SearchRequest{Collections: []string{"shared"}, Limit: 3})
	require.Equal(t, http.StatusOK, rr.Code, "page 1: %s", rr.Body.String())
	var page1 struct {
		Features []struct {
			ID string `json:"id"`
		} `json:"features"`
		Links []map[string]any `json:"links"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &page1))

	var next map[string]any
	for _, l := range page1.Links {
		if l["rel"] == "next" {
			next = l
		}
	}
	require.NotNil(t, next, "page 1 must carry a next link")
	assert.Equal(t, "POST", next["method"], "next link method")
	assert.Equal(t, true, next["merge"], "POST next link MUST set merge: true — without it compliant clients drop the original query and the cursor hash check fails")
	body, _ := next["body"].(map[string]any)
	require.NotNil(t, body, "next link body")
	token, _ := body["token"].(string)
	require.NotEmpty(t, token, "next link token")

	// Page 2 as a merge-compliant client: original body + token.
	rr2 := post(&stac.SearchRequest{Collections: []string{"shared"}, Limit: 3, Token: token})
	require.Equal(t, http.StatusOK, rr2.Code, "page 2 (merged body): %s", rr2.Body.String())

	// A non-merging client (token only) must get a 400 envelope, not 500.
	rr3 := post(&stac.SearchRequest{Token: token})
	require.Equal(t, http.StatusBadRequest, rr3.Code, "token-only POST: %s", rr3.Body.String())
	assert.Contains(t, rr3.Body.String(), "InvalidParameterValue")
}
