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

	"github.com/yourorg/stac-proxy/internal/federation"
	"github.com/yourorg/stac-proxy/internal/middleware"
	"github.com/yourorg/stac-proxy/internal/middleware/auth"
	"github.com/yourorg/stac-proxy/internal/stac"
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
		ConflictStrategy: federation.ConflictPriorityWins,
		MaxConcurrent:    4,
		AggregateTimeout: 10 * time.Second,
		DefaultPageSize:  3,
		MaxPageSize:      100,
		CursorSecret:     []byte("integration-test-secret"),
		ProxyBaseURL:     "https://proxy.test",
	})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

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
			if rr.Code != http.StatusOK {
				t.Fatalf("page %d: status %d body=%s", i, rr.Code, rr.Body.String())
			}
			var fc stac.FeatureCollection
			if err := json.Unmarshal(rr.Body.Bytes(), &fc); err != nil {
				t.Fatalf("page %d: unmarshal: %v", i, err)
			}
			pages++
			for _, it := range fc.Features {
				seen[it.ID]++
			}
			next := stac.ExtractNextLink(fc.Links)
			if next == nil {
				return seen, pages
			}
			if !strings.HasPrefix(next.Href, "https://proxy.test") {
				t.Errorf("next link not proxy-rooted: %q", next.Href)
			}
			u, err := url.Parse(next.Href)
			if err != nil {
				t.Fatalf("page %d: parse next: %v", i, err)
			}
			token = u.Query().Get("token")
			if token == "" {
				t.Fatalf("page %d: empty token on next link", i)
			}
		}
		return seen, pages
	}

	t.Run("search endpoint walks multiple pages", func(t *testing.T) {
		seen, pages := walk(t, "/search?limit=3", &middleware.STACInfo{RequestType: middleware.RequestTypeSearch})
		if pages < 2 {
			t.Errorf("expected at least 2 pages, got %d", pages)
		}
		for id, n := range seen {
			if n != 1 {
				t.Errorf("item %q seen %d times across pages", id, n)
			}
		}
		if len(seen) < 4 {
			t.Errorf("expected at least 4 unique items, got %d", len(seen))
		}
	})

	t.Run("items endpoint walks multiple pages", func(t *testing.T) {
		seen, pages := walk(t, "/collections/shared/items?limit=3", &middleware.STACInfo{
			RequestType: middleware.RequestTypeItems,
			Collection:  "shared",
		})
		if pages < 2 {
			t.Errorf("expected at least 2 pages, got %d", pages)
		}
		for id, n := range seen {
			if n != 1 {
				t.Errorf("item %q seen %d times across pages", id, n)
			}
		}
	})
}
