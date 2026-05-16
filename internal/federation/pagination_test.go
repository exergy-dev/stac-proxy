package federation

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yourorg/stac-proxy/internal/federation/pagecache"
	"github.com/yourorg/stac-proxy/internal/stac"
)

// Test helpers for pagination tests

var paginationTestSecret = []byte("pagination-test-secret-32-bytes!")

func paginationTestItem(id string, datetime time.Time) *stac.Item {
	dt := datetime.UTC().Format(time.RFC3339)
	return &stac.Item{
		Version:    "1.0.0",
		ID:         id,
		Collection: "test-collection",
		Bbox:       []float64{-180, -90, 180, 90},
		Properties: map[string]any{
			"datetime":     dt,
			"datetime_str": dt,
		},
		Links:  []*stac.Link{},
		Assets: map[string]*stac.Asset{},
	}
}

func paginationTestSearchRequest() *stac.SearchRequest {
	return &stac.SearchRequest{
		Limit: 10,
	}
}

// mustPaginatedSearcher creates a PaginatedSearcher in tests, failing
// fast on configuration errors.
func mustPaginatedSearcher(t *testing.T, cfg PaginatedSearchConfig) *PaginatedSearcher {
	t.Helper()
	if len(cfg.CursorSecret) == 0 {
		cfg.CursorSecret = paginationTestSecret
	}
	s, err := NewPaginatedSearcher(cfg)
	if err != nil {
		t.Fatalf("NewPaginatedSearcher: %v", err)
	}
	return s
}

type mockOriginClient struct {
	id         string
	priority   int
	enabled    bool
	searchFunc func(ctx context.Context, req *stac.SearchRequest) ([]*stac.Item, string, string, error)
}

func (m *mockOriginClient) Search(ctx context.Context, req *stac.SearchRequest) ([]*stac.Item, string, string, string, error) {
	if m.searchFunc != nil {
		items, tok, url, err := m.searchFunc(ctx, req)
		return items, tok, url, "", err
	}
	return nil, "", "", "", nil
}

func (m *mockOriginClient) BaseURL() string { return "https://" + m.id + ".example.com" }

func (m *mockOriginClient) ID() string       { return m.id }
func (m *mockOriginClient) Priority() int    { return m.priority }
func (m *mockOriginClient) IsEnabled() bool  { return m.enabled }

// mockSearchableOrigin is a test interface for origins that can search
type mockSearchableOrigin struct {
	originID   string
	originPri  int
	searchFunc func(ctx context.Context, req *stac.SearchRequest) ([]*stac.Item, string, string, error)
}

func (m *mockSearchableOrigin) Search(ctx context.Context, req *stac.SearchRequest) ([]*stac.Item, string, string, string, error) {
	if m.searchFunc != nil {
		items, tok, url, err := m.searchFunc(ctx, req)
		return items, tok, url, "", err
	}
	return nil, "", "", "", nil
}

func (m *mockSearchableOrigin) BaseURL() string                                                 { return "https://" + m.originID + ".example.com" }
func (m *mockSearchableOrigin) ID() string                                                      { return m.originID }
func (m *mockSearchableOrigin) Priority() int                                                   { return m.originPri }
func (m *mockSearchableOrigin) IsEnabled() bool                                                 { return true }
func (m *mockSearchableOrigin) HasCollection(id string) bool                                    { return true }
func (m *mockSearchableOrigin) GetCollections(ctx context.Context) ([]*stac.Collection, error) { return nil, nil }
func (m *mockSearchableOrigin) Origin() *Origin                                                 { return &Origin{ID: m.originID, Priority: m.originPri} }

// newMockSearchable creates a mock searchable origin for testing
func newMockSearchable(id string, priority int, searchFunc func(ctx context.Context, req *stac.SearchRequest) ([]*stac.Item, string, string, error)) *mockSearchableOrigin {
	return &mockSearchableOrigin{
		originID:   id,
		originPri:  priority,
		searchFunc: searchFunc,
	}
}

// TestNewPaginatedSearcher tests PaginatedSearcher creation and configuration
func TestNewPaginatedSearcher(t *testing.T) {
	t.Run("with default config", func(t *testing.T) {
		t.Parallel()

		cfg := PaginatedSearchConfig{
			Origins:      make(map[string]Searcher),
			Merger:       NewResultMerger(ConflictFirstWins),
			CursorSecret: paginationTestSecret,
		}

		searcher, err := NewPaginatedSearcher(cfg)
		if err != nil {
			t.Fatalf("NewPaginatedSearcher: %v", err)
		}

		if searcher.pageSize != 100 {
			t.Errorf("expected default page size 100, got %d", searcher.pageSize)
		}
		if searcher.maxPageSize != 1000 {
			t.Errorf("expected default max page size 1000, got %d", searcher.maxPageSize)
		}
	})

	t.Run("requires cursor secret", func(t *testing.T) {
		t.Parallel()

		cfg := PaginatedSearchConfig{
			Origins: make(map[string]Searcher),
			Merger:  NewResultMerger(ConflictFirstWins),
		}
		if _, err := NewPaginatedSearcher(cfg); err == nil {
			t.Error("expected error when CursorSecret is empty")
		}
	})

	t.Run("with custom page sizes", func(t *testing.T) {
		t.Parallel()
		cfg := PaginatedSearchConfig{
			Origins:         make(map[string]Searcher),
			Merger:          NewResultMerger(ConflictPriorityWins),
			DefaultPageSize: 50,
			MaxPageSize:     500,
			CursorSecret:    paginationTestSecret,
		}
		searcher := mustPaginatedSearcher(t, cfg)
		if searcher.pageSize != 50 || searcher.maxPageSize != 500 {
			t.Errorf("unexpected page sizes: %d/%d", searcher.pageSize, searcher.maxPageSize)
		}
	})

	t.Run("populates originBaseURLs from origins", func(t *testing.T) {
		t.Parallel()
		origins := map[string]Searcher{
			"origin1": newMockSearchable("origin1", 1, nil),
			"origin2": newMockSearchable("origin2", 2, nil),
		}
		searcher := mustPaginatedSearcher(t, PaginatedSearchConfig{
			Origins: origins,
			Merger:  NewResultMerger(ConflictFirstWins),
		})
		if searcher.originBaseURLs["origin1"] != "https://origin1.example.com" {
			t.Errorf("expected origin1 base URL, got %q", searcher.originBaseURLs["origin1"])
		}
		if searcher.originBaseURLs["origin2"] != "https://origin2.example.com" {
			t.Errorf("expected origin2 base URL, got %q", searcher.originBaseURLs["origin2"])
		}
	})
}

// TestSearch_NoCursor tests initial search without cursor
func TestSearch_NoCursor(t *testing.T) {
	t.Run("basic search", func(t *testing.T) {
		t.Parallel()

		origin1 := newMockSearchable("origin1", 1, func(ctx context.Context, req *stac.SearchRequest) ([]*stac.Item, string, string, error) {
			items := []*stac.Item{
				paginationTestItem("item1", time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)),
				paginationTestItem("item2", time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC)),
			}
			return items, "", "", nil
		})

		searcher := mustPaginatedSearcher(t, PaginatedSearchConfig{
			Origins: map[string]Searcher{"origin1": origin1},
			Merger:  NewResultMerger(ConflictFirstWins),
		})
		result, err := searcher.Search(context.Background(), paginationTestSearchRequest(), "")
		if err != nil {
			t.Fatalf("search failed: %v", err)
		}
		if len(result.Items) != 2 {
			t.Errorf("expected 2 items, got %d", len(result.Items))
		}
		if result.Context.Returned != 2 {
			t.Errorf("expected returned count 2, got %d", result.Context.Returned)
		}
	})

	t.Run("multiple origins", func(t *testing.T) {
		t.Parallel()
		origin1 := newMockSearchable("origin1", 1, func(ctx context.Context, req *stac.SearchRequest) ([]*stac.Item, string, string, error) {
			return []*stac.Item{paginationTestItem("item1", time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC))}, "", "", nil
		})
		origin2 := newMockSearchable("origin2", 2, func(ctx context.Context, req *stac.SearchRequest) ([]*stac.Item, string, string, error) {
			return []*stac.Item{paginationTestItem("item2", time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC))}, "", "", nil
		})
		searcher := mustPaginatedSearcher(t, PaginatedSearchConfig{
			Origins: map[string]Searcher{"origin1": origin1, "origin2": origin2},
			Merger:  NewResultMerger(ConflictFirstWins),
		})
		result, err := searcher.Search(context.Background(), paginationTestSearchRequest(), "")
		if err != nil {
			t.Fatalf("search failed: %v", err)
		}
		if len(result.Items) != 2 {
			t.Errorf("expected 2 items from 2 origins, got %d", len(result.Items))
		}
	})

	t.Run("no origins", func(t *testing.T) {
		t.Parallel()
		searcher := mustPaginatedSearcher(t, PaginatedSearchConfig{
			Origins: make(map[string]Searcher),
			Merger:  NewResultMerger(ConflictFirstWins),
		})
		result, err := searcher.Search(context.Background(), paginationTestSearchRequest(), "")
		if err != nil {
			t.Fatalf("search failed: %v", err)
		}
		if len(result.Items) != 0 {
			t.Errorf("expected 0 items, got %d", len(result.Items))
		}
		if result.NextCursor != "" {
			t.Error("expected no next cursor")
		}
	})

	t.Run("with next token creates cursor", func(t *testing.T) {
		t.Parallel()
		origin1 := newMockSearchable("origin1", 1, func(ctx context.Context, req *stac.SearchRequest) ([]*stac.Item, string, string, error) {
			return []*stac.Item{paginationTestItem("item1", time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC))}, "next-token", "", nil
		})
		searcher := mustPaginatedSearcher(t, PaginatedSearchConfig{
			Origins: map[string]Searcher{"origin1": origin1},
			Merger:  NewResultMerger(ConflictFirstWins),
		})
		result, err := searcher.Search(context.Background(), paginationTestSearchRequest(), "")
		if err != nil {
			t.Fatalf("search failed: %v", err)
		}
		if result.NextCursor == "" {
			t.Error("expected next cursor")
		}
	})
}

// TestSearch_WithCursor tests search continuation with cursor
func TestSearch_WithCursor(t *testing.T) {
	t.Run("valid cursor continues search", func(t *testing.T) {
		t.Parallel()

		callCount := 0
		var mu sync.Mutex

		origin1 := newMockSearchable("origin1", 1, func(ctx context.Context, req *stac.SearchRequest) ([]*stac.Item, string, string, error) {
			mu.Lock()
			callCount++
			count := callCount
			mu.Unlock()

			if count == 1 {
				return []*stac.Item{paginationTestItem("item1", time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC))}, "token1", "", nil
			}
			if req.Token != "token1" {
				t.Errorf("expected token 'token1', got %q", req.Token)
			}
			return []*stac.Item{paginationTestItem("item2", time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC))}, "", "", nil
		})

		searcher := mustPaginatedSearcher(t, PaginatedSearchConfig{
			Origins: map[string]Searcher{"origin1": origin1},
			Merger:  NewResultMerger(ConflictFirstWins),
		})
		req := &stac.SearchRequest{Limit: 1}

		result1, err := searcher.Search(context.Background(), req, "")
		if err != nil {
			t.Fatalf("first search failed: %v", err)
		}
		if result1.NextCursor == "" {
			t.Fatal("expected next cursor from first search")
		}

		result2, err := searcher.Search(context.Background(), req, result1.NextCursor)
		if err != nil {
			t.Fatalf("second search failed: %v", err)
		}
		if len(result2.Items) != 1 {
			t.Errorf("expected 1 item in second page, got %d", len(result2.Items))
		}
		if result2.NextCursor != "" {
			t.Error("expected no next cursor when origin is exhausted")
		}
	})

	t.Run("cursor validates query hash", func(t *testing.T) {
		t.Parallel()

		origin1 := newMockSearchable("origin1", 1, func(ctx context.Context, req *stac.SearchRequest) ([]*stac.Item, string, string, error) {
			return []*stac.Item{paginationTestItem("item1", time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC))}, "token", "", nil
		})
		searcher := mustPaginatedSearcher(t, PaginatedSearchConfig{
			Origins: map[string]Searcher{"origin1": origin1},
			Merger:  NewResultMerger(ConflictFirstWins),
		})
		req1 := &stac.SearchRequest{Collections: []string{"collection1"}}

		result1, err := searcher.Search(context.Background(), req1, "")
		if err != nil {
			t.Fatalf("first search failed: %v", err)
		}

		req2 := &stac.SearchRequest{Collections: []string{"collection2"}}
		_, err = searcher.Search(context.Background(), req2, result1.NextCursor)
		if err == nil {
			t.Fatal("expected error when cursor doesn't match query")
		}
		if !strings.Contains(err.Error(), "cursor does not match search parameters") {
			t.Errorf("expected cursor mismatch error, got: %v", err)
		}
	})
}

// TestSearch_InvalidCursor tests error handling for invalid cursors
func TestSearch_InvalidCursor(t *testing.T) {
	t.Run("malformed cursor", func(t *testing.T) {
		t.Parallel()
		searcher := mustPaginatedSearcher(t, PaginatedSearchConfig{
			Origins: make(map[string]Searcher),
			Merger:  NewResultMerger(ConflictFirstWins),
		})
		if _, err := searcher.Search(context.Background(), paginationTestSearchRequest(), "invalid-cursor!!!"); err == nil {
			t.Fatal("expected error for invalid cursor")
		}
	})

	t.Run("expired cursor", func(t *testing.T) {
		t.Parallel()
		searcher := mustPaginatedSearcher(t, PaginatedSearchConfig{
			Origins: make(map[string]Searcher),
			Merger:  NewResultMerger(ConflictFirstWins),
		})

		cursor := NewFederatedCursor("hash", "", []string{"origin1"}, nil)
		cursor.ExpiresAt = time.Now().Add(-1 * time.Hour).Unix()
		expiredCursor, _ := cursor.Encode(paginationTestSecret)

		_, err := searcher.Search(context.Background(), paginationTestSearchRequest(), expiredCursor)
		if err == nil {
			t.Fatal("expected error for expired cursor")
		}
		if !errors.Is(err, ErrCursorExpired) {
			t.Errorf("expected ErrCursorExpired, got: %v", err)
		}
	})
}

// TestFetchFromOrigins tests parallel origin fetching
func TestFetchFromOrigins(t *testing.T) {
	t.Run("handles origin errors", func(t *testing.T) {
		t.Parallel()
		origin1 := newMockSearchable("origin1", 1, func(ctx context.Context, req *stac.SearchRequest) ([]*stac.Item, string, string, error) {
			return nil, "", "", errors.New("origin1 error")
		})
		origin2 := newMockSearchable("origin2", 2, func(ctx context.Context, req *stac.SearchRequest) ([]*stac.Item, string, string, error) {
			return []*stac.Item{paginationTestItem("item2", time.Now())}, "", "", nil
		})
		searcher := mustPaginatedSearcher(t, PaginatedSearchConfig{
			Origins: map[string]Searcher{"origin1": origin1, "origin2": origin2},
			Merger:  NewResultMerger(ConflictFirstWins),
		})
		cursor := NewFederatedCursor("hash", "", []string{"origin1", "origin2"}, nil)
		results := searcher.fetchFromOrigins(context.Background(), paginationTestSearchRequest(), cursor, []string{"origin1", "origin2"}, 10)
		if len(results) != 2 {
			t.Errorf("expected 2 results, got %d", len(results))
		}
		errorCount := 0
		for _, r := range results {
			if r.Error != nil {
				errorCount++
			}
		}
		if errorCount != 1 {
			t.Errorf("expected 1 error result, got %d", errorCount)
		}
	})

	t.Run("applies cursor tokens", func(t *testing.T) {
		t.Parallel()
		var receivedToken string
		var mu sync.Mutex
		origin1 := newMockSearchable("origin1", 1, func(ctx context.Context, req *stac.SearchRequest) ([]*stac.Item, string, string, error) {
			mu.Lock()
			receivedToken = req.Token
			mu.Unlock()
			return []*stac.Item{paginationTestItem("item1", time.Now())}, "", "", nil
		})
		searcher := mustPaginatedSearcher(t, PaginatedSearchConfig{
			Origins: map[string]Searcher{"origin1": origin1},
			Merger:  NewResultMerger(ConflictFirstWins),
		})
		cursor := NewFederatedCursor("hash", "", []string{"origin1"}, nil)
		cursor.Origins["origin1"].NextToken = "test-token"
		searcher.fetchFromOrigins(context.Background(), paginationTestSearchRequest(), cursor, []string{"origin1"}, 10)
		mu.Lock()
		defer mu.Unlock()
		if receivedToken != "test-token" {
			t.Errorf("expected token 'test-token', got %q", receivedToken)
		}
	})

	t.Run("handles missing origin", func(t *testing.T) {
		t.Parallel()
		searcher := mustPaginatedSearcher(t, PaginatedSearchConfig{
			Origins: make(map[string]Searcher),
			Merger:  NewResultMerger(ConflictFirstWins),
		})
		cursor := NewFederatedCursor("hash", "", []string{"missing-origin"}, nil)
		results := searcher.fetchFromOrigins(context.Background(), paginationTestSearchRequest(), cursor, []string{"missing-origin"}, 10)
		if len(results) != 1 || results[0].Error == nil {
			t.Errorf("expected error for missing origin, got %+v", results)
		}
	})

	t.Run("requests extra items for merge buffer", func(t *testing.T) {
		t.Parallel()
		var receivedLimit int
		var mu sync.Mutex
		origin1 := newMockSearchable("origin1", 1, func(ctx context.Context, req *stac.SearchRequest) ([]*stac.Item, string, string, error) {
			mu.Lock()
			receivedLimit = req.Limit
			mu.Unlock()
			return []*stac.Item{paginationTestItem("item1", time.Now())}, "", "", nil
		})
		searcher := mustPaginatedSearcher(t, PaginatedSearchConfig{
			Origins: map[string]Searcher{"origin1": origin1},
			Merger:  NewResultMerger(ConflictFirstWins),
		})
		cursor := NewFederatedCursor("hash", "", []string{"origin1"}, nil)
		searcher.fetchFromOrigins(context.Background(), paginationTestSearchRequest(), cursor, []string{"origin1"}, 10)
		mu.Lock()
		defer mu.Unlock()
		if receivedLimit != 20 {
			t.Errorf("expected limit 20, got %d", receivedLimit)
		}
	})
}

// TestMergeResults tests result merging and deduplication
func TestMergeResults(t *testing.T) {
	t.Run("merges items from multiple origins", func(t *testing.T) {
		t.Parallel()
		searcher := mustPaginatedSearcher(t, PaginatedSearchConfig{
			Origins: make(map[string]Searcher),
			Merger:  NewResultMerger(ConflictFirstWins),
		})
		cursor := NewFederatedCursor("hash", "", []string{"origin1", "origin2"}, nil)
		results := []originFetchResult{
			{OriginID: "origin1", Items: []*stac.Item{paginationTestItem("item1", time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC))}},
			{OriginID: "origin2", Items: []*stac.Item{paginationTestItem("item2", time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC))}},
		}
		merged := searcher.mergeResults(results, cursor, 10, nil)
		if len(merged) != 2 {
			t.Errorf("expected 2 merged items, got %d", len(merged))
		}
	})

	t.Run("deduplicates items", func(t *testing.T) {
		t.Parallel()
		searcher := mustPaginatedSearcher(t, PaginatedSearchConfig{
			Origins: make(map[string]Searcher),
			Merger:  NewResultMerger(ConflictFirstWins),
		})
		cursor := NewFederatedCursor("hash", "", []string{"origin1", "origin2"}, nil)
		results := []originFetchResult{
			{OriginID: "origin1", Items: []*stac.Item{paginationTestItem("item1", time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC))}},
			{OriginID: "origin2", Items: []*stac.Item{paginationTestItem("item1", time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC))}},
		}
		merged := searcher.mergeResults(results, cursor, 10, nil)
		if len(merged) != 1 {
			t.Errorf("expected 1 item after deduplication, got %d", len(merged))
		}
	})

	t.Run("sorts by datetime descending", func(t *testing.T) {
		t.Parallel()
		searcher := mustPaginatedSearcher(t, PaginatedSearchConfig{
			Origins: make(map[string]Searcher),
			Merger:  NewResultMerger(ConflictFirstWins),
		})
		cursor := NewFederatedCursor("hash", "", []string{"origin1"}, nil)
		results := []originFetchResult{
			{OriginID: "origin1", Items: []*stac.Item{
				paginationTestItem("item1", time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)),
				paginationTestItem("item2", time.Date(2024, 1, 3, 0, 0, 0, 0, time.UTC)),
				paginationTestItem("item3", time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC)),
			}},
		}
		merged := searcher.mergeResults(results, cursor, 10, nil)
		if merged[0].ID != "item2" || merged[1].ID != "item3" || merged[2].ID != "item1" {
			t.Errorf("unexpected order: %s %s %s", merged[0].ID, merged[1].ID, merged[2].ID)
		}
	})

	t.Run("applies limit", func(t *testing.T) {
		t.Parallel()
		searcher := mustPaginatedSearcher(t, PaginatedSearchConfig{
			Origins: make(map[string]Searcher),
			Merger:  NewResultMerger(ConflictFirstWins),
		})
		cursor := NewFederatedCursor("hash", "", []string{"origin1"}, nil)
		results := []originFetchResult{
			{OriginID: "origin1", Items: []*stac.Item{
				paginationTestItem("item1", time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)),
				paginationTestItem("item2", time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC)),
				paginationTestItem("item3", time.Date(2024, 1, 3, 0, 0, 0, 0, time.UTC)),
			}},
		}
		merged := searcher.mergeResults(results, cursor, 2, nil)
		if len(merged) != 2 {
			t.Errorf("expected 2 items (limited), got %d", len(merged))
		}
	})

	t.Run("updates cursor for successful origins", func(t *testing.T) {
		t.Parallel()
		searcher := mustPaginatedSearcher(t, PaginatedSearchConfig{
			Origins: make(map[string]Searcher),
			Merger:  NewResultMerger(ConflictFirstWins),
		})
		cursor := NewFederatedCursor("hash", "", []string{"origin1"}, nil)
		results := []originFetchResult{
			{OriginID: "origin1", Items: []*stac.Item{paginationTestItem("item1", time.Now())}, NextToken: "next-token"},
		}
		searcher.mergeResults(results, cursor, 10, nil)
		origin := cursor.GetOriginCursor("origin1")
		if origin.NextToken != "next-token" || origin.ItemCount != 1 {
			t.Errorf("unexpected origin state: %+v", origin)
		}
	})

	t.Run("marks error origins", func(t *testing.T) {
		t.Parallel()
		searcher := mustPaginatedSearcher(t, PaginatedSearchConfig{
			Origins: make(map[string]Searcher),
			Merger:  NewResultMerger(ConflictFirstWins),
		})
		cursor := NewFederatedCursor("hash", "", []string{"origin1"}, nil)
		results := []originFetchResult{{OriginID: "origin1", Error: errors.New("fetch failed")}}
		searcher.mergeResults(results, cursor, 10, nil)
		if !cursor.GetOriginCursor("origin1").Error {
			t.Error("expected origin to be marked with error")
		}
	})

	t.Run("marks exhausted when no next token", func(t *testing.T) {
		t.Parallel()
		searcher := mustPaginatedSearcher(t, PaginatedSearchConfig{
			Origins: make(map[string]Searcher),
			Merger:  NewResultMerger(ConflictFirstWins),
		})
		cursor := NewFederatedCursor("hash", "", []string{"origin1"}, nil)
		results := []originFetchResult{
			{OriginID: "origin1", Items: []*stac.Item{paginationTestItem("item1", time.Now())}},
		}
		searcher.mergeResults(results, cursor, 10, nil)
		if !cursor.GetOriginCursor("origin1").Exhausted {
			t.Error("expected origin to be marked exhausted")
		}
	})

	t.Run("equal datetimes break ties by id asc and are deterministic", func(t *testing.T) {
		t.Parallel()
		dt := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
		// Two origins emit items with identical datetimes but different IDs.
		// Without a tiebreaker the order between pages is undefined; with
		// (datetime desc, id asc) the order is "item-a" then "item-b" and
		// must be identical across repeated merges.
		makeResults := func() []originFetchResult {
			return []originFetchResult{
				{OriginID: "origin2", Items: []*stac.Item{
					paginationTestItem("item-b", dt),
					paginationTestItem("item-d", dt),
				}},
				{OriginID: "origin1", Items: []*stac.Item{
					paginationTestItem("item-c", dt),
					paginationTestItem("item-a", dt),
				}},
			}
		}
		expectedIDs := []string{"item-a", "item-b", "item-c", "item-d"}
		// Run 5 times with fresh state and confirm the order is stable.
		for i := 0; i < 5; i++ {
			searcher := mustPaginatedSearcher(t, PaginatedSearchConfig{
				Origins: make(map[string]Searcher),
				Merger:  NewResultMerger(ConflictFirstWins),
			})
			cursor := NewFederatedCursor("hash", "", []string{"origin1", "origin2"}, nil)
			merged := searcher.mergeResults(makeResults(), cursor, 10, nil)
			if len(merged) != 4 {
				t.Fatalf("iter %d: got %d items, want 4", i, len(merged))
			}
			for j, id := range expectedIDs {
				if merged[j].ID != id {
					t.Errorf("iter %d: merged[%d].ID = %q, want %q", i, j, merged[j].ID, id)
				}
			}
		}
	})
}

// TestHashSearchRequest tests query hash determinism
func TestHashSearchRequest(t *testing.T) {
	t.Run("same request produces same hash", func(t *testing.T) {
		t.Parallel()
		req1 := &stac.SearchRequest{
			Collections: []string{"col1", "col2"},
			BBox:        []float64{-10, -10, 10, 10},
			Datetime:    "2024-01-01T00:00:00Z/2024-12-31T23:59:59Z",
		}
		req2 := &stac.SearchRequest{
			Collections: []string{"col1", "col2"},
			BBox:        []float64{-10, -10, 10, 10},
			Datetime:    "2024-01-01T00:00:00Z/2024-12-31T23:59:59Z",
		}
		if hashSearchRequest(req1) != hashSearchRequest(req2) {
			t.Errorf("expected same hash for identical requests")
		}
	})

	t.Run("collections affect hash", func(t *testing.T) {
		t.Parallel()
		if hashSearchRequest(&stac.SearchRequest{Collections: []string{"a"}}) == hashSearchRequest(&stac.SearchRequest{Collections: []string{"b"}}) {
			t.Error("expected different hashes")
		}
	})

	t.Run("order of collections matters", func(t *testing.T) {
		t.Parallel()
		req1 := &stac.SearchRequest{Collections: []string{"col1", "col2"}}
		req2 := &stac.SearchRequest{Collections: []string{"col2", "col1"}}
		if hashSearchRequest(req1) == hashSearchRequest(req2) {
			t.Error("expected different hashes for different collection orders")
		}
	})

	t.Run("bbox affects hash", func(t *testing.T) {
		t.Parallel()
		if hashSearchRequest(&stac.SearchRequest{BBox: []float64{-10, -10, 10, 10}}) ==
			hashSearchRequest(&stac.SearchRequest{BBox: []float64{-20, -20, 20, 20}}) {
			t.Error("expected different hashes for different bboxes")
		}
	})

	t.Run("datetime affects hash", func(t *testing.T) {
		t.Parallel()
		if hashSearchRequest(&stac.SearchRequest{Datetime: "a"}) == hashSearchRequest(&stac.SearchRequest{Datetime: "b"}) {
			t.Error("expected different hashes for different datetimes")
		}
	})
}

// TestHashSearchRequest_LimitChangeInvalidatesCursor verifies that
// changing Limit changes the hash, so a cursor issued for one page size
// can't be replayed at a different limit.
func TestHashSearchRequest_LimitChangeInvalidatesCursor(t *testing.T) {
	t.Parallel()
	req1 := &stac.SearchRequest{Collections: []string{"c1"}, Limit: 10}
	req2 := &stac.SearchRequest{Collections: []string{"c1"}, Limit: 20}
	if hashSearchRequest(req1) == hashSearchRequest(req2) {
		t.Error("limit must affect hash")
	}
}

// TestHashSearchRequest_IDsChangeInvalidates verifies that changing IDs
// changes the hash.
func TestHashSearchRequest_IDsChangeInvalidates(t *testing.T) {
	t.Parallel()
	req1 := &stac.SearchRequest{IDs: []string{"a", "b"}}
	req2 := &stac.SearchRequest{IDs: []string{"a", "c"}}
	if hashSearchRequest(req1) == hashSearchRequest(req2) {
		t.Error("IDs must affect hash")
	}
}

// TestHashSearchRequest_FullDigest verifies the hash is the full 64-char sha256.
func TestHashSearchRequest_FullDigest(t *testing.T) {
	t.Parallel()
	hash := hashSearchRequest(paginationTestSearchRequest())
	if len(hash) != 64 {
		t.Errorf("expected hash length 64, got %d (%q)", len(hash), hash)
	}
	for _, c := range hash {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("hash contains non-hex character: %c", c)
		}
	}
}

// TestHashSearchRequest_PaginationFieldsIgnored verifies that Cursor and
// Token do NOT affect the hash — otherwise the cursor would invalidate
// itself on the next page.
func TestHashSearchRequest_PaginationFieldsIgnored(t *testing.T) {
	t.Parallel()
	base := &stac.SearchRequest{Collections: []string{"c1"}, Datetime: "2024"}
	withCursor := *base
	withCursor.Cursor = "some-cursor-value"
	withToken := *base
	withToken.Token = "some-token-value"

	h := hashSearchRequest(base)
	if hashSearchRequest(&withCursor) != h {
		t.Error("Cursor must not affect hash")
	}
	if hashSearchRequest(&withToken) != h {
		t.Error("Token must not affect hash")
	}
}

// TestCloneSearchRequest tests deep copy of search requests
func TestCloneSearchRequest(t *testing.T) {
	t.Run("basic clone", func(t *testing.T) {
		t.Parallel()
		original := &stac.SearchRequest{
			Collections: []string{"col1", "col2"},
			BBox:        []float64{-10, -10, 10, 10},
			Limit:       10,
		}
		cloned := cloneSearchRequest(original)
		if cloned == original {
			t.Error("clone should be a different object")
		}
		if cloned.Limit != original.Limit || len(cloned.Collections) != 2 || len(cloned.BBox) != 4 {
			t.Error("fields not copied")
		}
	})

	t.Run("no shared slices", func(t *testing.T) {
		t.Parallel()
		original := &stac.SearchRequest{Collections: []string{"col1"}, BBox: []float64{1}, IDs: []string{"id1"}}
		cloned := cloneSearchRequest(original)
		original.Collections[0] = "x"
		original.BBox[0] = -999
		original.IDs[0] = "y"
		if cloned.Collections[0] == "x" || cloned.BBox[0] == -999 || cloned.IDs[0] == "y" {
			t.Error("clone shares slices with original")
		}
	})

	t.Run("handles nil slices", func(t *testing.T) {
		t.Parallel()
		original := &stac.SearchRequest{}
		cloned := cloneSearchRequest(original)
		if cloned.Collections != nil || cloned.BBox != nil || cloned.IDs != nil {
			t.Error("nil slices should remain nil")
		}
	})
}

// TestLimitEnforcement tests that limits are properly enforced
func TestLimitEnforcement(t *testing.T) {
	t.Run("uses request limit when within max", func(t *testing.T) {
		t.Parallel()
		origin1 := newMockSearchable("origin1", 1, func(ctx context.Context, req *stac.SearchRequest) ([]*stac.Item, string, string, error) {
			items := make([]*stac.Item, 0)
			for i := 0; i < 100; i++ {
				items = append(items, paginationTestItem(fmt.Sprintf("item%d", i), time.Now()))
			}
			return items, "", "", nil
		})
		searcher := mustPaginatedSearcher(t, PaginatedSearchConfig{
			Origins:     map[string]Searcher{"origin1": origin1},
			Merger:      NewResultMerger(ConflictFirstWins),
			MaxPageSize: 1000,
		})
		result, err := searcher.Search(context.Background(), &stac.SearchRequest{Limit: 25}, "")
		if err != nil {
			t.Fatalf("search failed: %v", err)
		}
		if len(result.Items) != 25 || result.Context.Limit != 25 {
			t.Errorf("unexpected limit handling: items=%d limit=%d", len(result.Items), result.Context.Limit)
		}
	})

	t.Run("uses default when request limit is zero", func(t *testing.T) {
		t.Parallel()
		origin1 := newMockSearchable("origin1", 1, func(ctx context.Context, req *stac.SearchRequest) ([]*stac.Item, string, string, error) {
			return []*stac.Item{paginationTestItem("item1", time.Now())}, "", "", nil
		})
		searcher := mustPaginatedSearcher(t, PaginatedSearchConfig{
			Origins:         map[string]Searcher{"origin1": origin1},
			Merger:          NewResultMerger(ConflictFirstWins),
			DefaultPageSize: 50,
		})
		result, err := searcher.Search(context.Background(), &stac.SearchRequest{}, "")
		if err != nil {
			t.Fatalf("search failed: %v", err)
		}
		if result.Context.Limit != 50 {
			t.Errorf("expected limit 50, got %d", result.Context.Limit)
		}
	})

	t.Run("caps request limit to max page size", func(t *testing.T) {
		t.Parallel()
		origin1 := newMockSearchable("origin1", 1, func(ctx context.Context, req *stac.SearchRequest) ([]*stac.Item, string, string, error) {
			return []*stac.Item{paginationTestItem("item1", time.Now())}, "", "", nil
		})
		searcher := mustPaginatedSearcher(t, PaginatedSearchConfig{
			Origins:         map[string]Searcher{"origin1": origin1},
			Merger:          NewResultMerger(ConflictFirstWins),
			DefaultPageSize: 100,
			MaxPageSize:     500,
		})
		result, err := searcher.Search(context.Background(), &stac.SearchRequest{Limit: 1000}, "")
		if err != nil {
			t.Fatalf("search failed: %v", err)
		}
		if result.Context.Limit != 100 {
			t.Errorf("expected default 100, got %d", result.Context.Limit)
		}
	})
}

// TestGetDatetime tests datetime extraction for sorting
func TestGetDatetime(t *testing.T) {
	t.Run("extracts valid datetime", func(t *testing.T) {
		t.Parallel()
		item := &stac.Item{Properties: map[string]any{"datetime": "2024-01-01T00:00:00Z"}}
		if got := getDatetime(item); got != "2024-01-01T00:00:00Z" {
			t.Errorf("unexpected datetime: %q", got)
		}
	})

	t.Run("extracts string-form datetime", func(t *testing.T) {
		t.Parallel()
		item := &stac.Item{Properties: map[string]any{"datetime": "2024-02-02T00:00:00Z"}}
		if got := getDatetime(item); got != "2024-02-02T00:00:00Z" {
			t.Errorf("unexpected datetime: %q", got)
		}
	})

	t.Run("empty for missing", func(t *testing.T) {
		t.Parallel()
		item := &stac.Item{Properties: map[string]any{}}
		if got := getDatetime(item); got != "" {
			t.Errorf("expected empty, got %q", got)
		}
	})
}

// TestPaginatedSearcher_ConcurrentSearches_DoNotCrossPollinateDedup
// guards Fix C4: PaginatedSearcher must not share dedup state across
// concurrent Search calls. Previously the deduplicator was a field on
// the receiver, so two concurrent searches could see each other's item
// IDs and silently drop results. This test spawns N concurrent
// goroutines split across two disjoint ID namespaces and asserts every
// goroutine sees the full count of its own namespace.
func TestPaginatedSearcher_ConcurrentSearches_DoNotCrossPollinateDedup(t *testing.T) {
	t.Parallel()

	const goroutinesPerSet = 5
	const itemsPerSearch = 20

	// Each Search request carries a "set" hint via Collections; the stub
	// origin emits items prefixed with that set name. Two disjoint sets
	// ("a", "b") run concurrently — if dedup state were shared, the
	// second goroutine in each set would see "duplicate" IDs from the
	// first and drop them.
	origin := newMockSearchable("origin1", 1, func(ctx context.Context, req *stac.SearchRequest) ([]*stac.Item, string, string, error) {
		set := "x"
		if len(req.Collections) > 0 {
			set = req.Collections[0]
		}
		items := make([]*stac.Item, 0, itemsPerSearch)
		base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
		for i := 0; i < itemsPerSearch; i++ {
			id := fmt.Sprintf("set-%s-%d", set, i)
			items = append(items, paginationTestItem(id, base.Add(time.Duration(i)*time.Hour)))
		}
		return items, "", "", nil
	})

	searcher := mustPaginatedSearcher(t, PaginatedSearchConfig{
		Origins:     map[string]Searcher{"origin1": origin},
		Merger:      NewResultMerger(ConflictFirstWins),
		MaxPageSize: 100,
	})

	type outcome struct {
		set   string
		items []*stac.Item
		err   error
	}

	results := make(chan outcome, goroutinesPerSet*2)
	var wg sync.WaitGroup

	launch := func(set string) {
		defer wg.Done()
		req := &stac.SearchRequest{Collections: []string{set}, Limit: itemsPerSearch}
		res, err := searcher.Search(context.Background(), req, "")
		if err != nil {
			results <- outcome{set: set, err: err}
			return
		}
		results <- outcome{set: set, items: res.Items}
	}

	for i := 0; i < goroutinesPerSet; i++ {
		wg.Add(2)
		go launch("a")
		go launch("b")
	}
	wg.Wait()
	close(results)

	for o := range results {
		if o.err != nil {
			t.Errorf("set %s: search failed: %v", o.set, o.err)
			continue
		}
		if len(o.items) != itemsPerSearch {
			t.Errorf("set %s: expected %d items, got %d (cross-pollination of dedup state suspected)", o.set, itemsPerSearch, len(o.items))
		}
		wantPrefix := "set-" + o.set + "-"
		for _, it := range o.items {
			if !strings.HasPrefix(it.ID, wantPrefix) {
				t.Errorf("set %s: got item with foreign ID %q", o.set, it.ID)
			}
		}
	}
}

// TestSearch_CursorV2_PrevFirstChain verifies that the cursor v2
// chain (PrevCursor/FirstCursor/PageSeq) propagates correctly across
// pages and that the page cache serves backwards-navigation lookups.
//
// Walks: page 0 → page 1 → page 2 → follow `prev` from page 2 → must
// return page 1's items. Without the page cache the prev follow
// would re-execute upstreams (which the mock allows), but with the
// cache the upstream call count proves the lookup hit.
func TestSearch_CursorV2_PrevFirstChain(t *testing.T) {
	t.Parallel()

	// Three pages of 1 item each. After page 3 the origin signals
	// exhaustion (empty next token).
	pages := []struct {
		items []*stac.Item
		token string
	}{
		{[]*stac.Item{paginationTestItem("item-1", time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC))}, "t1"},
		{[]*stac.Item{paginationTestItem("item-2", time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC))}, "t2"},
		{[]*stac.Item{paginationTestItem("item-3", time.Date(2024, 1, 3, 0, 0, 0, 0, time.UTC))}, ""},
	}

	var (
		mu        sync.Mutex
		callCount int
	)
	origin := newMockSearchable("origin1", 1, func(ctx context.Context, req *stac.SearchRequest) ([]*stac.Item, string, string, error) {
		mu.Lock()
		defer mu.Unlock()
		idx := 0
		for i, p := range pages {
			if i == 0 && req.Token == "" {
				idx = 0
				break
			}
			if i > 0 && p.token != "" && req.Token == pages[i-1].token {
				idx = i
				break
			}
		}
		callCount++
		return pages[idx].items, pages[idx].token, "", nil
	})

	store := newPageCacheTestStore()
	pc, err := pagecache.New(store, time.Hour, []byte("test-secret"))
	if err != nil {
		t.Fatalf("pagecache.New: %v", err)
	}

	searcher := mustPaginatedSearcher(t, PaginatedSearchConfig{
		Origins:   map[string]Searcher{"origin1": origin},
		Merger:    NewResultMerger(ConflictFirstWins),
		PageCache: pc,
	})

	req := &stac.SearchRequest{Limit: 1}

	// Page 0: no incoming cursor, no `prev`/`first`/`self` links.
	r0, err := searcher.Search(context.Background(), req, "")
	if err != nil {
		t.Fatalf("page 0: %v", err)
	}
	if r0.NextCursor == "" {
		t.Fatal("page 0: NextCursor empty; expected continuation")
	}
	if r0.PrevCursor != "" || r0.FirstCursor != "" || r0.SelfCursor != "" {
		t.Errorf("page 0: prev/first/self should be empty on first page; got prev=%q first=%q self=%q",
			r0.PrevCursor, r0.FirstCursor, r0.SelfCursor)
	}

	// Page 1: follow `next` from page 0. self == page 0's next-cursor
	// (which is the cursor we're consuming now), prev/first should
	// reflect page 0's empty cursor (no prev/first to navigate to).
	r1, err := searcher.Search(context.Background(), req, r0.NextCursor)
	if err != nil {
		t.Fatalf("page 1: %v", err)
	}
	if r1.SelfCursor != r0.NextCursor {
		t.Errorf("page 1: SelfCursor = %q, want %q", r1.SelfCursor, r0.NextCursor)
	}
	if r1.PrevCursor != "" {
		t.Errorf("page 1: PrevCursor = %q, want empty (page 0 had no cursor)", r1.PrevCursor)
	}
	if r1.NextCursor == "" {
		t.Fatal("page 1: NextCursor empty; expected continuation to page 2")
	}

	// Page 2: follow next from page 1. Now prev should point at page 1's cursor.
	r2, err := searcher.Search(context.Background(), req, r1.NextCursor)
	if err != nil {
		t.Fatalf("page 2: %v", err)
	}
	if r2.SelfCursor != r1.NextCursor {
		t.Errorf("page 2: SelfCursor = %q, want %q", r2.SelfCursor, r1.NextCursor)
	}
	if r2.PrevCursor != r0.NextCursor {
		t.Errorf("page 2: PrevCursor = %q, want %q (page 1's cursor)",
			r2.PrevCursor, r0.NextCursor)
	}

	callsBeforePrev := callCount

	// Follow `prev` from page 2 → should hit the page cache and
	// return page 1's items WITHOUT calling the upstream again.
	rPrev, err := searcher.Search(context.Background(), req, r2.PrevCursor)
	if err != nil {
		t.Fatalf("prev follow: %v", err)
	}
	if len(rPrev.Items) != 1 || rPrev.Items[0].ID != "item-2" {
		t.Errorf("prev follow: items = %v, want [item-2] (page 1)",
			itemIDs(rPrev.Items))
	}
	if callCount != callsBeforePrev {
		t.Errorf("prev follow: upstream was called %d times after lookup; want cache hit (no upstream calls)",
			callCount-callsBeforePrev)
	}
}

// pageCacheTestStore is a tiny in-memory implementation of
// pagecache.Store for tests. Mirrors the one in the pagecache
// package's own tests but kept local so this package doesn't need
// to import pagecache_test internals.
type pageCacheTestStore struct {
	mu   sync.Mutex
	data map[string][]byte
}

func newPageCacheTestStore() *pageCacheTestStore {
	return &pageCacheTestStore{data: make(map[string][]byte)}
}

func (s *pageCacheTestStore) Get(_ context.Context, key string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.data[key]
	return v, ok
}

func (s *pageCacheTestStore) Set(_ context.Context, key string, value []byte, _ time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[key] = value
	return nil
}

// itemIDs extracts IDs from a slice of items for test assertions.
func itemIDs(items []*stac.Item) []string {
	out := make([]string, 0, len(items))
	for _, it := range items {
		if it != nil {
			out = append(out, it.ID)
		}
	}
	return out
}
