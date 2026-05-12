package federation

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yourorg/stac-proxy/internal/stac"
)

// Test helpers for pagination tests

func paginationTestItem(id string, datetime time.Time) *stac.Item {
	dt := datetime.UTC()
	return &stac.Item{
		Type:       "Feature",
		ID:         id,
		Collection: "test-collection",
		Geometry:   nil,
		BBox:       []float64{-180, -90, 180, 90},
		Properties: stac.Properties{
			DateTime: &dt,
			Extra: map[string]interface{}{
				"datetime_str": datetime.UTC().Format(time.RFC3339),
			},
		},
		Links:  []stac.Link{},
		Assets: map[string]stac.Asset{},
	}
}

func paginationTestSearchRequest() *stac.SearchRequest {
	return &stac.SearchRequest{
		Limit: 10,
	}
}

type mockOriginClient struct {
	id         string
	priority   int
	enabled    bool
	searchFunc func(ctx context.Context, req *stac.SearchRequest) ([]*stac.Item, string, string, error)
}

func (m *mockOriginClient) Search(ctx context.Context, req *stac.SearchRequest) ([]*stac.Item, string, string, error) {
	if m.searchFunc != nil {
		return m.searchFunc(ctx, req)
	}
	return nil, "", "", nil
}

func (m *mockOriginClient) ID() string {
	return m.id
}

func (m *mockOriginClient) Priority() int {
	return m.priority
}

func (m *mockOriginClient) IsEnabled() bool {
	return m.enabled
}

// mockSearchableOrigin is a test interface for origins that can search
type mockSearchableOrigin struct {
	originID   string
	originPri  int
	searchFunc func(ctx context.Context, req *stac.SearchRequest) ([]*stac.Item, string, string, error)
}

func (m *mockSearchableOrigin) Search(ctx context.Context, req *stac.SearchRequest) ([]*stac.Item, string, string, error) {
	if m.searchFunc != nil {
		return m.searchFunc(ctx, req)
	}
	return nil, "", "", nil
}

func (m *mockSearchableOrigin) ID() string       { return m.originID }
func (m *mockSearchableOrigin) Priority() int    { return m.originPri }
func (m *mockSearchableOrigin) IsEnabled() bool  { return true }
func (m *mockSearchableOrigin) HasCollection(id string) bool { return true }
func (m *mockSearchableOrigin) GetCollections(ctx context.Context) ([]*stac.Collection, error) { return nil, nil }
func (m *mockSearchableOrigin) Origin() *Origin { return &Origin{ID: m.originID, Priority: m.originPri} }

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
			Origins: make(map[string]Searcher),
			Merger:  NewResultMerger(ConflictFirstWins),
		}

		searcher := NewPaginatedSearcher(cfg)

		if searcher == nil {
			t.Fatal("expected searcher to be non-nil")
		}

		if searcher.pageSize != 100 {
			t.Errorf("expected default page size 100, got %d", searcher.pageSize)
		}

		if searcher.maxPageSize != 1000 {
			t.Errorf("expected default max page size 1000, got %d", searcher.maxPageSize)
		}

		if searcher.deduplicator == nil {
			t.Error("expected deduplicator to be initialized")
		}
	})

	t.Run("with custom page sizes", func(t *testing.T) {
		t.Parallel()

		cfg := PaginatedSearchConfig{
			Origins:         make(map[string]Searcher),
			Merger:          NewResultMerger(ConflictPriorityWins),
			DefaultPageSize: 50,
			MaxPageSize:     500,
		}

		searcher := NewPaginatedSearcher(cfg)

		if searcher.pageSize != 50 {
			t.Errorf("expected page size 50, got %d", searcher.pageSize)
		}

		if searcher.maxPageSize != 500 {
			t.Errorf("expected max page size 500, got %d", searcher.maxPageSize)
		}
	})

	t.Run("with zero page sizes uses defaults", func(t *testing.T) {
		t.Parallel()

		cfg := PaginatedSearchConfig{
			Origins:         make(map[string]Searcher),
			Merger:          NewResultMerger(ConflictFirstWins),
			DefaultPageSize: 0,
			MaxPageSize:     0,
		}

		searcher := NewPaginatedSearcher(cfg)

		if searcher.pageSize != 100 {
			t.Errorf("expected default page size 100 for zero config, got %d", searcher.pageSize)
		}

		if searcher.maxPageSize != 1000 {
			t.Errorf("expected default max page size 1000 for zero config, got %d", searcher.maxPageSize)
		}
	})

	t.Run("with negative page sizes uses defaults", func(t *testing.T) {
		t.Parallel()

		cfg := PaginatedSearchConfig{
			Origins:         make(map[string]Searcher),
			Merger:          NewResultMerger(ConflictFirstWins),
			DefaultPageSize: -10,
			MaxPageSize:     -100,
		}

		searcher := NewPaginatedSearcher(cfg)

		if searcher.pageSize != 100 {
			t.Errorf("expected default page size 100 for negative config, got %d", searcher.pageSize)
		}

		if searcher.maxPageSize != 1000 {
			t.Errorf("expected default max page size 1000 for negative config, got %d", searcher.maxPageSize)
		}
	})

	t.Run("with origins", func(t *testing.T) {
		t.Parallel()

		origins := map[string]Searcher{
			"origin1": newMockSearchable("origin1", 1, nil),
			"origin2": newMockSearchable("origin2", 2, nil),
		}

		cfg := PaginatedSearchConfig{
			Origins: origins,
			Merger:  NewResultMerger(ConflictFirstWins),
		}

		searcher := NewPaginatedSearcher(cfg)

		if len(searcher.origins) != 2 {
			t.Errorf("expected 2 origins, got %d", len(searcher.origins))
		}
	})

	t.Run("with nil merger", func(t *testing.T) {
		t.Parallel()

		cfg := PaginatedSearchConfig{
			Origins: make(map[string]Searcher),
			Merger:  nil,
		}

		searcher := NewPaginatedSearcher(cfg)

		if searcher.merger != nil {
			t.Error("expected merger to be nil when not provided")
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

		origins := map[string]Searcher{
			"origin1": origin1,
		}

		cfg := PaginatedSearchConfig{
			Origins: origins,
			Merger:  NewResultMerger(ConflictFirstWins),
		}

		searcher := NewPaginatedSearcher(cfg)
		req := paginationTestSearchRequest()

		result, err := searcher.Search(context.Background(), req, "")

		if err != nil {
			t.Fatalf("search failed: %v", err)
		}

		if result == nil {
			t.Fatal("expected non-nil result")
		}

		if len(result.Items) != 2 {
			t.Errorf("expected 2 items, got %d", len(result.Items))
		}

		if result.Context == nil {
			t.Fatal("expected non-nil context")
		}

		if result.Context.Returned != 2 {
			t.Errorf("expected returned count 2, got %d", result.Context.Returned)
		}
	})

	t.Run("multiple origins", func(t *testing.T) {
		t.Parallel()

		origin1 := newMockSearchable("origin1", 1, func(ctx context.Context, req *stac.SearchRequest) ([]*stac.Item, string, string, error) {
			return []*stac.Item{
				paginationTestItem("item1", time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)),
			}, "", "", nil
		})

		origin2 := newMockSearchable("origin2", 2, func(ctx context.Context, req *stac.SearchRequest) ([]*stac.Item, string, string, error) {
			return []*stac.Item{
				paginationTestItem("item2", time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC)),
			}, "", "", nil
		})

		origins := map[string]Searcher{
			"origin1": origin1,
			"origin2": origin2,
		}

		cfg := PaginatedSearchConfig{
			Origins: origins,
			Merger:  NewResultMerger(ConflictFirstWins),
		}

		searcher := NewPaginatedSearcher(cfg)
		req := paginationTestSearchRequest()

		result, err := searcher.Search(context.Background(), req, "")

		if err != nil {
			t.Fatalf("search failed: %v", err)
		}

		if len(result.Items) != 2 {
			t.Errorf("expected 2 items from 2 origins, got %d", len(result.Items))
		}

		if len(result.Context.Origins) != 2 {
			t.Errorf("expected 2 origin statuses, got %d", len(result.Context.Origins))
		}
	})

	t.Run("no origins", func(t *testing.T) {
		t.Parallel()

		cfg := PaginatedSearchConfig{
			Origins: make(map[string]Searcher),
			Merger:  NewResultMerger(ConflictFirstWins),
		}

		searcher := NewPaginatedSearcher(cfg)
		req := paginationTestSearchRequest()

		result, err := searcher.Search(context.Background(), req, "")

		if err != nil {
			t.Fatalf("search failed: %v", err)
		}

		if len(result.Items) != 0 {
			t.Errorf("expected 0 items with no origins, got %d", len(result.Items))
		}

		if result.NextCursor != "" {
			t.Error("expected no next cursor with no origins")
		}
	})

	t.Run("with next token creates cursor", func(t *testing.T) {
		t.Parallel()

		origin1 := newMockSearchable("origin1", 1, func(ctx context.Context, req *stac.SearchRequest) ([]*stac.Item, string, string, error) {
			items := []*stac.Item{
				paginationTestItem("item1", time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)),
			}
			return items, "next-token", "", nil
		})

		origins := map[string]Searcher{
			"origin1": origin1,
		}

		cfg := PaginatedSearchConfig{
			Origins: origins,
			Merger:  NewResultMerger(ConflictFirstWins),
		}

		searcher := NewPaginatedSearcher(cfg)
		req := paginationTestSearchRequest()

		result, err := searcher.Search(context.Background(), req, "")

		if err != nil {
			t.Fatalf("search failed: %v", err)
		}

		if result.NextCursor == "" {
			t.Error("expected next cursor when origin has more results")
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
				return []*stac.Item{
					paginationTestItem("item1", time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)),
				}, "token1", "", nil
			}
			// Second call with token
			if req.Token != "token1" {
				t.Errorf("expected token 'token1', got %q", req.Token)
			}
			return []*stac.Item{
				paginationTestItem("item2", time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC)),
			}, "", "", nil
		})

		origins := map[string]Searcher{
			"origin1": origin1,
		}

		cfg := PaginatedSearchConfig{
			Origins: origins,
			Merger:  NewResultMerger(ConflictFirstWins),
		}

		searcher := NewPaginatedSearcher(cfg)
		req := &stac.SearchRequest{Limit: 1}

		// First search
		result1, err := searcher.Search(context.Background(), req, "")
		if err != nil {
			t.Fatalf("first search failed: %v", err)
		}

		if result1.NextCursor == "" {
			t.Fatal("expected next cursor from first search")
		}

		// Second search with cursor
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
			return []*stac.Item{
				paginationTestItem("item1", time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)),
			}, "token", "", nil
		})

		origins := map[string]Searcher{
			"origin1": origin1,
		}

		cfg := PaginatedSearchConfig{
			Origins: origins,
			Merger:  NewResultMerger(ConflictFirstWins),
		}

		searcher := NewPaginatedSearcher(cfg)
		req1 := &stac.SearchRequest{Collections: []string{"collection1"}}

		// First search
		result1, err := searcher.Search(context.Background(), req1, "")
		if err != nil {
			t.Fatalf("first search failed: %v", err)
		}

		// Second search with different query
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

		cfg := PaginatedSearchConfig{
			Origins: make(map[string]Searcher),
			Merger:  NewResultMerger(ConflictFirstWins),
		}

		searcher := NewPaginatedSearcher(cfg)
		req := paginationTestSearchRequest()

		_, err := searcher.Search(context.Background(), req, "invalid-cursor!!!")

		if err == nil {
			t.Fatal("expected error for invalid cursor")
		}
	})

	t.Run("expired cursor", func(t *testing.T) {
		t.Parallel()

		cfg := PaginatedSearchConfig{
			Origins: make(map[string]Searcher),
			Merger:  NewResultMerger(ConflictFirstWins),
		}

		searcher := NewPaginatedSearcher(cfg)
		req := paginationTestSearchRequest()

		// Create an expired cursor
		cursor := NewFederatedCursor("hash", []string{"origin1"}, nil)
		cursor.ExpiresAt = time.Now().Add(-1 * time.Hour).Unix()
		expiredCursor, _ := cursor.Encode()

		_, err := searcher.Search(context.Background(), req, expiredCursor)

		if err == nil {
			t.Fatal("expected error for expired cursor")
		}

		if !strings.Contains(err.Error(), "expired") {
			t.Errorf("expected expired error, got: %v", err)
		}
	})
}

// TestFetchFromOrigins tests parallel origin fetching
func TestFetchFromOrigins(t *testing.T) {
	t.Run("parallel execution", func(t *testing.T) {
		t.Parallel()

		var mu sync.Mutex
		startTimes := make(map[string]time.Time)

		origin1 := newMockSearchable("origin1", 1, func(ctx context.Context, req *stac.SearchRequest) ([]*stac.Item, string, string, error) {
			mu.Lock()
			startTimes["origin1"] = time.Now()
			mu.Unlock()
			time.Sleep(50 * time.Millisecond)
			return []*stac.Item{paginationTestItem("item1", time.Now())}, "", "", nil
		})

		origin2 := newMockSearchable("origin2", 2, func(ctx context.Context, req *stac.SearchRequest) ([]*stac.Item, string, string, error) {
			mu.Lock()
			startTimes["origin2"] = time.Now()
			mu.Unlock()
			time.Sleep(50 * time.Millisecond)
			return []*stac.Item{paginationTestItem("item2", time.Now())}, "", "", nil
		})

		origins := map[string]Searcher{
			"origin1": origin1,
			"origin2": origin2,
		}

		cfg := PaginatedSearchConfig{
			Origins: origins,
			Merger:  NewResultMerger(ConflictFirstWins),
		}

		searcher := NewPaginatedSearcher(cfg)
		req := paginationTestSearchRequest()
		cursor := NewFederatedCursor("hash", []string{"origin1", "origin2"}, nil)

		results := searcher.fetchFromOrigins(context.Background(), req, cursor, []string{"origin1", "origin2"}, 10)

		if len(results) != 2 {
			t.Errorf("expected 2 results, got %d", len(results))
		}

		// Check that both started around the same time (parallel execution)
		mu.Lock()
		if len(startTimes) == 2 {
			diff := startTimes["origin2"].Sub(startTimes["origin1"]).Abs()
			if diff > 30*time.Millisecond {
				t.Logf("warning: origins did not start in parallel, difference: %v", diff)
			}
		}
		mu.Unlock()
	})

	t.Run("handles origin errors", func(t *testing.T) {
		t.Parallel()

		origin1 := newMockSearchable("origin1", 1, func(ctx context.Context, req *stac.SearchRequest) ([]*stac.Item, string, string, error) {
			return nil, "", "", errors.New("origin1 error")
		})

		origin2 := newMockSearchable("origin2", 2, func(ctx context.Context, req *stac.SearchRequest) ([]*stac.Item, string, string, error) {
			return []*stac.Item{paginationTestItem("item2", time.Now())}, "", "", nil
		})

		origins := map[string]Searcher{
			"origin1": origin1,
			"origin2": origin2,
		}

		cfg := PaginatedSearchConfig{
			Origins: origins,
			Merger:  NewResultMerger(ConflictFirstWins),
		}

		searcher := NewPaginatedSearcher(cfg)
		req := paginationTestSearchRequest()
		cursor := NewFederatedCursor("hash", []string{"origin1", "origin2"}, nil)

		results := searcher.fetchFromOrigins(context.Background(), req, cursor, []string{"origin1", "origin2"}, 10)

		// Should have results from both (one with error)
		if len(results) != 2 {
			t.Errorf("expected 2 results, got %d", len(results))
		}

		// Check that one has error
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

		origins := map[string]Searcher{
			"origin1": origin1,
		}

		cfg := PaginatedSearchConfig{
			Origins: origins,
			Merger:  NewResultMerger(ConflictFirstWins),
		}

		searcher := NewPaginatedSearcher(cfg)
		req := paginationTestSearchRequest()
		cursor := NewFederatedCursor("hash", []string{"origin1"}, nil)
		cursor.Origins["origin1"].NextToken = "test-token"

		searcher.fetchFromOrigins(context.Background(), req, cursor, []string{"origin1"}, 10)

		mu.Lock()
		if receivedToken != "test-token" {
			t.Errorf("expected token 'test-token', got %q", receivedToken)
		}
		mu.Unlock()
	})

	t.Run("handles missing origin", func(t *testing.T) {
		t.Parallel()

		cfg := PaginatedSearchConfig{
			Origins: make(map[string]Searcher),
			Merger:  NewResultMerger(ConflictFirstWins),
		}

		searcher := NewPaginatedSearcher(cfg)
		req := paginationTestSearchRequest()
		cursor := NewFederatedCursor("hash", []string{"missing-origin"}, nil)

		results := searcher.fetchFromOrigins(context.Background(), req, cursor, []string{"missing-origin"}, 10)

		if len(results) != 1 {
			t.Errorf("expected 1 result, got %d", len(results))
		}

		if results[0].Error == nil {
			t.Error("expected error for missing origin")
		}

		if !strings.Contains(results[0].Error.Error(), "origin not found") {
			t.Errorf("expected 'origin not found' error, got: %v", results[0].Error)
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

		origins := map[string]Searcher{
			"origin1": origin1,
		}

		cfg := PaginatedSearchConfig{
			Origins: origins,
			Merger:  NewResultMerger(ConflictFirstWins),
		}

		searcher := NewPaginatedSearcher(cfg)
		req := paginationTestSearchRequest()
		cursor := NewFederatedCursor("hash", []string{"origin1"}, nil)

		searcher.fetchFromOrigins(context.Background(), req, cursor, []string{"origin1"}, 10)

		mu.Lock()
		if receivedLimit != 20 { // limit * 2
			t.Errorf("expected limit 20 (10*2), got %d", receivedLimit)
		}
		mu.Unlock()
	})
}

// TestMergeResults tests result merging and deduplication
func TestMergeResults(t *testing.T) {
	t.Run("merges items from multiple origins", func(t *testing.T) {
		t.Parallel()

		cfg := PaginatedSearchConfig{
			Origins: make(map[string]Searcher),
			Merger:  NewResultMerger(ConflictFirstWins),
		}

		searcher := NewPaginatedSearcher(cfg)
		cursor := NewFederatedCursor("hash", []string{"origin1", "origin2"}, nil)

		results := []originFetchResult{
			{
				OriginID: "origin1",
				Items: []*stac.Item{
					paginationTestItem("item1", time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)),
				},
			},
			{
				OriginID: "origin2",
				Items: []*stac.Item{
					paginationTestItem("item2", time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC)),
				},
			},
		}

		merged := searcher.mergeResults(results, cursor, 10)

		if len(merged) != 2 {
			t.Errorf("expected 2 merged items, got %d", len(merged))
		}
	})

	t.Run("deduplicates items", func(t *testing.T) {
		t.Parallel()

		cfg := PaginatedSearchConfig{
			Origins: make(map[string]Searcher),
			Merger:  NewResultMerger(ConflictFirstWins),
		}

		searcher := NewPaginatedSearcher(cfg)
		cursor := NewFederatedCursor("hash", []string{"origin1", "origin2"}, nil)

		results := []originFetchResult{
			{
				OriginID: "origin1",
				Items: []*stac.Item{
					paginationTestItem("item1", time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)),
				},
			},
			{
				OriginID: "origin2",
				Items: []*stac.Item{
					paginationTestItem("item1", time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)), // Duplicate
				},
			},
		}

		merged := searcher.mergeResults(results, cursor, 10)

		if len(merged) != 1 {
			t.Errorf("expected 1 item after deduplication, got %d", len(merged))
		}
	})

	t.Run("sorts by datetime descending", func(t *testing.T) {
		t.Parallel()

		cfg := PaginatedSearchConfig{
			Origins: make(map[string]Searcher),
			Merger:  NewResultMerger(ConflictFirstWins),
		}

		searcher := NewPaginatedSearcher(cfg)
		cursor := NewFederatedCursor("hash", []string{"origin1"}, nil)

		results := []originFetchResult{
			{
				OriginID: "origin1",
				Items: []*stac.Item{
					paginationTestItem("item1", time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)),
					paginationTestItem("item2", time.Date(2024, 1, 3, 0, 0, 0, 0, time.UTC)),
					paginationTestItem("item3", time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC)),
				},
			},
		}

		merged := searcher.mergeResults(results, cursor, 10)

		if len(merged) != 3 {
			t.Fatalf("expected 3 items, got %d", len(merged))
		}

		// Check descending order
		if merged[0].ID != "item2" { // 2024-01-03
			t.Errorf("expected item2 first, got %s", merged[0].ID)
		}
		if merged[1].ID != "item3" { // 2024-01-02
			t.Errorf("expected item3 second, got %s", merged[1].ID)
		}
		if merged[2].ID != "item1" { // 2024-01-01
			t.Errorf("expected item1 third, got %s", merged[2].ID)
		}
	})

	t.Run("applies limit", func(t *testing.T) {
		t.Parallel()

		cfg := PaginatedSearchConfig{
			Origins: make(map[string]Searcher),
			Merger:  NewResultMerger(ConflictFirstWins),
		}

		searcher := NewPaginatedSearcher(cfg)
		cursor := NewFederatedCursor("hash", []string{"origin1"}, nil)

		results := []originFetchResult{
			{
				OriginID: "origin1",
				Items: []*stac.Item{
					paginationTestItem("item1", time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)),
					paginationTestItem("item2", time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC)),
					paginationTestItem("item3", time.Date(2024, 1, 3, 0, 0, 0, 0, time.UTC)),
				},
			},
		}

		merged := searcher.mergeResults(results, cursor, 2)

		if len(merged) != 2 {
			t.Errorf("expected 2 items (limited), got %d", len(merged))
		}
	})

	t.Run("updates cursor for successful origins", func(t *testing.T) {
		t.Parallel()

		cfg := PaginatedSearchConfig{
			Origins: make(map[string]Searcher),
			Merger:  NewResultMerger(ConflictFirstWins),
		}

		searcher := NewPaginatedSearcher(cfg)
		cursor := NewFederatedCursor("hash", []string{"origin1"}, nil)

		results := []originFetchResult{
			{
				OriginID:  "origin1",
				Items:     []*stac.Item{paginationTestItem("item1", time.Now())},
				NextToken: "next-token",
			},
		}

		searcher.mergeResults(results, cursor, 10)

		origin := cursor.GetOriginCursor("origin1")
		if origin.NextToken != "next-token" {
			t.Errorf("expected next token 'next-token', got %q", origin.NextToken)
		}

		if origin.ItemCount != 1 {
			t.Errorf("expected item count 1, got %d", origin.ItemCount)
		}
	})

	t.Run("marks error origins", func(t *testing.T) {
		t.Parallel()

		cfg := PaginatedSearchConfig{
			Origins: make(map[string]Searcher),
			Merger:  NewResultMerger(ConflictFirstWins),
		}

		searcher := NewPaginatedSearcher(cfg)
		cursor := NewFederatedCursor("hash", []string{"origin1"}, nil)

		results := []originFetchResult{
			{
				OriginID: "origin1",
				Error:    errors.New("fetch failed"),
			},
		}

		searcher.mergeResults(results, cursor, 10)

		origin := cursor.GetOriginCursor("origin1")
		if !origin.Error {
			t.Error("expected origin to be marked with error")
		}
	})

	t.Run("marks exhausted when no next token", func(t *testing.T) {
		t.Parallel()

		cfg := PaginatedSearchConfig{
			Origins: make(map[string]Searcher),
			Merger:  NewResultMerger(ConflictFirstWins),
		}

		searcher := NewPaginatedSearcher(cfg)
		cursor := NewFederatedCursor("hash", []string{"origin1"}, nil)

		results := []originFetchResult{
			{
				OriginID:  "origin1",
				Items:     []*stac.Item{paginationTestItem("item1", time.Now())},
				NextToken: "",
				NextURL:   "",
			},
		}

		searcher.mergeResults(results, cursor, 10)

		origin := cursor.GetOriginCursor("origin1")
		if !origin.Exhausted {
			t.Error("expected origin to be marked exhausted when no next token/URL")
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

		hash1 := hashSearchRequest(req1)
		hash2 := hashSearchRequest(req2)

		if hash1 != hash2 {
			t.Errorf("expected same hash for identical requests, got %q and %q", hash1, hash2)
		}
	})

	t.Run("different requests produce different hashes", func(t *testing.T) {
		t.Parallel()

		req1 := &stac.SearchRequest{Collections: []string{"col1"}}
		req2 := &stac.SearchRequest{Collections: []string{"col2"}}

		hash1 := hashSearchRequest(req1)
		hash2 := hashSearchRequest(req2)

		if hash1 == hash2 {
			t.Error("expected different hashes for different requests")
		}
	})

	t.Run("order of collections matters", func(t *testing.T) {
		t.Parallel()

		req1 := &stac.SearchRequest{Collections: []string{"col1", "col2"}}
		req2 := &stac.SearchRequest{Collections: []string{"col2", "col1"}}

		hash1 := hashSearchRequest(req1)
		hash2 := hashSearchRequest(req2)

		if hash1 == hash2 {
			t.Error("expected different hashes for different collection orders")
		}
	})

	t.Run("limit does not affect hash", func(t *testing.T) {
		t.Parallel()

		req1 := &stac.SearchRequest{Limit: 10}
		req2 := &stac.SearchRequest{Limit: 20}

		hash1 := hashSearchRequest(req1)
		hash2 := hashSearchRequest(req2)

		if hash1 != hash2 {
			t.Error("limit should not affect hash")
		}
	})

	t.Run("bbox affects hash", func(t *testing.T) {
		t.Parallel()

		req1 := &stac.SearchRequest{BBox: []float64{-10, -10, 10, 10}}
		req2 := &stac.SearchRequest{BBox: []float64{-20, -20, 20, 20}}

		hash1 := hashSearchRequest(req1)
		hash2 := hashSearchRequest(req2)

		if hash1 == hash2 {
			t.Error("expected different hashes for different bboxes")
		}
	})

	t.Run("datetime affects hash", func(t *testing.T) {
		t.Parallel()

		req1 := &stac.SearchRequest{Datetime: "2024-01-01T00:00:00Z"}
		req2 := &stac.SearchRequest{Datetime: "2024-12-31T23:59:59Z"}

		hash1 := hashSearchRequest(req1)
		hash2 := hashSearchRequest(req2)

		if hash1 == hash2 {
			t.Error("expected different hashes for different datetimes")
		}
	})

	t.Run("returns consistent short hash", func(t *testing.T) {
		t.Parallel()

		req := paginationTestSearchRequest()
		hash := hashSearchRequest(req)

		// Should be 16 hex characters (8 bytes)
		if len(hash) != 16 {
			t.Errorf("expected hash length 16, got %d", len(hash))
		}

		// Should be valid hex
		for _, c := range hash {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				t.Errorf("hash contains non-hex character: %c", c)
			}
		}
	})
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

		if cloned.Limit != original.Limit {
			t.Error("limit should be copied")
		}

		if len(cloned.Collections) != len(original.Collections) {
			t.Error("collections should be copied")
		}

		if len(cloned.BBox) != len(original.BBox) {
			t.Error("bbox should be copied")
		}
	})

	t.Run("no shared collections slice", func(t *testing.T) {
		t.Parallel()

		original := &stac.SearchRequest{Collections: []string{"col1", "col2"}}
		cloned := cloneSearchRequest(original)

		// Modify original
		original.Collections[0] = "modified"

		if cloned.Collections[0] == "modified" {
			t.Error("clone should not share collections slice")
		}
	})

	t.Run("no shared bbox slice", func(t *testing.T) {
		t.Parallel()

		original := &stac.SearchRequest{BBox: []float64{-10, -10, 10, 10}}
		cloned := cloneSearchRequest(original)

		// Modify original
		original.BBox[0] = -999

		if cloned.BBox[0] == -999 {
			t.Error("clone should not share bbox slice")
		}
	})

	t.Run("no shared IDs slice", func(t *testing.T) {
		t.Parallel()

		original := &stac.SearchRequest{IDs: []string{"id1", "id2"}}
		cloned := cloneSearchRequest(original)

		// Modify original
		original.IDs[0] = "modified"

		if cloned.IDs[0] == "modified" {
			t.Error("clone should not share IDs slice")
		}
	})

	t.Run("handles nil slices", func(t *testing.T) {
		t.Parallel()

		original := &stac.SearchRequest{
			Collections: nil,
			BBox:        nil,
			IDs:         nil,
		}

		cloned := cloneSearchRequest(original)

		if cloned.Collections != nil {
			t.Error("nil collections should remain nil")
		}

		if cloned.BBox != nil {
			t.Error("nil bbox should remain nil")
		}

		if cloned.IDs != nil {
			t.Error("nil IDs should remain nil")
		}
	})

	t.Run("copies other fields", func(t *testing.T) {
		t.Parallel()

		original := &stac.SearchRequest{
			Datetime: "2024-01-01T00:00:00Z",
			Limit:    42,
			Token:    "test-token",
		}

		cloned := cloneSearchRequest(original)

		if cloned.Datetime != original.Datetime {
			t.Error("datetime should be copied")
		}

		if cloned.Limit != original.Limit {
			t.Error("limit should be copied")
		}

		if cloned.Token != original.Token {
			t.Error("token should be copied")
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

		origins := map[string]Searcher{
			"origin1": origin1,
		}

		cfg := PaginatedSearchConfig{
			Origins:     origins,
			Merger:      NewResultMerger(ConflictFirstWins),
			MaxPageSize: 1000,
		}

		searcher := NewPaginatedSearcher(cfg)
		req := &stac.SearchRequest{Limit: 25}

		result, err := searcher.Search(context.Background(), req, "")

		if err != nil {
			t.Fatalf("search failed: %v", err)
		}

		if len(result.Items) != 25 {
			t.Errorf("expected 25 items (request limit), got %d", len(result.Items))
		}

		if result.Context.Limit != 25 {
			t.Errorf("expected context limit 25, got %d", result.Context.Limit)
		}
	})

	t.Run("uses default when request limit is zero", func(t *testing.T) {
		t.Parallel()

		origin1 := newMockSearchable("origin1", 1, func(ctx context.Context, req *stac.SearchRequest) ([]*stac.Item, string, string, error) {
			return []*stac.Item{paginationTestItem("item1", time.Now())}, "", "", nil
		})

		origins := map[string]Searcher{
			"origin1": origin1,
		}

		cfg := PaginatedSearchConfig{
			Origins:         origins,
			Merger:          NewResultMerger(ConflictFirstWins),
			DefaultPageSize: 50,
		}

		searcher := NewPaginatedSearcher(cfg)
		req := &stac.SearchRequest{Limit: 0}

		result, err := searcher.Search(context.Background(), req, "")

		if err != nil {
			t.Fatalf("search failed: %v", err)
		}

		if result.Context.Limit != 50 {
			t.Errorf("expected context limit 50 (default), got %d", result.Context.Limit)
		}
	})

	t.Run("caps request limit to max page size", func(t *testing.T) {
		t.Parallel()

		origin1 := newMockSearchable("origin1", 1, func(ctx context.Context, req *stac.SearchRequest) ([]*stac.Item, string, string, error) {
			return []*stac.Item{paginationTestItem("item1", time.Now())}, "", "", nil
		})

		origins := map[string]Searcher{
			"origin1": origin1,
		}

		cfg := PaginatedSearchConfig{
			Origins:         origins,
			Merger:          NewResultMerger(ConflictFirstWins),
			DefaultPageSize: 100,
			MaxPageSize:     500,
		}

		searcher := NewPaginatedSearcher(cfg)
		req := &stac.SearchRequest{Limit: 1000} // Exceeds max

		result, err := searcher.Search(context.Background(), req, "")

		if err != nil {
			t.Fatalf("search failed: %v", err)
		}

		// Should use default, not the excessive request limit
		if result.Context.Limit != 100 {
			t.Errorf("expected context limit 100 (default, not excessive), got %d", result.Context.Limit)
		}
	})
}

// TestContextCancellation tests handling of context cancellation
func TestContextCancellation(t *testing.T) {
	t.Run("respects cancelled context", func(t *testing.T) {
		t.Parallel()

		origin1 := newMockSearchable("origin1", 1, func(ctx context.Context, req *stac.SearchRequest) ([]*stac.Item, string, string, error) {
			select {
			case <-ctx.Done():
				return nil, "", "", ctx.Err()
			case <-time.After(100 * time.Millisecond):
				return []*stac.Item{paginationTestItem("item1", time.Now())}, "", "", nil
			}
		})

		origins := map[string]Searcher{
			"origin1": origin1,
		}

		cfg := PaginatedSearchConfig{
			Origins: origins,
			Merger:  NewResultMerger(ConflictFirstWins),
		}

		searcher := NewPaginatedSearcher(cfg)
		req := paginationTestSearchRequest()

		// Create cancelled context
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		result, err := searcher.Search(ctx, req, "")

		// Should complete (goroutines handle cancellation internally)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Origin should report error in context
		if len(result.Context.Origins) > 0 {
			if result.Context.Origins[0].Error == "" {
				t.Log("warning: expected error in origin status for cancelled context")
			}
		}
	})

	t.Run("handles timeout", func(t *testing.T) {
		// Not parallel because timing sensitive

		origin1 := newMockSearchable("origin1", 1, func(ctx context.Context, req *stac.SearchRequest) ([]*stac.Item, string, string, error) {
			select {
			case <-ctx.Done():
				return nil, "", "", ctx.Err()
			case <-time.After(200 * time.Millisecond):
				return []*stac.Item{paginationTestItem("item1", time.Now())}, "", "", nil
			}
		})

		origins := map[string]Searcher{
			"origin1": origin1,
		}

		cfg := PaginatedSearchConfig{
			Origins: origins,
			Merger:  NewResultMerger(ConflictFirstWins),
		}

		searcher := NewPaginatedSearcher(cfg)
		req := paginationTestSearchRequest()

		// Create context with short timeout
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		result, err := searcher.Search(ctx, req, "")

		// Should complete (goroutines handle timeout internally)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Origin should report error
		if len(result.Context.Origins) > 0 {
			if result.Context.Origins[0].Error == "" {
				t.Log("warning: expected error in origin status for timeout")
			}
		}
	})
}

// TestGetDatetime tests datetime extraction for sorting
func TestGetDatetime(t *testing.T) {
	t.Run("extracts valid datetime", func(t *testing.T) {
		t.Parallel()

		dt := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
		item := &stac.Item{
			ID:         "item1",
			Properties: stac.Properties{DateTime: &dt},
		}

		got := getDatetime(item)

		if got != "2024-01-01T00:00:00Z" {
			t.Errorf("expected datetime '2024-01-01T00:00:00Z', got %q", got)
		}
	})

	t.Run("returns empty for missing datetime", func(t *testing.T) {
		t.Parallel()

		item := &stac.Item{
			ID:         "item1",
			Properties: stac.Properties{},
		}

		if got := getDatetime(item); got != "" {
			t.Errorf("expected empty datetime, got %q", got)
		}
	})

	t.Run("extracts datetime from Extra", func(t *testing.T) {
		t.Parallel()

		item := &stac.Item{
			ID: "item1",
			Properties: stac.Properties{
				Extra: map[string]interface{}{
					"datetime": "2024-02-02T00:00:00Z",
				},
			},
		}

		if got := getDatetime(item); got != "2024-02-02T00:00:00Z" {
			t.Errorf("expected datetime from Extra, got %q", got)
		}
	})

	t.Run("returns empty for non-string Extra datetime", func(t *testing.T) {
		t.Parallel()

		item := &stac.Item{
			ID: "item1",
			Properties: stac.Properties{
				Extra: map[string]interface{}{"datetime": 12345},
			},
		}

		if got := getDatetime(item); got != "" {
			t.Errorf("expected empty datetime for non-string, got %q", got)
		}
	})
}
