package federation

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	require.NoError(t, err, "NewPaginatedSearcher")
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

func (m *mockOriginClient) ID() string      { return m.id }
func (m *mockOriginClient) Priority() int   { return m.priority }
func (m *mockOriginClient) IsEnabled() bool { return m.enabled }

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

func (m *mockSearchableOrigin) BaseURL() string                                                  { return "https://" + m.originID + ".example.com" }
func (m *mockSearchableOrigin) ID() string                                                       { return m.originID }
func (m *mockSearchableOrigin) Priority() int                                                    { return m.originPri }
func (m *mockSearchableOrigin) IsEnabled() bool                                                  { return true }
func (m *mockSearchableOrigin) HasCollection(id string) bool                                     { return true }
func (m *mockSearchableOrigin) GetCollections(ctx context.Context) ([]*stac.Collection, error)  { return nil, nil }
func (m *mockSearchableOrigin) Origin() *Origin                                                  { return &Origin{ID: m.originID, Priority: m.originPri} }

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
		require.NoError(t, err, "NewPaginatedSearcher")

		assert.Equal(t, 100, searcher.pageSize, "expected default page size 100")
		assert.Equal(t, 1000, searcher.maxPageSize, "expected default max page size 1000")
	})

	t.Run("requires cursor secret", func(t *testing.T) {
		t.Parallel()

		cfg := PaginatedSearchConfig{
			Origins: make(map[string]Searcher),
			Merger:  NewResultMerger(ConflictFirstWins),
		}
		_, err := NewPaginatedSearcher(cfg)
		assert.Error(t, err, "expected error when CursorSecret is empty")
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
		assert.Equal(t, 50, searcher.pageSize, "pageSize")
		assert.Equal(t, 500, searcher.maxPageSize, "maxPageSize")
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
		assert.Equal(t, "https://origin1.example.com", searcher.originBaseURLs["origin1"], "origin1 base URL")
		assert.Equal(t, "https://origin2.example.com", searcher.originBaseURLs["origin2"], "origin2 base URL")
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
		require.NoError(t, err, "search failed")
		assert.Len(t, result.Items, 2, "expected 2 items")
		assert.Equal(t, 2, result.Context.Returned, "expected returned count 2")
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
		require.NoError(t, err, "search failed")
		assert.Len(t, result.Items, 2, "expected 2 items from 2 origins")
	})

	t.Run("no origins", func(t *testing.T) {
		t.Parallel()
		searcher := mustPaginatedSearcher(t, PaginatedSearchConfig{
			Origins: make(map[string]Searcher),
			Merger:  NewResultMerger(ConflictFirstWins),
		})
		result, err := searcher.Search(context.Background(), paginationTestSearchRequest(), "")
		require.NoError(t, err, "search failed")
		assert.Empty(t, result.Items, "expected 0 items")
		assert.Empty(t, result.NextCursor, "expected no next cursor")
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
		require.NoError(t, err, "search failed")
		assert.NotEmpty(t, result.NextCursor, "expected next cursor")
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
		require.NoError(t, err, "first search failed")
		require.NotEmpty(t, result1.NextCursor, "expected next cursor from first search")

		result2, err := searcher.Search(context.Background(), req, result1.NextCursor)
		require.NoError(t, err, "second search failed")
		assert.Len(t, result2.Items, 1, "expected 1 item in second page")
		assert.Empty(t, result2.NextCursor, "expected no next cursor when origin is exhausted")
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
		require.NoError(t, err, "first search failed")

		req2 := &stac.SearchRequest{Collections: []string{"collection2"}}
		_, err = searcher.Search(context.Background(), req2, result1.NextCursor)
		require.Error(t, err, "expected error when cursor doesn't match query")
		assert.ErrorContainsf(t, err, "cursor does not match search parameters", "expected cursor mismatch error, got: %v", err)
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
		_, err := searcher.Search(context.Background(), paginationTestSearchRequest(), "invalid-cursor!!!")
		require.Error(t, err, "expected error for invalid cursor")
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
		require.Error(t, err, "expected error for expired cursor")
		assert.ErrorIsf(t, err, ErrCursorExpired, "expected ErrCursorExpired, got: %v", err)
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
		assert.Len(t, results, 2, "expected 2 results")
		errorCount := 0
		for _, r := range results {
			if r.Error != nil {
				errorCount++
			}
		}
		assert.Equal(t, 1, errorCount, "expected 1 error result")
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
		assert.Equal(t, "test-token", receivedToken, "received token")
	})

	t.Run("handles missing origin", func(t *testing.T) {
		t.Parallel()
		searcher := mustPaginatedSearcher(t, PaginatedSearchConfig{
			Origins: make(map[string]Searcher),
			Merger:  NewResultMerger(ConflictFirstWins),
		})
		cursor := NewFederatedCursor("hash", "", []string{"missing-origin"}, nil)
		results := searcher.fetchFromOrigins(context.Background(), paginationTestSearchRequest(), cursor, []string{"missing-origin"}, 10)
		require.Len(t, results, 1, "expected one result")
		assert.NotNil(t, results[0].Error, "expected error for missing origin")
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
		assert.Equal(t, 20, receivedLimit, "expected limit 20")
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
		assert.Len(t, merged, 2, "expected 2 merged items")
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
		assert.Len(t, merged, 1, "expected 1 item after deduplication")
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
		require.Len(t, merged, 3, "merged length")
		assert.Equal(t, "item2", merged[0].ID, "merged[0]")
		assert.Equal(t, "item3", merged[1].ID, "merged[1]")
		assert.Equal(t, "item1", merged[2].ID, "merged[2]")
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
		assert.Len(t, merged, 2, "expected 2 items (limited)")
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
		assert.Equalf(t, "next-token", origin.NextToken, "unexpected origin state: %+v", origin)
		assert.Equalf(t, 1, origin.ItemCount, "unexpected origin state: %+v", origin)
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
		assert.True(t, cursor.GetOriginCursor("origin1").Error, "expected origin to be marked with error")
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
		assert.True(t, cursor.GetOriginCursor("origin1").Exhausted, "expected origin to be marked exhausted")
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
			require.Lenf(t, merged, 4, "iter %d: merged length", i)
			for j, id := range expectedIDs {
				assert.Equalf(t, id, merged[j].ID, "iter %d: merged[%d].ID", i, j)
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
		assert.Equal(t, hashSearchRequest(req1), hashSearchRequest(req2), "expected same hash for identical requests")
	})

	t.Run("collections affect hash", func(t *testing.T) {
		t.Parallel()
		assert.NotEqual(t,
			hashSearchRequest(&stac.SearchRequest{Collections: []string{"a"}}),
			hashSearchRequest(&stac.SearchRequest{Collections: []string{"b"}}),
			"expected different hashes")
	})

	t.Run("order of collections matters", func(t *testing.T) {
		t.Parallel()
		req1 := &stac.SearchRequest{Collections: []string{"col1", "col2"}}
		req2 := &stac.SearchRequest{Collections: []string{"col2", "col1"}}
		assert.NotEqual(t, hashSearchRequest(req1), hashSearchRequest(req2), "expected different hashes for different collection orders")
	})

	t.Run("bbox affects hash", func(t *testing.T) {
		t.Parallel()
		assert.NotEqual(t,
			hashSearchRequest(&stac.SearchRequest{BBox: []float64{-10, -10, 10, 10}}),
			hashSearchRequest(&stac.SearchRequest{BBox: []float64{-20, -20, 20, 20}}),
			"expected different hashes for different bboxes")
	})

	t.Run("datetime affects hash", func(t *testing.T) {
		t.Parallel()
		assert.NotEqual(t,
			hashSearchRequest(&stac.SearchRequest{Datetime: "a"}),
			hashSearchRequest(&stac.SearchRequest{Datetime: "b"}),
			"expected different hashes for different datetimes")
	})
}

// TestHashSearchRequest_LimitChangeInvalidatesCursor verifies that
// changing Limit changes the hash, so a cursor issued for one page size
// can't be replayed at a different limit.
func TestHashSearchRequest_LimitChangeInvalidatesCursor(t *testing.T) {
	t.Parallel()
	req1 := &stac.SearchRequest{Collections: []string{"c1"}, Limit: 10}
	req2 := &stac.SearchRequest{Collections: []string{"c1"}, Limit: 20}
	assert.NotEqual(t, hashSearchRequest(req1), hashSearchRequest(req2), "limit must affect hash")
}

// TestHashSearchRequest_IDsChangeInvalidates verifies that changing IDs
// changes the hash.
func TestHashSearchRequest_IDsChangeInvalidates(t *testing.T) {
	t.Parallel()
	req1 := &stac.SearchRequest{IDs: []string{"a", "b"}}
	req2 := &stac.SearchRequest{IDs: []string{"a", "c"}}
	assert.NotEqual(t, hashSearchRequest(req1), hashSearchRequest(req2), "IDs must affect hash")
}

// TestHashSearchRequest_FullDigest verifies the hash is the full 64-char sha256.
func TestHashSearchRequest_FullDigest(t *testing.T) {
	t.Parallel()
	hash := hashSearchRequest(paginationTestSearchRequest())
	require.Lenf(t, hash, 64, "expected hash length 64, got %d (%q)", len(hash), hash)
	for _, c := range hash {
		assert.Truef(t, (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'), "hash contains non-hex character: %c", c)
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
	assert.Equal(t, h, hashSearchRequest(&withCursor), "Cursor must not affect hash")
	assert.Equal(t, h, hashSearchRequest(&withToken), "Token must not affect hash")
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
		assert.NotSame(t, original, cloned, "clone should be a different object")
		assert.Equal(t, original.Limit, cloned.Limit, "Limit not copied")
		assert.Len(t, cloned.Collections, 2, "Collections not copied")
		assert.Len(t, cloned.BBox, 4, "BBox not copied")
	})

	t.Run("no shared slices", func(t *testing.T) {
		t.Parallel()
		original := &stac.SearchRequest{Collections: []string{"col1"}, BBox: []float64{1}, IDs: []string{"id1"}}
		cloned := cloneSearchRequest(original)
		original.Collections[0] = "x"
		original.BBox[0] = -999
		original.IDs[0] = "y"
		assert.NotEqual(t, "x", cloned.Collections[0], "clone shares Collections slice with original")
		assert.NotEqual(t, float64(-999), cloned.BBox[0], "clone shares BBox slice with original")
		assert.NotEqual(t, "y", cloned.IDs[0], "clone shares IDs slice with original")
	})

	t.Run("handles nil slices", func(t *testing.T) {
		t.Parallel()
		original := &stac.SearchRequest{}
		cloned := cloneSearchRequest(original)
		assert.Nil(t, cloned.Collections, "nil Collections should remain nil")
		assert.Nil(t, cloned.BBox, "nil BBox should remain nil")
		assert.Nil(t, cloned.IDs, "nil IDs should remain nil")
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
		require.NoError(t, err, "search failed")
		assert.Len(t, result.Items, 25, "items count")
		assert.Equal(t, 25, result.Context.Limit, "limit")
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
		require.NoError(t, err, "search failed")
		assert.Equal(t, 50, result.Context.Limit, "expected limit 50")
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
		require.NoError(t, err, "search failed")
		assert.Equal(t, 100, result.Context.Limit, "expected default 100")
	})
}

// TestGetDatetime tests datetime extraction for sorting
func TestGetDatetime(t *testing.T) {
	t.Run("extracts valid datetime", func(t *testing.T) {
		t.Parallel()
		item := &stac.Item{Properties: map[string]any{"datetime": "2024-01-01T00:00:00Z"}}
		assert.Equal(t, "2024-01-01T00:00:00Z", getDatetime(item))
	})

	t.Run("extracts string-form datetime", func(t *testing.T) {
		t.Parallel()
		item := &stac.Item{Properties: map[string]any{"datetime": "2024-02-02T00:00:00Z"}}
		assert.Equal(t, "2024-02-02T00:00:00Z", getDatetime(item))
	})

	t.Run("empty for missing", func(t *testing.T) {
		t.Parallel()
		item := &stac.Item{Properties: map[string]any{}}
		assert.Empty(t, getDatetime(item), "expected empty")
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
		assert.Lenf(t, o.items, itemsPerSearch, "set %s: cross-pollination of dedup state suspected", o.set)
		wantPrefix := "set-" + o.set + "-"
		for _, it := range o.items {
			assert.Truef(t, len(it.ID) >= len(wantPrefix) && it.ID[:len(wantPrefix)] == wantPrefix, "set %s: got item with foreign ID %q", o.set, it.ID)
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
	require.NoError(t, err, "pagecache.New")

	searcher := mustPaginatedSearcher(t, PaginatedSearchConfig{
		Origins:   map[string]Searcher{"origin1": origin},
		Merger:    NewResultMerger(ConflictFirstWins),
		PageCache: pc,
	})

	req := &stac.SearchRequest{Limit: 1}

	// Page 0: no incoming cursor, no `prev`/`first`/`self` links.
	r0, err := searcher.Search(context.Background(), req, "")
	require.NoError(t, err, "page 0")
	require.NotEmpty(t, r0.NextCursor, "page 0: NextCursor empty; expected continuation")
	assert.Empty(t, r0.PrevCursor, "page 0: prev should be empty on first page")
	assert.Empty(t, r0.FirstCursor, "page 0: first should be empty on first page")
	assert.Empty(t, r0.SelfCursor, "page 0: self should be empty on first page")

	// Page 1: follow `next` from page 0. self == page 0's next-cursor
	// (which is the cursor we're consuming now), prev/first should
	// reflect page 0's empty cursor (no prev/first to navigate to).
	r1, err := searcher.Search(context.Background(), req, r0.NextCursor)
	require.NoError(t, err, "page 1")
	assert.Equal(t, r0.NextCursor, r1.SelfCursor, "page 1: SelfCursor")
	assert.Empty(t, r1.PrevCursor, "page 1: PrevCursor (page 0 had no cursor)")
	require.NotEmpty(t, r1.NextCursor, "page 1: NextCursor empty; expected continuation to page 2")

	// Page 2: follow next from page 1. Now prev should point at page 1's cursor.
	r2, err := searcher.Search(context.Background(), req, r1.NextCursor)
	require.NoError(t, err, "page 2")
	assert.Equal(t, r1.NextCursor, r2.SelfCursor, "page 2: SelfCursor")
	assert.Equal(t, r0.NextCursor, r2.PrevCursor, "page 2: PrevCursor should be page 1's cursor")

	callsBeforePrev := callCount

	// Follow `prev` from page 2 → should hit the page cache and
	// return page 1's items WITHOUT calling the upstream again.
	rPrev, err := searcher.Search(context.Background(), req, r2.PrevCursor)
	require.NoError(t, err, "prev follow")
	require.Lenf(t, rPrev.Items, 1, "prev follow: items = %v, want [item-2] (page 1)", itemIDs(rPrev.Items))
	assert.Equalf(t, "item-2", rPrev.Items[0].ID, "prev follow: items = %v, want [item-2] (page 1)", itemIDs(rPrev.Items))
	assert.Equalf(t, callsBeforePrev, callCount, "prev follow: upstream was called %d times after lookup; want cache hit", callCount-callsBeforePrev)
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
