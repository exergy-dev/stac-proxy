package federation

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/exergy-dev/stac-proxy/internal/federation/pagecache"
	"github.com/exergy-dev/stac-proxy/internal/stac"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPageCache_SkipsDegradedPages: a page rendered while any origin
// was failing must NOT be stored — the cache fast path returns hits
// before any refetch, so a cached failure page would replay for its
// whole TTL and brick the session even after the origins recover.
func TestPageCache_SkipsDegradedPages(t *testing.T) {
	t.Parallel()

	now := time.Now()
	healthy := newMockSearchable("healthy", 1, func(_ context.Context, req *stac.SearchRequest) ([]*stac.Item, string, string, error) {
		// Two pages: token "" -> item-1 + next token; token "p2" -> item-2, done.
		if req.Token == "p2" {
			return []*stac.Item{paginationTestItem("item-2", now.Add(-2*time.Hour))}, "", "", nil
		}
		return []*stac.Item{paginationTestItem("item-1", now.Add(-1*time.Hour))}, "p2", "", nil
	})
	flaky := newMockSearchable("flaky", 2, func(_ context.Context, _ *stac.SearchRequest) ([]*stac.Item, string, string, error) {
		return nil, "", "", errors.New("origin down")
	})

	store := newPageCacheTestStore()
	pc, err := pagecache.New(store, time.Hour, paginationTestSecret)
	require.NoError(t, err)

	searcher := mustPaginatedSearcher(t, PaginatedSearchConfig{
		Origins:   map[string]Searcher{"healthy": healthy, "flaky": flaky},
		Merger:    NewResultMerger(),
		PageCache: pc,
	})

	req := &stac.SearchRequest{Limit: 1}
	r0, err := searcher.Search(context.Background(), req, "")
	require.NoError(t, err, "page 0")
	require.NotEmpty(t, r0.NextCursor)

	// Page 1: rendered while `flaky` is erroring → must not be cached.
	r1, err := searcher.Search(context.Background(), req, r0.NextCursor)
	require.NoError(t, err, "page 1")
	hasErr := false
	for _, st := range r1.Context.Origins {
		if st.Error != "" {
			hasErr = true
		}
	}
	require.True(t, hasErr, "test setup: page 1 must be degraded")

	_, cached := pc.Get(context.Background(), pagecache.SignatureOf(r0.NextCursor), "")
	assert.False(t, cached, "degraded page must not be stored in the page cache")
}

// TestPageCache_StoresHealthyPages is the positive control for the
// skip-degraded rule.
func TestPageCache_StoresHealthyPages(t *testing.T) {
	t.Parallel()

	now := time.Now()
	healthy := newMockSearchable("healthy", 1, func(_ context.Context, req *stac.SearchRequest) ([]*stac.Item, string, string, error) {
		switch req.Token {
		case "p2":
			return []*stac.Item{paginationTestItem("item-2", now.Add(-2*time.Hour))}, "p3", "", nil
		case "p3":
			return []*stac.Item{paginationTestItem("item-3", now.Add(-3*time.Hour))}, "", "", nil
		default:
			return []*stac.Item{paginationTestItem("item-1", now.Add(-1*time.Hour))}, "p2", "", nil
		}
	})

	store := newPageCacheTestStore()
	pc, err := pagecache.New(store, time.Hour, paginationTestSecret)
	require.NoError(t, err)
	searcher := mustPaginatedSearcher(t, PaginatedSearchConfig{
		Origins:   map[string]Searcher{"healthy": healthy},
		Merger:    NewResultMerger(),
		PageCache: pc,
	})

	req := &stac.SearchRequest{Limit: 1}
	r0, err := searcher.Search(context.Background(), req, "")
	require.NoError(t, err)
	_, err = searcher.Search(context.Background(), req, r0.NextCursor)
	require.NoError(t, err)

	_, cached := pc.Get(context.Background(), pagecache.SignatureOf(r0.NextCursor), "")
	assert.True(t, cached, "healthy page must be stored in the page cache")
}

// TestRetiredOriginStashStillMerges: when an origin exhausts its
// retry budget mid-session, items already fetched into its stash must
// still be emitted — they cost nothing to serve and dropping them is
// silent data loss.
func TestRetiredOriginStashStillMerges(t *testing.T) {
	t.Parallel()

	cursor := NewFederatedCursor("qh", "", []string{"gone"}, nil)
	oc := cursor.GetOriginCursor("gone")
	oc.Stash = []*stac.Item{paginationTestItem("stashed-1", time.Now())}
	for i := 0; i < maxOriginErrorRetries; i++ {
		cursor.MarkError("gone")
	}
	require.True(t, oc.retired(), "test setup: origin must be retired")

	assert.Contains(t, cursor.ActiveOrigins(), "gone",
		"retired origin with a stash must stay active for the merge phase")
	assert.True(t, cursor.HasMore(),
		"stashed items must keep the session alive until drained")

	oc.Stash = nil
	assert.NotContains(t, cursor.ActiveOrigins(), "gone",
		"retired origin with an empty stash must drop out")
	assert.False(t, cursor.HasMore(),
		"drained retired origin must end the session")
}

// TestHealthClientBypassesBreaker: readiness probes must observe the
// origin, not the breaker — an open circuit failing the probe would
// drain every replica at the load balancer during any origin outage.
func TestHealthClientBypassesBreaker(t *testing.T) {
	t.Parallel()

	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Error(w, "down", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	client, err := NewOriginClientWithContext(context.Background(), nil, &Origin{
		ID:      "o1",
		BaseURL: srv.URL,
		Enabled: true,
		Timeout: 2 * time.Second,
		CircuitBreaker: &BreakerPolicy{
			FailureThreshold: 1,
			OpenDuration:     time.Hour,
			MaxOpenDuration:  time.Hour,
		},
	})
	require.NoError(t, err)

	// One failure opens the circuit (threshold 1)...
	resp, err := client.HTTPClient().Get(srv.URL + "/search")
	require.NoError(t, err)
	resp.Body.Close()
	// ...so the traffic client now fast-fails without dialing.
	before := hits.Load()
	_, err = client.HTTPClient().Get(srv.URL + "/search")
	require.Error(t, err, "traffic must fast-fail while open")
	assert.Equal(t, before, hits.Load(), "open circuit must not dial")

	// The health client still reaches the network.
	resp, err = client.HealthClient().Get(srv.URL + "/")
	require.NoError(t, err, "health probe must bypass the breaker")
	resp.Body.Close()
	assert.Equal(t, before+1, hits.Load(), "health probe must observe the real origin")
}
