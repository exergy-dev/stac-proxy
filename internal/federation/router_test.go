package federation

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper functions for creating test origins

func testOrigin(id string, opts ...func(*Origin)) *Origin {
	origin := &Origin{
		ID:         id,
		Name:       "Test Origin " + id,
		BaseURL:    "https://example.com/" + id,
		Enabled:    true,
		Searchable: true,
		Priority:   1,
		Timeout:    30 * time.Second,
	}
	for _, opt := range opts {
		opt(origin)
	}
	return origin
}

func routerWithCollections(collections ...string) func(*Origin) {
	return func(o *Origin) {
		o.Collections = collections
	}
}

func withPrefix(prefix string) func(*Origin) {
	return func(o *Origin) {
		o.CollectionPrefix = prefix
	}
}

func withSearchable(searchable bool) func(*Origin) {
	return func(o *Origin) {
		o.Searchable = searchable
	}
}

func withEnabled(enabled bool) func(*Origin) {
	return func(o *Origin) {
		o.Enabled = enabled
	}
}

func withExclude(collections ...string) func(*Origin) {
	return func(o *Origin) {
		o.ExcludeCollections = collections
	}
}

func withPriority(priority int) func(*Origin) {
	return func(o *Origin) {
		o.Priority = priority
	}
}

// Test NewCollectionRouter

func TestNewCollectionRouter(t *testing.T) {
	t.Parallel()

	t.Run("creates empty router", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		require.NotNil(t, router, "NewCollectionRouter returned nil")
		assert.NotNil(t, router.collectionToOrigins, "collectionToOrigins map is nil")
		assert.Empty(t, router.collectionToOrigins, "collectionToOrigins length")
		assert.Nil(t, router.allOrigins, "allOrigins should be uninitialized slice")
	})
}

// Test Register

func TestRegister(t *testing.T) {
	t.Parallel()

	t.Run("register searchable origin without collections", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin := testOrigin("origin-1", withSearchable(true))

		router.Register(origin)

		require.Len(t, router.allOrigins, 1, "allOrigins length")
		assert.Equal(t, "origin-1", router.allOrigins[0].ID, "allOrigins[0].ID")
		assert.Empty(t, router.collectionToOrigins, "collectionToOrigins length (no explicit collections)")
	})

	t.Run("register origin with explicit collections", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin := testOrigin("origin-1", routerWithCollections("coll-a", "coll-b", "coll-c"))

		router.Register(origin)

		assert.Len(t, router.allOrigins, 1, "allOrigins length")
		assert.Len(t, router.collectionToOrigins, 3, "collectionToOrigins length")

		// Verify each collection is mapped
		for _, coll := range []string{"coll-a", "coll-b", "coll-c"} {
			origins, ok := router.collectionToOrigins[coll]
			if !assert.Truef(t, ok, "collection %s not found in mapping", coll) {
				continue
			}
			if !assert.Lenf(t, origins, 1, "collection %s: origins length", coll) {
				continue
			}
			assert.Equalf(t, "origin-1", origins[0].ID, "collection %s: origin ID", coll)
		}
	})

	t.Run("register origin with collection prefix", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin := testOrigin("origin-1",
			routerWithCollections("coll-a", "coll-b"),
			withPrefix("prefix_"))

		router.Register(origin)

		// Collections should be registered with prefix
		assert.NotContains(t, router.collectionToOrigins, "coll-a", "collection coll-a should not exist without prefix")
		assert.Contains(t, router.collectionToOrigins, "prefix_coll-a", "collection prefix_coll-a not found")
		assert.Contains(t, router.collectionToOrigins, "prefix_coll-b", "collection prefix_coll-b not found")
	})

	t.Run("register multiple origins for same collection", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin1 := testOrigin("origin-1", routerWithCollections("shared-coll"))
		origin2 := testOrigin("origin-2", routerWithCollections("shared-coll"))

		router.Register(origin1)
		router.Register(origin2)

		assert.Len(t, router.allOrigins, 2, "allOrigins length")

		origins := router.collectionToOrigins["shared-coll"]
		assert.Len(t, origins, 2, "shared-coll origins length")

		foundOrigin1, foundOrigin2 := false, false
		for _, o := range origins {
			if o.ID == "origin-1" {
				foundOrigin1 = true
			}
			if o.ID == "origin-2" {
				foundOrigin2 = true
			}
		}
		assert.True(t, foundOrigin1 && foundOrigin2, "both origins should be registered for shared-coll")
	})

	t.Run("register non-searchable origin without collections", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin := testOrigin("origin-1",
			withSearchable(false),
			routerWithCollections())

		router.Register(origin)

		// Should not be added to allOrigins (not searchable and no collections)
		assert.Empty(t, router.allOrigins, "allOrigins should be empty (not searchable, no collections)")
	})

	t.Run("register non-searchable origin with collections", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin := testOrigin("origin-1",
			withSearchable(false),
			routerWithCollections("coll-a"))

		router.Register(origin)

		// Should be added to allOrigins (has collections)
		assert.Len(t, router.allOrigins, 1, "allOrigins length (has collections)")
		assert.Len(t, router.collectionToOrigins, 1, "collectionToOrigins length")
	})
}

// Test Route

func TestRoute(t *testing.T) {
	t.Parallel()

	t.Run("empty collection filter returns all searchable origins", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin1 := testOrigin("origin-1", withSearchable(true))
		origin2 := testOrigin("origin-2", withSearchable(true))
		origin3 := testOrigin("origin-3", withSearchable(false))

		router.Register(origin1)
		router.Register(origin2)
		router.Register(origin3)

		results := router.Route(nil)

		assert.Len(t, results, 2, "results length (only searchable origins)")

		foundOrigin1, foundOrigin2 := false, false
		for _, o := range results {
			if o.ID == "origin-1" {
				foundOrigin1 = true
			}
			if o.ID == "origin-2" {
				foundOrigin2 = true
			}
			assert.NotEqual(t, "origin-3", o.ID, "origin-3 should not be in results (not searchable)")
		}
		assert.True(t, foundOrigin1 && foundOrigin2, "both searchable origins should be in results")
	})

	t.Run("empty slice collection filter returns all searchable origins", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin1 := testOrigin("origin-1", withSearchable(true))
		origin2 := testOrigin("origin-2", withSearchable(true))

		router.Register(origin1)
		router.Register(origin2)

		results := router.Route([]string{})

		assert.Len(t, results, 2, "results length")
	})

	t.Run("route to origin with explicit collection", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin1 := testOrigin("origin-1", routerWithCollections("coll-a", "coll-b"))
		origin2 := testOrigin("origin-2", routerWithCollections("coll-c"))

		router.Register(origin1)
		router.Register(origin2)

		results := router.Route([]string{"coll-a"})

		require.Len(t, results, 1, "results length")
		assert.Equal(t, "origin-1", results[0].ID, "result origin ID")
	})

	t.Run("route to multiple origins with explicit collections", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin1 := testOrigin("origin-1", routerWithCollections("coll-a"))
		origin2 := testOrigin("origin-2", routerWithCollections("coll-b"))

		router.Register(origin1)
		router.Register(origin2)

		results := router.Route([]string{"coll-a", "coll-b"})

		assert.Len(t, results, 2, "results length")
	})

	t.Run("route to origin without explicit collections", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin1 := testOrigin("origin-1") // No explicit collections, searchable
		origin2 := testOrigin("origin-2", routerWithCollections("coll-a"))

		router.Register(origin1)
		router.Register(origin2)

		results := router.Route([]string{"unknown-collection"})

		// origin-1 should match (no explicit collection list, no exclusions)
		require.Len(t, results, 1, "results length")
		assert.Equal(t, "origin-1", results[0].ID, "result origin ID")
	})

	t.Run("disabled origins are filtered out", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin1 := testOrigin("origin-1", withEnabled(true), routerWithCollections("coll-a"))
		origin2 := testOrigin("origin-2", withEnabled(false), routerWithCollections("coll-a"))

		router.Register(origin1)
		router.Register(origin2)

		results := router.Route([]string{"coll-a"})

		require.Len(t, results, 1, "results length (only enabled origins)")
		assert.Equal(t, "origin-1", results[0].ID, "result origin ID")
	})

	t.Run("disabled origins filtered in empty collection query", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin1 := testOrigin("origin-1", withEnabled(true), withSearchable(true))
		origin2 := testOrigin("origin-2", withEnabled(false), withSearchable(true))

		router.Register(origin1)
		router.Register(origin2)

		results := router.Route(nil)

		require.Len(t, results, 1, "results length (disabled origin filtered)")
		assert.Equal(t, "origin-1", results[0].ID, "result origin ID")
	})

	t.Run("excluded collections are not routed", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin1 := testOrigin("origin-1",
			withExclude("coll-exclude"),
		) // No explicit collections

		router.Register(origin1)

		results := router.Route([]string{"coll-exclude"})

		assert.Empty(t, results, "results should be empty (collection excluded)")
	})

	t.Run("non-excluded collection routes correctly", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin1 := testOrigin("origin-1",
			withExclude("coll-exclude"),
		) // No explicit collections

		router.Register(origin1)

		results := router.Route([]string{"coll-allowed"})

		require.Len(t, results, 1, "results length")
		assert.Equal(t, "origin-1", results[0].ID, "result origin ID")
	})

	t.Run("collection with prefix routes correctly", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin1 := testOrigin("origin-1",
			routerWithCollections("coll-a"),
			withPrefix("prefix_"))

		router.Register(origin1)

		// Query without prefix should not match
		results := router.Route([]string{"coll-a"})
		assert.Empty(t, results, "results should be empty (query without prefix)")

		// Query with prefix should match
		results = router.Route([]string{"prefix_coll-a"})
		require.Len(t, results, 1, "results length (query with prefix)")
		assert.Equal(t, "origin-1", results[0].ID, "result origin ID")
	})

	t.Run("deduplicates origins in results", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin1 := testOrigin("origin-1", routerWithCollections("coll-a", "coll-b"))

		router.Register(origin1)

		// Query both collections that origin-1 serves
		results := router.Route([]string{"coll-a", "coll-b"})

		// Should only appear once in results
		require.Len(t, results, 1, "results length (origin should be deduplicated)")
		assert.Equal(t, "origin-1", results[0].ID, "result origin ID")
	})

	t.Run("mixed explicit and implicit collection routing", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin1 := testOrigin("origin-1", routerWithCollections("coll-a")) // Explicit
		origin2 := testOrigin("origin-2")                                  // Implicit (no collection list)

		router.Register(origin1)
		router.Register(origin2)

		results := router.Route([]string{"coll-a"})

		// Both should match: origin-1 explicitly, origin-2 implicitly
		assert.Len(t, results, 2, "results length")

		foundOrigin1, foundOrigin2 := false, false
		for _, o := range results {
			if o.ID == "origin-1" {
				foundOrigin1 = true
			}
			if o.ID == "origin-2" {
				foundOrigin2 = true
			}
		}
		assert.True(t, foundOrigin1 && foundOrigin2, "both origins should match coll-a")
	})

	t.Run("no matching origins returns empty slice", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin1 := testOrigin("origin-1", routerWithCollections("coll-a"))

		router.Register(origin1)

		results := router.Route([]string{"coll-nonexistent"})

		assert.Empty(t, results, "results length")
		assert.NotNil(t, results, "results should be empty slice, not nil")
	})

	t.Run("multiple collections same origin", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin1 := testOrigin("origin-1", routerWithCollections("coll-a", "coll-b"))
		origin2 := testOrigin("origin-2", routerWithCollections("coll-c"))

		router.Register(origin1)
		router.Register(origin2)

		results := router.Route([]string{"coll-a", "coll-c"})

		assert.Len(t, results, 2, "results length")
	})
}

// Test RouteCollection

func TestRouteCollection(t *testing.T) {
	t.Parallel()

	router := NewCollectionRouter()
	router.Register(testOrigin("origin-1", routerWithCollections("coll-a")))

	results := router.RouteCollection("coll-a")
	require.Len(t, results, 1, "results length")
	assert.Equal(t, "origin-1", results[0].ID, "result origin ID")
}

// Test UpdateFromDiscovery

func TestUpdateFromDiscovery(t *testing.T) {
	t.Parallel()

	t.Run("updates collections for existing origin", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin1 := testOrigin("origin-1", routerWithCollections("old-coll"))

		router.Register(origin1)

		// Verify initial state
		assert.Contains(t, router.collectionToOrigins, "old-coll", "old-coll should be registered initially")

		// Update with new collections
		router.UpdateFromDiscovery("origin-1", []string{"new-coll-a", "new-coll-b"})

		// Old collection should be removed
		assert.NotContains(t, router.collectionToOrigins, "old-coll", "old-coll should be removed after discovery update")

		// New collections should be added
		assert.Contains(t, router.collectionToOrigins, "new-coll-a", "new-coll-a should be registered after discovery")
		assert.Contains(t, router.collectionToOrigins, "new-coll-b", "new-coll-b should be registered after discovery")
	})

	t.Run("updates collections with prefix", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin1 := testOrigin("origin-1",
			routerWithCollections("old-coll"),
			withPrefix("prefix_"))

		router.Register(origin1)

		// Update with new collections (should apply prefix)
		router.UpdateFromDiscovery("origin-1", []string{"new-coll"})

		assert.NotContains(t, router.collectionToOrigins, "prefix_old-coll", "prefix_old-coll should be removed")
		assert.Contains(t, router.collectionToOrigins, "prefix_new-coll", "prefix_new-coll should be registered with prefix")
		assert.NotContains(t, router.collectionToOrigins, "new-coll", "new-coll should not be registered without prefix")
	})

	t.Run("does not affect other origins", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin1 := testOrigin("origin-1", routerWithCollections("coll-a", "shared-coll"))
		origin2 := testOrigin("origin-2", routerWithCollections("coll-b", "shared-coll"))

		router.Register(origin1)
		router.Register(origin2)

		// Update origin-1
		router.UpdateFromDiscovery("origin-1", []string{"new-coll"})

		// origin-2's collections should remain unchanged
		origins := router.collectionToOrigins["coll-b"]
		require.Len(t, origins, 1, "coll-b for origin-2 should remain unchanged")
		assert.Equal(t, "origin-2", origins[0].ID, "coll-b for origin-2 should remain unchanged")

		// shared-coll should still have origin-2
		origins = router.collectionToOrigins["shared-coll"]
		require.Len(t, origins, 1, "shared-coll should still have origin-2")
		assert.Equal(t, "origin-2", origins[0].ID, "shared-coll should still have origin-2")
	})

	t.Run("handles non-existent origin gracefully", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin1 := testOrigin("origin-1", routerWithCollections("coll-a"))

		router.Register(origin1)

		// Update non-existent origin
		router.UpdateFromDiscovery("non-existent", []string{"new-coll"})

		// Should not panic or modify anything
		assert.NotContains(t, router.collectionToOrigins, "new-coll", "new-coll should not be registered for non-existent origin")
		assert.Contains(t, router.collectionToOrigins, "coll-a", "coll-a should remain unchanged")
	})

	t.Run("handles empty collection list", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin1 := testOrigin("origin-1", routerWithCollections("coll-a", "coll-b"))

		router.Register(origin1)

		// Update with empty list
		router.UpdateFromDiscovery("origin-1", []string{})

		// Old collections should be removed
		assert.NotContains(t, router.collectionToOrigins, "coll-a", "coll-a should be removed")
		assert.NotContains(t, router.collectionToOrigins, "coll-b", "coll-b should be removed")
	})

	t.Run("removes origin from shared collection", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin1 := testOrigin("origin-1", routerWithCollections("shared-coll"))
		origin2 := testOrigin("origin-2", routerWithCollections("shared-coll"))

		router.Register(origin1)
		router.Register(origin2)

		// Both origins should be registered for shared-coll
		origins := router.collectionToOrigins["shared-coll"]
		assert.Len(t, origins, 2, "shared-coll should have 2 origins")

		// Update origin-1 to remove shared-coll
		router.UpdateFromDiscovery("origin-1", []string{"other-coll"})

		// shared-coll should now only have origin-2
		origins = router.collectionToOrigins["shared-coll"]
		require.Len(t, origins, 1, "shared-coll should have 1 origin")
		assert.Equal(t, "origin-2", origins[0].ID, "shared-coll should have origin-2")
	})

	t.Run("cleans up collection when last origin removed", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin1 := testOrigin("origin-1", routerWithCollections("coll-unique"))

		router.Register(origin1)

		// Update to remove coll-unique
		router.UpdateFromDiscovery("origin-1", []string{"other-coll"})

		// coll-unique should be removed from map entirely
		assert.NotContains(t, router.collectionToOrigins, "coll-unique", "coll-unique should be removed from map when no origins serve it")
	})
}

// Test GetCollectionOrigins

func TestGetCollectionOrigins(t *testing.T) {
	t.Parallel()

	t.Run("returns origins with explicit collection mapping", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin1 := testOrigin("origin-1", routerWithCollections("coll-a"))
		origin2 := testOrigin("origin-2", routerWithCollections("coll-a"))

		router.Register(origin1)
		router.Register(origin2)

		results := router.GetCollectionOrigins("coll-a")

		assert.Len(t, results, 2, "results length")
	})

	t.Run("filters disabled origins", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin1 := testOrigin("origin-1", withEnabled(true), routerWithCollections("coll-a"))
		origin2 := testOrigin("origin-2", withEnabled(false), routerWithCollections("coll-a"))

		router.Register(origin1)
		router.Register(origin2)

		results := router.GetCollectionOrigins("coll-a")

		require.Len(t, results, 1, "results length (disabled filtered)")
		assert.Equal(t, "origin-1", results[0].ID, "result origin ID")
	})

	t.Run("returns origins without explicit collections", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin1 := testOrigin("origin-1") // No explicit collections

		router.Register(origin1)

		results := router.GetCollectionOrigins("any-collection")

		require.Len(t, results, 1, "results length")
		assert.Equal(t, "origin-1", results[0].ID, "result origin ID")
	})

	t.Run("excludes excluded collections", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin1 := testOrigin("origin-1", withExclude("excluded-coll"))

		router.Register(origin1)

		results := router.GetCollectionOrigins("excluded-coll")

		assert.Empty(t, results, "results should be empty (collection excluded)")
	})

	t.Run("returns empty slice for non-existent collection", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin1 := testOrigin("origin-1", routerWithCollections("coll-a"))

		router.Register(origin1)

		results := router.GetCollectionOrigins("non-existent")

		assert.Empty(t, results, "results length")
		assert.NotNil(t, results, "results should be empty slice, not nil")
	})
}

// Test AllOrigins

// TestRouter_Accessors exercises AllOrigins / EnabledOrigins / OriginCount /
// CollectionCount in a single table-driven setup.
func TestRouter_Accessors(t *testing.T) {
	t.Parallel()

	router := NewCollectionRouter()
	router.Register(testOrigin("origin-1", withEnabled(true), routerWithCollections("coll-a", "coll-b")))
	router.Register(testOrigin("origin-2", withEnabled(false), routerWithCollections("coll-b", "coll-c")))
	router.Register(testOrigin("origin-3", withEnabled(true))) // implicit, no explicit collections

	assert.Len(t, router.AllOrigins(), 3, "AllOrigins includes disabled")
	assert.Equal(t, 3, router.OriginCount(), "OriginCount includes disabled")

	enabled := router.EnabledOrigins()
	assert.Len(t, enabled, 2, "EnabledOrigins filters disabled")
	for _, o := range enabled {
		assert.Truef(t, o.Enabled, "origin %s should be enabled", o.ID)
	}

	// coll-a (origin-1), coll-b (origin-1+origin-2 dedup'd), coll-c (origin-2) = 3 unique
	assert.Equal(t, 3, router.CollectionCount(), "CollectionCount counts unique explicit collections only")

	// AllOrigins returns a copy.
	r1 := router.AllOrigins()
	r2 := router.AllOrigins()
	r1[0] = nil
	assert.NotNil(t, r2[0], "AllOrigins should return a defensive copy")

	// Empty router edge.
	empty := NewCollectionRouter()
	assert.Empty(t, empty.AllOrigins())
	assert.Equal(t, 0, empty.OriginCount())
	assert.Equal(t, 0, empty.CollectionCount())
}

// Concurrency tests

func TestRouterConcurrency(t *testing.T) {
	t.Parallel()

	router := NewCollectionRouter()
	origin1 := testOrigin("origin-1", routerWithCollections("coll-a"))
	router.Register(origin1)

	done := make(chan bool)

	// Concurrent readers
	for i := 0; i < 5; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				_ = router.Route([]string{"coll-a"})
			}
			done <- true
		}()
	}

	// Concurrent writers
	for i := 0; i < 5; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				router.UpdateFromDiscovery("origin-1", []string{"coll-a", "coll-b"})
				router.UpdateFromDiscovery("origin-1", []string{"coll-a"})
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}

// Edge cases and complex scenarios

func TestRouterComplexScenarios(t *testing.T) {
	t.Parallel()

	t.Run("mixed prefixes and exclusions", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin1 := testOrigin("origin-1",
			routerWithCollections("coll-a"),
			withPrefix("o1_"))
		origin2 := testOrigin("origin-2",
			withExclude("o1_coll-a"),
		)

		router.Register(origin1)
		router.Register(origin2)

		// Query o1_coll-a
		results := router.Route([]string{"o1_coll-a"})

		// origin-1 matches (explicit), origin-2 excluded
		require.Len(t, results, 1, "results length")
		assert.Equal(t, "origin-1", results[0].ID, "result origin ID")
	})

	t.Run("priority does not affect routing decision", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin1 := testOrigin("origin-1", withPriority(10), routerWithCollections("coll-a"))
		origin2 := testOrigin("origin-2", withPriority(1), routerWithCollections("coll-a"))

		router.Register(origin1)
		router.Register(origin2)

		results := router.Route([]string{"coll-a"})

		// Both should be returned regardless of priority
		assert.Len(t, results, 2, "results length (priority doesn't filter)")
	})

	t.Run("searchable flag only affects empty collection queries", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin1 := testOrigin("origin-1",
			withSearchable(false),
			routerWithCollections("coll-a"))

		router.Register(origin1)

		// Should still route to explicit collection
		results := router.Route([]string{"coll-a"})
		assert.Len(t, results, 1, "results length (explicit collection)")

		// Should not appear in empty collection query
		results = router.Route(nil)
		assert.Empty(t, results, "results length (not searchable)")
	})

	t.Run("update discovery with same collections is idempotent", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin1 := testOrigin("origin-1", routerWithCollections("coll-a"))

		router.Register(origin1)

		// Update with same collections
		router.UpdateFromDiscovery("origin-1", []string{"coll-a"})

		origins := router.collectionToOrigins["coll-a"]
		require.Len(t, origins, 1, "coll-a origins length")
		assert.Equal(t, "origin-1", origins[0].ID, "origin ID")
	})

}

// TestRouter_PrecomputesImplicitAllOnce is the M-federation-4
// regression: Route() previously rescanned r.allOrigins for every
// queried collection (O(collections × allOrigins)). The implicit-all
// origin set is now cached on the router and only refreshed when
// Register/UpdateFromDiscovery actually mutates membership. We verify
// that 100 Route() calls do NOT trigger 100 recomputes — the hook
// fires once per Register and zero times per Route.
func TestRouter_PrecomputesImplicitAllOnce(t *testing.T) {
	t.Parallel()

	router := NewCollectionRouter()

	var recomputes int
	router.recomputeImplicitHook = func() { recomputes++ }

	// Two implicit-all origins (no Collections list) and one explicit.
	router.Register(testOrigin("implicit-1"))
	router.Register(testOrigin("implicit-2"))
	router.Register(testOrigin("explicit", routerWithCollections("c1", "c2")))

	priorRegisterRecomputes := recomputes
	require.GreaterOrEqualf(t, priorRegisterRecomputes, 3, "expected at least one recompute per Register; got %d", priorRegisterRecomputes)

	// Now slam Route() — none of these should trigger a recompute.
	for i := 0; i < 100; i++ {
		_ = router.Route([]string{"c1", "c2", "c-other"})
	}

	assert.Equalf(t, priorRegisterRecomputes, recomputes, "Route() triggered recomputes: prior=%d now=%d (expected stable)", priorRegisterRecomputes, recomputes)
}
