package federation

import (
	"fmt"
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

	t.Run("routes single collection", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin1 := testOrigin("origin-1", routerWithCollections("coll-a"))

		router.Register(origin1)

		results := router.RouteCollection("coll-a")

		require.Len(t, results, 1, "results length")
		assert.Equal(t, "origin-1", results[0].ID, "result origin ID")
	})

	t.Run("is equivalent to Route with single collection", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin1 := testOrigin("origin-1", routerWithCollections("coll-a", "coll-b"))
		origin2 := testOrigin("origin-2", routerWithCollections("coll-a"))

		router.Register(origin1)
		router.Register(origin2)

		results1 := router.RouteCollection("coll-a")
		results2 := router.Route([]string{"coll-a"})

		assert.Equalf(t, len(results2), len(results1), "RouteCollection vs Route origin count")
	})
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

func TestAllOrigins(t *testing.T) {
	t.Parallel()

	t.Run("returns all registered origins", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin1 := testOrigin("origin-1")
		origin2 := testOrigin("origin-2")
		origin3 := testOrigin("origin-3")

		router.Register(origin1)
		router.Register(origin2)
		router.Register(origin3)

		results := router.AllOrigins()

		assert.Len(t, results, 3, "results length")
	})

	t.Run("returns copy of origins", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin1 := testOrigin("origin-1")

		router.Register(origin1)

		results1 := router.AllOrigins()
		results2 := router.AllOrigins()

		// Modifying results1 should not affect results2
		if len(results1) > 0 {
			results1[0] = nil
		}
		assert.NotNil(t, results2[0], "results2 should not be affected by modifications to results1")
	})

	t.Run("returns empty slice for no origins", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()

		results := router.AllOrigins()

		assert.Empty(t, results, "results length")
	})

	t.Run("includes disabled origins", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin1 := testOrigin("origin-1", withEnabled(true))
		origin2 := testOrigin("origin-2", withEnabled(false))

		router.Register(origin1)
		router.Register(origin2)

		results := router.AllOrigins()

		assert.Len(t, results, 2, "results length (includes disabled)")
	})
}

// Test EnabledOrigins

func TestEnabledOrigins(t *testing.T) {
	t.Parallel()

	t.Run("returns only enabled origins", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin1 := testOrigin("origin-1", withEnabled(true))
		origin2 := testOrigin("origin-2", withEnabled(false))
		origin3 := testOrigin("origin-3", withEnabled(true))

		router.Register(origin1)
		router.Register(origin2)
		router.Register(origin3)

		results := router.EnabledOrigins()

		assert.Len(t, results, 2, "results length (only enabled)")

		for _, o := range results {
			assert.Truef(t, o.Enabled, "origin %s is disabled but in enabled origins list", o.ID)
		}
	})

	t.Run("returns empty slice when no enabled origins", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin1 := testOrigin("origin-1", withEnabled(false))

		router.Register(origin1)

		results := router.EnabledOrigins()

		assert.Empty(t, results, "results length")
		assert.NotNil(t, results, "results should be empty slice, not nil")
	})
}

// Test OriginCount

func TestOriginCount(t *testing.T) {
	t.Parallel()

	t.Run("returns correct count", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin1 := testOrigin("origin-1")
		origin2 := testOrigin("origin-2")

		assert.Equal(t, 0, router.OriginCount(), "initial count")

		router.Register(origin1)
		assert.Equal(t, 1, router.OriginCount(), "count after 1 registration")

		router.Register(origin2)
		assert.Equal(t, 2, router.OriginCount(), "count after 2 registrations")
	})

	t.Run("includes disabled origins", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin1 := testOrigin("origin-1", withEnabled(true))
		origin2 := testOrigin("origin-2", withEnabled(false))

		router.Register(origin1)
		router.Register(origin2)

		assert.Equal(t, 2, router.OriginCount(), "count (includes disabled)")
	})
}

// Test CollectionCount

func TestCollectionCount(t *testing.T) {
	t.Parallel()

	t.Run("returns correct count", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()

		assert.Equal(t, 0, router.CollectionCount(), "initial count")

		origin1 := testOrigin("origin-1", routerWithCollections("coll-a", "coll-b"))
		router.Register(origin1)

		assert.Equal(t, 2, router.CollectionCount(), "count after registering 2 collections")

		origin2 := testOrigin("origin-2", routerWithCollections("coll-c"))
		router.Register(origin2)

		assert.Equal(t, 3, router.CollectionCount(), "count after registering 1 more collection")
	})

	t.Run("does not count origins without explicit collections", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin1 := testOrigin("origin-1") // No explicit collections

		router.Register(origin1)

		assert.Equal(t, 0, router.CollectionCount(), "count (no explicit collections)")
	})

	t.Run("does not double-count shared collections", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin1 := testOrigin("origin-1", routerWithCollections("shared-coll"))
		origin2 := testOrigin("origin-2", routerWithCollections("shared-coll"))

		router.Register(origin1)
		router.Register(origin2)

		assert.Equal(t, 1, router.CollectionCount(), "count (shared collection counted once)")
	})
}

// Test isExcluded (internal method, tested via Route)

func TestIsExcluded(t *testing.T) {
	t.Parallel()

	t.Run("returns true for excluded collection", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin := testOrigin("origin-1", withExclude("excluded-a", "excluded-b"))

		assert.True(t, router.isExcluded(origin, "excluded-a"), "excluded-a should be excluded")
		assert.True(t, router.isExcluded(origin, "excluded-b"), "excluded-b should be excluded")
	})

	t.Run("returns false for non-excluded collection", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin := testOrigin("origin-1", withExclude("excluded-a"))

		assert.False(t, router.isExcluded(origin, "allowed-coll"), "allowed-coll should not be excluded")
	})

	t.Run("returns false when no exclusions", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin := testOrigin("origin-1")

		assert.False(t, router.isExcluded(origin, "any-coll"), "any-coll should not be excluded when no exclusions defined")
	})
}

// Concurrency tests

func TestRouterConcurrency(t *testing.T) {
	t.Parallel()

	t.Run("concurrent reads are safe", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin1 := testOrigin("origin-1", routerWithCollections("coll-a"))
		origin2 := testOrigin("origin-2", routerWithCollections("coll-b"))

		router.Register(origin1)
		router.Register(origin2)

		// Start multiple concurrent readers
		done := make(chan bool)
		for i := 0; i < 10; i++ {
			go func() {
				_ = router.Route([]string{"coll-a"})
				_ = router.AllOrigins()
				_ = router.EnabledOrigins()
				_ = router.OriginCount()
				_ = router.CollectionCount()
				done <- true
			}()
		}

		// Wait for all readers
		for i := 0; i < 10; i++ {
			<-done
		}
	})

	t.Run("concurrent writes are safe", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()

		// Start multiple concurrent writers
		done := make(chan bool)
		for i := 0; i < 10; i++ {
			id := i
			go func() {
				origin := testOrigin("origin-"+string(rune('0'+id)), routerWithCollections("coll-a"))
				router.Register(origin)
				done <- true
			}()
		}

		// Wait for all writers
		for i := 0; i < 10; i++ {
			<-done
		}

		// Verify all origins were registered
		assert.Equal(t, 10, router.OriginCount(), "origin count")
	})

	t.Run("concurrent reads and writes are safe", func(t *testing.T) {
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
	})
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

	t.Run("large number of collections", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()

		// Create origin with 1000 unique collections.
		collections := make([]string, 1000)
		for i := 0; i < 1000; i++ {
			collections[i] = fmt.Sprintf("coll-%03d", i)
		}

		origin1 := testOrigin("origin-1", routerWithCollections(collections...))
		router.Register(origin1)

		assert.Equal(t, 1000, router.CollectionCount(), "collection count")

		// Route to one of them
		results := router.Route([]string{"coll-000"})
		assert.Len(t, results, 1, "results length")
	})

	t.Run("large number of origins", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()

		// Register 100 origins
		for i := 0; i < 100; i++ {
			origin := testOrigin("origin-"+string(rune('0'+i%10))+string(rune('0'+(i/10)%10)), withSearchable(true))
			router.Register(origin)
		}

		assert.Equal(t, 100, router.OriginCount(), "origin count")

		results := router.Route(nil)
		assert.Len(t, results, 100, "results length (all searchable)")
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
