package federation

import (
	"fmt"
	"testing"
	"time"
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
		if router == nil {
			t.Fatal("NewCollectionRouter returned nil")
		}
		if router.collectionToOrigins == nil {
			t.Error("collectionToOrigins map is nil")
		}
		if len(router.collectionToOrigins) != 0 {
			t.Errorf("collectionToOrigins length = %d, want 0", len(router.collectionToOrigins))
		}
		if router.allOrigins != nil {
			t.Errorf("allOrigins = %v, want nil (uninitialized slice)", router.allOrigins)
		}
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

		if len(router.allOrigins) != 1 {
			t.Errorf("allOrigins length = %d, want 1", len(router.allOrigins))
		}
		if router.allOrigins[0].ID != "origin-1" {
			t.Errorf("allOrigins[0].ID = %s, want origin-1", router.allOrigins[0].ID)
		}
		if len(router.collectionToOrigins) != 0 {
			t.Errorf("collectionToOrigins length = %d, want 0 (no explicit collections)", len(router.collectionToOrigins))
		}
	})

	t.Run("register origin with explicit collections", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin := testOrigin("origin-1", routerWithCollections("coll-a", "coll-b", "coll-c"))

		router.Register(origin)

		if len(router.allOrigins) != 1 {
			t.Errorf("allOrigins length = %d, want 1", len(router.allOrigins))
		}
		if len(router.collectionToOrigins) != 3 {
			t.Errorf("collectionToOrigins length = %d, want 3", len(router.collectionToOrigins))
		}

		// Verify each collection is mapped
		for _, coll := range []string{"coll-a", "coll-b", "coll-c"} {
			origins, ok := router.collectionToOrigins[coll]
			if !ok {
				t.Errorf("collection %s not found in mapping", coll)
				continue
			}
			if len(origins) != 1 {
				t.Errorf("collection %s: origins length = %d, want 1", coll, len(origins))
				continue
			}
			if origins[0].ID != "origin-1" {
				t.Errorf("collection %s: origin ID = %s, want origin-1", coll, origins[0].ID)
			}
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
		if _, ok := router.collectionToOrigins["coll-a"]; ok {
			t.Error("collection coll-a should not exist without prefix")
		}
		if _, ok := router.collectionToOrigins["prefix_coll-a"]; !ok {
			t.Error("collection prefix_coll-a not found")
		}
		if _, ok := router.collectionToOrigins["prefix_coll-b"]; !ok {
			t.Error("collection prefix_coll-b not found")
		}
	})

	t.Run("register multiple origins for same collection", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin1 := testOrigin("origin-1", routerWithCollections("shared-coll"))
		origin2 := testOrigin("origin-2", routerWithCollections("shared-coll"))

		router.Register(origin1)
		router.Register(origin2)

		if len(router.allOrigins) != 2 {
			t.Errorf("allOrigins length = %d, want 2", len(router.allOrigins))
		}

		origins := router.collectionToOrigins["shared-coll"]
		if len(origins) != 2 {
			t.Errorf("shared-coll origins length = %d, want 2", len(origins))
		}

		foundOrigin1, foundOrigin2 := false, false
		for _, o := range origins {
			if o.ID == "origin-1" {
				foundOrigin1 = true
			}
			if o.ID == "origin-2" {
				foundOrigin2 = true
			}
		}
		if !foundOrigin1 || !foundOrigin2 {
			t.Error("both origins should be registered for shared-coll")
		}
	})

	t.Run("register non-searchable origin without collections", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin := testOrigin("origin-1",
			withSearchable(false),
			routerWithCollections())

		router.Register(origin)

		// Should not be added to allOrigins (not searchable and no collections)
		if len(router.allOrigins) != 0 {
			t.Errorf("allOrigins length = %d, want 0 (not searchable, no collections)", len(router.allOrigins))
		}
	})

	t.Run("register non-searchable origin with collections", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin := testOrigin("origin-1",
			withSearchable(false),
			routerWithCollections("coll-a"))

		router.Register(origin)

		// Should be added to allOrigins (has collections)
		if len(router.allOrigins) != 1 {
			t.Errorf("allOrigins length = %d, want 1 (has collections)", len(router.allOrigins))
		}
		if len(router.collectionToOrigins) != 1 {
			t.Errorf("collectionToOrigins length = %d, want 1", len(router.collectionToOrigins))
		}
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

		if len(results) != 2 {
			t.Errorf("results length = %d, want 2 (only searchable origins)", len(results))
		}

		foundOrigin1, foundOrigin2 := false, false
		for _, o := range results {
			if o.ID == "origin-1" {
				foundOrigin1 = true
			}
			if o.ID == "origin-2" {
				foundOrigin2 = true
			}
			if o.ID == "origin-3" {
				t.Error("origin-3 should not be in results (not searchable)")
			}
		}
		if !foundOrigin1 || !foundOrigin2 {
			t.Error("both searchable origins should be in results")
		}
	})

	t.Run("empty slice collection filter returns all searchable origins", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin1 := testOrigin("origin-1", withSearchable(true))
		origin2 := testOrigin("origin-2", withSearchable(true))

		router.Register(origin1)
		router.Register(origin2)

		results := router.Route([]string{})

		if len(results) != 2 {
			t.Errorf("results length = %d, want 2", len(results))
		}
	})

	t.Run("route to origin with explicit collection", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin1 := testOrigin("origin-1", routerWithCollections("coll-a", "coll-b"))
		origin2 := testOrigin("origin-2", routerWithCollections("coll-c"))

		router.Register(origin1)
		router.Register(origin2)

		results := router.Route([]string{"coll-a"})

		if len(results) != 1 {
			t.Errorf("results length = %d, want 1", len(results))
		}
		if results[0].ID != "origin-1" {
			t.Errorf("result origin ID = %s, want origin-1", results[0].ID)
		}
	})

	t.Run("route to multiple origins with explicit collections", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin1 := testOrigin("origin-1", routerWithCollections("coll-a"))
		origin2 := testOrigin("origin-2", routerWithCollections("coll-b"))

		router.Register(origin1)
		router.Register(origin2)

		results := router.Route([]string{"coll-a", "coll-b"})

		if len(results) != 2 {
			t.Errorf("results length = %d, want 2", len(results))
		}
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
		if len(results) != 1 {
			t.Errorf("results length = %d, want 1", len(results))
		}
		if results[0].ID != "origin-1" {
			t.Errorf("result origin ID = %s, want origin-1", results[0].ID)
		}
	})

	t.Run("disabled origins are filtered out", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin1 := testOrigin("origin-1", withEnabled(true), routerWithCollections("coll-a"))
		origin2 := testOrigin("origin-2", withEnabled(false), routerWithCollections("coll-a"))

		router.Register(origin1)
		router.Register(origin2)

		results := router.Route([]string{"coll-a"})

		if len(results) != 1 {
			t.Errorf("results length = %d, want 1 (only enabled origins)", len(results))
		}
		if results[0].ID != "origin-1" {
			t.Errorf("result origin ID = %s, want origin-1", results[0].ID)
		}
	})

	t.Run("disabled origins filtered in empty collection query", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin1 := testOrigin("origin-1", withEnabled(true), withSearchable(true))
		origin2 := testOrigin("origin-2", withEnabled(false), withSearchable(true))

		router.Register(origin1)
		router.Register(origin2)

		results := router.Route(nil)

		if len(results) != 1 {
			t.Errorf("results length = %d, want 1 (disabled origin filtered)", len(results))
		}
		if results[0].ID != "origin-1" {
			t.Errorf("result origin ID = %s, want origin-1", results[0].ID)
		}
	})

	t.Run("excluded collections are not routed", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin1 := testOrigin("origin-1",
			withExclude("coll-exclude"),
		) // No explicit collections

		router.Register(origin1)

		results := router.Route([]string{"coll-exclude"})

		if len(results) != 0 {
			t.Errorf("results length = %d, want 0 (collection excluded)", len(results))
		}
	})

	t.Run("non-excluded collection routes correctly", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin1 := testOrigin("origin-1",
			withExclude("coll-exclude"),
		) // No explicit collections

		router.Register(origin1)

		results := router.Route([]string{"coll-allowed"})

		if len(results) != 1 {
			t.Errorf("results length = %d, want 1", len(results))
		}
		if results[0].ID != "origin-1" {
			t.Errorf("result origin ID = %s, want origin-1", results[0].ID)
		}
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
		if len(results) != 0 {
			t.Errorf("results length = %d, want 0 (query without prefix)", len(results))
		}

		// Query with prefix should match
		results = router.Route([]string{"prefix_coll-a"})
		if len(results) != 1 {
			t.Errorf("results length = %d, want 1 (query with prefix)", len(results))
		}
		if results[0].ID != "origin-1" {
			t.Errorf("result origin ID = %s, want origin-1", results[0].ID)
		}
	})

	t.Run("deduplicates origins in results", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin1 := testOrigin("origin-1", routerWithCollections("coll-a", "coll-b"))

		router.Register(origin1)

		// Query both collections that origin-1 serves
		results := router.Route([]string{"coll-a", "coll-b"})

		// Should only appear once in results
		if len(results) != 1 {
			t.Errorf("results length = %d, want 1 (origin should be deduplicated)", len(results))
		}
		if results[0].ID != "origin-1" {
			t.Errorf("result origin ID = %s, want origin-1", results[0].ID)
		}
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
		if len(results) != 2 {
			t.Errorf("results length = %d, want 2", len(results))
		}

		foundOrigin1, foundOrigin2 := false, false
		for _, o := range results {
			if o.ID == "origin-1" {
				foundOrigin1 = true
			}
			if o.ID == "origin-2" {
				foundOrigin2 = true
			}
		}
		if !foundOrigin1 || !foundOrigin2 {
			t.Error("both origins should match coll-a")
		}
	})

	t.Run("no matching origins returns empty slice", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin1 := testOrigin("origin-1", routerWithCollections("coll-a"))

		router.Register(origin1)

		results := router.Route([]string{"coll-nonexistent"})

		if len(results) != 0 {
			t.Errorf("results length = %d, want 0", len(results))
		}
		if results == nil {
			t.Error("results should be empty slice, not nil")
		}
	})

	t.Run("multiple collections same origin", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin1 := testOrigin("origin-1", routerWithCollections("coll-a", "coll-b"))
		origin2 := testOrigin("origin-2", routerWithCollections("coll-c"))

		router.Register(origin1)
		router.Register(origin2)

		results := router.Route([]string{"coll-a", "coll-c"})

		if len(results) != 2 {
			t.Errorf("results length = %d, want 2", len(results))
		}
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

		if len(results) != 1 {
			t.Errorf("results length = %d, want 1", len(results))
		}
		if results[0].ID != "origin-1" {
			t.Errorf("result origin ID = %s, want origin-1", results[0].ID)
		}
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

		if len(results1) != len(results2) {
			t.Errorf("RouteCollection returned %d origins, Route returned %d", len(results1), len(results2))
		}
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
		if _, ok := router.collectionToOrigins["old-coll"]; !ok {
			t.Error("old-coll should be registered initially")
		}

		// Update with new collections
		router.UpdateFromDiscovery("origin-1", []string{"new-coll-a", "new-coll-b"})

		// Old collection should be removed
		if _, ok := router.collectionToOrigins["old-coll"]; ok {
			t.Error("old-coll should be removed after discovery update")
		}

		// New collections should be added
		if _, ok := router.collectionToOrigins["new-coll-a"]; !ok {
			t.Error("new-coll-a should be registered after discovery")
		}
		if _, ok := router.collectionToOrigins["new-coll-b"]; !ok {
			t.Error("new-coll-b should be registered after discovery")
		}
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

		if _, ok := router.collectionToOrigins["prefix_old-coll"]; ok {
			t.Error("prefix_old-coll should be removed")
		}
		if _, ok := router.collectionToOrigins["prefix_new-coll"]; !ok {
			t.Error("prefix_new-coll should be registered with prefix")
		}
		if _, ok := router.collectionToOrigins["new-coll"]; ok {
			t.Error("new-coll should not be registered without prefix")
		}
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
		if len(origins) != 1 || origins[0].ID != "origin-2" {
			t.Error("coll-b for origin-2 should remain unchanged")
		}

		// shared-coll should still have origin-2
		origins = router.collectionToOrigins["shared-coll"]
		if len(origins) != 1 || origins[0].ID != "origin-2" {
			t.Error("shared-coll should still have origin-2")
		}
	})

	t.Run("handles non-existent origin gracefully", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin1 := testOrigin("origin-1", routerWithCollections("coll-a"))

		router.Register(origin1)

		// Update non-existent origin
		router.UpdateFromDiscovery("non-existent", []string{"new-coll"})

		// Should not panic or modify anything
		if _, ok := router.collectionToOrigins["new-coll"]; ok {
			t.Error("new-coll should not be registered for non-existent origin")
		}
		if _, ok := router.collectionToOrigins["coll-a"]; !ok {
			t.Error("coll-a should remain unchanged")
		}
	})

	t.Run("handles empty collection list", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin1 := testOrigin("origin-1", routerWithCollections("coll-a", "coll-b"))

		router.Register(origin1)

		// Update with empty list
		router.UpdateFromDiscovery("origin-1", []string{})

		// Old collections should be removed
		if _, ok := router.collectionToOrigins["coll-a"]; ok {
			t.Error("coll-a should be removed")
		}
		if _, ok := router.collectionToOrigins["coll-b"]; ok {
			t.Error("coll-b should be removed")
		}
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
		if len(origins) != 2 {
			t.Errorf("shared-coll should have 2 origins, got %d", len(origins))
		}

		// Update origin-1 to remove shared-coll
		router.UpdateFromDiscovery("origin-1", []string{"other-coll"})

		// shared-coll should now only have origin-2
		origins = router.collectionToOrigins["shared-coll"]
		if len(origins) != 1 {
			t.Errorf("shared-coll should have 1 origin, got %d", len(origins))
		}
		if origins[0].ID != "origin-2" {
			t.Errorf("shared-coll should have origin-2, got %s", origins[0].ID)
		}
	})

	t.Run("cleans up collection when last origin removed", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin1 := testOrigin("origin-1", routerWithCollections("coll-unique"))

		router.Register(origin1)

		// Update to remove coll-unique
		router.UpdateFromDiscovery("origin-1", []string{"other-coll"})

		// coll-unique should be removed from map entirely
		if _, ok := router.collectionToOrigins["coll-unique"]; ok {
			t.Error("coll-unique should be removed from map when no origins serve it")
		}
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

		if len(results) != 2 {
			t.Errorf("results length = %d, want 2", len(results))
		}
	})

	t.Run("filters disabled origins", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin1 := testOrigin("origin-1", withEnabled(true), routerWithCollections("coll-a"))
		origin2 := testOrigin("origin-2", withEnabled(false), routerWithCollections("coll-a"))

		router.Register(origin1)
		router.Register(origin2)

		results := router.GetCollectionOrigins("coll-a")

		if len(results) != 1 {
			t.Errorf("results length = %d, want 1 (disabled filtered)", len(results))
		}
		if results[0].ID != "origin-1" {
			t.Errorf("result origin ID = %s, want origin-1", results[0].ID)
		}
	})

	t.Run("returns origins without explicit collections", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin1 := testOrigin("origin-1") // No explicit collections

		router.Register(origin1)

		results := router.GetCollectionOrigins("any-collection")

		if len(results) != 1 {
			t.Errorf("results length = %d, want 1", len(results))
		}
		if results[0].ID != "origin-1" {
			t.Errorf("result origin ID = %s, want origin-1", results[0].ID)
		}
	})

	t.Run("excludes excluded collections", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin1 := testOrigin("origin-1", withExclude("excluded-coll"))

		router.Register(origin1)

		results := router.GetCollectionOrigins("excluded-coll")

		if len(results) != 0 {
			t.Errorf("results length = %d, want 0 (collection excluded)", len(results))
		}
	})

	t.Run("returns empty slice for non-existent collection", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin1 := testOrigin("origin-1", routerWithCollections("coll-a"))

		router.Register(origin1)

		results := router.GetCollectionOrigins("non-existent")

		if len(results) != 0 {
			t.Errorf("results length = %d, want 0", len(results))
		}
		if results == nil {
			t.Error("results should be empty slice, not nil")
		}
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

		if len(results) != 3 {
			t.Errorf("results length = %d, want 3", len(results))
		}
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
		if results2[0] == nil {
			t.Error("results2 should not be affected by modifications to results1")
		}
	})

	t.Run("returns empty slice for no origins", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()

		results := router.AllOrigins()

		if len(results) != 0 {
			t.Errorf("results length = %d, want 0", len(results))
		}
	})

	t.Run("includes disabled origins", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin1 := testOrigin("origin-1", withEnabled(true))
		origin2 := testOrigin("origin-2", withEnabled(false))

		router.Register(origin1)
		router.Register(origin2)

		results := router.AllOrigins()

		if len(results) != 2 {
			t.Errorf("results length = %d, want 2 (includes disabled)", len(results))
		}
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

		if len(results) != 2 {
			t.Errorf("results length = %d, want 2 (only enabled)", len(results))
		}

		for _, o := range results {
			if !o.Enabled {
				t.Errorf("origin %s is disabled but in enabled origins list", o.ID)
			}
		}
	})

	t.Run("returns empty slice when no enabled origins", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin1 := testOrigin("origin-1", withEnabled(false))

		router.Register(origin1)

		results := router.EnabledOrigins()

		if len(results) != 0 {
			t.Errorf("results length = %d, want 0", len(results))
		}
		if results == nil {
			t.Error("results should be empty slice, not nil")
		}
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

		if router.OriginCount() != 0 {
			t.Errorf("initial count = %d, want 0", router.OriginCount())
		}

		router.Register(origin1)
		if router.OriginCount() != 1 {
			t.Errorf("count after 1 registration = %d, want 1", router.OriginCount())
		}

		router.Register(origin2)
		if router.OriginCount() != 2 {
			t.Errorf("count after 2 registrations = %d, want 2", router.OriginCount())
		}
	})

	t.Run("includes disabled origins", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin1 := testOrigin("origin-1", withEnabled(true))
		origin2 := testOrigin("origin-2", withEnabled(false))

		router.Register(origin1)
		router.Register(origin2)

		if router.OriginCount() != 2 {
			t.Errorf("count = %d, want 2 (includes disabled)", router.OriginCount())
		}
	})
}

// Test CollectionCount

func TestCollectionCount(t *testing.T) {
	t.Parallel()

	t.Run("returns correct count", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()

		if router.CollectionCount() != 0 {
			t.Errorf("initial count = %d, want 0", router.CollectionCount())
		}

		origin1 := testOrigin("origin-1", routerWithCollections("coll-a", "coll-b"))
		router.Register(origin1)

		if router.CollectionCount() != 2 {
			t.Errorf("count after registering 2 collections = %d, want 2", router.CollectionCount())
		}

		origin2 := testOrigin("origin-2", routerWithCollections("coll-c"))
		router.Register(origin2)

		if router.CollectionCount() != 3 {
			t.Errorf("count after registering 1 more collection = %d, want 3", router.CollectionCount())
		}
	})

	t.Run("does not count origins without explicit collections", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin1 := testOrigin("origin-1") // No explicit collections

		router.Register(origin1)

		if router.CollectionCount() != 0 {
			t.Errorf("count = %d, want 0 (no explicit collections)", router.CollectionCount())
		}
	})

	t.Run("does not double-count shared collections", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin1 := testOrigin("origin-1", routerWithCollections("shared-coll"))
		origin2 := testOrigin("origin-2", routerWithCollections("shared-coll"))

		router.Register(origin1)
		router.Register(origin2)

		if router.CollectionCount() != 1 {
			t.Errorf("count = %d, want 1 (shared collection counted once)", router.CollectionCount())
		}
	})
}

// Test isExcluded (internal method, tested via Route)

func TestIsExcluded(t *testing.T) {
	t.Parallel()

	t.Run("returns true for excluded collection", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin := testOrigin("origin-1", withExclude("excluded-a", "excluded-b"))

		if !router.isExcluded(origin, "excluded-a") {
			t.Error("excluded-a should be excluded")
		}
		if !router.isExcluded(origin, "excluded-b") {
			t.Error("excluded-b should be excluded")
		}
	})

	t.Run("returns false for non-excluded collection", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin := testOrigin("origin-1", withExclude("excluded-a"))

		if router.isExcluded(origin, "allowed-coll") {
			t.Error("allowed-coll should not be excluded")
		}
	})

	t.Run("returns false when no exclusions", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin := testOrigin("origin-1")

		if router.isExcluded(origin, "any-coll") {
			t.Error("any-coll should not be excluded when no exclusions defined")
		}
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
		if router.OriginCount() != 10 {
			t.Errorf("origin count = %d, want 10", router.OriginCount())
		}
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
		if len(results) != 1 {
			t.Errorf("results length = %d, want 1", len(results))
		}
		if results[0].ID != "origin-1" {
			t.Errorf("result origin ID = %s, want origin-1", results[0].ID)
		}
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
		if len(results) != 2 {
			t.Errorf("results length = %d, want 2 (priority doesn't filter)", len(results))
		}
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
		if len(results) != 1 {
			t.Errorf("results length = %d, want 1 (explicit collection)", len(results))
		}

		// Should not appear in empty collection query
		results = router.Route(nil)
		if len(results) != 0 {
			t.Errorf("results length = %d, want 0 (not searchable)", len(results))
		}
	})

	t.Run("update discovery with same collections is idempotent", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()
		origin1 := testOrigin("origin-1", routerWithCollections("coll-a"))

		router.Register(origin1)

		// Update with same collections
		router.UpdateFromDiscovery("origin-1", []string{"coll-a"})

		origins := router.collectionToOrigins["coll-a"]
		if len(origins) != 1 {
			t.Errorf("coll-a origins length = %d, want 1", len(origins))
		}
		if origins[0].ID != "origin-1" {
			t.Errorf("origin ID = %s, want origin-1", origins[0].ID)
		}
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

		if router.CollectionCount() != 1000 {
			t.Errorf("collection count = %d, want 1000", router.CollectionCount())
		}

		// Route to one of them
		results := router.Route([]string{"coll-000"})
		if len(results) != 1 {
			t.Errorf("results length = %d, want 1", len(results))
		}
	})

	t.Run("large number of origins", func(t *testing.T) {
		t.Parallel()
		router := NewCollectionRouter()

		// Register 100 origins
		for i := 0; i < 100; i++ {
			origin := testOrigin("origin-"+string(rune('0'+i%10))+string(rune('0'+(i/10)%10)), withSearchable(true))
			router.Register(origin)
		}

		if router.OriginCount() != 100 {
			t.Errorf("origin count = %d, want 100", router.OriginCount())
		}

		results := router.Route(nil)
		if len(results) != 100 {
			t.Errorf("results length = %d, want 100 (all searchable)", len(results))
		}
	})
}
