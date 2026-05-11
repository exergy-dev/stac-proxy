// Package federation provides collection routing for federated origins.
package federation

import (
	"sync"
)

// CollectionRouter maintains a mapping of which collections are served by which origins.
type CollectionRouter struct {
	// collection ID -> list of origins that serve it
	collectionToOrigins map[string][]*Origin
	// All origins (for queries without collection filter)
	allOrigins []*Origin
	mu         sync.RWMutex
}

// NewCollectionRouter creates a new collection router.
func NewCollectionRouter() *CollectionRouter {
	return &CollectionRouter{
		collectionToOrigins: make(map[string][]*Origin),
	}
}

// Register adds an origin to the router.
func (r *CollectionRouter) Register(origin *Origin) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if origin.Searchable || len(origin.Collections) > 0 {
		r.allOrigins = append(r.allOrigins, origin)
	}

	// If origin has explicit collection list, register those
	if len(origin.Collections) > 0 {
		for _, collID := range origin.Collections {
			// Apply prefix if configured
			fullID := origin.CollectionPrefix + collID
			r.collectionToOrigins[fullID] = append(
				r.collectionToOrigins[fullID], origin)
		}
	}
}

// Route returns origins that should be queried for the given collections.
func (r *CollectionRouter) Route(collections []string) []*Origin {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// No collection filter = query all searchable origins
	if len(collections) == 0 {
		result := make([]*Origin, 0, len(r.allOrigins))
		for _, o := range r.allOrigins {
			if o.Enabled && o.Searchable {
				result = append(result, o)
			}
		}
		return result
	}

	// Find origins that serve any of the requested collections
	originSet := make(map[string]*Origin)
	for _, collID := range collections {
		// Check explicit mappings
		if origins, ok := r.collectionToOrigins[collID]; ok {
			for _, o := range origins {
				if o.Enabled {
					originSet[o.ID] = o
				}
			}
			continue
		}

		// For origins without explicit collection lists, they might serve it
		for _, o := range r.allOrigins {
			if !o.Enabled {
				continue
			}
			if len(o.Collections) == 0 && !r.isExcluded(o, collID) {
				originSet[o.ID] = o
			}
		}
	}

	result := make([]*Origin, 0, len(originSet))
	for _, o := range originSet {
		result = append(result, o)
	}
	return result
}

// RouteCollection returns origins that serve a specific collection.
func (r *CollectionRouter) RouteCollection(collectionID string) []*Origin {
	return r.Route([]string{collectionID})
}

// isExcluded checks if a collection is explicitly excluded from an origin.
func (r *CollectionRouter) isExcluded(origin *Origin, collID string) bool {
	for _, excluded := range origin.ExcludeCollections {
		if excluded == collID {
			return true
		}
	}
	return false
}

// UpdateFromDiscovery updates routing based on discovered collections.
func (r *CollectionRouter) UpdateFromDiscovery(originID string, collections []string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Find the origin
	var origin *Origin
	for _, o := range r.allOrigins {
		if o.ID == originID {
			origin = o
			break
		}
	}
	if origin == nil {
		return
	}

	// Remove old mappings for this origin
	for collID, origins := range r.collectionToOrigins {
		var filtered []*Origin
		for _, o := range origins {
			if o.ID != originID {
				filtered = append(filtered, o)
			}
		}
		if len(filtered) > 0 {
			r.collectionToOrigins[collID] = filtered
		} else {
			delete(r.collectionToOrigins, collID)
		}
	}

	// Add new mappings
	for _, collID := range collections {
		fullID := origin.CollectionPrefix + collID
		r.collectionToOrigins[fullID] = append(
			r.collectionToOrigins[fullID], origin)
	}
}

// GetCollectionOrigins returns all origins that serve a specific collection.
func (r *CollectionRouter) GetCollectionOrigins(collectionID string) []*Origin {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if origins, ok := r.collectionToOrigins[collectionID]; ok {
		result := make([]*Origin, 0, len(origins))
		for _, o := range origins {
			if o.Enabled {
				result = append(result, o)
			}
		}
		return result
	}

	// Check origins without explicit lists
	var result []*Origin
	for _, o := range r.allOrigins {
		if o.Enabled && len(o.Collections) == 0 && !r.isExcluded(o, collectionID) {
			result = append(result, o)
		}
	}
	return result
}

// AllOrigins returns all registered origins.
func (r *CollectionRouter) AllOrigins() []*Origin {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]*Origin, len(r.allOrigins))
	copy(result, r.allOrigins)
	return result
}

// EnabledOrigins returns all enabled origins.
func (r *CollectionRouter) EnabledOrigins() []*Origin {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []*Origin
	for _, o := range r.allOrigins {
		if o.Enabled {
			result = append(result, o)
		}
	}
	return result
}

// OriginCount returns the total number of origins.
func (r *CollectionRouter) OriginCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.allOrigins)
}

// CollectionCount returns the number of explicitly mapped collections.
func (r *CollectionRouter) CollectionCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.collectionToOrigins)
}
