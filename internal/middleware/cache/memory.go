// Package cache provides in-memory cache implementation.
package cache

import (
	"context"
	"sync"
	"time"
)

// MemoryStore is an in-memory cache implementation with LRU eviction.
type MemoryStore struct {
	items    map[string]*cacheItem
	order    []string // For LRU tracking
	maxSize  int
	mu       sync.RWMutex
	stats    Stats
	statsMu  sync.Mutex
}

type cacheItem struct {
	value     []byte
	expiresAt time.Time
}

// MemoryConfig contains configuration for the memory store.
type MemoryConfig struct {
	MaxSize int // Maximum number of items
}

// NewMemoryStore creates a new in-memory cache store.
func NewMemoryStore(cfg MemoryConfig) *MemoryStore {
	if cfg.MaxSize <= 0 {
		cfg.MaxSize = 10000
	}

	store := &MemoryStore{
		items:   make(map[string]*cacheItem),
		order:   make([]string, 0, cfg.MaxSize),
		maxSize: cfg.MaxSize,
	}

	// Start cleanup goroutine
	go store.cleanupLoop()

	return store
}

// Get retrieves a value from the cache.
func (s *MemoryStore) Get(ctx context.Context, key string) ([]byte, bool) {
	s.mu.RLock()
	item, exists := s.items[key]
	s.mu.RUnlock()

	if !exists {
		s.recordMiss()
		return nil, false
	}

	if time.Now().After(item.expiresAt) {
		// Expired
		s.Delete(ctx, key)
		s.recordMiss()
		return nil, false
	}

	s.recordHit()

	// Move to end of LRU list (most recently used)
	s.mu.Lock()
	s.moveToEnd(key)
	s.mu.Unlock()

	return item.value, true
}

// Set stores a value in the cache.
func (s *MemoryStore) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Evict if at capacity
	for len(s.items) >= s.maxSize {
		s.evictOldest()
	}

	// Store the item
	s.items[key] = &cacheItem{
		value:     value,
		expiresAt: time.Now().Add(ttl),
	}

	// Add to LRU order
	s.order = append(s.order, key)

	return nil
}

// Delete removes a value from the cache.
func (s *MemoryStore) Delete(ctx context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.items, key)
	s.removeFromOrder(key)

	return nil
}

// Clear removes all values from the cache.
func (s *MemoryStore) Clear(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.items = make(map[string]*cacheItem)
	s.order = make([]string, 0, s.maxSize)

	return nil
}

// Close releases resources.
func (s *MemoryStore) Close() error {
	return s.Clear(context.Background())
}

// Stats returns cache statistics.
func (s *MemoryStore) Stats() Stats {
	s.statsMu.Lock()
	defer s.statsMu.Unlock()

	s.mu.RLock()
	s.stats.Size = int64(len(s.items))
	s.mu.RUnlock()

	return s.stats
}

// evictOldest removes the least recently used item.
func (s *MemoryStore) evictOldest() {
	if len(s.order) == 0 {
		return
	}

	oldest := s.order[0]
	s.order = s.order[1:]
	delete(s.items, oldest)
}

// moveToEnd moves a key to the end of the LRU list.
func (s *MemoryStore) moveToEnd(key string) {
	s.removeFromOrder(key)
	s.order = append(s.order, key)
}

// removeFromOrder removes a key from the LRU list.
func (s *MemoryStore) removeFromOrder(key string) {
	for i, k := range s.order {
		if k == key {
			s.order = append(s.order[:i], s.order[i+1:]...)
			return
		}
	}
}

// cleanupLoop periodically removes expired items.
func (s *MemoryStore) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		s.cleanupExpired()
	}
}

// cleanupExpired removes all expired items.
func (s *MemoryStore) cleanupExpired() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for key, item := range s.items {
		if now.After(item.expiresAt) {
			delete(s.items, key)
			s.removeFromOrder(key)
		}
	}
}

// recordHit increments the hit counter.
func (s *MemoryStore) recordHit() {
	s.statsMu.Lock()
	s.stats.Hits++
	s.statsMu.Unlock()
}

// recordMiss increments the miss counter.
func (s *MemoryStore) recordMiss() {
	s.statsMu.Lock()
	s.stats.Misses++
	s.statsMu.Unlock()
}
