// Package cache provides in-memory cache implementation.
package cache

import (
	"bytes"
	"container/list"
	"context"
	"sync"
	"time"
)

// MemoryStore is an in-memory cache implementation with LRU eviction.
//
// Internal layout (HIGH H-cache-2): a doubly-linked list (lru) holds
// keys in usage order — front = most recently used, back = least
// recently used. The items map indexes from key to a *cacheItem
// carrying the value, expiry, and the *list.Element pointing back into
// lru. This makes Get's move-to-front, Set's push-front, and
// evictOldest's pop-back all O(1); the previous slice-based approach
// was O(n) per operation.
type MemoryStore struct {
	items   map[string]*cacheItem
	lru     *list.List // values: string keys; front = MRU, back = LRU
	maxSize int
	mu      sync.RWMutex
	stats   Stats
	statsMu sync.Mutex
	stop    chan struct{}
	stopped sync.Once
}

type cacheItem struct {
	value     []byte
	expiresAt time.Time
	elem      *list.Element // points into MemoryStore.lru; never nil for live items
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
		lru:     list.New(),
		maxSize: cfg.MaxSize,
		stop:    make(chan struct{}),
	}

	// Start cleanup goroutine; Close() stops it.
	go store.cleanupLoop()

	return store
}

// Get retrieves a value from the cache.
//
// CONTRACT: the returned slice is an independent copy of the stored
// bytes. Callers may mutate or retain it freely without affecting the
// cache entry. This is required because the underlying buffer can
// otherwise be mutated by a concurrent Set or evictOldest while a
// reader still holds the slice (HIGH H-cache-1).
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

	// Move to front of LRU list (most recently used). O(1).
	s.mu.Lock()
	if item.elem != nil {
		s.lru.MoveToFront(item.elem)
	}
	s.mu.Unlock()

	// Return an independent copy so subsequent Set/evict cannot mutate
	// what the caller is holding (and vice versa).
	return bytes.Clone(item.value), true
}

// Set stores a value in the cache.
func (s *MemoryStore) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Update path: existing key gets a new value/TTL and is bumped to MRU.
	if existing, ok := s.items[key]; ok {
		existing.value = value
		existing.expiresAt = time.Now().Add(ttl)
		if existing.elem != nil {
			s.lru.MoveToFront(existing.elem)
		}
		return nil
	}

	// Evict if at capacity (rare loop in case maxSize was lowered).
	for len(s.items) >= s.maxSize {
		s.evictOldest()
	}

	elem := s.lru.PushFront(key)
	s.items[key] = &cacheItem{
		value:     value,
		expiresAt: time.Now().Add(ttl),
		elem:      elem,
	}

	return nil
}

// Delete removes a value from the cache.
func (s *MemoryStore) Delete(ctx context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if item, ok := s.items[key]; ok {
		if item.elem != nil {
			s.lru.Remove(item.elem)
		}
		delete(s.items, key)
	}

	return nil
}

// Clear removes all values from the cache.
func (s *MemoryStore) Clear(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.items = make(map[string]*cacheItem)
	s.lru = list.New()

	return nil
}

// Close releases resources and stops the cleanup goroutine.
func (s *MemoryStore) Close() error {
	s.stopped.Do(func() { close(s.stop) })
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

// evictOldest removes the least recently used item. O(1). Caller MUST
// hold s.mu (write).
func (s *MemoryStore) evictOldest() {
	back := s.lru.Back()
	if back == nil {
		return
	}
	key, _ := back.Value.(string)
	s.lru.Remove(back)
	delete(s.items, key)
}

// cleanupLoop periodically removes expired items until Close() is called.
func (s *MemoryStore) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-s.stop:
			return
		case <-ticker.C:
			s.cleanupExpired()
		}
	}
}

// cleanupExpired removes all expired items.
func (s *MemoryStore) cleanupExpired() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for key, item := range s.items {
		if now.After(item.expiresAt) {
			if item.elem != nil {
				s.lru.Remove(item.elem)
			}
			delete(s.items, key)
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
