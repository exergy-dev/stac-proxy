// Package cache: in-memory Store backed by hashicorp/golang-lru/v2.
//
// Per-entry TTL is layered on top of the library's plain LRU because
// expirable.LRU only supports a single global TTL. Expired entries are
// purged lazily on Get; natural LRU eviction handles the rest, so no
// background goroutine is needed.
package cache

import (
	"bytes"
	"context"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
)

const defaultMaxSize = 10000

// MemoryStore is the in-memory implementation of Store.
type MemoryStore struct {
	lru *lru.Cache[string, entry]
}

type entry struct {
	value     []byte
	expiresAt time.Time
}

// MemoryConfig contains configuration for the memory store.
type MemoryConfig struct {
	MaxSize int
}

// NewMemoryStore creates an in-memory LRU cache.
func NewMemoryStore(cfg MemoryConfig) *MemoryStore {
	size := cfg.MaxSize
	if size <= 0 {
		size = defaultMaxSize
	}
	c, _ := lru.New[string, entry](size)
	return &MemoryStore{lru: c}
}

// Get returns an independent copy of the stored bytes (HIGH H-cache-1:
// callers must be free to mutate or retain the slice without affecting
// the cache entry).
func (s *MemoryStore) Get(_ context.Context, key string) ([]byte, bool) {
	e, ok := s.lru.Get(key)
	if !ok {
		return nil, false
	}
	if time.Now().After(e.expiresAt) {
		s.lru.Remove(key)
		return nil, false
	}
	return bytes.Clone(e.value), true
}

// Set stores an independent copy of value with the given TTL.
func (s *MemoryStore) Set(_ context.Context, key string, value []byte, ttl time.Duration) error {
	s.lru.Add(key, entry{
		value:     bytes.Clone(value),
		expiresAt: time.Now().Add(ttl),
	})
	return nil
}

func (s *MemoryStore) Delete(_ context.Context, key string) error { s.lru.Remove(key); return nil }
func (s *MemoryStore) Clear(_ context.Context) error              { s.lru.Purge(); return nil }
func (s *MemoryStore) Close() error                               { s.lru.Purge(); return nil }
