package cache

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MemoryStore is now a thin adapter over hashicorp/golang-lru/v2.
// These tests cover only the behavior this package adds on top: byte-
// copy semantics on Get/Set (HIGH H-cache-1) and lazy TTL expiry.
// LRU eviction order, concurrency, etc. are the library's concern.

func TestMemoryStore_GetSet_RoundTrip(t *testing.T) {
	t.Parallel()
	store := NewMemoryStore(MemoryConfig{MaxSize: 16})

	ctx := context.Background()
	require.NoError(t, store.Set(ctx, "k", []byte("v"), time.Minute))
	got, ok := store.Get(ctx, "k")
	require.True(t, ok, "expected hit for key 'k'")
	require.Equal(t, "v", string(got))

	_, ok = store.Get(ctx, "missing")
	require.False(t, ok, "missing key reported hit")
}

func TestMemoryStore_GetReturnsIndependentCopy(t *testing.T) {
	t.Parallel()
	store := NewMemoryStore(MemoryConfig{MaxSize: 4})
	ctx := context.Background()

	original := []byte("hello")
	_ = store.Set(ctx, "k", original, time.Minute)

	// Caller mutates the buffer returned by Get; second Get must
	// still see the unmodified stored bytes.
	first, _ := store.Get(ctx, "k")
	for i := range first {
		first[i] = 'x'
	}
	second, _ := store.Get(ctx, "k")
	require.Equal(t, []byte("hello"), second, "Get returned a shared buffer")
}

func TestMemoryStore_SetCopiesInput(t *testing.T) {
	t.Parallel()
	store := NewMemoryStore(MemoryConfig{MaxSize: 4})
	ctx := context.Background()

	buf := []byte("hello")
	_ = store.Set(ctx, "k", buf, time.Minute)
	for i := range buf {
		buf[i] = 'x'
	}
	got, _ := store.Get(ctx, "k")
	require.Equal(t, []byte("hello"), got, "Set captured a shared reference")
}

func TestMemoryStore_TTLExpiry(t *testing.T) {
	t.Parallel()
	store := NewMemoryStore(MemoryConfig{MaxSize: 4})
	ctx := context.Background()

	_ = store.Set(ctx, "k", []byte("v"), 5*time.Millisecond)
	time.Sleep(20 * time.Millisecond)
	_, ok := store.Get(ctx, "k")
	assert.False(t, ok, "expired entry returned a hit")
}

func TestMemoryStore_DefaultMaxSize(t *testing.T) {
	t.Parallel()
	store := NewMemoryStore(MemoryConfig{MaxSize: 0})
	require.NoError(t, store.Set(context.Background(), "k", []byte("v"), time.Minute))
}
