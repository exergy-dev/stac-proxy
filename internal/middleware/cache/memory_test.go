package cache

import (
	"bytes"
	"context"
	"testing"
	"time"
)

// MemoryStore is now a thin adapter over hashicorp/golang-lru/v2.
// These tests cover only the behavior this package adds on top: byte-
// copy semantics on Get/Set (HIGH H-cache-1) and lazy TTL expiry.
// LRU eviction order, concurrency, etc. are the library's concern.

func TestMemoryStore_GetSet_RoundTrip(t *testing.T) {
	t.Parallel()
	store := NewMemoryStore(MemoryConfig{MaxSize: 16})
	defer store.Close()

	ctx := context.Background()
	if err := store.Set(ctx, "k", []byte("v"), time.Minute); err != nil {
		t.Fatal(err)
	}
	got, ok := store.Get(ctx, "k")
	if !ok || string(got) != "v" {
		t.Fatalf("got=%q ok=%v", got, ok)
	}

	if _, ok := store.Get(ctx, "missing"); ok {
		t.Fatal("missing key reported hit")
	}
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
	if !bytes.Equal(second, []byte("hello")) {
		t.Fatalf("Get returned a shared buffer; second=%q", second)
	}
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
	if !bytes.Equal(got, []byte("hello")) {
		t.Fatalf("Set captured a shared reference; got=%q", got)
	}
}

func TestMemoryStore_TTLExpiry(t *testing.T) {
	t.Parallel()
	store := NewMemoryStore(MemoryConfig{MaxSize: 4})
	ctx := context.Background()

	_ = store.Set(ctx, "k", []byte("v"), 5*time.Millisecond)
	time.Sleep(20 * time.Millisecond)
	if _, ok := store.Get(ctx, "k"); ok {
		t.Fatal("expired entry returned a hit")
	}
}

func TestMemoryStore_DefaultMaxSize(t *testing.T) {
	t.Parallel()
	store := NewMemoryStore(MemoryConfig{MaxSize: 0})
	defer store.Close()
	if err := store.Set(context.Background(), "k", []byte("v"), time.Minute); err != nil {
		t.Fatal(err)
	}
}

func TestMemoryStore_DeleteAndClear(t *testing.T) {
	t.Parallel()
	store := NewMemoryStore(MemoryConfig{MaxSize: 8})
	ctx := context.Background()

	_ = store.Set(ctx, "a", []byte("1"), time.Minute)
	_ = store.Set(ctx, "b", []byte("2"), time.Minute)
	_ = store.Delete(ctx, "a")
	if _, ok := store.Get(ctx, "a"); ok {
		t.Fatal("deleted key still present")
	}
	if _, ok := store.Get(ctx, "b"); !ok {
		t.Fatal("non-deleted key missing")
	}
	_ = store.Clear(ctx)
	if _, ok := store.Get(ctx, "b"); ok {
		t.Fatal("clear left entries behind")
	}
}
