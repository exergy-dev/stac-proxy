package pagecache

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/yourorg/stac-proxy/internal/stac"
)

// memStore is a minimal in-memory Store for tests. The real
// implementation (internal/middleware/cache.MemoryStore) is heavier
// and pulls in unrelated middleware concerns; a tiny test store keeps
// these tests dependency-free.
type memStore struct {
	mu   sync.Mutex
	data map[string]storeEntry
}

type storeEntry struct {
	value []byte
	exp   time.Time
}

func newMemStore() *memStore {
	return &memStore{data: make(map[string]storeEntry)}
}

func (m *memStore) Get(_ context.Context, key string) ([]byte, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.data[key]
	if !ok {
		return nil, false
	}
	if !e.exp.IsZero() && time.Now().After(e.exp) {
		delete(m.data, key)
		return nil, false
	}
	return e.value, true
}

func (m *memStore) Set(_ context.Context, key string, value []byte, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var exp time.Time
	if ttl > 0 {
		exp = time.Now().Add(ttl)
	}
	m.data[key] = storeEntry{value: value, exp: exp}
	return nil
}

func makeResult() *SearchResult {
	return &SearchResult{
		Items: []*stac.Item{
			{ID: "item-1", Collection: "col"},
			{ID: "item-2", Collection: "col"},
		},
		TotalCount: 42,
		NextCursor: "next.sig",
		PrevCursor: "prev.sig",
		Context:    json.RawMessage(`{"returned":2}`),
	}
}

func TestNew_RejectsEmptySecret(t *testing.T) {
	t.Parallel()
	if _, err := New(newMemStore(), time.Hour, nil); err == nil {
		t.Fatal("expected error for empty secret; got nil")
	}
}

func TestNew_RejectsNonPositiveTTL(t *testing.T) {
	t.Parallel()
	if _, err := New(newMemStore(), 0, []byte("k")); err == nil {
		t.Fatal("expected error for zero TTL; got nil")
	}
}

func TestNew_NilStoreReturnsNil(t *testing.T) {
	t.Parallel()
	c, err := New(nil, time.Hour, []byte("k"))
	if err != nil {
		t.Fatalf("New(nil store): %v", err)
	}
	if c != nil {
		t.Errorf("expected nil cache when store is nil, got %v", c)
	}
}

func TestCache_RoundTrip(t *testing.T) {
	t.Parallel()
	c, err := New(newMemStore(), time.Hour, []byte("secret-key-do-not-share"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const sig = "cursor-signature-abc"
	const principal = "ph-deadbeef"

	if err := c.Put(context.Background(), sig, principal, makeResult(), time.Hour); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, ok := c.Get(context.Background(), sig, principal)
	if !ok {
		t.Fatal("Get: cache miss after Put")
	}
	if got.TotalCount != 42 {
		t.Errorf("TotalCount = %d, want 42", got.TotalCount)
	}
	if got.NextCursor != "next.sig" {
		t.Errorf("NextCursor = %q, want %q", got.NextCursor, "next.sig")
	}
	if len(got.Items) != 2 || got.Items[0].ID != "item-1" {
		t.Errorf("Items not preserved: %+v", got.Items)
	}
}

func TestCache_PrincipalIsolation(t *testing.T) {
	t.Parallel()
	c, _ := New(newMemStore(), time.Hour, []byte("k"))

	const sig = "cursor-signature"
	if err := c.Put(context.Background(), sig, "principal-A", makeResult(), time.Hour); err != nil {
		t.Fatalf("Put: %v", err)
	}
	// Same signature, different principal → MUST miss. Defends
	// against a leaked cache key being usable by a different
	// principal even though the underlying cursor encoder already
	// binds to principal.
	if _, ok := c.Get(context.Background(), sig, "principal-B"); ok {
		t.Error("Get: principal-B got principal-A's cached page (isolation failed)")
	}
}

func TestCache_TTLCapping(t *testing.T) {
	t.Parallel()
	c, _ := New(newMemStore(), 10*time.Second, []byte("k"))

	// Put with a remaining of 50ms — Put should use the smaller
	// remaining value rather than the cache's default TTL.
	if err := c.Put(context.Background(), "sig", "ph", makeResult(), 50*time.Millisecond); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, ok := c.Get(context.Background(), "sig", "ph"); !ok {
		t.Fatal("Get: should hit before TTL expiry")
	}
	time.Sleep(80 * time.Millisecond)
	if _, ok := c.Get(context.Background(), "sig", "ph"); ok {
		t.Error("Get: should miss after capped TTL expiry")
	}
}

func TestCache_NoOpsWhenNonPositiveRemaining(t *testing.T) {
	t.Parallel()
	c, _ := New(newMemStore(), time.Hour, []byte("k"))

	// remaining=0 → no-op (cursor already expired); cache must NOT
	// store this entry.
	if err := c.Put(context.Background(), "sig", "ph", makeResult(), 0); err != nil {
		t.Fatalf("Put with 0 remaining: %v", err)
	}
	if _, ok := c.Get(context.Background(), "sig", "ph"); ok {
		t.Error("Get: cache should not hold entries put with non-positive remaining")
	}
}

func TestCache_NilSafeOps(t *testing.T) {
	t.Parallel()
	var c *Cache // nil
	if _, ok := c.Get(context.Background(), "sig", "ph"); ok {
		t.Error("nil cache Get returned a hit")
	}
	if err := c.Put(context.Background(), "sig", "ph", makeResult(), time.Hour); err != nil {
		t.Errorf("nil cache Put returned an error: %v", err)
	}
	if got := c.TTL(); got != 0 {
		t.Errorf("nil cache TTL = %v, want 0", got)
	}
}

func TestSignatureOf(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want string
	}{
		{"payload.signature", "signature"},
		{"a.b.c", "c"},              // takes the LAST dot
		{"nosignaturesplit", ""},    // no dot
		{"trailingdot.", ""},        // signature half is empty
		{"", ""},                    // empty
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			if got := SignatureOf(c.in); got != c.want {
				t.Errorf("SignatureOf(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}
