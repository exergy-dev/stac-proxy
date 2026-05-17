package pagecache

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	_, err := New(newMemStore(), time.Hour, nil)
	require.Error(t, err, "expected error for empty secret")
}

func TestNew_RejectsNonPositiveTTL(t *testing.T) {
	t.Parallel()
	_, err := New(newMemStore(), 0, []byte("k"))
	require.Error(t, err, "expected error for zero TTL")
}

func TestNew_NilStoreReturnsNil(t *testing.T) {
	t.Parallel()
	c, err := New(nil, time.Hour, []byte("k"))
	require.NoError(t, err, "New(nil store)")
	assert.Nil(t, c, "expected nil cache when store is nil")
}

func TestCache_RoundTrip(t *testing.T) {
	t.Parallel()
	c, err := New(newMemStore(), time.Hour, []byte("secret-key-do-not-share"))
	require.NoError(t, err, "New")

	const sig = "cursor-signature-abc"
	const principal = "ph-deadbeef"

	require.NoError(t, c.Put(context.Background(), sig, principal, makeResult(), time.Hour), "Put")
	got, ok := c.Get(context.Background(), sig, principal)
	require.True(t, ok, "Get: cache miss after Put")
	assert.Equal(t, 42, got.TotalCount, "TotalCount")
	assert.Equal(t, "next.sig", got.NextCursor, "NextCursor")
	require.Len(t, got.Items, 2, "Items not preserved")
	assert.Equal(t, "item-1", got.Items[0].ID, "Items not preserved")
}

func TestCache_PrincipalIsolation(t *testing.T) {
	t.Parallel()
	c, _ := New(newMemStore(), time.Hour, []byte("k"))

	const sig = "cursor-signature"
	require.NoError(t, c.Put(context.Background(), sig, "principal-A", makeResult(), time.Hour), "Put")
	// Same signature, different principal → MUST miss. Defends
	// against a leaked cache key being usable by a different
	// principal even though the underlying cursor encoder already
	// binds to principal.
	_, ok := c.Get(context.Background(), sig, "principal-B")
	assert.False(t, ok, "Get: principal-B got principal-A's cached page (isolation failed)")
}

func TestCache_TTLCapping(t *testing.T) {
	t.Parallel()
	c, _ := New(newMemStore(), 10*time.Second, []byte("k"))

	// Put with a remaining of 50ms — Put should use the smaller
	// remaining value rather than the cache's default TTL.
	require.NoError(t, c.Put(context.Background(), "sig", "ph", makeResult(), 50*time.Millisecond), "Put")
	_, ok := c.Get(context.Background(), "sig", "ph")
	require.True(t, ok, "Get: should hit before TTL expiry")
	time.Sleep(80 * time.Millisecond)
	_, ok = c.Get(context.Background(), "sig", "ph")
	assert.False(t, ok, "Get: should miss after capped TTL expiry")
}

func TestCache_NoOpsWhenNonPositiveRemaining(t *testing.T) {
	t.Parallel()
	c, _ := New(newMemStore(), time.Hour, []byte("k"))

	// remaining=0 → no-op (cursor already expired); cache must NOT
	// store this entry.
	require.NoError(t, c.Put(context.Background(), "sig", "ph", makeResult(), 0), "Put with 0 remaining")
	_, ok := c.Get(context.Background(), "sig", "ph")
	assert.False(t, ok, "Get: cache should not hold entries put with non-positive remaining")
}

func TestCache_NilSafeOps(t *testing.T) {
	t.Parallel()
	var c *Cache // nil
	_, ok := c.Get(context.Background(), "sig", "ph")
	assert.False(t, ok, "nil cache Get returned a hit")
	assert.NoError(t, c.Put(context.Background(), "sig", "ph", makeResult(), time.Hour), "nil cache Put returned an error")
	assert.Equal(t, time.Duration(0), c.TTL(), "nil cache TTL")
}

func TestSignatureOf(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want string
	}{
		{"payload.signature", "signature"},
		{"a.b.c", "c"},           // takes the LAST dot
		{"nosignaturesplit", ""}, // no dot
		{"trailingdot.", ""},     // signature half is empty
		{"", ""},                 // empty
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			assert.Equal(t, c.want, SignatureOf(c.in), "SignatureOf(%q)", c.in)
		})
	}
}
