package integration

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/stac-proxy/internal/federation/pagecache"
	"github.com/yourorg/stac-proxy/internal/stac"
	redisstore "github.com/yourorg/stac-proxy/internal/store/redis"
)

// TestIntegration_RedisBackedPageCache verifies the federation page
// cache over a shared Redis: a page Put by one pagecache.Cache
// instance (replica A) is readable by another instance (replica B) —
// the property that lets rel:prev / rel:first navigation survive
// non-sticky load balancing. Also covers TTL expiry and outage
// fail-open (miss, not error).
func TestIntegration_RedisBackedPageCache(t *testing.T) {
	mr := miniredis.RunT(t)
	client, err := redisstore.New(redisstore.Config{Addr: mr.Addr()})
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	secret := []byte("test-cursor-secret")
	newReplica := func() *pagecache.Cache {
		store := redisstore.NewKV(client, "stacproxy:pg:", nil)
		c, err := pagecache.New(store, time.Hour, secret)
		require.NoError(t, err)
		require.NotNil(t, c)
		return c
	}
	replicaA, replicaB := newReplica(), newReplica()
	ctx := context.Background()

	page := &pagecache.SearchResult{
		Items:      []*stac.Item{{ID: "item-1", Collection: "c1"}},
		TotalCount: 1,
		NextCursor: "next-cursor-opaque",
	}
	require.NoError(t, replicaA.Put(ctx, "cursor-sig-1", "principal-hash-1", page, 30*time.Minute))

	got, ok := replicaB.Get(ctx, "cursor-sig-1", "principal-hash-1")
	require.True(t, ok, "replica B must see the page replica A cached")
	require.Len(t, got.Items, 1)
	assert.Equal(t, "item-1", got.Items[0].ID)
	assert.Equal(t, "next-cursor-opaque", got.NextCursor)

	// Principal binding: a different principal hash must miss.
	_, ok = replicaB.Get(ctx, "cursor-sig-1", "other-principal")
	assert.False(t, ok, "page must not leak across principals")

	// TTL: Put bounded the entry at 30m; after that it expires.
	mr.FastForward(31 * time.Minute)
	_, ok = replicaA.Get(ctx, "cursor-sig-1", "principal-hash-1")
	assert.False(t, ok, "entry must expire with the cursor lifetime bound")

	// Outage: miss, not error — pagination re-executes the fan-out.
	require.NoError(t, replicaA.Put(ctx, "cursor-sig-2", "principal-hash-1", page, 30*time.Minute))
	mr.Close()
	_, ok = replicaA.Get(ctx, "cursor-sig-2", "principal-hash-1")
	assert.False(t, ok, "redis outage must read as a miss")
}
