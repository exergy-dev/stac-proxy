package redisstore

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestKV(t *testing.T, prefix string) (*KV, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return NewKV(client, prefix, slog.Default()), mr
}

func TestKV_SetGetRoundTrip(t *testing.T) {
	t.Parallel()
	kv, _ := newTestKV(t, "t:rc:")
	ctx := context.Background()

	require.NoError(t, kv.Set(ctx, "k1", []byte("payload"), time.Minute))
	got, ok := kv.Get(ctx, "k1")
	require.True(t, ok, "expected hit after Set")
	assert.Equal(t, []byte("payload"), got)

	_, ok = kv.Get(ctx, "absent")
	assert.False(t, ok, "expected miss for absent key")
}

func TestKV_TTLExpiry(t *testing.T) {
	t.Parallel()
	kv, mr := newTestKV(t, "t:rc:")
	ctx := context.Background()

	require.NoError(t, kv.Set(ctx, "k1", []byte("v"), 10*time.Second))
	mr.FastForward(11 * time.Second)
	_, ok := kv.Get(ctx, "k1")
	assert.False(t, ok, "entry must expire after TTL")
}

func TestKV_NonPositiveTTLNotStored(t *testing.T) {
	t.Parallel()
	kv, _ := newTestKV(t, "t:rc:")
	ctx := context.Background()

	require.NoError(t, kv.Set(ctx, "zero", []byte("v"), 0))
	require.NoError(t, kv.Set(ctx, "neg", []byte("v"), -time.Second))
	_, ok := kv.Get(ctx, "zero")
	assert.False(t, ok)
	_, ok = kv.Get(ctx, "neg")
	assert.False(t, ok)
}

func TestKV_PrefixIsolation(t *testing.T) {
	t.Parallel()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	a := NewKV(client, "t:a:", nil)
	b := NewKV(client, "t:b:", nil)
	ctx := context.Background()

	require.NoError(t, a.Set(ctx, "shared", []byte("from-a"), time.Minute))
	require.NoError(t, b.Set(ctx, "shared", []byte("from-b"), time.Minute))

	got, ok := a.Get(ctx, "shared")
	require.True(t, ok)
	assert.Equal(t, []byte("from-a"), got, "prefixes must not collide")

	got, ok = b.Get(ctx, "shared")
	require.True(t, ok)
	assert.Equal(t, []byte("from-b"), got, "prefixes must not collide")
}

func TestKV_RedisDownFailsOpen(t *testing.T) {
	t.Parallel()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	kv := NewKV(client, "t:rc:", slog.Default())
	ctx := context.Background()

	require.NoError(t, kv.Set(ctx, "k1", []byte("v"), time.Minute))
	mr.Close() // simulate outage

	got, ok := kv.Get(ctx, "k1")
	assert.False(t, ok, "down Redis must read as a miss, not an error")
	assert.Nil(t, got)
	assert.Error(t, kv.Set(ctx, "k2", []byte("v"), time.Minute),
		"Set surfaces the error (callers already ignore it)")
}

func TestNew_RequiresAddr(t *testing.T) {
	t.Parallel()
	_, err := New(Config{})
	require.Error(t, err)
}

func TestNew_DefaultsApplied(t *testing.T) {
	t.Parallel()
	mr := miniredis.RunT(t)
	client, err := New(Config{Addr: mr.Addr()})
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	require.NoError(t, client.Ping(context.Background()).Err())
}
