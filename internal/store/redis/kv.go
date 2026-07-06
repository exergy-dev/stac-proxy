package redisstore

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"
)

// KV is a Redis-backed byte KV store implementing the method set of
// cache.Store (and, structurally, pagecache.Store). All operations
// fail open: a Redis error is a cache miss, never a request failure.
// The response cache and page cache are optimizations by contract —
// see cache.Store.Get's (value, bool) shape and the pagecache package
// doc ("Correctness never depends on the cache having an entry").
type KV struct {
	rdb     redis.UniversalClient
	prefix  string
	logger  *slog.Logger
	logGate *LogThrottle
}

// NewKV returns a KV writing keys under prefix (e.g. "stacproxy:rc:").
// logger may be nil; errors are then silent misses.
func NewKV(rdb redis.UniversalClient, prefix string, logger *slog.Logger) *KV {
	return &KV{
		rdb:     rdb,
		prefix:  prefix,
		logger:  logger,
		logGate: NewLogThrottle(30 * time.Second),
	}
}

// Get retrieves a value. Any backend error (including a down Redis)
// is reported as a miss; a throttled warning is logged.
func (s *KV) Get(ctx context.Context, key string) ([]byte, bool) {
	val, err := s.rdb.Get(ctx, s.prefix+key).Bytes()
	if err != nil {
		if !errors.Is(err, redis.Nil) {
			s.logGate.Warn(s.logger, "redis get failed; treating as cache miss",
				"prefix", s.prefix, "error", err)
		}
		return nil, false
	}
	return val, true
}

// Set stores value with the given TTL. Non-positive TTLs are dropped
// (a TTL-less SET would persist forever; the memory store's semantics
// are "expired immediately", so skipping the write is the equivalent).
func (s *KV) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	if ttl <= 0 {
		return nil
	}
	err := s.rdb.Set(ctx, s.prefix+key, value, ttl).Err()
	if err != nil {
		s.logGate.Warn(s.logger, "redis set failed; entry not cached",
			"prefix", s.prefix, "error", err)
	}
	return err
}

// Delete removes a key.
func (s *KV) Delete(ctx context.Context, key string) error {
	return s.rdb.Del(ctx, s.prefix+key).Err()
}

// Clear removes every key under this KV's prefix using SCAN+DEL in
// batches (never KEYS — O(N) blocking on a shared Redis).
func (s *KV) Clear(ctx context.Context) error {
	var cursor uint64
	for {
		keys, next, err := s.rdb.Scan(ctx, cursor, s.prefix+"*", 512).Result()
		if err != nil {
			return err
		}
		if len(keys) > 0 {
			if err := s.rdb.Del(ctx, keys...).Err(); err != nil {
				return err
			}
		}
		if next == 0 {
			return nil
		}
		cursor = next
	}
}

// Close is a no-op: the underlying client is shared across stores and
// owned by main, which closes it on shutdown.
func (s *KV) Close() error { return nil }
