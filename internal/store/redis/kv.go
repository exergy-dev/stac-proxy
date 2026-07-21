package redisstore

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/yourorg/stac-proxy/internal/logx"
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
	logGate *logx.LogThrottle
}

// NewKV returns a KV writing keys under prefix (e.g. "stacproxy:rc:").
// logger may be nil; errors are then silent misses.
func NewKV(rdb redis.UniversalClient, prefix string, logger *slog.Logger) *KV {
	return &KV{
		rdb:     rdb,
		prefix:  prefix,
		logger:  logger,
		logGate: logx.NewLogThrottle(30 * time.Second),
	}
}

// kvCallTimeout bounds a single cache operation end-to-end (dial
// included — the client sets ContextTimeoutEnabled). This, not the
// client's Read/WriteTimeout, is what keeps a Redis outage to a
// milliseconds-scale degradation per request: without a per-op
// deadline the first request after an outage serially eats full dial
// timeouts across cache get/set and page-cache get/put.
const kvCallTimeout = 250 * time.Millisecond

// Get retrieves a value. Any backend error (including a down Redis)
// is reported as a miss; a throttled warning is logged.
func (s *KV) Get(ctx context.Context, key string) ([]byte, bool) {
	ctx, cancel := context.WithTimeout(ctx, kvCallTimeout)
	defer cancel()
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
	ctx, cancel := context.WithTimeout(ctx, kvCallTimeout)
	defer cancel()
	err := s.rdb.Set(ctx, s.prefix+key, value, ttl).Err()
	if err != nil {
		s.logGate.Warn(s.logger, "redis set failed; entry not cached",
			"prefix", s.prefix, "error", err)
	}
	return err
}
