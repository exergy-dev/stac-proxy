// Redis-backed Limiter: one atomic Lua round trip per decision, so
// concurrent requests across replicas cannot race a read-modify-write
// window. State layout per bucket (hash): tokens (float), ts (ms of
// last refill computation).
package ratelimit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"math"
	"time"

	"github.com/redis/go-redis/v9"

	redisstore "github.com/yourorg/stac-proxy/internal/store/redis"
)

// tokenBucketScript implements the same semantics as
// TokenBucketLimiter (golang.org/x/time/rate): continuous refill at
// requests/window up to burst, cost of 1 per request.
//
// `now` arrives as ARGV, not redis.call('TIME'): scripts must be
// deterministic to replicate safely, and it keeps miniredis-based
// tests (FastForward has no effect on TIME) faithful. Millisecond
// clock skew across replicas is noise at these window sizes.
//
// Returns {allowed, tostring(pre_tokens), tostring(post_tokens),
// retry_ms}. Token counts travel as strings because Redis truncates
// Lua numbers to integers in protocol replies.
var tokenBucketScript = redis.NewScript(`
local rate  = tonumber(ARGV[1])  -- tokens per second
local burst = tonumber(ARGV[2])
local now   = tonumber(ARGV[3])  -- unix millis
local cost  = tonumber(ARGV[4])

local b = redis.call('HMGET', KEYS[1], 'tokens', 'ts')
local tokens = tonumber(b[1])
local ts     = tonumber(b[2])
if tokens == nil or ts == nil then
  tokens = burst
  ts = now
end
if now > ts then
  tokens = math.min(burst, tokens + (now - ts) / 1000.0 * rate)
  ts = now
end

local pre = tokens
local allowed = 0
local retry_ms = 0
if tokens >= cost then
  tokens = tokens - cost
  allowed = 1
else
  retry_ms = math.ceil((cost - tokens) / rate * 1000.0)
end

redis.call('HSET', KEYS[1], 'tokens', tokens, 'ts', ts)
-- GC idle buckets once they would have fully refilled (x2 margin).
redis.call('PEXPIRE', KEYS[1], math.ceil(burst / rate * 1000.0) * 2)

return {allowed, tostring(pre), tostring(tokens), retry_ms}
`)

// redisCallTimeout bounds a single Allow round trip so a degraded
// Redis adds at most this much latency to a request before the
// middleware's failure mode takes over.
const redisCallTimeout = 100 * time.Millisecond

// RedisLimiter is the Limiter implementation over the shared Redis
// client. Buckets are global across replicas — the property that
// makes quotas hold behind a non-sticky load balancer.
type RedisLimiter struct {
	rdb     redis.UniversalClient
	prefix  string
	logger  *slog.Logger
	logGate *redisstore.LogThrottle
}

// NewRedisLimiter returns a RedisLimiter writing bucket hashes under
// prefix (e.g. "stacproxy:rl:"). logger may be nil.
func NewRedisLimiter(rdb redis.UniversalClient, prefix string, logger *slog.Logger) *RedisLimiter {
	return &RedisLimiter{
		rdb:     rdb,
		prefix:  prefix,
		logger:  logger,
		logGate: redisstore.NewLogThrottle(30 * time.Second),
	}
}

// Stop is a no-op, mirroring TokenBucketLimiter.
func (l *RedisLimiter) Stop() {}

// Allow consumes one token from the shared bucket for key. Errors
// (Redis down, script failure) are returned to the middleware, which
// applies the configured failure mode; a throttled warning is logged
// here so the operator sees the degradation either way.
func (l *RedisLimiter) Allow(ctx context.Context, key string, quota Quota) (bool, Info, error) {
	if quota.Requests <= 0 || quota.Window <= 0 {
		// Degenerate quota: mirror the memory limiter's practical
		// outcome (rate.NewLimiter with 0 limit blocks everything).
		return false, Info{Limit: quota.Requests, RetryAfter: 1}, nil
	}
	burst := quota.Burst
	if burst == 0 {
		burst = quota.Requests
	}
	ratePerSec := float64(quota.Requests) / quota.Window.Seconds()

	ctx, cancel := context.WithTimeout(ctx, redisCallTimeout)
	defer cancel()

	now := time.Now()
	res, err := tokenBucketScript.Run(ctx, l.rdb,
		[]string{l.bucketKey(key, quota)},
		ratePerSec, burst, now.UnixMilli(), 1,
	).Slice()
	if err != nil {
		l.logGate.Warn(l.logger, "redis rate limiter unavailable; middleware failure mode applies",
			"error", err)
		return false, Info{}, err
	}
	if len(res) != 4 {
		err := fmt.Errorf("rate limit script returned %d values, want 4", len(res))
		l.logGate.Warn(l.logger, "redis rate limiter script mismatch", "error", err)
		return false, Info{}, err
	}

	allowed := toInt64(res[0]) == 1
	preTokens := toFloat(res[1])
	postTokens := toFloat(res[2])
	retryMs := toInt64(res[3])

	preRem := int(math.Floor(preTokens))
	if preRem < 0 {
		preRem = 0
	}
	info := Info{
		Limit:     quota.Requests,
		Remaining: preRem,
		ResetAt:   resetAt(now, postTokens, float64(burst), quota).Unix(),
	}
	if !allowed {
		info.RetryAfter = int(math.Ceil(float64(retryMs) / 1000.0))
		if info.RetryAfter < 1 {
			info.RetryAfter = 1
		}
	}
	return allowed, info, nil
}

// bucketKey namespaces and hashes the caller key. Hashing (a) keeps
// principal IDs and client IPs out of Redis keyspace listings, and
// (b) folds in a quota fingerprint so a role/quota change starts a
// fresh bucket — parity with TokenBucketLimiter.getOrCreate, which
// discards the bucket when the quota differs.
func (l *RedisLimiter) bucketKey(key string, quota Quota) string {
	fp := fmt.Sprintf("%s\x00%d:%d:%d", key, quota.Requests, int64(quota.Window), quota.Burst)
	sum := sha256.Sum256([]byte(fp))
	return l.prefix + hex.EncodeToString(sum[:16])
}

func toInt64(v interface{}) int64 {
	if n, ok := v.(int64); ok {
		return n
	}
	return 0
}

func toFloat(v interface{}) float64 {
	s, ok := v.(string)
	if !ok {
		return 0
	}
	var f float64
	_, _ = fmt.Sscanf(s, "%g", &f)
	return f
}
