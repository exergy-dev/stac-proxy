// Package cache provides caching middleware.
package cache

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisStore implements CacheStore using Redis.
type RedisStore struct {
	client    redis.UniversalClient
	keyPrefix string
}

// RedisConfig configures the Redis cache store.
type RedisConfig struct {
	// Single node
	Addr     string
	Password string
	DB       int

	// Cluster
	Addrs []string

	// Sentinel
	MasterName       string
	SentinelAddrs    []string
	SentinelPassword string

	// Common options
	KeyPrefix      string
	PoolSize       int
	MinIdleConns   int
	MaxRetries     int
	DialTimeout    time.Duration
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
	PoolTimeout    time.Duration
	ConnMaxIdleAge time.Duration
}

// NewRedisStore creates a new Redis cache store.
func NewRedisStore(cfg RedisConfig) (*RedisStore, error) {
	var client redis.UniversalClient

	if len(cfg.Addrs) > 1 {
		// Cluster mode
		client = redis.NewClusterClient(&redis.ClusterOptions{
			Addrs:           cfg.Addrs,
			Password:        cfg.Password,
			PoolSize:        cfg.PoolSize,
			MinIdleConns:    cfg.MinIdleConns,
			MaxRetries:      cfg.MaxRetries,
			DialTimeout:     cfg.DialTimeout,
			ReadTimeout:     cfg.ReadTimeout,
			WriteTimeout:    cfg.WriteTimeout,
			PoolTimeout:     cfg.PoolTimeout,
			ConnMaxIdleTime: cfg.ConnMaxIdleAge,
		})
	} else if cfg.MasterName != "" {
		// Sentinel mode
		client = redis.NewFailoverClient(&redis.FailoverOptions{
			MasterName:       cfg.MasterName,
			SentinelAddrs:    cfg.SentinelAddrs,
			SentinelPassword: cfg.SentinelPassword,
			Password:         cfg.Password,
			DB:               cfg.DB,
			PoolSize:         cfg.PoolSize,
			MinIdleConns:     cfg.MinIdleConns,
			MaxRetries:       cfg.MaxRetries,
			DialTimeout:      cfg.DialTimeout,
			ReadTimeout:      cfg.ReadTimeout,
			WriteTimeout:     cfg.WriteTimeout,
			PoolTimeout:      cfg.PoolTimeout,
			ConnMaxIdleTime:  cfg.ConnMaxIdleAge,
		})
	} else {
		// Single node
		addr := cfg.Addr
		if addr == "" && len(cfg.Addrs) == 1 {
			addr = cfg.Addrs[0]
		}
		if addr == "" {
			addr = "localhost:6379"
		}

		client = redis.NewClient(&redis.Options{
			Addr:            addr,
			Password:        cfg.Password,
			DB:              cfg.DB,
			PoolSize:        cfg.PoolSize,
			MinIdleConns:    cfg.MinIdleConns,
			MaxRetries:      cfg.MaxRetries,
			DialTimeout:     cfg.DialTimeout,
			ReadTimeout:     cfg.ReadTimeout,
			WriteTimeout:    cfg.WriteTimeout,
			PoolTimeout:     cfg.PoolTimeout,
			ConnMaxIdleTime: cfg.ConnMaxIdleAge,
		})
	}

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, err
	}

	prefix := cfg.KeyPrefix
	if prefix == "" {
		prefix = "stac-proxy:"
	}

	return &RedisStore{
		client:    client,
		keyPrefix: prefix,
	}, nil
}

// prefixKey adds the key prefix.
func (s *RedisStore) prefixKey(key string) string {
	return s.keyPrefix + key
}

// Get retrieves a cached entry.
func (s *RedisStore) Get(ctx context.Context, key string) (*CacheEntry, error) {
	data, err := s.client.Get(ctx, s.prefixKey(key)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, nil // Cache miss
		}
		return nil, err
	}

	var entry CacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, err
	}

	return &entry, nil
}

// Set stores a cache entry.
func (s *RedisStore) Set(ctx context.Context, key string, entry *CacheEntry, ttl time.Duration) error {
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	return s.client.Set(ctx, s.prefixKey(key), data, ttl).Err()
}

// Delete removes a cache entry.
func (s *RedisStore) Delete(ctx context.Context, key string) error {
	return s.client.Del(ctx, s.prefixKey(key)).Err()
}

// Clear removes all cached entries with the prefix.
func (s *RedisStore) Clear(ctx context.Context) error {
	// Use SCAN to find and delete all keys with prefix
	var cursor uint64
	var keysDeleted int64

	for {
		var keys []string
		var err error

		keys, cursor, err = s.client.Scan(ctx, cursor, s.keyPrefix+"*", 100).Result()
		if err != nil {
			return err
		}

		if len(keys) > 0 {
			deleted, err := s.client.Del(ctx, keys...).Result()
			if err != nil {
				return err
			}
			keysDeleted += deleted
		}

		if cursor == 0 {
			break
		}
	}

	return nil
}

// Stats returns cache statistics.
func (s *RedisStore) Stats() CacheStats {
	ctx := context.Background()

	// Get info from Redis
	info, err := s.client.Info(ctx, "stats", "memory").Result()
	if err != nil {
		return CacheStats{}
	}

	// Parse relevant fields (simplified)
	stats := CacheStats{}

	// Count keys with prefix
	var cursor uint64
	var count int64
	for {
		keys, nextCursor, err := s.client.Scan(ctx, cursor, s.keyPrefix+"*", 100).Result()
		if err != nil {
			break
		}
		count += int64(len(keys))
		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}
	stats.Size = int(count)

	_ = info // Would parse for hit/miss rates

	return stats
}

// Close closes the Redis connection.
func (s *RedisStore) Close() error {
	return s.client.Close()
}

// Ping checks Redis connectivity.
func (s *RedisStore) Ping(ctx context.Context) error {
	return s.client.Ping(ctx).Err()
}

// SetNX sets a value only if the key doesn't exist (for distributed locks).
func (s *RedisStore) SetNX(ctx context.Context, key string, value interface{}, ttl time.Duration) (bool, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return false, err
	}
	return s.client.SetNX(ctx, s.prefixKey(key), data, ttl).Result()
}

// Expire updates the TTL of a key.
func (s *RedisStore) Expire(ctx context.Context, key string, ttl time.Duration) error {
	return s.client.Expire(ctx, s.prefixKey(key), ttl).Err()
}

// Keys returns all keys matching a pattern.
func (s *RedisStore) Keys(ctx context.Context, pattern string) ([]string, error) {
	var allKeys []string
	var cursor uint64

	for {
		keys, nextCursor, err := s.client.Scan(ctx, cursor, s.prefixKey(pattern), 100).Result()
		if err != nil {
			return nil, err
		}

		// Remove prefix from keys
		for _, k := range keys {
			if len(k) > len(s.keyPrefix) {
				allKeys = append(allKeys, k[len(s.keyPrefix):])
			}
		}

		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}

	return allKeys, nil
}
