// Package redisstore provides the shared Redis client and the KV cache
// store used when a component selects `store: redis`.
//
// One client is built in main() and shared by every consumer (response
// cache, page cache, rate limiter); main owns its lifecycle. Per-store
// Close() is therefore a no-op — see KV.Close.
package redisstore

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/redis/go-redis/v9"
)

// Config mirrors the top-level `redis:` YAML block. Field semantics
// follow go-redis defaults when zero-valued.
type Config struct {
	Addr         string
	Username     string
	Password     string
	DB           int
	KeyPrefix    string
	PoolSize     int
	MinIdleConns int
	DialTimeout  time.Duration
	ReadTimeout  time.Duration
	WriteTimeout time.Duration

	TLS TLSConfig
}

// TLSConfig configures TLS for the Redis connection.
type TLSConfig struct {
	Enabled            bool
	CAFile             string
	CertFile           string
	KeyFile            string
	InsecureSkipVerify bool
}

// Default connection budgets: short enough that a slow or dead Redis
// degrades requests by milliseconds (every consumer fails open), long
// enough for a healthy round trip under load.
const (
	defaultDialTimeout  = 2 * time.Second
	defaultReadTimeout  = 250 * time.Millisecond
	defaultWriteTimeout = 250 * time.Millisecond
)

// Keyspace layout. Every key is <operator key_prefix><component ns><digest>;
// the constants live here so wiring (main.go) and tests reference one
// definition and two components can never silently collide.
const (
	// DefaultKeyPrefix namespaces all of a proxy fleet's keys; override
	// via redis.key_prefix when multiple fleets share one Redis.
	DefaultKeyPrefix = "stacproxy:"
	// NSResponseCache prefixes response-cache entries.
	NSResponseCache = "rc:"
	// NSPageCache prefixes federation page-cache entries.
	NSPageCache = "pg:"
	// NSRateLimit prefixes rate-limit bucket hashes.
	NSRateLimit = "rl:"
)

// New builds a redis.UniversalClient from cfg. Single-node today;
// UniversalClient keeps the door open for Sentinel/Cluster without
// changing any consumer. Reachability is NOT verified here — callers
// that want a boot-time probe should PING and log, not fail: every
// consumer is designed to fail open, so a proxy that boots during a
// Redis outage must still serve traffic.
func New(cfg Config) (redis.UniversalClient, error) {
	if cfg.Addr == "" {
		return nil, fmt.Errorf("redis: addr is required")
	}
	opts := &redis.UniversalOptions{
		Addrs:        []string{cfg.Addr},
		Username:     cfg.Username,
		Password:     cfg.Password,
		DB:           cfg.DB,
		PoolSize:     cfg.PoolSize,
		MinIdleConns: cfg.MinIdleConns,
		DialTimeout:  orDefault(cfg.DialTimeout, defaultDialTimeout),
		ReadTimeout:  orDefault(cfg.ReadTimeout, defaultReadTimeout),
		WriteTimeout: orDefault(cfg.WriteTimeout, defaultWriteTimeout),
		// No command retries: every consumer fails open, so the right
		// response to a struggling Redis is an immediate miss, not
		// stacked retry latency on the request path.
		MaxRetries: -1,
		// Honor context deadlines for the WHOLE operation including
		// dial. Without this, go-redis v9 bounds commands only by
		// Dial/Read/WriteTimeout — so during an outage each consumer's
		// per-call context deadline is ignored and sequential ops
		// stack full 2s dial timeouts into user-visible seconds
		// (observed: 20s on the first request after killing Redis).
		ContextTimeoutEnabled: true,
	}
	if cfg.TLS.Enabled {
		tc, err := buildTLSConfig(cfg.TLS)
		if err != nil {
			return nil, fmt.Errorf("redis: %w", err)
		}
		opts.TLSConfig = tc
	}
	return redis.NewUniversalClient(opts), nil
}

// go-redis logs pool/dial trouble via a package-global logger set with
// redis.SetLogger — a plain variable write that races against any live
// client's pool goroutines. Setting it in init(), before any client
// can exist, is the only safe point. It also swaps go-redis's raw
// log.Printf lines (which would break the proxy's structured JSON
// output) for slog Debug; the stores' throttled warnings remain the
// operator-facing signal.
func init() {
	redis.SetLogger(slogAdapter{})
}

// slogAdapter satisfies go-redis's internal Logging interface.
type slogAdapter struct{}

func (slogAdapter) Printf(ctx context.Context, format string, v ...interface{}) {
	slog.DebugContext(ctx, fmt.Sprintf(format, v...), "component", "go-redis")
}

func orDefault(d, def time.Duration) time.Duration {
	if d <= 0 {
		return def
	}
	return d
}

func buildTLSConfig(cfg TLSConfig) (*tls.Config, error) {
	tc := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: cfg.InsecureSkipVerify, // #nosec G402 — operator opt-in, mirrors server TLS posture
	}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read tls ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("tls ca_file %q contains no usable certificates", cfg.CAFile)
		}
		tc.RootCAs = pool
	}
	if cfg.CertFile != "" || cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load tls cert/key pair: %w", err)
		}
		tc.Certificates = []tls.Certificate{cert}
	}
	return tc, nil
}
