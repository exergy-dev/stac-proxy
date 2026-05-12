// Package observability provides metrics, health checks, and tracing.
package observability

import (
	"net/http"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics contains all Prometheus metrics for the proxy.
type Metrics struct {
	// Request metrics
	RequestsTotal    *prometheus.CounterVec
	RequestDuration  *prometheus.HistogramVec
	RequestsInFlight prometheus.Gauge

	// Upstream/Origin metrics
	UpstreamRequestsTotal   *prometheus.CounterVec
	UpstreamRequestDuration *prometheus.HistogramVec
	UpstreamErrors          *prometheus.CounterVec

	// Cache metrics
	CacheHits   *prometheus.CounterVec
	CacheMisses *prometheus.CounterVec
	CacheSize   prometheus.Gauge

	// Auth metrics
	AuthSuccesses *prometheus.CounterVec
	AuthFailures  *prometheus.CounterVec

	// Rate limit metrics
	RateLimitExceeded *prometheus.CounterVec

	// Federation metrics
	FederationOriginsQueried *prometheus.CounterVec
	FederationItemsMerged    prometheus.Counter
	FederationDuplicates     prometheus.Counter

	// CQL2 injection metrics
	CQL2Injected *prometheus.CounterVec // labels: lang, reason ("policy"|"geofence"|"merged")
}

// NewMetrics creates and registers all metrics.
func NewMetrics(namespace string) *Metrics {
	if namespace == "" {
		namespace = "stac_proxy"
	}

	return &Metrics{
		RequestsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "requests_total",
				Help:      "Total number of HTTP requests",
			},
			[]string{"method", "path", "status"},
		),

		RequestDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Name:      "request_duration_seconds",
				Help:      "HTTP request duration in seconds",
				Buckets:   prometheus.DefBuckets,
			},
			[]string{"method", "path"},
		),

		RequestsInFlight: promauto.NewGauge(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Name:      "requests_in_flight",
				Help:      "Number of HTTP requests currently being processed",
			},
		),

		UpstreamRequestsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "upstream_requests_total",
				Help:      "Total number of requests to upstream servers",
			},
			[]string{"origin", "status"},
		),

		UpstreamRequestDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Name:      "upstream_request_duration_seconds",
				Help:      "Upstream request duration in seconds",
				Buckets:   prometheus.DefBuckets,
			},
			[]string{"origin"},
		),

		UpstreamErrors: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "upstream_errors_total",
				Help:      "Total number of upstream request errors",
			},
			[]string{"origin", "error_type"},
		),

		CacheHits: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "cache_hits_total",
				Help:      "Total number of cache hits",
			},
			[]string{"type"},
		),

		CacheMisses: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "cache_misses_total",
				Help:      "Total number of cache misses",
			},
			[]string{"type"},
		),

		CacheSize: promauto.NewGauge(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Name:      "cache_size_bytes",
				Help:      "Current cache size in bytes",
			},
		),

		AuthSuccesses: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "auth_successes_total",
				Help:      "Total number of successful authentications",
			},
			[]string{"provider"},
		),

		AuthFailures: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "auth_failures_total",
				Help:      "Total number of failed authentications",
			},
			[]string{"provider", "reason"},
		),

		RateLimitExceeded: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "rate_limit_exceeded_total",
				Help:      "Total number of rate limit exceeded events",
			},
			[]string{"key_type"},
		),

		FederationOriginsQueried: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "federation_origins_queried_total",
				Help:      "Total number of origins queried in federation",
			},
			[]string{"origin", "success"},
		),

		FederationItemsMerged: promauto.NewCounter(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "federation_items_merged_total",
				Help:      "Total number of items merged from federated sources",
			},
		),

		FederationDuplicates: promauto.NewCounter(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "federation_duplicates_total",
				Help:      "Total number of duplicate items detected in federation",
			},
		),

		CQL2Injected: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "cql2_injected_total",
				Help:      "Total number of requests where an authz-derived CQL2 filter was injected",
			},
			[]string{"lang", "reason"},
		),
	}
}

// Handler returns the Prometheus exposition HTTP handler for these
// metrics. Mount on /metrics from the metrics server.
func (m *Metrics) Handler() http.Handler {
	return promhttp.Handler()
}

// Process-wide instance, set once from main. Handlers and middleware
// call Default() to emit metrics without having to thread *Metrics
// through every constructor; Default() returns nil before SetDefault
// fires (so tests that don't initialise it stay silent).
var (
	defaultMu sync.RWMutex
	def       *Metrics
)

// SetDefault registers the process-wide *Metrics instance. Called
// once from main after NewMetrics succeeds. Subsequent calls
// overwrite (useful for tests that swap in a fresh registry).
func SetDefault(m *Metrics) {
	defaultMu.Lock()
	def = m
	defaultMu.Unlock()
}

// Default returns the process-wide *Metrics, or nil if SetDefault
// hasn't been called. Callers should guard with `if m := Default();
// m != nil { ... }` to no-op cleanly in tests.
func Default() *Metrics {
	defaultMu.RLock()
	defer defaultMu.RUnlock()
	return def
}
