// Package observability provides metrics, health checks, and tracing.
package observability

import (
	"net/http"

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
	}
}

// DefaultMetrics is the global metrics instance.
var DefaultMetrics = NewMetrics("")

// Handler returns the Prometheus exposition HTTP handler for these
// metrics. Mount on /metrics from the metrics server.
func (m *Metrics) Handler() http.Handler {
	return promhttp.Handler()
}
