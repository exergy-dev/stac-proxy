// Package observability provides metrics, health checks, and tracing.
package observability

import (
	"net/http"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics contains all Prometheus metrics for the proxy.
type Metrics struct {
	// Request metrics
	RequestsTotal   *prometheus.CounterVec
	RequestDuration *prometheus.HistogramVec

	// Upstream/Origin metrics
	UpstreamRequestsTotal   *prometheus.CounterVec
	UpstreamRequestDuration *prometheus.HistogramVec
	UpstreamErrors          *prometheus.CounterVec

	// Cache metrics
	CacheHits   *prometheus.CounterVec
	CacheMisses *prometheus.CounterVec

	// Auth metrics
	AuthSuccesses *prometheus.CounterVec
	AuthFailures  *prometheus.CounterVec

	// Rate limit metrics
	RateLimitExceeded *prometheus.CounterVec

	// Federation metrics
	FederationOriginsQueried *prometheus.CounterVec

	// CQL2 injection metrics
	CQL2Injected *prometheus.CounterVec // labels: lang, reason ("policy"|"geofence"|"merged")
}

// NewMetrics creates all metrics and registers them on the global
// Prometheus registry. Equivalent to NewMetricsWith(namespace,
// prometheus.DefaultRegisterer). Panics on duplicate registration —
// callers that may run more than once per process (notably tests)
// should use NewMetricsWith with a per-instance registerer.
func NewMetrics(namespace string) *Metrics {
	return NewMetricsWith(namespace, prometheus.DefaultRegisterer)
}

// NewMetricsWith creates all metrics and registers them on reg. A nil
// reg is treated as "do not register" (useful for in-memory test
// scaffolds that just want the *Vec handles without a registry).
func NewMetricsWith(namespace string, reg prometheus.Registerer) *Metrics {
	if namespace == "" {
		namespace = "stac_proxy"
	}

	register := func(c prometheus.Collector) {
		if reg != nil {
			reg.MustRegister(c)
		}
	}

	requestsTotal := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "requests_total",
			Help:      "Total number of HTTP requests",
		},
		[]string{"method", "path", "status"},
	)
	register(requestsTotal)

	requestDuration := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "request_duration_seconds",
			Help:      "HTTP request duration in seconds",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"method", "path"},
	)
	register(requestDuration)

	upstreamRequestsTotal := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "upstream_requests_total",
			Help:      "Total number of requests to upstream servers",
		},
		[]string{"origin", "status"},
	)
	register(upstreamRequestsTotal)

	upstreamRequestDuration := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "upstream_request_duration_seconds",
			Help:      "Upstream request duration in seconds",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"origin"},
	)
	register(upstreamRequestDuration)

	upstreamErrors := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "upstream_errors_total",
			Help:      "Total number of upstream request errors",
		},
		[]string{"origin", "error_type"},
	)
	register(upstreamErrors)

	cacheHits := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "cache_hits_total",
			Help:      "Total number of cache hits",
		},
		[]string{"type"},
	)
	register(cacheHits)

	cacheMisses := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "cache_misses_total",
			Help:      "Total number of cache misses",
		},
		[]string{"type"},
	)
	register(cacheMisses)

	authSuccesses := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "auth_successes_total",
			Help:      "Total number of successful authentications",
		},
		[]string{"provider"},
	)
	register(authSuccesses)

	authFailures := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "auth_failures_total",
			Help:      "Total number of failed authentications",
		},
		[]string{"provider", "reason"},
	)
	register(authFailures)

	rateLimitExceeded := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "rate_limit_exceeded_total",
			Help:      "Total number of rate limit exceeded events",
		},
		[]string{"key_type"},
	)
	register(rateLimitExceeded)

	federationOriginsQueried := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "federation_origins_queried_total",
			Help:      "Total number of origins queried in federation",
		},
		[]string{"origin", "success"},
	)
	register(federationOriginsQueried)

	cql2Injected := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "cql2_injected_total",
			Help:      "Total number of requests where an authz-derived CQL2 filter was injected",
		},
		[]string{"lang", "reason"},
	)
	register(cql2Injected)

	return &Metrics{
		RequestsTotal:            requestsTotal,
		RequestDuration:          requestDuration,
		UpstreamRequestsTotal:    upstreamRequestsTotal,
		UpstreamRequestDuration:  upstreamRequestDuration,
		UpstreamErrors:           upstreamErrors,
		CacheHits:                cacheHits,
		CacheMisses:              cacheMisses,
		AuthSuccesses:            authSuccesses,
		AuthFailures:             authFailures,
		RateLimitExceeded:        rateLimitExceeded,
		FederationOriginsQueried: federationOriginsQueried,
		CQL2Injected:             cql2Injected,
	}
}

// Handler returns the Prometheus exposition HTTP handler for these
// metrics. Mount on /metrics from the metrics server.
func (m *Metrics) Handler() http.Handler {
	return promhttp.Handler()
}

// Label values used across metric emissions. Defined as constants so
// PromQL queries can be grepped to a single declaration and label
// cardinality stays under control.
const (
	UpstreamStatusOK    = "ok"
	UpstreamStatusError = "error"

	ErrClassNetwork  = "network"
	ErrClassCanceled = "canceled"
	ErrClassTimeout  = "timeout"

	CQL2ReasonPolicy   = "policy"
	CQL2ReasonGeofence = "geofence"
	CQL2ReasonMerged   = "merged"
)

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
