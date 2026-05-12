# Observability reference

## Metrics

stac-proxy exposes Prometheus metrics on a separate port (default 9090,
configurable via `metrics.port`) at `metrics.path` (default `/metrics`).
All metric names are prefixed `stac_proxy_`.

### HTTP / proxy hot path

| Metric | Type | Labels | When emitted |
|---|---|---|---|
| `stac_proxy_requests_total` | counter | `method`, `path`, `status` | Per inbound request |
| `stac_proxy_request_duration_seconds` | histogram | `method`, `path` | Per inbound request |
| `stac_proxy_requests_in_flight` | gauge | — | Currently-processing requests |
| `stac_proxy_upstream_requests_total` | counter | `origin`, `status` | Per upstream call (federation origin ID, or `"upstream"` in single mode) |
| `stac_proxy_upstream_request_duration_seconds` | histogram | `origin` | Per upstream call |
| `stac_proxy_upstream_errors_total` | counter | `origin`, `error_type` | Upstream call failed. `error_type` ∈ `network`, `timeout`, `canceled` |

### Cache

| Metric | Type | Labels |
|---|---|---|
| `stac_proxy_cache_hits_total` | counter | `type` (request type: search, items, collections) |
| `stac_proxy_cache_misses_total` | counter | `type` |
| `stac_proxy_cache_size` | gauge | — |

### Auth

| Metric | Type | Labels |
|---|---|---|
| `stac_proxy_auth_successes_total` | counter | `provider` (bearer/api_key/anonymous), `principal_type` |
| `stac_proxy_auth_failures_total` | counter | `provider`, `reason` |

### Rate limit

| Metric | Type | Labels |
|---|---|---|
| `stac_proxy_rate_limit_exceeded_total` | counter | `key_type` (`principal` or `ip`) |

### Federation

| Metric | Type | Labels |
|---|---|---|
| `stac_proxy_federation_origins_queried_total` | counter | `origin`, `status` (`ok` / `error`) |
| `stac_proxy_federation_items_merged_total` | counter | — |
| `stac_proxy_federation_duplicates_total` | counter | — |

### CQL2 injection

| Metric | Type | Labels |
|---|---|---|
| `stac_proxy_cql2_injected_total` | counter | `lang` (`cql2-text` / `cql2-json`), `reason` (`policy` / `geofence` / `merged`) |

`reason=merged` indicates both a policy filter and a pushed-down geofence
were AND-combined.

## Suggested Grafana panels

- **Request rate by status**: `sum by (status) (rate(stac_proxy_requests_total[1m]))`
- **p95 latency**: `histogram_quantile(0.95, sum by (le, path) (rate(stac_proxy_request_duration_seconds_bucket[5m])))`
- **Cache hit ratio**: `rate(stac_proxy_cache_hits_total[5m]) / (rate(stac_proxy_cache_hits_total[5m]) + rate(stac_proxy_cache_misses_total[5m]))`
- **Federation per-origin success**: `sum by (origin) (rate(stac_proxy_federation_origins_queried_total{status="ok"}[5m]))`
- **CQL2 injection mix**: `sum by (reason) (rate(stac_proxy_cql2_injected_total[5m]))`

## Health endpoints

| Path | Purpose | Behaviour |
|---|---|---|
| `/health` | Aggregate — runs every Check on demand | 200 only if all checks healthy |
| `/health/live` | Liveness | Always 200 unless the server's in a fatal state |
| `/health/ready` | Readiness | Alias to `/health` today; will become smarter when background health polling lands |

## Logs

stac-proxy uses [zap](https://github.com/uber-go/zap) and emits JSON by
default (`logging.format: json`).

### Standard fields

| Field | Where emitted | Notes |
|---|---|---|
| `timestamp` | always | ISO8601 |
| `level` | always | debug/info/warn/error |
| `caller` | always | `file:line` |
| `msg` | always | event name (e.g. `request_started`, `request_completed`, `federation_origin_search_failed`) |
| `request_id` | request-scoped | UUIDv4 |
| `method` | request-scoped | HTTP method |
| `path` | request-scoped | URL path |
| `status` | response-scoped | HTTP status code |
| `duration` | response-scoped | request → response time, `time.Duration` (ns) |
| `origin` | federation paths | origin ID |
| `error` | error-scoped | wrapped error string |

### Severity per status code

- `5xx` → `error`
- `4xx` → `warn`
- `2xx`/`3xx` → `info`

## Request ID flow

1. The chi router's `RequestID` middleware mints (or honours) an
   `X-Request-ID` header from the inbound HTTP request.
2. The proxy's logging middleware overrides this with a fresh UUIDv4
   when none is present, stores it in the request context, and surfaces
   it in `X-Request-ID` on the outbound response.
3. The proxy/federation HTTP clients forward the context's request ID
   as an `X-Request-ID` header on every upstream call.
4. Upstreams that honour `X-Request-ID` will log it on their side,
   making end-to-end traces grep-able by a single ID.

## Tracing

OpenTelemetry instrumentation isn't wired in v0.1. It's on the v0.2
roadmap (W3C Trace-Context propagation to upstreams + spans around
every middleware + federation fan-out).
