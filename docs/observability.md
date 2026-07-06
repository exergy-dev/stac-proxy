# Observability reference

## Metrics

stac-proxy does **not** expose a `/metrics` endpoint. Prometheus
exposition was intentionally removed; the binary is intended to be
observed via its structured logs. Downstream collectors (Loki, Vector,
Datadog logs, Elastic) can derive rate / error / latency series from
the per-request log events described below.

If you need a counter your environment depends on, derive it from logs:

- request rate by status — count of `msg="request_completed"` grouped by `status`
- p95 latency — quantile over the `duration` field on `msg="request_completed"`
- federation origin failures — `msg="federation_origin_search_failed"` grouped by `origin`

## Health endpoints

| Path | Purpose | Behaviour |
|---|---|---|
| `/health` | Aggregate — runs every Check on demand | 200 only if all checks healthy |
| `/health/live` | Liveness | Always 200 unless the server's in a fatal state |
| `/health/ready` | Readiness | Alias to `/health` today; will become smarter when background health polling lands |

## Logs

stac-proxy uses Go's standard [`log/slog`](https://pkg.go.dev/log/slog)
and emits JSON by default (`logging.format: json`). Setting
`logging.format: console` (or `text`) switches to the text handler for
local development.

### Standard fields

| Field | Where emitted | Notes |
|---|---|---|
| `time` | always | RFC3339Nano (slog default) |
| `level` | always | DEBUG / INFO / WARN / ERROR |
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

### Operational events worth alerting on (added in 1.0)

| `msg` | Level | Meaning |
|---|---|---|
| `circuit breaker opened; fast-failing origin` | warn | origin hit its consecutive-failure threshold; carries `origin`, `open_for` |
| `circuit breaker half-open; probing origin` / `circuit breaker closed; origin recovered` | info | breaker lifecycle |
| `federation returned partial results` | warn | a 200 was served with ≥1 origin missing (`failed_origins`); throttled to 1/30s |
| `federated search failed on every routed origin` | warn | the request became a 502 `UpstreamFederationFailure` |
| `redis get failed; treating as cache miss` (and similar `redis …` warns) | warn | Redis degraded; consumers are failing open; throttled to 1/30s with a `suppressed` count |
| `rate limiter backend unavailable` | warn | Redis limiter erroring; `failure_mode` decides allow vs 503 |

Partial responses also carry `X-Federation-Partial: true` and
`X-Federation-Failed-Origins` headers plus a per-origin
`stac_proxy:origins` block in the body's `context`, so client-side
detection doesn't require log access.

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

OpenTelemetry instrumentation isn't wired in. Observability is
log-based by design (structured slog with request-id propagation);
Prometheus exposition was intentionally removed. Tracing (W3C
Trace-Context propagation to upstreams + spans around every middleware
and federation fan-out) remains a possible future addition, not a
committed roadmap item.
