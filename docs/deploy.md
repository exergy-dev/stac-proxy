# Deployment guide

## Docker (single node)

```bash
make image                                  # builds stac-proxy:dev
docker run --rm -p 8080:8080 stac-proxy:dev \
  --config /etc/stac-proxy/example.yaml
```

The image:
- Runs as non-root UID 65532.
- Exposes 8080 (HTTP API).
- Self-healthchecks via `stac-proxy --healthcheck` (no curl/wget in the runtime image).
- Responds to SIGTERM with a 30s graceful drain.

## docker compose

```bash
docker compose -f deployments/docker/docker-compose.yaml up -d
curl -fsS http://localhost:8080/health
docker compose -f deployments/docker/docker-compose.yaml logs -f
docker compose -f deployments/docker/docker-compose.yaml down
```

The compose file mounts `configs/example.yaml` + `policies/` read-only,
injects placeholder env vars, and sets `stop_grace_period: 45s` so the
drain finishes cleanly.

## Multiple replicas (Compose + HAProxy)

For horizontal scale on a single VM, run N replicas behind a sticky
HAProxy edge:

```
client → HAProxy (:8080) → { replica-1, replica-2, … replica-N }
```

```bash
CURSOR_SECRET=$(openssl rand -hex 32) \
  docker compose -f deployments/docker/docker-compose.multi.yaml up -d --scale stac-proxy=3
curl -fsS http://localhost:8080/health          # via HAProxy
docker compose -f deployments/docker/docker-compose.multi.yaml down
```

**Why stickiness.** Every replica keeps its hot state in-memory and
per-replica: the response cache, the rate-limit token buckets, and the
federation page cache. There is no Redis. HAProxy uses `balance source`
with consistent hashing to pin each client to one replica, so that
per-replica state behaves correctly — a client's cache hits, rate-limit
counters, and page-cache-backed `rel: prev`/`rel: first` navigation all
stay on the instance that holds them.

**Quota semantics.** Because a client sticks to one replica, its
per-client rate-limit quota is preserved exactly. The aggregate cluster
quota across *distinct* clients is `quota × N` (N replicas each enforce
the quota against the subset of clients hashed to them). This is
intended: the limiter is a per-client control, not a global one.

**`cursor_secret` is required and must be identical.** In federation
mode the cursor secret is mandatory (validation fails without it), and
every replica must use the **same** value so a cursor minted on one
replica verifies on any other. Generate once and inject via the
`CURSOR_SECRET` env var:

```bash
CURSOR_SECRET=$(openssl rand -hex 32)
```

The multi-replica compose has a single `stac-proxy` service definition,
so all scaled replicas inherit the same env — the secret is identical by
construction.

**Replica death.** When a replica fails its `GET /health` check (2
consecutive failures) HAProxy removes it from the hash ring. Consistent
hashing remaps only the clients that were pinned to the dead replica
(~1/N), leaving everyone else put. A remapped client's in-flight
`rel: prev`/`rel: first` requests degrade to a fresh re-fan-out, because
the new replica does not hold that client's page cache — but the cursors
themselves still verify anywhere, since the secret is shared.

**Scale ceiling.** HAProxy's `server-template` pre-templates a fixed
number of replica slots (6 in the bundled `haproxy.cfg`). Scaling beyond
that leaves extra replicas unrouted; raise the template count and
re-deploy the edge to lift the ceiling.

**Never publish replica ports directly.** Only HAProxy is bound off-box.
Publishing a replica's port bypasses the edge and re-opens
`X-Forwarded-For` spoofing of the rate limiter and logs (chi RealIP
trusts XFF unconditionally). HAProxy owning that header — deleting the
inbound value and setting it from the real source — is the whole point
of the trust boundary.

## Configuration

YAML with environment-variable expansion applied at load. Expansion
runs over config **values only** — never comments or mapping keys.

| Top-level key | Required | Purpose |
|---|---|---|
| `server` | yes | host/port/TLS/timeouts/`max_body_bytes`/`max_header_bytes` (inbound request-header cap, default 64 KiB) |
| `logging` | no | level (debug/info/warn/error), format (json/console) |
| `health` | no | `/health` settings + upstream probe interval |
| `mode` | yes | `single` or `federation` |
| `upstream` | iff `mode: single` | URL, timeout, `supports_filter_extension` |
| `federation` | iff `mode: federation` | origins list + conflict strategy + page size limits |
| `middleware` | no | ordered list: `logging`, `auth`, `cache`, `cors`, `rate_limit`, `url_remap` |
| `authz` | no | OPA-backed authorization with optional CQL2 injection |

### Environment-variable injection

Expansion follows a strict, url_remap-safe contract:

- `${VAR}` — substitutes `VAR`. If `VAR` is unset **and** has no
  `:-default`, the load fails with an error listing every missing
  variable (an unset secret must never silently become `""`).
- `${VAR:-default}` — `VAR`'s value when set and non-empty, otherwise
  the literal `default` text (the default is not itself expanded).
- `$$` — escapes a single literal `$`.
- Bare `$VAR` (no braces) is left **literal** and never expanded. This
  protects `url_remap` regex replacements such as `$1`/`$2`.

Expansion applies to string **values** only — YAML comments and keys
are untouched. Example:

```yaml
upstream:
  url: "${STAC_UPSTREAM_URL}"
middleware:
  - name: auth
    config:
      providers:
        - type: bearer
          secret: "${JWT_SECRET}"
```

Validate before deploy:

```bash
./stac-proxy --validate --config /etc/stac-proxy/config.yaml
```

## TLS termination

Two supported patterns:

**1. Sidecar (recommended for K8s/cloud-run).** Terminate TLS at an
ingress / load balancer / Caddy / Envoy sidecar; run stac-proxy on
plain HTTP behind it. Set `server.tls.enabled: false`.

**2. Proxy-managed.** Point `server.tls.cert_file` and `key_file` at
PEM files mounted into the container. stac-proxy negotiates TLS 1.2+
with modern ECDHE-AES-GCM cipher suites; weaker cipher suites are
disabled (no per-config override in v0.1).

```yaml
server:
  tls:
    enabled: true
    cert_file: /etc/ssl/certs/stac-proxy.pem
    key_file:  /etc/ssl/private/stac-proxy.key
```

## Observability

Operational signals are exposed via:
- structured `log/slog` JSON logs (every request, every upstream call),
- `/health`, `/health/live`, `/health/ready` endpoints (aggregated origin status).

Metrics exposition was intentionally removed in favour of log-based
analysis; downstream collectors (Loki, Vector, Datadog logs) can derive
rate/error/latency series from the structured logs.

## Sizing & resource limits

The compose file sets a conservative 1 CPU / 512 MB limit. Tune by
load profile:

| Workload | CPU | Memory | Notes |
|---|---|---|---|
| Read-mostly federation of 2–3 origins | 0.5–1 | 256 MB | Cache miss dominated by upstream latency |
| Heavy CQL2 injection (geofence + per-tenant filter) | 1–2 | 512 MB | Evaluator + JSON marshal hot path |
| Cache-warm read traffic (>1k RPS) | 1 | 1 GB | Larger `cache.max_size` for hit-rate; CPU pinned by JSON encode |

Vertical-scale first; horizontal-scale once you cap a single instance.
stac-proxy is stateless except for the in-memory cache, so horizontal
scaling Just Works — at the cost of cache duplication per replica.

## Pagination & page cache

Federation responses paginate via HMAC-signed cursors. To enable
backwards navigation (`rel: prev`, `rel: first`) the proxy keeps a
rendered-page cache so a returning client can replay an earlier page
without re-fanning out to every origin.

**Prerequisite.** `federation.cursor_secret` (HMAC key, ≥32 bytes
recommended; generate with `openssl rand -hex 32`) is **required** in
federation mode — validation fails without it. Use the identical value
across every replica, otherwise a client's `next`/`prev` cursor breaks
when it lands on a different instance.

**When to enable.** Federation deployments with deep pagination
workloads where clients walk back over previously-returned pages. The
cache is keyed by cursor signature + principal hash, so entries never
cross tenants. Single-origin pass-through deployments do not need it.

**Configuration.** Defaults are usually fine; tune only if profiling
shows pressure.

```yaml
federation:
  cursor_secret: "${CURSOR_SECRET}"
  page_cache:
    enabled: true        # omit to default-on whenever cursor_secret is set
    max_entries: 1024    # LRU eviction at the cap
    ttl: 1h              # capped at the cursor's remaining lifetime
```

**Memory footprint (rough).** Each entry stores one rendered page of
items. Estimate `max_entries × page_size × avg_item_bytes`. For
1024 entries × 100 items × 4 KB ≈ 400 MB worst case; in practice items
are smaller and the LRU rarely fills.

**Disabling.** Set `page_cache.enabled: false` while keeping the
cursor secret (forward-only pagination remains signed). The cursor
secret itself cannot be omitted in federation mode.

**Horizontal scaling.** Like the response cache, the page cache is
per-replica in-memory only. A sticky-session load balancer keeps a
given client's page chain on the same replica; without stickiness, a
`prev` request that lands on a different replica falls back to re-
fetching from origins.

## Graceful shutdown

stac-proxy traps SIGINT/SIGTERM, cancels the parent context, and calls
`srv.Shutdown` with a 30-second deadline. Operators should:

- Set the container `stop_grace_period` to at least 35s (compose
  default is 10s; the bundled compose uses 45s).
- Send SIGTERM, not SIGKILL, for rolling deploys.
- Drain at the load balancer first (stop sending new requests, wait
  for the readiness probe to flip) so in-flight requests can complete.

## Health endpoints

- `/health` — runs every registered Check on demand and reports
  per-check status. Returns 200 only if all are healthy.
- `/health/live` — process liveness; always 200 unless the server has
  failed catastrophically.
- `/health/ready` — readiness; alias to `/health` today.

Configure your orchestrator's probes:

| Probe | Path | Behaviour |
|---|---|---|
| `livenessProbe` | `/health/live` | Restart on failure |
| `readinessProbe` | `/health/ready` | Pull from LB rotation on failure |
| `startupProbe` (K8s 1.18+) | `/health/ready` | Allow slow first boot |

## Trust boundary: deploy behind an L7 proxy

`stac-proxy` uses chi's `RealIP` middleware (wired automatically; no
configuration surface) to populate `http.Request.RemoteAddr` from
`X-Forwarded-For` / `X-Real-IP`. That middleware **does not** validate
the source — any unauthenticated client can spoof its IP simply by
adding the header.

You MUST deploy this service behind a TLS-terminating L7 reverse proxy
(nginx, Envoy, ALB, Cloud Run, etc.) that:

1. Sets `X-Forwarded-For` / `X-Forwarded-Proto` / `X-Forwarded-Host`
   itself based on the real connecting socket.
2. **Strips or overwrites** any inbound `X-Forwarded-*` headers the
   client supplies so they cannot leak through.

If you expose `stac-proxy` directly to untrusted clients, every log
entry's `remote_addr`, every IP-based rate-limit decision, and every
audit field that quotes the request's client IP is forgeable.

## Migration / upgrades

Stateless; rolling upgrade is the default. To rotate configs, push a
new ConfigMap or rebuild the image and `docker compose up -d --force-recreate`.
