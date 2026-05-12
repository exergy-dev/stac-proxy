# Deployment guide

## Docker (single node)

```bash
make image                                  # builds stac-proxy:dev
docker run --rm -p 8080:8080 stac-proxy:dev \
  --config /etc/stac-proxy/example.yaml
```

The image:
- Runs as non-root UID 65532.
- Exposes 8080 (HTTP API) and 9090 (Prometheus `/metrics`).
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

## Configuration

YAML; `${ENV_VAR}` expansion happens at load (`os.ExpandEnv`).

| Top-level key | Required | Purpose |
|---|---|---|
| `server` | yes | host/port/TLS/timeouts/`max_body_bytes`/`hot_reload` (v0.2) |
| `logging` | no | level (debug/info/warn/error), format (json/console) |
| `metrics` | no | enable Prometheus exposition on a separate port |
| `health` | no | `/health` settings + upstream probe interval |
| `mode` | yes | `single` or `federation` |
| `upstream` | iff `mode: single` | URL, timeout, `supports_filter_extension` |
| `federation` | iff `mode: federation` | origins list + conflict strategy + page size limits |
| `middleware` | no | ordered list: `logging`, `auth`, `cache`, `rate_limit`, `url_remap` |
| `authz` | no | OPA-backed authorization with optional CQL2 injection |

### Environment-variable injection

Use `${VAR}` or `${VAR:-default}` in any string value. Example:

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

## Observability scrape

Prometheus example:

```yaml
- job_name: stac-proxy
  static_configs:
    - targets: ['stac-proxy:9090']
  scrape_interval: 15s
```

See [observability.md](observability.md) for the full metric inventory.

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
scaling Just Works — at the cost of cache duplication per replica
(switch to Redis when v0.2 ships).

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

## Migration / upgrades

Stateless; rolling upgrade is the default. To rotate configs, push a
new ConfigMap or rebuild the image and `docker compose up -d --force-recreate`.
Hot reload (`server.hot_reload: true`) is currently a no-op — coming in v0.2.
