# stac-proxy

A high-performance reverse proxy for [STAC](https://stacspec.org/) APIs,
written in Go. It mediates between clients and one or many upstream STAC
servers, adding authentication, authorization (OPA + geofencing +
CQL2-injection), caching, rate limiting, URL signing, and federation.

> **Status: v0.1.0 — first production-ready release.**
> Pre-1.0; API and config keys may evolve. See [CHANGELOG.md](CHANGELOG.md).

## Why

Most STAC APIs are read-only and unauthenticated; the moment you put one
behind an enterprise login, geofence it, or stitch several together, you
need a middlebox. stac-proxy is that middlebox. Compared to
[developmentseed/stac-auth-proxy](https://github.com/developmentseed/stac-auth-proxy)
(Python), stac-proxy is a single statically-linked Go binary, can
federate multiple upstreams, and ships geofence push-down via
`S_INTERSECTS` for upstreams that support the STAC Filter Extension.

## Quickstart

```bash
# Build + run against a public STAC catalog
make build
./stac-proxy --config configs/example.yaml &
curl -s http://localhost:8080/search?limit=1 | jq '.features[0].id'

# Or via Docker
make image
make compose-up
curl -fsS http://localhost:8080/health
```

## Features

| | |
|---|---|
| **Auth** | Bearer/JWT (static HMAC or remote JWKS with key rotation), OIDC discovery (RSA/EC), API key (header or query) |
| **AuthZ** | Embedded OPA (Rego), CQL2 filter injection, geofencing (push-down via S_INTERSECTS or response-side post-filter) |
| **Modes** | Single-origin transparent proxy or N-origin federation with merge/dedup |
| **Caching** | In-memory LRU + TTL (Redis store is wired in code but not in main; v0.2) |
| **Rate limiting** | Sliding-window, per-principal or per-IP |
| **URL rewriting** | Configurable regex rules + optional HMAC / CloudFront signing |
| **Observability** | Prometheus metrics on every middleware, structured `log/slog` logs with UUID request IDs forwarded to upstream as `X-Request-ID` |
| **Resilience** | Graceful shutdown drains in-flight requests up to 30s on SIGTERM |
| **Security** | Configurable request body size cap (default 1 MiB), TLS 1.2+ with modern cipher suite |

## Configuration

YAML, with `${ENV_VAR}` expansion. See:

- [`configs/example.yaml`](configs/example.yaml) — single-origin
- [`configs/federation-example.yaml`](configs/federation-example.yaml) — multi-origin
- [`policies/stac_authz.rego`](policies/stac_authz.rego) — example OPA policy

Validate before deploying:

```bash
./stac-proxy --validate --config /path/to/your/config.yaml
```

## Docs

- [docs/deploy.md](docs/deploy.md) — Docker / docker-compose deployment, env-var matrix, TLS, observability scrape
- [docs/policies.md](docs/policies.md) — Writing OPA policies: AuthzInput schema, every constraint key the proxy understands, worked examples
- [docs/observability.md](docs/observability.md) — Every metric, health endpoints, log fields, request-ID flow
- [design.md](design.md) — Architecture deep dive (3,710 lines; for contributors)

## Build & test

```bash
make build          # ./stac-proxy
make test           # all unit + integration
make race           # with -race
make lint           # golangci-lint
make image          # container image
make ci             # what GitHub Actions runs
```

## Versioning & release

- Tags: `vMAJOR.MINOR.PATCH` (semver). Tag pushes trigger the release workflow.
- Container images: `ghcr.io/<org>/stac-proxy:<tag>` and `:latest`.
- Binary embeds version/commit/date via `-ldflags`. Check with `./stac-proxy --version`.

## Roadmap

- v0.2: STAC Transaction Extension, external OPA URL mode, Redis cache, config hot-reload, OpenTelemetry tracing, per-origin circuit breakers, Kubernetes / Helm artefacts.
- See [CHANGELOG.md](CHANGELOG.md) for what shipped when.

## Contributing & security

- [CONTRIBUTING.md](CONTRIBUTING.md) — dev setup, test/lint conventions, PR guidance
- [SECURITY.md](SECURITY.md) — vulnerability reporting
- [LICENSE](LICENSE) — Apache-2.0
