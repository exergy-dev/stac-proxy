# Changelog

All notable changes to this project will be documented here. Format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] — 2026-05-11

First production-ready release. Single binary, opt-in CQL2 filter
injection, federation across N upstream STAC APIs.

### Added

- **CQL2 filter injection** (authz middleware). When `cql2_injection.enabled`
  is true, an OPA policy can emit `cql2_filter` (or `cql2_filter_json`)
  constraints; the proxy AND-combines them with the client filter and
  forwards to the upstream STAC API. Honours `filter-lang`.
- **Geofence push-down** as `S_INTERSECTS` for upstreams that advertise
  the STAC Filter Extension; response-side post-filter for those that
  don't, including `NOT S_INTERSECTS` for `DeniedArea`.
- **Single-record GET validation**: GET `/collections/{id}/items/{id}`
  responses are evaluated against the policy CQL2; non-matches return
  404 rather than leaking existence.
- **Conformance probe at boot**: each federation origin and the
  single-origin upstream is probed for the Filter Extension URI, and
  `SupportsFilterExtension` is auto-populated when unset.
- **All auth providers wired**: bearer/JWT (static HMAC, remote JWKS
  with key rotation via singleflight), OIDC discovery with RSA and EC
  key parsing per RFC 7518, API key (header or query parameter).
- **Per-origin Filter Extension gate**: CQL2 push-down only fires when
  the target upstream advertises support; conservative AND across
  origins in federation mode.
- **Per-method / per-collection Rego branching** example in
  `policies/stac_authz.rego`.
- **Observability**: every Prometheus metric is emitted by the relevant
  middleware (`requests_total`, `upstream_*`, `cache_*`, `auth_*`,
  `ratelimit_exceeded_total`, `federation_*`, new `cql2_injected_total`).
- **Request ID flow**: UUIDv4 generated when missing; propagated to
  upstream calls via `X-Request-ID`; surfaced in response headers.
- **Graceful shutdown**: SIGTERM now drains in-flight requests up to
  30s before exit (previously: shutdown was a no-op and requests were
  abandoned).
- **Request body size limit**: default 1 MiB via `http.MaxBytesReader`
  middleware; configurable via `server.max_body_bytes`.
- **STAC Properties extras round-trip**: custom MarshalJSON /
  UnmarshalJSON so extension properties (`eo:cloud_cover`,
  `stac_proxy:origin`, etc.) survive proxy → upstream → response.
- **Container hardening**: pinned base image patch versions, non-root
  numeric UID, no shell or HTTP client in the runtime image, healthcheck
  via the binary's own `--healthcheck` flag.
- **CI/CD**: GitHub Actions workflows for test+lint+image-build on PR,
  multi-arch container release on tag push, golangci-lint config,
  Makefile with self-documenting targets, ldflags-based version
  injection.
- **Docs**: README, deployment guide, OPA policy authoring guide,
  observability reference, LICENSE (Apache-2.0), SECURITY, CONTRIBUTING.

### Fixed

- Federation route logic was short-circuiting on explicit collection
  matches and excluding implicit origins.
- Federation `MergeSearchResults` was returning un-merged feature
  copies even when the merge strategy fired.
- `FederatedCursor.IsExpired` boundary off-by-one — second-granularity
  expiry never tripped at the boundary.
- Federation `parseSearchRequest` panicked on absent bodies (typed nil
  in `*bytes.Reader`).
- Authz: `Properties.Extra` was tagged `json:"-"` and silently dropped
  through JSON round-trips; custom marshalers added.
- Authz: `policy.matches()` treated an empty `Actions` slice as "no
  constraint" (match-all); now fails closed.
- Authz geofence: `ValidateRequest` allowed bboxes that merely
  overlapped the geofence; strict-Contains is the secure default.
- OPA constraints: `parseEmbeddedResult` now unwraps the `result`
  field when the default query is `data.stac.authz`; numeric values
  tolerate `json.Number`, `int*`, and `float64`; `required_filters`
  is extracted.
- OPA multi-file loading: `dedupeDefaultRules` strips duplicate
  `default <rule>` declarations across modules so policies can be
  split across files without OPA's "multiple defaults" error.
- Proxy: empty `baseURL` errors loudly; `Do` parses query strings out
  of `path` properly; `--version` reports something meaningful.
- Server: actually calls `srv.Shutdown` on signal.

### Known limitations (deferred to v0.2)

- STAC Transaction Extension (POST/PUT/PATCH/DELETE) routes not wired.
- External OPA URL mode rejected by main; only embedded OPA works.
- Redis cache store interface mismatched with MemoryStore; main
  rejects `store: redis`.
- Config hot reload (`server.hot_reload`) is a no-op stub.
- OpenTelemetry tracing not yet instrumented.
- Per-origin circuit breakers and retry budgets are config-only —
  no enforcement loop yet.
- mTLS for federation origins; AWS SigV4 IAM role chain.
- Kubernetes manifests / Helm chart (Docker-only deploy supported).
