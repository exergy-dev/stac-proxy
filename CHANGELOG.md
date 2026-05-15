# Changelog

All notable changes to this project will be documented here. Format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

This release rolls up the post-v0.1.0 review-driven hardening pass: 5
subsystem-snapshot commits + 4 severity-tier PRs (CRITICAL → NIT) + a
docs PR, totaling ~80 fixes across auth, authz, federation, cache,
ratelimit, server, config, observability, stac, and remap. Highlights
below; see git log for the full list.

### Security (CRITICAL)

- **Auth** (`oidc.go`): JWT verification restricted to RSA/EC algs via
  `jwt.WithValidMethods` — closes the alg-confusion attack where an
  attacker forges HS256 using the JWKS public key bytes as the HMAC
  secret.
- **AuthZ**: `AllowedCollections`, `DeniedCollections`, and
  `RequiredFilters` constraints are now actually *enforced* (previously
  collected but ignored). New `searchParserMiddleware` in
  `internal/server` parses the search body before authz so constraint
  application is no longer a no-op in production.
- **Cache** key now includes a principal-class component — anonymous
  responses no longer leak to authenticated callers and vice-versa.
- **Federation pagination**: per-search dedup state (was shared across
  concurrent searches, racing and silently dropping items).
- **Federation OAuth2**: first-call no longer returns an empty Bearer
  token; refresh wrapped in singleflight; lock released across the
  HTTP RTT.
- **Federation reverse-proxy fast path** uses
  `httpx.NewResponseCaptureWithLimit(MaxResponseBytes)` — a
  multi-GB upstream response can no longer OOM the proxy.
- **Remap** (breaking): stub `CloudFrontSigner` and `S3PresignedSigner`
  removed (they performed no real signing); `signer.type: cloudfront` /
  `signer.type: s3_presigned` now error at config validation. Use
  `hmac` for now or contribute a real signer.

### Security (HIGH)

- **Auth provider chain** fails closed on a bad-signature credential
  rather than falling through to anonymous (new optional
  `CredentialClaimer` interface).
- **JWKS** unknown-`kid` flood is throttled (per-URL min refresh
  interval + negative cache for missing kids).
- **API keys** are now stored as HMAC-SHA256 digests, not plaintext —
  database-leak defense in depth.
- **mTLS provider** rejects nil `trustedCAs` in its constructor.
- **Single-record CQL2 validation** runs unconditionally when
  constraints exist (was gated on `CQL2InjectionEnabled`).
- **Geofence**: `maybePushDownGeofence` no longer mutates shared
  constraints; geometry property name configurable per backend;
  push-down skipped when upstream lacks spatial-predicate support;
  malformed FeatureCollection on a 2xx returns 502 (was fail-open).
- **Local CQL2 evaluator** implements `S_INTERSECTS` via the geo
  package — items that match a pushed-down geofence are no longer
  spuriously 404'd.
- **OPA dedupe**: regex-based `default`-rule dedup removed; duplicate
  defaults now surface as compile errors (the regex could silently
  strip `default allow = false`, turning policies fail-open).
- **TLS**: hardcoded `CipherSuites` dropped (lets Go pick the vetted
  set); `NextProtos: [h2, http/1.1]` added.
- **Federation**: SigV4 swapped from a hand-rolled implementation to
  `aws-sdk-go-v2/aws/signer/v4` (correctly handles non-default ports
  and URI-encoded paths); GET `/search` parsing delegated to
  `stac.Parser`; asset signing honors request context.
- **Cache memory**: `Get` returns an independent copy; LRU now O(1) via
  `container/list`; cache key normalizes query-param order.
- **httpx**: retryable transport no longer retries POST/PATCH by
  default (avoids double-execution of non-idempotent search).
- **XFF**: trusted-proxy aware client-IP derivation honored only when
  the immediate hop is in `server.trusted_proxies`.
- **Ratelimit** map is now LRU-bounded — defeats memory exhaustion via
  IP-rotation floods.
- **Prometheus** metrics use the chi route pattern instead of the raw
  path — bounded label cardinality.

### Security (MEDIUM)

- **JWKS**: stale-while-revalidate during issuer outages; `use=sig`
  filter; binds cached keys to declared `alg`.
- **Basic auth**: bcrypt-prefix detection prevents corrupt base64-
  decoded hashes.
- **OIDC** copies only allowlisted claims into `Principal.Attributes`
  and stamps `auth_method=oidc` server-side (token can't spoof).
- **API key** query-parameter mode disabled by default; opt-in emits
  WARN logs.
- **Authz**: external OPA `OnError: deny|allow` config (default
  `deny`); empty `PrincipalMatcher` matches nothing (was: matches
  everyone); header extraction switched to allowlist; missing OPA
  `allow` key surfaces as InternalError instead of silent deny.
- **Cache**: status allowlist with negative-cache TTL for 4xx; client
  IP read from middleware context.
- **Ratelimit**: deterministic role ordering; carries remaining
  tokens on quota change; correct `Reset`/`Remaining` semantics.
- **Remap**: JSON decode gated on Content-Type; HMAC key rotation
  (`secrets [][]byte`); `signingMessage` clones `url.Values`;
  `path.Clean` normalization.
- **Health**: per-check TTL cache + background refresh — slow checks
  no longer DoS upstreams; OriginCheck shares the project's
  instrumented HTTP client.
- **Federation handler**: `transformResponse` skips decode when no
  rewriting needed; `rewriteLinks` recursion bounded to known link
  keys; precomputed implicit-all origin set; helper extraction.
- **Stac/geo**: `intersects` validated via `geo.ParseGeoJSON`; null
  geometry items with bbox now accepted; `BboxToGeometry` splits
  antimeridian-crossing bboxes into MultiPolygon.
- **Config** (breaking): `${VAR}` env-var expansion errors on
  undefined variables (no more silent empty-string substitution);
  `${VAR:-default}` syntax supported; `KnownFields(true)` decoder
  rejects orphan YAML keys; `aws_sigv4` consistent spelling
  end-to-end (was `aws_sig_v4` in some places); `custom_headers`
  removed from auth-type validation; `reject_duplicates` conflict
  strategy actually wired through; metrics server gracefully shut
  down on SIGTERM; `oidc`, `basic`, `mtls` auth types now wired in
  main (were silently no-op'd).

### Cleanup (LOW + NIT)

- Logging: UA + RemoteAddr redacted by default; `duration_ms`
  numeric field.
- httpx: strips RFC 7239 `Forwarded` header.
- Observability: `prometheus.Registerer` injected (no more `promauto`
  global-registry panics in tests).
- Federation: `joinStrings` → `strings.Join`; `errors.As` for
  `*middleware.InternalError`; `time.Sleep` race in
  `asset_proxy_test.go` replaced with sync channel; merger.Links
  defensive copy.
- Cache: redis backend rejected at config validation (until
  implemented).
- Ratelimit: `NewSlidingWindowLimiter` renamed to
  `NewTokenBucketLimiter` (impl was always token-bucket); legacy
  name kept as deprecation alias; `net.SplitHostPort` for IP keying.
- Remap: `strconv.ParseInt`; recursion-depth guard.
- Main: typed config parsing for ratelimit `requests`; healthcheck
  honors `cfg.Server.Port`.
- Stac: `ItemDatetime` accepts `RFC3339Nano` and date-only;
  `ExtractNextToken` uses `url.Parse`; `cql2_eval.compare` errors
  propagated.
- Policies: consolidated `constraints` rule in `stac_authz.rego`
  using `if`/`else` to avoid Rego-version brittleness.

### Changed (breaking) — also covered above

- `auth.OIDCConfig.ClaimsFunc` signature aligned with
  `auth.BearerConfig.ClaimsFunc` — accepts `jwt.MapClaims` instead
  of `map[string]interface{}`. Source-only change.
- API key storage uses HMAC digests rather than plaintext map keys —
  operators must rebuild their key store on upgrade.
- `signer.type: cloudfront` / `signer.type: s3_presigned` now reject
  at config validation.
- `${VAR}` env expansion errors on undefined variables (use
  `${VAR:-}` to opt-out).
- YAML decoder rejects unknown keys (`KnownFields(true)`).
- AWS SigV4 origin-auth requires `github.com/aws/aws-sdk-go-v2`
  (added as a direct dep).

### Removed

- Dead fields on `OIDCProvider` (`jwksURL`, `httpClient`) and the
  redundant `CacheTTL` zero-default in `NewOIDCProvider` —
  `JWKSClient` owns both the URL and the TTL fallback after the
  v0.1 merge.
- Stub `CloudFrontSigner` and `S3PresignedSigner` (no real signing).
- Hand-rolled SigV4 implementation (replaced by aws-sdk-go-v2).
- Regex-based `default`-rule dedup in `opa_embedded.go`.

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
