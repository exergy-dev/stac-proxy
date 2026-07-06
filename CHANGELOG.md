# Changelog

All notable changes to this project will be documented here. Format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — 2026-07-06

Production release. Two architectural changes close the gaps that kept
0.x deployments pinned to sticky single-replica topologies: a shared
Redis backend makes replicas stateless behind any load balancer, and
origin failures are now circuit-broken and explicitly signaled instead
of silently absorbed. The YAML config schema is now covered by the
semver compatibility promise: breaking config changes require a major
version from here on.

### Added — stateless replicas (opt-in `store: redis`)

- **Top-level `redis:` block** — one shared client (go-redis v9,
  `UniversalClient`) for every consumer; addr/auth/DB/TLS/pool/timeout
  settings; tight 250 ms default op timeouts and no command retries so
  a degraded Redis costs milliseconds, not stacked latency. go-redis's
  internal logging is routed into slog.
- **Response cache `store: redis`** — coherent across replicas; every
  operation fails open (Redis error = cache miss, never a request
  failure) with warnings throttled to one line per 30 s.
- **Federation `page_cache.store: redis`** — `rel: prev`/`rel: first`
  navigation works on any replica; principal binding and
  cursor-lifetime TTLs unchanged.
- **Rate limit `store: redis`** — token buckets become global and
  exact across the fleet via an atomic Lua check-and-decrement (no
  read-modify-write race; verified by a 50-goroutine burst test
  admitting exactly `burst`). Bucket keys are SHA256 digests (no
  principal IDs/IPs in the keyspace) and fold in a quota fingerprint
  so role changes start fresh buckets. New `failure_mode: open|closed`
  knob (default open; closed refuses with 503 + Retry-After while the
  backend is down).
- Validation: `store: redis` anywhere requires the `redis:` block
  (boot error); a `redis:` block nothing consumes warns. Redis is
  deliberately NOT part of readiness — a cache-tier outage must not
  make load balancers drain every replica.
- Deployment: optional `redis` service in
  `docker-compose.multi.yaml`; with Redis mode, HAProxy stickiness is
  optional (docs/deploy.md "Stateless replicas" section).

### Added — origin resilience & partial-result signaling

- **Per-origin circuit breaker, on by default** (opt-out via
  `circuit_breaker.enabled: false`): 5 consecutive failures open the
  circuit for a jittered 10 s window doubling to 2 m; one half-open
  probe re-admits traffic. Wired outermost in the origin transport
  stack so one user request is one breaker sample and open circuits
  skip OAuth2 token fetches. `context.Canceled` is neutral; timeouts
  and 5xx count; 4xx/429 don't. Transitions are logged (the breaker's
  slog lines are its dashboard).
- **502 `UpstreamFederationFailure`** when every routed origin fails —
  previously an empty 200 FeatureCollection indistinguishable from
  zero matches. Applies to both search paths and `GET /collections`.
- **Partial results are explicit**: `X-Federation-Partial: true` +
  `X-Federation-Failed-Origins` headers, per-origin status in the
  response context under `stac_proxy:origins` (with `circuit_open` vs
  `fetch_failed` causes), a throttled warn log, and the response cache
  refuses to store partial pages.
- **Paginated sessions survive transient origin failures**: an errored
  origin is retried on subsequent pages (up to 3 failed pages, then
  retired) instead of being silently dropped for the rest of the
  session; its stashed items still merge. Success resets the budget.
- **Retry backoff is jittered** (full jitter on the upper half);
  upstream `Retry-After` on 429/503 is still honored exactly.

### Added — hygiene

- `govulncheck` job in CI.
- Boot errors for guessable cursor secrets (< 16 chars) and for
  `rewrite_assets: sign` without a signing secret (previously a silent
  unsigned fallback).
- Dedicated unit tests for all five pagination adapters; cursor-secret
  rotation procedure documented in docs/deploy.md.

## [0.2.0] — 2026-07-06

Post-v0.1.0 hardening: a severity-tiered review pass (CRITICAL → NIT,
~80 fixes across auth, authz, federation, cache, ratelimit, server,
config, observability, stac, and remap) followed by a dead-feature
purge that removed every config surface for paths that were either
silently broken (per-origin mTLS) or never implemented (external OPA
server, Redis cache, CloudFront/S3-presigned signers, AWS SigV4 IAM
role, `server.hot_reload`). The `Removed` block below is the breaking
change set; everything else is fixes and wiring. See git log for the
full list.

### Deployment & operations

- **Multi-replica deployment topology.** New
  `deployments/docker/docker-compose.multi.yaml` + `haproxy.cfg` put a
  sticky HAProxy edge in front of N proxy replicas. Since all hot state
  (response cache, rate-limit buckets, federation page cache) is
  in-memory per replica, HAProxy uses consistent source-IP hashing so
  each client sticks to one replica — making per-replica state correct
  without Redis. The edge owns `X-Forwarded-For` (drops inbound, sets
  from the real source) because chi's `RealIP` trusts it
  unconditionally; active `GET /health` checks pull dead replicas from
  the hash ring. See the new "Multiple replicas" section in
  `docs/deploy.md`.
- **`server.max_header_bytes`** (default 64 KiB) caps inbound request
  headers, 16× tighter than net/http's 1 MiB default; oversized
  headers get HTTP 431.
- **Startup warning when the server is unauthenticated.** Boot logs a
  prominent WARN, naming the keys to lock it down, when no auth
  provider or authz enforcer is configured to reject anonymous
  requests. `allow_anonymous` defaults are unchanged.
- **Lifecycle correctness.** Background work (JWKS refresh, origin
  discovery, OPA policy compile) is bound to the server lifetime
  context so it cancels cleanly on shutdown; the duplicate
  "Server starting" boot log was removed.
- **Federated pagination — per-origin item stashing.** Items fetched
  but not emitted on the current page are stashed on the cursor and
  carried to the next page instead of being dropped, and over-fetching
  was reduced. Adds the `post_body` pagination adapter (below).
- **Toolchain.** Build and CI moved to Go 1.25.x; linting migrated to
  golangci-lint v2. Fuzz targets added (`FuzzExpandEnvStrict`,
  `FuzzDecodeCursor`) with a `make fuzz` runner; the container builder
  image was bumped to match the `go 1.25` directive.

### Federation — backwards navigation + page cache

- **New `pagecache` package** stores rendered federated-search pages
  keyed by cursor signature so the paginator can serve `rel: prev` /
  `rel: first` navigation without re-fanning-out to origins. Entries
  are HMAC-keyed (cursor signature + principal hash), TTL-bounded by
  the cursor's remaining lifetime, and stored in a dedicated in-memory
  LRU separate from the HTTP middleware cache.
- **Cursor v2** adds `PrevCursor`, `FirstCursor`, and `PageSeq` fields
  to `FederatedCursor`. The paginator stamps these on each emitted
  cursor so the link emitter can offer the full nav set. `Version`
  bumped from 1 to 2; existing decoders accept v2 cursors via JSON
  field tolerance, but cursors are short-lived (~1h default) so the
  format change is operationally invisible.
- **Link emission**: `buildPaginatedSearchResponse` now emits `rel:
  self`, `rel: prev`, `rel: first` alongside the existing `rel: next`
  whenever the cursor chain populates the corresponding field. All
  four share the same POST `body.token` / GET `?token=` wire shape;
  `cursorSearchLink` (formerly `nextSearchLink`) is the unified
  builder.
- **Config**: `federation.page_cache` with `enabled`, `max_entries`,
  `ttl`. Defaults: **enabled when `cursor_secret` is set**,
  `max_entries: 1024`, `ttl: 1h`. Set `enabled: false` to opt out
  even with a cursor secret.
- **Acceptance**: `tests/live/federation_live_extra_test.go ::
  TestLive_BackwardsNavigation` paginates a federated search across
  Earth Search + Planetary Computer forward two pages, follows
  `rel: prev` from page 2, and asserts the response items match
  page 1 verbatim. Plus a focused unit test
  (`TestSearch_CursorV2_PrevFirstChain`) that proves the cache hit
  doesn't re-call upstreams.

### Federation — pluggable pagination adapters

- **New `pageadapter` package** abstracts upstream pagination
  conventions. The federation handler no longer hardcodes the STAC API
  spec's `?token=` / POST `body.token` shape — it routes through a
  per-origin `Adapter` that knows how to capture next-state from the
  upstream response and how to drive the next call.
- **Built-in adapters**: `token` (STAC spec — Planetary Computer),
  `next_url` (Earth Search and any upstream that emits a `rel: next`
  href the proxy can follow verbatim), `offset` (offset-based catalogs;
  configurable param name — `offset` or `page`), `link_header` (RFC 5988
  `Link:` header; OGC API Features gateways), `post_body` (upstreams —
  e.g. Earth Search — that emit `rel: next` with `method: POST` and a
  request `body` cursor field, replayed verbatim), and `auto` (the
  default — probes the first response and locks its choice into the
  cursor for the rest of the session).
- **Fixes a real bug**: Earth Search uses `?next=<id>` for pagination.
  The proxy previously captured the upstream's full next-URL on
  `OriginCursor.NextURL` but never read it on follow-up calls, so
  federated pagination against ES silently looped page 1. The
  `next_url` adapter (and `auto` by extension) closes this gap.
- **Per-origin config**: `federation.origins[].pagination` with
  `adapter`, `offset_param`, and `token_param`. Omit to use `auto`.
  Validator allowlists the adapter name; unknown names fail at boot.
- **Internal transport fields** added to `stac.SearchRequest`:
  `OverrideURL` and `AdapterName` (both `json:"-"`). Adapters use the
  former to ask the origin client to fetch a verbatim next-URL with
  GET instead of POST-ing the standard `/search`. The latter carries
  the locked adapter name across the Searcher boundary.
- **Cursor field**: `OriginCursor.AdapterName` (additive, no version
  bump). Records `auto`'s lock decision so subsequent pages route to
  the named adapter without re-probing.
- **Acceptance test**: `tests/live/federation_live_extra_test.go ::
  TestLive_PaginatedNextLink` paginates a federated search across
  Earth Search and Planetary Computer (different pagination
  conventions per upstream) and asserts page 2 doesn't repeat page 1
  IDs from either origin. Previously skipped with a `XXX(pagination)`
  comment.

### Production readiness — config wiring

- **`server.public_base_url`** is now read from YAML and threaded into
  the federation handler in both single and federation modes.
  Previously `HandlerConfig.ProxyBaseURL` was never set from config,
  so `next` pagination links were path-only, `rewrite_assets: proxy`
  silently fell back to passthrough, and link rewriting was a no-op.
  Set this to the externally reachable URL of the proxy.
- **Per-origin field wiring**: `retry`, `max_idle_conns_per_host`,
  `max_response_bytes`, and `forward_user_identity` are now actually
  copied from `OriginConfig` into the `federation.Origin` used at
  runtime. The fields existed in YAML but were dropped on the floor.
- **Origin auth field wiring**: `aws_sigv4` origin auth config is now
  copied into the federation layer; previously AWS SigV4 origin auth
  was completely unreachable from config despite the implementation
  existing. `oauth2.audience` is now also copied. (Per-origin
  `client_cert` was copied through too, but the transport never loaded
  the cert — it has since been removed entirely; see `Removed` below.)
- **STAC landing page** now emits the §1.4 required link rels (`self`,
  `root`, `data`, `conformance`, `search` GET+POST), absolute when
  `server.public_base_url` is set and relative otherwise. Previously
  the `links` array was empty.
- **Breaking — unknown middleware names** now fail validation rather
  than emit a warning. Typos in the middleware list (e.g.
  `rate-limit` vs `rate_limit`) historically resulted in deployments
  with authz / rate-limit silently disabled.
- New round-trip wiring test (`TestBuildFederationHandler_CopiesEvery
  ConfiguredField`) asserts every documented `OriginConfig` /
  `OriginAuthConfig` field reaches `federation.Origin` and that
  `server.public_base_url` reaches `Handler.ProxyBaseURL()`. Adding a
  new origin field requires extending this test — that's the point.

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
- `${VAR}` env expansion errors on undefined variables (use
  `${VAR:-}` to opt-out).
- **Env expansion is now `${VAR}`-only.** Expansion runs over parsed
  YAML scalar *values* (never comments or keys) and recognizes only
  `${VAR}` / `${VAR:-default}`; a bare `$NAME` is left literal and `$$`
  escapes a `$`. This permanently protects `url_remap` regex
  replacements (`$1`/`$2`) and stops references inside comments from
  being demanded. Configs that relied on undocumented bare-`$VAR`
  expansion must switch to `${VAR}`.
- **`federation.cursor_secret` is now required in federation mode.**
  Previously an empty secret only warned and silently disabled
  paginated search; it is now a load-time error. Generate one with
  `openssl rand -hex 32` and keep it identical across replicas.
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
- **Breaking — per-origin `client_cert` (mTLS) removed.** The
  `federation.origins[].auth.client_cert` block was accepted by config
  and copied into `federation.AuthConfig` but never loaded into the
  origin's `http.Transport`, so configuring it silently produced a
  plain-TLS connection. Removing the field forces operators to notice;
  it can be re-added if/when the transport wiring is implemented.
  YAML decoder is `KnownFields(true)`, so leftover `client_cert:` keys
  will now error at startup.
- **Breaking — `aws_sigv4.use_iam_role` removed.** The flag was
  accepted by config but the SigV4 provider only honors static
  `access_key` / `secret_key`; `use_iam_role: true` produced an
  `AWS credentials not configured` error at sign time. Drop the key;
  set static credentials (or wait for an IAM-role provider to land).
- **`server.hot_reload`** — never had a Go-side field, only docs
  mentions. Roadmap claim retracted; doc references removed.
- **Breaking — external OPA server mode removed.** `authz.opa.url` and
  the `OPAEnforcer` HTTP client are gone — only `authz.opa.embedded:
  true` is supported. The external-OPA path was rejected at startup
  before, but the field, struct, and `OPAErrorMode` (`OnError: deny|
  allow`) enum lingered in the API surface; all gone. The
  `Final`-decision short-circuit on `CompositeEnforcer.authorizeAny`
  stays — it's a general property of authoritative decisions.
- **Breaking — `cache.store: redis` and `cache.redis_url` removed.**
  Previously rejected at validation; now the enum only accepts
  `memory`. The `github.com/redis/go-redis/v9` reference was never an
  actual dependency.
- **Breaking — `signer.type: cloudfront` / `signer.type: s3_presigned`
  removed.** Previously the named-and-rejected leftover from the
  v0.1 stub-signer removal; now they're "unknown signer type" like any
  other typo. The stub impls were already gone in v0.1.
- **Breaking — `authz.cql2_injection.combine` removed.** The field was
  parsed and stored on `CQL2InjectionConfig` but never read; the
  injector always AND-folds via `andNonNil`. AND is the only safe
  authorization composition (narrowing); `or`/`replace` would let
  policy broaden or hide a client's filter and were never going to
  ship. With the `KnownFields(true)` decoder, leftover `combine:`
  keys will now error at startup.
- **Breaking — `federation.conflict_strategy` removed.** The enum
  (`first-wins`/`priority`/`merge`/`namespace`) and its merger paths
  are gone; result merging is now always first-wins-by-origin-priority.
  Leftover `conflict_strategy:` keys error at startup under
  `KnownFields(true)`.
- Bloom-filter dedup fallback in the federation paginator (internal;
  no config surface). Realistic federated pages never approached its
  threshold, so it was dead complexity; dedup is exact-match.
- `config.MustValidate` (panicking, unused) helper.

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

> **Note (post-v0.1.0):** several of the items above have since been
> *removed* rather than completed. See `Unreleased > Removed` for the
> reclassification (external OPA URL, Redis cache, `client_cert`,
> `use_iam_role`, `hot_reload`, cloudfront/s3_presigned signers).
