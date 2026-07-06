# Security policy

## Supported versions

We maintain the current minor + the one previous.

| Version | Supported          |
|---------|--------------------|
| 1.0.x   | ✅                 |
| 0.2.x   | ✅                 |
| < 0.2   | ❌                 |

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security reports.

Email `security@yourorg.example` with:

- a clear description of the vulnerability,
- the version (or commit) affected,
- a minimal reproducer if possible,
- whether you'd like public credit.

We aim to acknowledge within 3 business days and to ship a fix or
mitigation within 30 days for high-severity issues. Coordinated public
disclosure follows the fix being available in a tagged release.

## Hardening defaults shipped in v0.1

- TLS 1.2 minimum; only modern ECDHE-AES-GCM cipher suites enabled.
- Request bodies capped at 1 MiB by default (configurable per deployment).
- Non-root container UID (65532); no shell or HTTP client in the runtime
  image; healthcheck runs the proxy binary itself.
- Bearer/JWT tokens verified against issuer, audience, expiry; signing
  algorithm enforced per provider (HS256 with static secret, or RS/ES
  via JWKS).
- API keys compared in constant time.
- Graceful shutdown drains in-flight requests up to 30s on SIGTERM.

## Added in v1.0

- Federation cursor secrets shorter than 16 characters are rejected at
  boot (`openssl rand -hex 32` remains the recommendation).
- `rewrite_assets: sign` without a signing secret is a boot error
  instead of a silent unsigned fallback.
- **Redis (optional, `store: redis`)**: inject `redis.password` via
  `${REDIS_PASSWORD}` env expansion, enable `redis.tls` when the link
  crosses a trust boundary, and treat the Redis instance as inside the
  proxy's trust zone — it holds cache entries and rate-limit state (no
  tokens or credentials; all keys are SHA256/HMAC digests, so no
  principal IDs or client IPs appear in the keyspace). All consumers
  fail open on Redis errors; set `rate_limit.failure_mode: closed` if
  quota enforcement must survive a Redis outage at the cost of
  availability.

## Known gaps

- API keys are HMAC-SHA256-digested at load; plaintext keys are never
  retained in memory (see the storage-format comment in
  `internal/middleware/auth/apikey.go`). The residual exposure is the
  plaintext key sitting in the YAML *file*. Mitigate it today by
  injecting keys via `${VAR}` env expansion — so the secret lives in the
  environment / secrets manager rather than committed YAML — plus
  restrictive file permissions (`chmod 600`). A pre-hashed
  `sha256:<hex>`-in-YAML key option (never handling the plaintext at all)
  is backlog for v0.3, not yet shipped.
- The proxy trusts `X-Forwarded-For` unconditionally (chi's
  `middleware.RealIP`), so it MUST be deployed behind a trusted L7 edge
  that strips any inbound `X-Forwarded-For` and re-sets it from the real
  client connection — the shipped `deployments/docker/haproxy.cfg` does
  exactly this. Exposing the proxy directly to untrusted clients lets
  them spoof the source IP used for rate-limiting keys and request logs.
  See `docs/deploy.md` for the reverse-proxy deployment topology.
- mTLS for federated upstream origins is not yet implemented.
- AWS SigV4 IAM role chaining isn't implemented; only static
  AccessKey/SecretKey credentials work today.
