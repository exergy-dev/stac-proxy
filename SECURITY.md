# Security policy

## Supported versions

Only the latest minor release is supported with security fixes during the
pre-1.0 series. Once 1.0 ships we'll maintain the current minor + the one
previous.

| Version | Supported          |
|---------|--------------------|
| 0.1.x   | ✅                 |
| < 0.1   | ❌                 |

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

## Known gaps

- API keys are stored plaintext in YAML config. Use restrictive file
  permissions (`chmod 600`) and prefer env-var injection. Hashed-at-rest
  storage is on the v0.2 roadmap.
- mTLS for federated upstream origins is not yet implemented.
- AWS SigV4 IAM role chaining isn't implemented; only static
  AccessKey/SecretKey credentials work today.
