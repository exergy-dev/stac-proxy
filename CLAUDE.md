# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

stac-proxy is a high-performance, extensible proxy server for SpatioTemporal Asset Catalog (STAC) APIs written in Go. It provides a unified middleware layer supporting authentication, authorization (with OPA/geofencing), request/response transformation, URL remapping, caching, and federation of multiple upstream STAC servers into a single cohesive API.

## Build & Development Commands

```bash
# Build the binary
go build -o stac-proxy ./cmd/stac-proxy

# Run tests
go test ./...

# Run a single test
go test -run TestName ./path/to/package

# Run with race detector
go test -race ./...

# Run the proxy
./stac-proxy --config config.yaml
```

## Architecture

### Core Components

The proxy operates in two modes: **single-origin** (transparent proxy to one STAC server) and **federation** (aggregate multiple STAC servers).

```
Client → Middleware Chain → Router/Handler → Origins
                ↓                   ↓
         [Auth, AuthZ,        [Proxy Handler or
          RateLimit,           Federation Handler]
          Cache, Remap]
```

### Package Structure

- `cmd/stac-proxy/` - Main entry point
- `internal/config/` - Configuration loading and validation
- `internal/server/` - HTTP server, chi router, search-body parser middleware, asset endpoint
- `internal/middleware/` - Chi-style `func(http.Handler) http.Handler` middleware components:
  - `auth/` - Authentication providers (JWT bearer, JWKS, OIDC discovery, API key, basic, mTLS)
  - `authz/` - Authorization with OPA (embedded + external), CQL2 injection, geofencing
  - `cache/` - Response caching (memory; redis backend not yet implemented)
  - `ratelimit/` - Token-bucket rate limiting (per-IP / per-principal)
  - `remap/` - URL remapping and HMAC URL signing
  - `logging/` - Structured slog request logging with request-id propagation
- `internal/federation/` - Multi-origin federation (also handles single-origin as federation-of-1):
  - `handler.go` - Fan-out/merge orchestration; conformance intersection; asset proxy
  - `router.go` - Collection-to-origin routing
  - `origin.go` - Per-origin HTTP client with auth and bounded response capture
  - `merger.go` - Result aggregation with conflict resolution
  - `pagination.go` - Federated cursor-based pagination with per-search dedup
  - `cursor.go` - Principal-bound cursor encoding
  - `auth_providers.go` - Per-origin auth (basic, bearer, oauth2 with singleflight, AWS SigV4 via aws-sdk-go-v2)
- `internal/geo/` - Geospatial operations (geometry, GeoJSON, antimeridian-aware bbox, spatial index)
- `internal/stac/` - STAC types (aliased from `go-stac-client`), parser, conformance helpers, CQL2 evaluator (incl. S_INTERSECTS)
- `internal/httpx/` - HTTP utilities: bounded response capture, retry transport (retryablehttp), trusted-proxy XFF, hop-by-hop header stripping
- `internal/observability/` - Prometheus metrics with chi-route-pattern labels, cached `/health` checks

### Key Interfaces

**Chi Middleware** — every middleware in `internal/middleware/*` exposes a constructor returning `func(http.Handler) http.Handler`. The buffered `Chain`/`Middleware`/`Handler` types were removed in commit 32ac06a; everything is standard `http.Handler` now.

**Auth Provider** (`internal/middleware/auth/provider.go`):
```go
type Provider interface {
    Name() string
    Authenticate(ctx context.Context, req *http.Request) (*Principal, error)
}

// Optional: providers that own a credential type implement
// CredentialClaimer so the chain fails closed (401) on a bad
// signature instead of falling through to anonymous.
type CredentialClaimer interface {
    ClaimsCredential(req *http.Request) bool
}
```

**Origin Auth** (`internal/federation/origin.go`):
```go
type AuthProvider interface {
    ApplyAuth(ctx context.Context, req *http.Request) error
    Refresh(ctx context.Context) error
}
```

### Federation Flow

1. Parse incoming search request
2. Route to applicable origins based on `collections` parameter
3. Fan out requests to origins in parallel (each with its own auth)
4. Merge results using configured conflict strategy (first-wins, priority, merge, namespace)
5. Handle pagination via encoded cursors with merge-sort across origins
6. Rewrite all links to route through proxy

### Authorization with OPA

Authorization uses Open Policy Agent (OPA) with Rego policies. Supports:
- Collection-level access control
- Geofencing (spatial restrictions per user/organization)
- Temporal filters
- Result field redaction
- Embedded OPA engine or external OPA server

### Configuration

YAML-based configuration with environment variable expansion. Key sections:
- `server` - HTTP server settings
- `middleware` - Ordered middleware chain
- `mode` - "single" or "federation"
- `federation.origins` - Upstream servers with per-origin auth configs

## Key Dependencies

- `github.com/go-chi/chi/v5` - HTTP router
- `github.com/open-policy-agent/opa` - Authorization engine
- `github.com/golang-jwt/jwt/v5` - JWT handling
- `github.com/paulmach/orb` - GeoJSON/geometry
- `github.com/tidwall/rtree` - Spatial indexing
- `github.com/redis/go-redis/v9` - Redis caching
- `github.com/bits-and-blooms/bloom/v3` - Bloom filters for deduplication
