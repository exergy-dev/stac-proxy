# STAC Server Proxy Design Document

**Project Name:** stac-proxy  
**Language:** Go  
**Date:** December 2024  
**Status:** Historical proposal — kept for architectural context

---

> ⚠ **This document is the original pre-implementation proposal.** It
> predates v0.1.0 and has not been kept in lockstep with the code. Use
> it for the architectural narrative (sections 1–3, the federation
> diagrams, the design rationale); do **not** treat its config samples,
> field lists, or roadmap as authoritative. Authoritative sources:
>
> - **What ships today:** [`README.md`](README.md) feature table and
>   [`CHANGELOG.md`](CHANGELOG.md) `Unreleased` + `[0.1.0]` blocks.
> - **Config schema:** the YAML tags on `internal/config/config.go`
>   structs.
> - **Operator docs:** [`docs/deploy.md`](docs/deploy.md),
>   [`docs/policies.md`](docs/policies.md),
>   [`docs/observability.md`](docs/observability.md).
>
> Specifically, code samples below referencing `use_iam_role`,
> `store: redis`, `redis_url`, `signer.type: cloudfront`/`s3_presigned`,
> per-origin `client_cert`, `authz.opa.url`, or `server.hot_reload` are
> features that were either never implemented or have since been
> removed. See `CHANGELOG.md > Unreleased > Removed`.

---

## 1. Executive Summary

This document describes the architecture and design of `stac-proxy`, a high-performance, extensible proxy server for SpatioTemporal Asset Catalog (STAC) APIs written in Go. The proxy provides a unified middleware layer supporting authentication, request/response transformation, URL remapping, caching, and federation of multiple upstream STAC servers into a single cohesive API.

---

## 2. Background

### 2.1 What is STAC?

The SpatioTemporal Asset Catalog (STAC) specification provides a common language to describe geospatial information, enabling easier indexing and discovery of satellite imagery, drone captures, and other geospatial assets. STAC consists of four semi-independent specifications:

- **STAC Item**: The core atomic unit describing a single spatiotemporal asset
- **STAC Catalog**: A simple, flexible JSON structure for organizing items
- **STAC Collection**: Extends Catalog with additional metadata about a group of items
- **STAC API**: A RESTful API specification for searching and accessing STAC data

### 2.2 Problem Statement

Organizations operating STAC infrastructure face several challenges:

1. **Authentication Heterogeneity**: Different STAC servers use different auth mechanisms
2. **Federation**: No standard way to query multiple STAC servers as a unified catalog
3. **Access Control**: Limited fine-grained authorization on existing STAC servers
4. **URL Management**: Asset URLs may need remapping for CDN, caching, or security
5. **Observability**: Lack of unified logging, metrics, and tracing across STAC operations
6. **Rate Limiting**: Protecting upstream servers from abuse

### 2.3 Goals

- Provide a transparent proxy layer for any STAC API-compliant server
- Implement a flexible, chainable middleware architecture
- Enable federation of multiple STAC servers under a single endpoint
- Support pluggable authentication and authorization
- Allow URL remapping and response transformation
- Maintain full STAC API specification compliance
- Achieve high performance with minimal latency overhead

### 2.4 Non-Goals

- Implementing a full STAC server (this is a proxy, not a database)
- Providing a web UI for catalog browsing
- Supporting non-STAC geospatial APIs (WMS, WFS, etc.)
- Data transformation or format conversion of assets

---

## 3. Architecture Overview

### 3.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              Clients                                     │
│                    (QGIS, STAC Browser, Custom Apps)                    │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                           stac-proxy                                     │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                      Middleware Chain                              │  │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────────┐  │  │
│  │  │ Logging │→│  Auth   │→│  Rate   │→│ Cache   │→│   Custom    │  │  │
│  │  │         │ │         │ │ Limit   │ │         │ │ Middleware  │  │  │
│  │  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────────┘  │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                        Router / Handler                            │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐ │  │
│  │  │ Single-Origin│  │  Federation  │  │  Response Transformer    │ │  │
│  │  │    Proxy     │  │   Handler    │  │  (Remapping, Filtering)  │ │  │
│  │  └──────────────┘  └──────────────┘  └──────────────────────────┘ │  │
│  └───────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    ▼               ▼               ▼
           ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
           │ STAC Server  │ │ STAC Server  │ │ STAC Server  │
           │   (Origin A) │ │   (Origin B) │ │   (Origin C) │
           └──────────────┘ └──────────────┘ └──────────────┘
```

### 3.2 Core Components

| Component | Responsibility |
|-----------|----------------|
| **HTTP Server** | Accept incoming connections, TLS termination |
| **Router** | Route requests to appropriate handlers based on path/method |
| **Middleware Chain** | Process requests/responses through configured middleware |
| **Proxy Handler** | Forward requests to single upstream STAC server |
| **Federation Handler** | Aggregate requests across multiple upstream servers |
| **Response Transformer** | Modify responses (URL remapping, filtering, enrichment) |
| **Config Manager** | Load and hot-reload configuration |
| **Health/Metrics** | Expose operational metrics and health checks |

---

## 4. Detailed Design

### 4.1 Middleware System

The middleware system is the core extensibility mechanism. Middleware components implement a standard interface and can be chained together.

#### 4.1.1 Middleware Interface

```go
package middleware

import (
    "context"
    "net/http"
)

// STACRequest wraps an HTTP request with STAC-specific context
type STACRequest struct {
    *http.Request
    Context     context.Context
    Params      map[string]interface{}  // Parsed STAC query parameters
    Collection  string                   // Target collection (if applicable)
    ItemID      string                   // Target item ID (if applicable)
    RequestType RequestType              // Enum: Search, GetItem, GetCollection, etc.
}

// STACResponse wraps an HTTP response with parsed STAC data
type STACResponse struct {
    StatusCode int
    Headers    http.Header
    Body       []byte
    Items      []Item       // Parsed items (if applicable)
    Collections []Collection // Parsed collections (if applicable)
}

// Middleware defines the interface for all middleware components
type Middleware interface {
    // Name returns a unique identifier for this middleware
    Name() string
    
    // ProcessRequest handles incoming requests before upstream
    // Return modified request, or error to short-circuit
    ProcessRequest(ctx context.Context, req *STACRequest) (*STACRequest, error)
    
    // ProcessResponse handles responses before returning to client
    ProcessResponse(ctx context.Context, req *STACRequest, resp *STACResponse) (*STACResponse, error)
    
    // Priority determines ordering (lower = earlier in chain)
    Priority() int
}

// MiddlewareFunc is a convenience type for simple middleware
type MiddlewareFunc func(next http.Handler) http.Handler
```

#### 4.1.2 Middleware Chain Execution

```go
package middleware

type Chain struct {
    middlewares []Middleware
}

func NewChain(middlewares ...Middleware) *Chain {
    // Sort by priority
    sort.Slice(middlewares, func(i, j int) bool {
        return middlewares[i].Priority() < middlewares[j].Priority()
    })
    return &Chain{middlewares: middlewares}
}

func (c *Chain) Execute(ctx context.Context, req *STACRequest, 
    upstream func(*STACRequest) (*STACResponse, error)) (*STACResponse, error) {
    
    // Process request through chain
    currentReq := req
    for _, mw := range c.middlewares {
        var err error
        currentReq, err = mw.ProcessRequest(ctx, currentReq)
        if err != nil {
            return nil, fmt.Errorf("middleware %s request error: %w", mw.Name(), err)
        }
    }
    
    // Call upstream
    resp, err := upstream(currentReq)
    if err != nil {
        return nil, err
    }
    
    // Process response through chain (reverse order)
    currentResp := resp
    for i := len(c.middlewares) - 1; i >= 0; i-- {
        mw := c.middlewares[i]
        currentResp, err = mw.ProcessResponse(ctx, currentReq, currentResp)
        if err != nil {
            return nil, fmt.Errorf("middleware %s response error: %w", mw.Name(), err)
        }
    }
    
    return currentResp, nil
}
```

### 4.2 Built-in Middleware

#### 4.2.1 Authentication Middleware

Supports multiple authentication mechanisms with a pluggable provider system.

```go
package auth

type AuthProvider interface {
    Name() string
    Authenticate(ctx context.Context, req *http.Request) (*Principal, error)
}

type Principal struct {
    ID          string
    Type        string            // "user", "service", "anonymous"
    Attributes  map[string]string
    Roles       []string
    Collections []string          // Allowed collections (empty = all)
}

// Supported providers
type BasicAuthProvider struct { /* ... */ }
type BearerTokenProvider struct { /* ... */ }
type OAuth2Provider struct { /* ... */ }
type APIKeyProvider struct { /* ... */ }
type OIDCProvider struct { /* ... */ }
type MTLSProvider struct { /* ... */ }

type AuthMiddleware struct {
    providers     []AuthProvider
    allowAnonymous bool
    anonPrincipal *Principal
}

func (m *AuthMiddleware) ProcessRequest(ctx context.Context, req *STACRequest) (*STACRequest, error) {
    for _, provider := range m.providers {
        principal, err := provider.Authenticate(ctx, req.Request)
        if err != nil {
            continue // Try next provider
        }
        if principal != nil {
            ctx = context.WithValue(ctx, PrincipalKey, principal)
            req.Context = ctx
            return req, nil
        }
    }
    
    if m.allowAnonymous {
        ctx = context.WithValue(ctx, PrincipalKey, m.anonPrincipal)
        req.Context = ctx
        return req, nil
    }
    
    return nil, ErrUnauthorized
}
```

#### 4.2.2 Authorization Middleware

Fine-grained access control based on collections, spatial extent (geofencing), temporal range, and integration with Open Policy Agent (OPA).

```go
package authz

// AuthzMiddleware handles authorization decisions
type AuthzMiddleware struct {
    enforcer    Enforcer
    geofencer   *Geofencer
    config      *AuthzConfig
}

type AuthzConfig struct {
    // Policy source
    PolicySource    string `yaml:"policy_source"` // "file", "opa", "both"
    PolicyFile      string `yaml:"policy_file"`
    
    // OPA configuration
    OPA             *OPAConfig `yaml:"opa"`
    
    // Geofencing
    Geofencing      *GeofencingConfig `yaml:"geofencing"`
    
    // Default behavior
    DefaultEffect   Effect `yaml:"default_effect"` // Allow or Deny
}

// Enforcer interface for pluggable policy engines
type Enforcer interface {
    Evaluate(ctx context.Context, input *AuthzInput) (*AuthzDecision, error)
}
```

**Open Policy Agent (OPA) Integration:**

```go
package authz

type OPAConfig struct {
    // OPA server mode
    URL             string        `yaml:"url"`              // e.g., "http://opa:8181"
    PolicyPath      string        `yaml:"policy_path"`      // e.g., "v1/data/stac/authz"
    
    // Embedded OPA mode (no external server)
    Embedded        bool          `yaml:"embedded"`
    BundleURL       string        `yaml:"bundle_url"`       // OPA bundle URL
    BundlePollInterval time.Duration `yaml:"bundle_poll_interval"`
    
    // Policy files for embedded mode
    RegoFiles       []string      `yaml:"rego_files"`
    DataFiles       []string      `yaml:"data_files"`       // JSON/YAML data
    
    // Performance
    Timeout         time.Duration `yaml:"timeout"`
    CacheDecisions  bool          `yaml:"cache_decisions"`
    CacheTTL        time.Duration `yaml:"cache_ttl"`
}

// OPAEnforcer implements authorization using Open Policy Agent
type OPAEnforcer struct {
    config      *OPAConfig
    client      *http.Client
    engine      *rego.Rego          // For embedded mode
    query       rego.PreparedEvalQuery
    cache       *DecisionCache
}

func NewOPAEnforcer(config *OPAConfig) (*OPAEnforcer, error) {
    enforcer := &OPAEnforcer{
        config: config,
        client: &http.Client{Timeout: config.Timeout},
    }
    
    if config.Embedded {
        if err := enforcer.initEmbedded(); err != nil {
            return nil, fmt.Errorf("failed to init embedded OPA: %w", err)
        }
    }
    
    if config.CacheDecisions {
        enforcer.cache = NewDecisionCache(config.CacheTTL)
    }
    
    return enforcer, nil
}

func (e *OPAEnforcer) initEmbedded() error {
    ctx := context.Background()
    
    // Load rego files
    var modules []func(*rego.Rego)
    for _, file := range e.config.RegoFiles {
        content, err := os.ReadFile(file)
        if err != nil {
            return fmt.Errorf("failed to read rego file %s: %w", file, err)
        }
        modules = append(modules, rego.Module(file, string(content)))
    }
    
    // Load data files
    store := inmem.New()
    for _, file := range e.config.DataFiles {
        content, err := os.ReadFile(file)
        if err != nil {
            return fmt.Errorf("failed to read data file %s: %w", file, err)
        }
        
        var data map[string]interface{}
        if err := yaml.Unmarshal(content, &data); err != nil {
            return fmt.Errorf("failed to parse data file %s: %w", file, err)
        }
        
        txn, _ := store.NewTransaction(ctx, storage.WriteParams)
        store.Write(ctx, txn, storage.AddOp, storage.Path{}, data)
        store.Commit(ctx, txn)
    }
    
    // Prepare query
    r := rego.New(
        append(modules,
            rego.Query("data.stac.authz.allow"),
            rego.Store(store),
        )...,
    )
    
    query, err := r.PrepareForEval(ctx)
    if err != nil {
        return fmt.Errorf("failed to prepare rego query: %w", err)
    }
    
    e.query = query
    return nil
}

// AuthzInput is sent to OPA for policy evaluation
type AuthzInput struct {
    // Principal information
    Principal   *PrincipalInfo    `json:"principal"`
    
    // Request information
    Request     *RequestInfo      `json:"request"`
    
    // STAC-specific context
    STAC        *STACContext      `json:"stac"`
}

type PrincipalInfo struct {
    ID          string            `json:"id"`
    Type        string            `json:"type"`           // "user", "service", "anonymous"
    Email       string            `json:"email,omitempty"`
    Groups      []string          `json:"groups,omitempty"`
    Roles       []string          `json:"roles,omitempty"`
    Attributes  map[string]string `json:"attributes,omitempty"`
    
    // Geofencing attributes (set by identity provider or config)
    AllowedRegions []string       `json:"allowed_regions,omitempty"` // Named regions
    AllowedGeometry *GeoJSON      `json:"allowed_geometry,omitempty"` // Explicit geometry
    DeniedGeometry  *GeoJSON      `json:"denied_geometry,omitempty"`  // Exclusion zones
}

type RequestInfo struct {
    Method      string            `json:"method"`
    Path        string            `json:"path"`
    Query       map[string]string `json:"query,omitempty"`
    Headers     map[string]string `json:"headers,omitempty"`
    ClientIP    string            `json:"client_ip"`
    Timestamp   time.Time         `json:"timestamp"`
}

type STACContext struct {
    Operation     string   `json:"operation"`      // "search", "get_item", "get_collection", etc.
    Collections   []string `json:"collections,omitempty"`
    ItemID        string   `json:"item_id,omitempty"`
    BBox          []float64 `json:"bbox,omitempty"`
    Intersects    *GeoJSON `json:"intersects,omitempty"`
    Datetime      string   `json:"datetime,omitempty"`
    QueryParams   map[string]interface{} `json:"query_params,omitempty"`
}

// AuthzDecision is the result of policy evaluation
type AuthzDecision struct {
    Allow           bool              `json:"allow"`
    Reason          string            `json:"reason,omitempty"`
    
    // Filters to apply to the request (policy can modify queries)
    SpatialFilter   *GeoJSON          `json:"spatial_filter,omitempty"`
    TemporalFilter  *TimeRange        `json:"temporal_filter,omitempty"`
    CollectionFilter []string         `json:"collection_filter,omitempty"`
    PropertyFilters map[string]interface{} `json:"property_filters,omitempty"`
    
    // Restrictions on response
    RedactFields    []string          `json:"redact_fields,omitempty"`
    MaxResults      int               `json:"max_results,omitempty"`
}

func (e *OPAEnforcer) Evaluate(ctx context.Context, input *AuthzInput) (*AuthzDecision, error) {
    // Check cache first
    if e.cache != nil {
        if decision, ok := e.cache.Get(input); ok {
            return decision, nil
        }
    }
    
    var decision *AuthzDecision
    var err error
    
    if e.config.Embedded {
        decision, err = e.evaluateEmbedded(ctx, input)
    } else {
        decision, err = e.evaluateRemote(ctx, input)
    }
    
    if err != nil {
        return nil, err
    }
    
    // Cache the decision
    if e.cache != nil && decision != nil {
        e.cache.Set(input, decision)
    }
    
    return decision, nil
}

func (e *OPAEnforcer) evaluateEmbedded(ctx context.Context, input *AuthzInput) (*AuthzDecision, error) {
    results, err := e.query.Eval(ctx, rego.EvalInput(input))
    if err != nil {
        return nil, fmt.Errorf("OPA evaluation failed: %w", err)
    }
    
    if len(results) == 0 || len(results[0].Expressions) == 0 {
        return &AuthzDecision{Allow: false, Reason: "no policy decision"}, nil
    }
    
    // Parse decision from OPA result
    return parseOPAResult(results[0].Expressions[0].Value)
}

func (e *OPAEnforcer) evaluateRemote(ctx context.Context, input *AuthzInput) (*AuthzDecision, error) {
    body, _ := json.Marshal(map[string]interface{}{"input": input})
    
    url := fmt.Sprintf("%s/%s", e.config.URL, e.config.PolicyPath)
    req, _ := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
    req.Header.Set("Content-Type", "application/json")
    
    resp, err := e.client.Do(req)
    if err != nil {
        return nil, fmt.Errorf("OPA request failed: %w", err)
    }
    defer resp.Body.Close()
    
    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("OPA returned status %d", resp.StatusCode)
    }
    
    var result struct {
        Result *AuthzDecision `json:"result"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        return nil, fmt.Errorf("failed to parse OPA response: %w", err)
    }
    
    return result.Result, nil
}
```

**Example OPA Policy (Rego):**

```rego
# policy/stac/authz.rego
package stac.authz

import future.keywords.if
import future.keywords.in

default allow := false

# Allow decision with optional filters
allow := decision if {
    is_authenticated
    has_collection_access
    passes_geofence
    decision := build_decision
}

# Must be authenticated (not anonymous)
is_authenticated if {
    input.principal.type != "anonymous"
}

# User must have access to requested collections
has_collection_access if {
    count(input.stac.collections) == 0  # No collection filter = search all allowed
}

has_collection_access if {
    every coll in input.stac.collections {
        collection_allowed(coll)
    }
}

collection_allowed(coll) if {
    # Check if user's role grants access
    some role in input.principal.roles
    coll in data.role_collections[role]
}

collection_allowed(coll) if {
    # Public collections are always allowed
    coll in data.public_collections
}

# Geofencing check
passes_geofence if {
    not geofence_required
}

passes_geofence if {
    geofence_required
    request_within_allowed_region
}

geofence_required if {
    count(input.principal.allowed_regions) > 0
}

geofence_required if {
    input.principal.allowed_geometry != null
}

request_within_allowed_region if {
    # Check if request bbox is within allowed geometry
    bbox := input.stac.bbox
    allowed := input.principal.allowed_geometry
    geo.within(bbox_to_polygon(bbox), allowed)
}

request_within_allowed_region if {
    # Check if request intersects geometry is within allowed
    intersects := input.stac.intersects
    allowed := input.principal.allowed_geometry
    geo.within(intersects, allowed)
}

request_within_allowed_region if {
    # Check named regions
    some region in input.principal.allowed_regions
    region_geometry := data.regions[region]
    bbox := input.stac.bbox
    geo.within(bbox_to_polygon(bbox), region_geometry)
}

# Build the final decision with any filters
build_decision := decision if {
    decision := {
        "allow": true,
        "spatial_filter": effective_geofence,
        "collection_filter": allowed_collections,
        "max_results": max_results_for_user,
    }
}

# Calculate effective geofence for this user
effective_geofence := geom if {
    geom := input.principal.allowed_geometry
} else := geom if {
    # Merge all allowed region geometries
    geom := merge_regions([data.regions[r] | some r in input.principal.allowed_regions])
}

# Collections this user can access
allowed_collections := colls if {
    colls := [c | 
        some role in input.principal.roles
        some c in data.role_collections[role]
    ]
}

# Different users get different result limits
max_results_for_user := limit if {
    "premium" in input.principal.roles
    limit := 10000
} else := limit if {
    "standard" in input.principal.roles
    limit := 1000
} else := 100

# Helper to convert bbox to polygon
bbox_to_polygon(bbox) := polygon if {
    polygon := {
        "type": "Polygon",
        "coordinates": [[
            [bbox[0], bbox[1]],
            [bbox[2], bbox[1]],
            [bbox[2], bbox[3]],
            [bbox[0], bbox[3]],
            [bbox[0], bbox[1]]
        ]]
    }
}
```

**OPA Policy Data (data.json):**

```json
{
  "public_collections": [
    "sentinel-2-l2a",
    "landsat-c2-l2"
  ],
  "role_collections": {
    "admin": ["*"],
    "analyst": ["sentinel-2-l2a", "landsat-c2-l2", "planet-nicfi", "internal-drone"],
    "viewer": ["sentinel-2-l2a", "landsat-c2-l2"]
  },
  "regions": {
    "conus": {
      "type": "Polygon",
      "coordinates": [[[-125, 24], [-66, 24], [-66, 50], [-125, 50], [-125, 24]]]
    },
    "europe": {
      "type": "Polygon", 
      "coordinates": [[[-10, 35], [40, 35], [40, 72], [-10, 72], [-10, 35]]]
    },
    "california": {
      "type": "Polygon",
      "coordinates": [[[-124.4, 32.5], [-114.1, 32.5], [-114.1, 42], [-124.4, 42], [-124.4, 32.5]]]
    }
  }
}
```

**Geofencing System:**

```go
package authz

// Geofencer handles geographic access control based on user identity
type Geofencer struct {
    regions     map[string]*geojson.Geometry  // Named regions
    userFences  map[string]*UserGeofence      // Per-user overrides
    config      *GeofencingConfig
    spatialIndex *rtree.RTree                  // For efficient spatial lookups
}

type GeofencingConfig struct {
    Enabled         bool              `yaml:"enabled"`
    
    // Region definitions
    RegionsFile     string            `yaml:"regions_file"`     // GeoJSON file with named regions
    RegionsURL      string            `yaml:"regions_url"`      // URL to fetch regions
    RefreshInterval time.Duration     `yaml:"refresh_interval"`
    
    // Default behavior
    DefaultAllow    bool              `yaml:"default_allow"`    // If no geofence defined
    EnforceOnSearch bool              `yaml:"enforce_on_search"`
    EnforceOnItems  bool              `yaml:"enforce_on_items"`
    
    // User fence sources
    UserFenceSource string            `yaml:"user_fence_source"` // "jwt_claim", "ldap", "database", "config"
    UserFenceClaimName string         `yaml:"user_fence_claim"`  // JWT claim containing geometry
    
    // Exclusion zones (no one can access)
    ExclusionZones  []string          `yaml:"exclusion_zones"`   // Region names
}

type UserGeofence struct {
    UserID          string
    AllowedRegions  []string           // Named regions user can access
    AllowedGeometry *geojson.Geometry  // Explicit allowed geometry
    DeniedRegions   []string           // Explicit denied regions
    DeniedGeometry  *geojson.Geometry  // Explicit denied geometry
    ValidUntil      time.Time          // Expiration
}

func NewGeofencer(config *GeofencingConfig) (*Geofencer, error) {
    gf := &Geofencer{
        config:      config,
        regions:     make(map[string]*geojson.Geometry),
        userFences:  make(map[string]*UserGeofence),
        spatialIndex: rtree.New(),
    }
    
    if err := gf.loadRegions(); err != nil {
        return nil, err
    }
    
    // Start background refresh if configured
    if config.RefreshInterval > 0 {
        go gf.refreshLoop()
    }
    
    return gf, nil
}

func (gf *Geofencer) loadRegions() error {
    if gf.config.RegionsFile != "" {
        data, err := os.ReadFile(gf.config.RegionsFile)
        if err != nil {
            return err
        }
        
        var fc geojson.FeatureCollection
        if err := json.Unmarshal(data, &fc); err != nil {
            return err
        }
        
        for _, feature := range fc.Features {
            name, _ := feature.Properties["name"].(string)
            if name != "" {
                gf.regions[name] = feature.Geometry
                gf.spatialIndex.Insert(feature.Geometry.Bound(), name)
            }
        }
    }
    
    return nil
}

// GetUserGeofence returns the effective geofence for a user
func (gf *Geofencer) GetUserGeofence(ctx context.Context, principal *Principal) (*EffectiveGeofence, error) {
    fence := &EffectiveGeofence{
        Allowed: nil,
        Denied:  nil,
    }
    
    // Check for user-specific fence
    if userFence, ok := gf.userFences[principal.ID]; ok {
        if time.Now().Before(userFence.ValidUntil) {
            fence = gf.buildFromUserFence(userFence)
        }
    }
    
    // Check JWT claims for geometry
    if gf.config.UserFenceSource == "jwt_claim" {
        if geom := gf.extractGeometryFromClaims(principal); geom != nil {
            fence.Allowed = geom
        }
    }
    
    // Check allowed regions from principal attributes
    if regions, ok := principal.Attributes["allowed_regions"]; ok {
        regionNames := strings.Split(regions, ",")
        fence.Allowed = gf.mergeRegions(regionNames)
    }
    
    // Always apply global exclusion zones
    for _, zoneName := range gf.config.ExclusionZones {
        if zone, ok := gf.regions[zoneName]; ok {
            fence.Denied = gf.unionGeometry(fence.Denied, zone)
        }
    }
    
    return fence, nil
}

type EffectiveGeofence struct {
    Allowed *geojson.Geometry  // User can only access within this area
    Denied  *geojson.Geometry  // User cannot access this area (takes precedence)
}

// ValidateRequest checks if a STAC request is within the user's geofence
func (gf *Geofencer) ValidateRequest(fence *EffectiveGeofence, req *STACRequest) (*GeofenceResult, error) {
    result := &GeofenceResult{
        Allowed:        true,
        ModifiedBBox:   nil,
        ModifiedIntersects: nil,
    }
    
    if fence.Allowed == nil && fence.Denied == nil {
        // No geofence = allow everything (if default_allow is true)
        result.Allowed = gf.config.DefaultAllow
        return result, nil
    }
    
    // Extract spatial extent from request
    var requestGeom *geojson.Geometry
    if req.Params["bbox"] != nil {
        requestGeom = bboxToGeometry(req.Params["bbox"].([]float64))
    } else if req.Params["intersects"] != nil {
        requestGeom = req.Params["intersects"].(*geojson.Geometry)
    }
    
    // If no spatial filter in request, constrain to user's allowed area
    if requestGeom == nil && fence.Allowed != nil {
        result.ModifiedIntersects = fence.Allowed
        return result, nil
    }
    
    // Check if request is within allowed area
    if fence.Allowed != nil && requestGeom != nil {
        if !gf.geometryWithin(requestGeom, fence.Allowed) {
            // Clip request to allowed area
            clipped := gf.clipGeometry(requestGeom, fence.Allowed)
            if clipped == nil || gf.geometryIsEmpty(clipped) {
                result.Allowed = false
                result.Reason = "request area outside allowed region"
                return result, nil
            }
            result.ModifiedIntersects = clipped
        }
    }
    
    // Check if request overlaps denied area
    if fence.Denied != nil && requestGeom != nil {
        if gf.geometryIntersects(requestGeom, fence.Denied) {
            // Subtract denied area from request
            subtracted := gf.subtractGeometry(requestGeom, fence.Denied)
            if subtracted == nil || gf.geometryIsEmpty(subtracted) {
                result.Allowed = false
                result.Reason = "request area overlaps restricted zone"
                return result, nil
            }
            result.ModifiedIntersects = subtracted
        }
    }
    
    return result, nil
}

type GeofenceResult struct {
    Allowed            bool
    Reason             string
    ModifiedBBox       []float64
    ModifiedIntersects *geojson.Geometry
}

// FilterResults removes items that fall outside the user's geofence
func (gf *Geofencer) FilterResults(fence *EffectiveGeofence, items []Item) []Item {
    if fence.Allowed == nil && fence.Denied == nil {
        return items
    }
    
    var filtered []Item
    for _, item := range items {
        itemGeom := item.Geometry
        
        // Check if item is within allowed area
        if fence.Allowed != nil {
            if !gf.geometryIntersects(itemGeom, fence.Allowed) {
                continue // Skip item outside allowed area
            }
        }
        
        // Check if item is in denied area
        if fence.Denied != nil {
            if gf.geometryWithin(itemGeom, fence.Denied) {
                continue // Skip item in denied area
            }
        }
        
        filtered = append(filtered, item)
    }
    
    return filtered
}

// Spatial operations using GEOS bindings
func (gf *Geofencer) geometryWithin(inner, outer *geojson.Geometry) bool {
    // Use GEOS or S2 geometry library
    innerGeos := geos.FromGeoJSON(inner)
    outerGeos := geos.FromGeoJSON(outer)
    return innerGeos.Within(outerGeos)
}

func (gf *Geofencer) geometryIntersects(a, b *geojson.Geometry) bool {
    aGeos := geos.FromGeoJSON(a)
    bGeos := geos.FromGeoJSON(b)
    return aGeos.Intersects(bGeos)
}

func (gf *Geofencer) clipGeometry(geom, clipper *geojson.Geometry) *geojson.Geometry {
    geomGeos := geos.FromGeoJSON(geom)
    clipperGeos := geos.FromGeoJSON(clipper)
    result := geomGeos.Intersection(clipperGeos)
    return result.ToGeoJSON()
}

func (gf *Geofencer) subtractGeometry(geom, subtract *geojson.Geometry) *geojson.Geometry {
    geomGeos := geos.FromGeoJSON(geom)
    subtractGeos := geos.FromGeoJSON(subtract)
    result := geomGeos.Difference(subtractGeos)
    return result.ToGeoJSON()
}

func (gf *Geofencer) mergeRegions(regionNames []string) *geojson.Geometry {
    var merged *geos.Geometry
    for _, name := range regionNames {
        if region, ok := gf.regions[name]; ok {
            regionGeos := geos.FromGeoJSON(region)
            if merged == nil {
                merged = regionGeos
            } else {
                merged = merged.Union(regionGeos)
            }
        }
    }
    if merged == nil {
        return nil
    }
    return merged.ToGeoJSON()
}
```

**Middleware Integration:**

```go
func (m *AuthzMiddleware) ProcessRequest(ctx context.Context, req *STACRequest) (*STACRequest, error) {
    principal := PrincipalFromContext(ctx)
    
    // Build authorization input
    input := &AuthzInput{
        Principal: buildPrincipalInfo(principal),
        Request:   buildRequestInfo(req),
        STAC:      buildSTACContext(req),
    }
    
    // Get geofence for user
    var fence *EffectiveGeofence
    if m.geofencer != nil && m.config.Geofencing.Enabled {
        var err error
        fence, err = m.geofencer.GetUserGeofence(ctx, principal)
        if err != nil {
            return nil, fmt.Errorf("geofence lookup failed: %w", err)
        }
        input.Principal.AllowedGeometry = fence.Allowed
        input.Principal.DeniedGeometry = fence.Denied
    }
    
    // Evaluate policy (OPA or built-in)
    decision, err := m.enforcer.Evaluate(ctx, input)
    if err != nil {
        return nil, fmt.Errorf("policy evaluation failed: %w", err)
    }
    
    if !decision.Allow {
        return nil, &ForbiddenError{
            Reason:    decision.Reason,
            Principal: principal.ID,
        }
    }
    
    // Apply decision filters to request
    if decision.SpatialFilter != nil {
        req.Params["intersects"] = mergeGeometry(
            req.Params["intersects"],
            decision.SpatialFilter,
        )
    }
    
    if decision.TemporalFilter != nil {
        req.Params["datetime"] = mergeTemporalFilter(
            req.Params["datetime"],
            decision.TemporalFilter,
        )
    }
    
    if len(decision.CollectionFilter) > 0 {
        req.Params["collections"] = filterCollections(
            req.Params["collections"],
            decision.CollectionFilter,
        )
    }
    
    // Store decision for response processing
    ctx = context.WithValue(ctx, AuthzDecisionKey, decision)
    ctx = context.WithValue(ctx, GeofenceKey, fence)
    req.Context = ctx
    
    return req, nil
}

func (m *AuthzMiddleware) ProcessResponse(ctx context.Context, 
    req *STACRequest, resp *STACResponse) (*STACResponse, error) {
    
    decision := ctx.Value(AuthzDecisionKey).(*AuthzDecision)
    fence := ctx.Value(GeofenceKey).(*EffectiveGeofence)
    
    // Filter results by geofence (belt and suspenders with query filter)
    if fence != nil && m.geofencer != nil {
        var items []Item
        if err := json.Unmarshal(resp.Body, &items); err == nil {
            filtered := m.geofencer.FilterResults(fence, items)
            resp.Body, _ = json.Marshal(filtered)
        }
    }
    
    // Redact fields if policy requires
    if len(decision.RedactFields) > 0 {
        resp.Body = redactFields(resp.Body, decision.RedactFields)
    }
    
    // Enforce max results
    if decision.MaxResults > 0 {
        resp.Body = truncateResults(resp.Body, decision.MaxResults)
    }
    
    return resp, nil
}
```

#### 4.2.3 URL Remapping Middleware

Transform asset URLs in responses for CDN routing, signed URLs, or security.

```go
package remap

type RemapRule struct {
    Match    *regexp.Regexp
    Replace  string
    SignURL  bool
    SignTTL  time.Duration
    Signer   URLSigner
}

type URLRemapMiddleware struct {
    rules []RemapRule
}

func (m *URLRemapMiddleware) ProcessResponse(ctx context.Context, 
    req *STACRequest, resp *STACResponse) (*STACResponse, error) {
    
    // Parse response body
    var data map[string]interface{}
    if err := json.Unmarshal(resp.Body, &data); err != nil {
        return resp, nil // Not JSON, pass through
    }
    
    // Recursively transform URLs
    transformed := m.transformURLs(ctx, data)
    
    body, _ := json.Marshal(transformed)
    resp.Body = body
    
    return resp, nil
}

func (m *URLRemapMiddleware) transformURLs(ctx context.Context, 
    data interface{}) interface{} {
    
    switch v := data.(type) {
    case map[string]interface{}:
        // Check for "href" keys (STAC asset links)
        if href, ok := v["href"].(string); ok {
            v["href"] = m.remapURL(ctx, href)
        }
        // Recurse into nested objects
        for key, val := range v {
            v[key] = m.transformURLs(ctx, val)
        }
        return v
    case []interface{}:
        for i, val := range v {
            v[i] = m.transformURLs(ctx, val)
        }
        return v
    default:
        return data
    }
}

func (m *URLRemapMiddleware) remapURL(ctx context.Context, url string) string {
    for _, rule := range m.rules {
        if rule.Match.MatchString(url) {
            newURL := rule.Match.ReplaceAllString(url, rule.Replace)
            if rule.SignURL && rule.Signer != nil {
                newURL = rule.Signer.Sign(ctx, newURL, rule.SignTTL)
            }
            return newURL
        }
    }
    return url
}
```

#### 4.2.4 Caching Middleware

```go
package cache

type CacheMiddleware struct {
    store    CacheStore
    strategy CacheStrategy
}

type CacheStore interface {
    Get(ctx context.Context, key string) ([]byte, bool)
    Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
    Delete(ctx context.Context, key string) error
}

type CacheStrategy interface {
    ShouldCache(req *STACRequest) bool
    CacheKey(req *STACRequest) string
    TTL(req *STACRequest, resp *STACResponse) time.Duration
}

// Default strategy caches GET requests for collections and items
type DefaultCacheStrategy struct {
    CollectionTTL time.Duration
    ItemTTL       time.Duration
    SearchTTL     time.Duration
}

func (s *DefaultCacheStrategy) ShouldCache(req *STACRequest) bool {
    return req.Request.Method == http.MethodGet
}

func (s *DefaultCacheStrategy) CacheKey(req *STACRequest) string {
    return fmt.Sprintf("%s:%s:%s", 
        req.RequestType, 
        req.Request.URL.Path, 
        req.Request.URL.RawQuery,
    )
}
```

#### 4.2.5 Rate Limiting Middleware

```go
package ratelimit

type RateLimitMiddleware struct {
    limiter    Limiter
    keyFunc    KeyFunc
    quotaFunc  QuotaFunc
}

type Limiter interface {
    Allow(ctx context.Context, key string, quota Quota) (bool, RateLimitInfo, error)
}

type Quota struct {
    Requests int
    Window   time.Duration
    Burst    int
}

type KeyFunc func(req *STACRequest) string
type QuotaFunc func(req *STACRequest, principal *Principal) Quota

// Default: rate limit by principal ID or IP
func DefaultKeyFunc(req *STACRequest) string {
    if p := PrincipalFromContext(req.Context); p != nil {
        return p.ID
    }
    return req.Request.RemoteAddr
}
```

### 4.3 Federation System

The federation system is a core capability that enables querying multiple disparate STAC servers as if they were a single unified catalog. Clients interact with one endpoint and receive aggregated results from all configured downstream servers transparently.

#### 4.3.1 Federation Concepts

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Client Request                                  │
│                     POST /search {"collections": ["sentinel-2"]}            │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              stac-proxy                                      │
│                                                                              │
│   1. Parse request                                                           │
│   2. Determine which origins serve "sentinel-2"                              │
│   3. Fan out requests to applicable origins (with per-origin auth)          │
│   4. Collect and merge results                                               │
│   5. Rewrite links to route through proxy                                    │
│   6. Return unified response                                                 │
└─────────────────────────────────────────────────────────────────────────────┘
          │                           │                           │
          ▼                           ▼                           ▼
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│   AWS Earth      │     │   Planet NICFI   │     │  Internal STAC   │
│   (public)       │     │   (API key)      │     │  (OAuth2 + mTLS) │
│                  │     │                  │     │                  │
│  sentinel-2-l2a  │     │  planet-nicfi    │     │  sentinel-2-l1c  │
│  landsat-c2-l2   │     │                  │     │  internal-drone  │
└──────────────────┘     └──────────────────┘     └──────────────────┘
```

**Key Principles:**
- **Transparency**: Clients don't know or care that data comes from multiple servers
- **Per-Origin Auth**: Each downstream server can have completely different authentication
- **Collection Routing**: Proxy knows which origins serve which collections
- **Unified Pagination**: Federated results support seamless pagination
- **Failure Isolation**: One origin failing doesn't break the entire request

#### 4.3.2 Per-Origin Authentication

Each downstream STAC server can have its own authentication configuration. The proxy handles all auth negotiation transparently.

```go
package federation

// OriginAuth defines authentication for a downstream STAC server
type OriginAuth struct {
    Type string `yaml:"type"` // none, basic, bearer, api_key, oauth2, aws_sig_v4, custom

    // Basic Auth
    Username string `yaml:"username"`
    Password string `yaml:"password"`

    // Bearer Token (static)
    Token string `yaml:"token"`

    // API Key
    APIKeyHeader string `yaml:"api_key_header"` // e.g., "X-API-Key"
    APIKeyValue  string `yaml:"api_key_value"`
    APIKeyInQuery bool  `yaml:"api_key_in_query"` // Send as query param instead

    // OAuth2 Client Credentials Flow
    OAuth2 *OAuth2Config `yaml:"oauth2"`

    // AWS Signature V4 (for AWS-hosted STAC servers)
    AWSSigV4 *AWSSigV4Config `yaml:"aws_sig_v4"`

    // Custom header injection
    CustomHeaders map[string]string `yaml:"custom_headers"`

    // mTLS client certificate
    ClientCert *ClientCertConfig `yaml:"client_cert"`
}

type OAuth2Config struct {
    TokenURL     string   `yaml:"token_url"`
    ClientID     string   `yaml:"client_id"`
    ClientSecret string   `yaml:"client_secret"`
    Scopes       []string `yaml:"scopes"`
    Audience     string   `yaml:"audience"`
    // Token caching handled automatically
}

type AWSSigV4Config struct {
    Region    string `yaml:"region"`
    Service   string `yaml:"service"` // Usually "execute-api" or "s3"
    AccessKey string `yaml:"access_key"`
    SecretKey string `yaml:"secret_key"`
    // Or use IAM role
    UseIAMRole bool `yaml:"use_iam_role"`
}

type ClientCertConfig struct {
    CertFile string `yaml:"cert_file"`
    KeyFile  string `yaml:"key_file"`
    CAFile   string `yaml:"ca_file"` // For server verification
}
```

#### 4.3.3 Origin Configuration

```go
package federation

type Origin struct {
    // Identity
    ID          string `yaml:"id"`           // Unique identifier (e.g., "aws-earth-search")
    Name        string `yaml:"name"`         // Human-readable name
    Description string `yaml:"description"`

    // Connection
    BaseURL     string            `yaml:"base_url"`     // e.g., "https://earth-search.aws.element84.com/v1"
    Enabled     bool              `yaml:"enabled"`
    Timeout     time.Duration     `yaml:"timeout"`
    RetryPolicy *RetryPolicy      `yaml:"retry"`

    // Authentication for this downstream server
    Auth *OriginAuth `yaml:"auth"`

    // Collection routing
    Collections        []string `yaml:"collections"`         // Whitelist (empty = all)
    ExcludeCollections []string `yaml:"exclude_collections"` // Blacklist

    // Behavior
    Priority    int  `yaml:"priority"`     // Lower = preferred for conflicts
    ReadOnly    bool `yaml:"read_only"`    // If true, never route writes here
    Searchable  bool `yaml:"searchable"`   // Include in federated searches (default: true)

    // Collection discovery
    AutoDiscover       bool          `yaml:"auto_discover"`        // Fetch collections on startup
    DiscoveryInterval  time.Duration `yaml:"discovery_interval"`   // Re-fetch interval

    // Transformations
    CollectionPrefix   string            `yaml:"collection_prefix"`    // Prefix collection IDs
    CollectionMapping  map[string]string `yaml:"collection_mapping"`   // Rename collections
    StripPathPrefix    string            `yaml:"strip_path_prefix"`    // Remove path prefix from origin
}

type RetryPolicy struct {
    MaxRetries     int           `yaml:"max_retries"`
    InitialBackoff time.Duration `yaml:"initial_backoff"`
    MaxBackoff     time.Duration `yaml:"max_backoff"`
    RetryOn        []int         `yaml:"retry_on"` // HTTP status codes to retry
}

type FederationConfig struct {
    Origins           []Origin
    ConflictStrategy  ConflictStrategy  // How to handle ID collisions
    SearchStrategy    SearchStrategy    // Parallel, sequential, priority
    MaxConcurrent     int               // Max parallel requests
    AggregateTimeout  time.Duration     // Overall timeout for federated requests
}

#### 4.3.4 Origin Client with Authentication

Each origin gets its own HTTP client configured with the appropriate authentication mechanism.

```go
package federation

// OriginClient handles communication with a single downstream STAC server
type OriginClient struct {
    origin     *Origin
    httpClient *http.Client
    authProvider AuthProvider
    baseURL    *url.URL
    
    // Cached collection info
    collections     map[string]*Collection
    collectionsLock sync.RWMutex
    lastDiscovery   time.Time
}

// AuthProvider handles authentication for a specific origin
type AuthProvider interface {
    // ApplyAuth modifies the request with appropriate credentials
    ApplyAuth(ctx context.Context, req *http.Request) error
    // Refresh updates credentials if needed (e.g., OAuth2 token refresh)
    Refresh(ctx context.Context) error
}

func NewOriginClient(origin *Origin) (*OriginClient, error) {
    baseURL, err := url.Parse(origin.BaseURL)
    if err != nil {
        return nil, fmt.Errorf("invalid base URL: %w", err)
    }

    // Build HTTP client with optional mTLS
    transport := &http.Transport{
        MaxIdleConns:        100,
        MaxIdleConnsPerHost: 10,
        IdleConnTimeout:     90 * time.Second,
    }

    if origin.Auth != nil && origin.Auth.ClientCert != nil {
        tlsConfig, err := buildTLSConfig(origin.Auth.ClientCert)
        if err != nil {
            return nil, fmt.Errorf("TLS config error: %w", err)
        }
        transport.TLSClientConfig = tlsConfig
    }

    httpClient := &http.Client{
        Transport: transport,
        Timeout:   origin.Timeout,
    }

    // Build auth provider based on config
    authProvider, err := buildAuthProvider(origin.Auth)
    if err != nil {
        return nil, fmt.Errorf("auth provider error: %w", err)
    }

    client := &OriginClient{
        origin:       origin,
        httpClient:   httpClient,
        authProvider: authProvider,
        baseURL:      baseURL,
        collections:  make(map[string]*Collection),
    }

    // Initial collection discovery if enabled
    if origin.AutoDiscover {
        if err := client.discoverCollections(context.Background()); err != nil {
            log.Warn("initial collection discovery failed", 
                "origin", origin.ID, "error", err)
        }
    }

    return client, nil
}

func buildAuthProvider(auth *OriginAuth) (AuthProvider, error) {
    if auth == nil || auth.Type == "none" || auth.Type == "" {
        return &NoOpAuthProvider{}, nil
    }

    switch auth.Type {
    case "basic":
        return &BasicAuthProvider{
            Username: auth.Username,
            Password: auth.Password,
        }, nil

    case "bearer":
        return &BearerAuthProvider{
            Token: auth.Token,
        }, nil

    case "api_key":
        return &APIKeyAuthProvider{
            Header:   auth.APIKeyHeader,
            Value:    auth.APIKeyValue,
            InQuery:  auth.APIKeyInQuery,
        }, nil

    case "oauth2":
        return NewOAuth2Provider(auth.OAuth2)

    case "aws_sig_v4":
        return NewAWSSigV4Provider(auth.AWSSigV4)

    case "custom":
        return &CustomHeadersProvider{
            Headers: auth.CustomHeaders,
        }, nil

    default:
        return nil, fmt.Errorf("unknown auth type: %s", auth.Type)
    }
}

// OAuth2Provider handles OAuth2 client credentials flow with token caching
type OAuth2Provider struct {
    config      *OAuth2Config
    token       *oauth2.Token
    tokenLock   sync.RWMutex
    tokenSource oauth2.TokenSource
}

func NewOAuth2Provider(config *OAuth2Config) (*OAuth2Provider, error) {
    oauth2Config := &clientcredentials.Config{
        ClientID:     config.ClientID,
        ClientSecret: config.ClientSecret,
        TokenURL:     config.TokenURL,
        Scopes:       config.Scopes,
    }

    if config.Audience != "" {
        oauth2Config.EndpointParams = url.Values{
            "audience": {config.Audience},
        }
    }

    return &OAuth2Provider{
        config:      config,
        tokenSource: oauth2Config.TokenSource(context.Background()),
    }, nil
}

func (p *OAuth2Provider) ApplyAuth(ctx context.Context, req *http.Request) error {
    token, err := p.tokenSource.Token()
    if err != nil {
        return fmt.Errorf("failed to get OAuth2 token: %w", err)
    }
    req.Header.Set("Authorization", "Bearer "+token.AccessToken)
    return nil
}

// DoRequest executes an HTTP request to the origin with authentication
func (c *OriginClient) DoRequest(ctx context.Context, method, path string, 
    body io.Reader) (*http.Response, error) {
    
    reqURL := c.baseURL.ResolveReference(&url.URL{Path: path})
    
    req, err := http.NewRequestWithContext(ctx, method, reqURL.String(), body)
    if err != nil {
        return nil, err
    }

    req.Header.Set("Accept", "application/geo+json")
    if body != nil {
        req.Header.Set("Content-Type", "application/json")
    }

    // Apply origin-specific authentication
    if c.authProvider != nil {
        if err := c.authProvider.ApplyAuth(ctx, req); err != nil {
            return nil, fmt.Errorf("auth failed for origin %s: %w", c.origin.ID, err)
        }
    }

    // Execute with retry
    return c.doWithRetry(ctx, req)
}

func (c *OriginClient) doWithRetry(ctx context.Context, req *http.Request) (*http.Response, error) {
    policy := c.origin.RetryPolicy
    if policy == nil {
        return c.httpClient.Do(req)
    }

    var lastErr error
    backoff := policy.InitialBackoff

    for attempt := 0; attempt <= policy.MaxRetries; attempt++ {
        if attempt > 0 {
            select {
            case <-ctx.Done():
                return nil, ctx.Err()
            case <-time.After(backoff):
                backoff = min(backoff*2, policy.MaxBackoff)
            }
        }

        resp, err := c.httpClient.Do(req)
        if err != nil {
            lastErr = err
            continue
        }

        // Check if we should retry based on status code
        if !shouldRetry(resp.StatusCode, policy.RetryOn) {
            return resp, nil
        }

        resp.Body.Close()
        lastErr = fmt.Errorf("received status %d", resp.StatusCode)
    }

    return nil, fmt.Errorf("max retries exceeded: %w", lastErr)
}
```

#### 4.3.5 Federation Handler

The FederationHandler orchestrates queries across all configured origins and merges results into a unified response.

```go
package federation

type FederationHandler struct {
    config       *FederationConfig
    origins      map[string]*OriginClient
    router       *CollectionRouter
    merger       *ResultMerger
}

func NewFederationHandler(config *FederationConfig) (*FederationHandler, error) {
    handler := &FederationHandler{
        config:  config,
        origins: make(map[string]*OriginClient),
        router:  NewCollectionRouter(),
        merger:  NewResultMerger(config.ConflictStrategy),
    }

    // Initialize origin clients with their auth
    for i := range config.Origins {
        origin := &config.Origins[i]
        if !origin.Enabled {
            continue
        }

        client, err := NewOriginClient(origin)
        if err != nil {
            return nil, fmt.Errorf("failed to init origin %s: %w", origin.ID, err)
        }

        handler.origins[origin.ID] = client
        handler.router.Register(origin)
    }

    return handler, nil
}

// Search fans out a search request to applicable origins and merges results
func (h *FederationHandler) Search(ctx context.Context, 
    req *STACRequest) (*STACResponse, error) {
    
    // Parse the search request
    searchReq, err := ParseSearchRequest(req)
    if err != nil {
        return nil, fmt.Errorf("invalid search request: %w", err)
    }

    // Determine which origins to query based on requested collections
    origins := h.router.Route(searchReq.Collections)
    if len(origins) == 0 {
        // No origins match - return empty result
        return h.emptySearchResponse(searchReq), nil
    }

    // Create context with aggregate timeout
    ctx, cancel := context.WithTimeout(ctx, h.config.AggregateTimeout)
    defer cancel()

    // Fan out requests
    results := h.fanOutSearch(ctx, origins, searchReq)

    // Merge results from all origins
    return h.merger.MergeSearchResults(results, searchReq)
}

func (h *FederationHandler) fanOutSearch(ctx context.Context, 
    origins []*Origin, searchReq *SearchRequest) []*OriginSearchResult {
    
    resultsChan := make(chan *OriginSearchResult, len(origins))
    sem := make(chan struct{}, h.config.MaxConcurrent)

    var wg sync.WaitGroup
    for _, origin := range origins {
        wg.Add(1)
        go func(origin *Origin) {
            defer wg.Done()
            
            sem <- struct{}{}
            defer func() { <-sem }()

            result := h.searchOrigin(ctx, origin, searchReq)
            resultsChan <- result
        }(origin)
    }

    go func() {
        wg.Wait()
        close(resultsChan)
    }()

    var results []*OriginSearchResult
    for result := range resultsChan {
        results = append(results, result)
    }

    return results
}

func (h *FederationHandler) searchOrigin(ctx context.Context, 
    origin *Origin, searchReq *SearchRequest) *OriginSearchResult {
    
    client := h.origins[origin.ID]
    
    result := &OriginSearchResult{
        OriginID: origin.ID,
        Priority: origin.Priority,
    }

    // Adapt request for this specific origin
    originReq := h.adaptRequestForOrigin(searchReq, origin)
    
    // Execute the search
    body, _ := json.Marshal(originReq)
    resp, err := client.DoRequest(ctx, "POST", "/search", bytes.NewReader(body))
    if err != nil {
        result.Error = err
        log.Warn("origin search failed", 
            "origin", origin.ID, 
            "error", err)
        return result
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        result.Error = fmt.Errorf("origin returned status %d", resp.StatusCode)
        return result
    }

    // Parse response
    var featureCollection FeatureCollection
    if err := json.NewDecoder(resp.Body).Decode(&featureCollection); err != nil {
        result.Error = fmt.Errorf("failed to parse response: %w", err)
        return result
    }

    result.Items = featureCollection.Features
    result.Context = featureCollection.Context
    result.Links = featureCollection.Links
    
    return result
}

// adaptRequestForOrigin modifies the search request for a specific origin
func (h *FederationHandler) adaptRequestForOrigin(req *SearchRequest, 
    origin *Origin) *SearchRequest {
    
    adapted := req.Clone()

    // Map collection names if the origin uses different names
    if len(origin.CollectionMapping) > 0 {
        var mappedCollections []string
        for _, coll := range adapted.Collections {
            if mapped, ok := origin.CollectionMapping[coll]; ok {
                mappedCollections = append(mappedCollections, mapped)
            } else {
                mappedCollections = append(mappedCollections, coll)
            }
        }
        adapted.Collections = mappedCollections
    }

    // Remove collection prefix if origin uses prefixed names internally
    if origin.CollectionPrefix != "" {
        for i, coll := range adapted.Collections {
            adapted.Collections[i] = strings.TrimPrefix(coll, origin.CollectionPrefix)
        }
    }

    return adapted
}

// GetCollections returns a unified list of collections from all origins
func (h *FederationHandler) GetCollections(ctx context.Context) (*STACResponse, error) {
    ctx, cancel := context.WithTimeout(ctx, h.config.AggregateTimeout)
    defer cancel()

    var allCollections []*Collection
    var mu sync.Mutex
    var wg sync.WaitGroup

    for originID, client := range h.origins {
        originID, client := originID, client
        origin := h.config.getOrigin(originID)
        
        wg.Add(1)
        go func() {
            defer wg.Done()

            collections, err := client.FetchCollections(ctx)
            if err != nil {
                log.Warn("failed to fetch collections", 
                    "origin", originID, "error", err)
                return
            }

            mu.Lock()
            defer mu.Unlock()

            for _, coll := range collections {
                // Apply collection prefix
                if origin.CollectionPrefix != "" {
                    coll.ID = origin.CollectionPrefix + coll.ID
                }
                
                // Add origin metadata
                if coll.Properties == nil {
                    coll.Properties = make(map[string]interface{})
                }
                coll.Properties["stac_proxy:origin"] = originID
                coll.Properties["stac_proxy:origin_name"] = origin.Name

                allCollections = append(allCollections, coll)
            }
        }()
    }

    wg.Wait()

    // Deduplicate and sort
    collections := h.merger.DeduplicateCollections(allCollections)

    return h.buildCollectionsResponse(collections), nil
}
```

#### 4.3.6 Collection Router

The collection router maintains a mapping of which collections are served by which origins, enabling efficient request routing.

```go
package federation

type CollectionRouter struct {
    // collection ID -> list of origins that serve it
    collectionToOrigins map[string][]*Origin
    // All origins (for queries without collection filter)
    allOrigins          []*Origin
    mu                  sync.RWMutex
}

func NewCollectionRouter() *CollectionRouter {
    return &CollectionRouter{
        collectionToOrigins: make(map[string][]*Origin),
    }
}

func (r *CollectionRouter) Register(origin *Origin) {
    r.mu.Lock()
    defer r.mu.Unlock()

    r.allOrigins = append(r.allOrigins, origin)

    // If origin has explicit collection list, register those
    if len(origin.Collections) > 0 {
        for _, collID := range origin.Collections {
            // Apply prefix if configured
            fullID := origin.CollectionPrefix + collID
            r.collectionToOrigins[fullID] = append(
                r.collectionToOrigins[fullID], origin)
        }
    }
}

// Route returns origins that should be queried for the given collections
func (r *CollectionRouter) Route(collections []string) []*Origin {
    r.mu.RLock()
    defer r.mu.RUnlock()

    // No collection filter = query all origins
    if len(collections) == 0 {
        return r.allOrigins
    }

    // Find origins that serve any of the requested collections
    originSet := make(map[string]*Origin)
    for _, collID := range collections {
        // Check explicit mappings
        if origins, ok := r.collectionToOrigins[collID]; ok {
            for _, o := range origins {
                originSet[o.ID] = o
            }
            continue
        }

        // For origins without explicit collection lists, they might serve it
        for _, o := range r.allOrigins {
            if len(o.Collections) == 0 && !r.isExcluded(o, collID) {
                originSet[o.ID] = o
            }
        }
    }

    var result []*Origin
    for _, o := range originSet {
        result = append(result, o)
    }
    return result
}

func (r *CollectionRouter) isExcluded(origin *Origin, collID string) bool {
    for _, excluded := range origin.ExcludeCollections {
        if excluded == collID {
            return true
        }
    }
    return false
}

// UpdateFromDiscovery updates routing based on discovered collections
func (r *CollectionRouter) UpdateFromDiscovery(originID string, collections []string) {
    r.mu.Lock()
    defer r.mu.Unlock()

    // Remove old mappings for this origin
    for collID, origins := range r.collectionToOrigins {
        var filtered []*Origin
        for _, o := range origins {
            if o.ID != originID {
                filtered = append(filtered, o)
            }
        }
        r.collectionToOrigins[collID] = filtered
    }

    // Add new mappings
    var origin *Origin
    for _, o := range r.allOrigins {
        if o.ID == originID {
            origin = o
            break
        }
    }
    if origin == nil {
        return
    }

    for _, collID := range collections {
        fullID := origin.CollectionPrefix + collID
        r.collectionToOrigins[fullID] = append(
            r.collectionToOrigins[fullID], origin)
    }
}
```

#### 4.3.7 Result Aggregation

```go
package federation

type ConflictStrategy int

const (
    // ConflictFirstWins - First origin's item wins (based on response time)
    ConflictFirstWins ConflictStrategy = iota
    // ConflictPriorityWins - Highest priority origin wins
    ConflictPriorityWins
    // ConflictMerge - Merge items with same ID (combine assets, keep latest properties)
    ConflictMerge
    // ConflictNamespace - Prefix item IDs with origin ID (no conflicts possible)
    ConflictNamespace
    // ConflictRejectDuplicates - Return error if duplicates found
    ConflictRejectDuplicates
)

type OriginSearchResult struct {
    OriginID string
    Priority int
    Items    []Item
    Context  *SearchContext
    Links    []Link
    Error    error
}

type ResultMerger struct {
    strategy ConflictStrategy
}

func NewResultMerger(strategy ConflictStrategy) *ResultMerger {
    return &ResultMerger{strategy: strategy}
}

func (m *ResultMerger) MergeSearchResults(results []*OriginSearchResult, 
    req *SearchRequest) (*STACResponse, error) {
    
    // Sort by priority (lower = higher priority)
    sort.Slice(results, func(i, j int) bool {
        return results[i].Priority < results[j].Priority
    })

    // Track items by ID for conflict resolution
    itemsByID := make(map[string]*itemWithOrigin)
    var orderedItems []Item
    var totalMatched int

    for _, result := range results {
        if result.Error != nil {
            continue // Skip failed origins
        }

        if result.Context != nil {
            totalMatched += result.Context.Matched
        }

        for _, item := range result.Items {
            key := m.itemKey(result.OriginID, item)
            
            if existing, exists := itemsByID[key]; exists {
                // Handle conflict
                merged, err := m.resolveConflict(existing, &item, result.OriginID)
                if err != nil {
                    return nil, err
                }
                itemsByID[key].item = merged
            } else {
                // New item
                transformed := m.transformItem(item, result.OriginID)
                itemsByID[key] = &itemWithOrigin{
                    item:     transformed,
                    originID: result.OriginID,
                    priority: result.Priority,
                }
                orderedItems = append(orderedItems, transformed)
            }
        }
    }

    // Apply pagination from the request
    items := m.paginate(orderedItems, req)

    // Build the response
    return &STACResponse{
        StatusCode: http.StatusOK,
        Body:       m.buildFeatureCollectionJSON(items, totalMatched, req),
    }, nil
}

func (m *ResultMerger) itemKey(originID string, item Item) string {
    if m.strategy == ConflictNamespace {
        return originID + ":" + item.ID
    }
    // Use collection + item ID as key (items across collections can have same ID)
    return item.Collection + ":" + item.ID
}

func (m *ResultMerger) resolveConflict(existing *itemWithOrigin, 
    incoming *Item, incomingOrigin string) (Item, error) {
    
    switch m.strategy {
    case ConflictFirstWins:
        return existing.item, nil

    case ConflictPriorityWins:
        // existing is already sorted by priority, so keep it
        return existing.item, nil

    case ConflictMerge:
        return m.mergeItems(existing.item, *incoming, incomingOrigin), nil

    case ConflictNamespace:
        // Shouldn't happen since keys are different
        return existing.item, nil

    case ConflictRejectDuplicates:
        return Item{}, fmt.Errorf("duplicate item ID %s from origins %s and %s",
            incoming.ID, existing.originID, incomingOrigin)

    default:
        return existing.item, nil
    }
}

func (m *ResultMerger) mergeItems(existing, incoming Item, incomingOrigin string) Item {
    merged := existing

    // Merge assets from both items
    if merged.Assets == nil {
        merged.Assets = make(map[string]Asset)
    }
    for key, asset := range incoming.Assets {
        // Prefix asset keys with origin to avoid overwrites
        mergedKey := key
        if _, exists := merged.Assets[key]; exists {
            mergedKey = incomingOrigin + ":" + key
        }
        merged.Assets[mergedKey] = asset
    }

    // Keep the most recent properties (by datetime)
    if incoming.Properties.DateTime.After(existing.Properties.DateTime) {
        merged.Properties = incoming.Properties
    }

    // Merge links
    merged.Links = append(merged.Links, incoming.Links...)

    return merged
}

func (m *ResultMerger) transformItem(item Item, originID string) Item {
    // Add origin metadata to item properties
    if item.Properties.Extra == nil {
        item.Properties.Extra = make(map[string]interface{})
    }
    item.Properties.Extra["stac_proxy:origin"] = originID

    // Namespace item ID if configured
    if m.strategy == ConflictNamespace {
        item.ID = originID + ":" + item.ID
    }

    return item
}

func (m *ResultMerger) DeduplicateCollections(collections []*Collection) []*Collection {
    seen := make(map[string]bool)
    var result []*Collection

    for _, coll := range collections {
        if !seen[coll.ID] {
            seen[coll.ID] = true
            result = append(result, coll)
        }
    }

    // Sort by ID for consistent ordering
    sort.Slice(result, func(i, j int) bool {
        return result[i].ID < result[j].ID
    })

    return result
}

type itemWithOrigin struct {
    item     Item
    originID string
    priority int
}
```

#### 4.3.8 Federated Pagination

Pagination across multiple origins is one of the most complex aspects of federation. The proxy implements a cursor-based pagination system that guarantees no duplicates and no skipped items, even when querying heterogeneous backends with different page sizes and response times.

**Challenges:**
- Each origin has its own independent pagination
- Items must be sorted consistently across all origins
- Cannot use simple offset-based pagination (items may be added/removed)
- Must track state for each origin independently
- Origins may exhaust at different times

**Solution: Federated Cursor with Merge-Sort**

```go
package federation

// FederatedCursor encodes the pagination state across all origins
type FederatedCursor struct {
    // Per-origin state
    OriginCursors map[string]*OriginCursor `json:"o"`
    
    // Global sort state
    SortField     string    `json:"sf"`  // e.g., "properties.datetime"
    SortOrder     string    `json:"so"`  // "asc" or "desc"
    LastValue     string    `json:"lv"`  // Last emitted sort value
    LastItemID    string    `json:"li"`  // Last emitted item ID (tiebreaker)
    
    // Deduplication
    SeenItems     *BloomFilter `json:"seen,omitempty"` // Space-efficient duplicate tracking
    
    // Metadata
    Created       time.Time `json:"c"`
    RequestHash   string    `json:"rh"`  // Hash of original search params
}

type OriginCursor struct {
    OriginID    string `json:"id"`
    NextLink    string `json:"nl,omitempty"`  // Origin's next page URL
    Exhausted   bool   `json:"ex"`            // No more results from this origin
    LastFetched string `json:"lf,omitempty"`  // Last sort value fetched
    BufferedCount int  `json:"bc"`            // Items buffered but not yet emitted
}

// EncodeCursor serializes the cursor for use in response links
func (c *FederatedCursor) Encode() string {
    data, _ := json.Marshal(c)
    compressed := snappy.Encode(nil, data)
    return base64.RawURLEncoding.EncodeToString(compressed)
}

// DecodeCursor deserializes a cursor from a request
func DecodeCursor(encoded string) (*FederatedCursor, error) {
    compressed, err := base64.RawURLEncoding.DecodeString(encoded)
    if err != nil {
        return nil, fmt.Errorf("invalid cursor encoding: %w", err)
    }
    
    data, err := snappy.Decode(nil, compressed)
    if err != nil {
        return nil, fmt.Errorf("invalid cursor compression: %w", err)
    }
    
    var cursor FederatedCursor
    if err := json.Unmarshal(data, &cursor); err != nil {
        return nil, fmt.Errorf("invalid cursor format: %w", err)
    }
    
    return &cursor, nil
}
```

**Merge-Sort Based Pagination:**

```go
package federation

// PaginatedSearch executes a search with proper federated pagination
func (h *FederationHandler) PaginatedSearch(ctx context.Context, 
    req *STACRequest) (*STACResponse, error) {
    
    searchReq, err := ParseSearchRequest(req)
    if err != nil {
        return nil, err
    }

    // Decode cursor if continuing pagination
    var cursor *FederatedCursor
    if searchReq.Cursor != "" {
        cursor, err = DecodeCursor(searchReq.Cursor)
        if err != nil {
            return nil, fmt.Errorf("invalid pagination cursor: %w", err)
        }
        
        // Validate cursor matches this search
        if cursor.RequestHash != hashSearchParams(searchReq) {
            return nil, fmt.Errorf("cursor does not match search parameters")
        }
    } else {
        // First page - initialize cursor
        cursor = h.initCursor(searchReq)
    }

    // Determine page size
    limit := searchReq.Limit
    if limit <= 0 || limit > h.config.MaxPageSize {
        limit = h.config.DefaultPageSize
    }

    // Execute paginated search
    items, nextCursor, err := h.fetchPage(ctx, searchReq, cursor, limit)
    if err != nil {
        return nil, err
    }

    return h.buildPaginatedResponse(items, nextCursor, searchReq)
}

// fetchPage retrieves exactly `limit` items using merge-sort across origins
func (h *FederationHandler) fetchPage(ctx context.Context, 
    req *SearchRequest, cursor *FederatedCursor, limit int) ([]Item, *FederatedCursor, error) {
    
    // Create merge heap for sorted iteration
    heap := NewMergeHeap(cursor.SortField, cursor.SortOrder)
    
    // Fetch/buffer items from each non-exhausted origin
    originBuffers := make(map[string]*OriginBuffer)
    
    var wg sync.WaitGroup
    var mu sync.Mutex
    
    for originID, originCursor := range cursor.OriginCursors {
        if originCursor.Exhausted {
            continue
        }
        
        wg.Add(1)
        go func(oid string, oc *OriginCursor) {
            defer wg.Done()
            
            buffer, err := h.fetchOriginBuffer(ctx, oid, oc, req)
            if err != nil {
                log.Warn("origin fetch failed", "origin", oid, "error", err)
                return
            }
            
            mu.Lock()
            originBuffers[oid] = buffer
            mu.Unlock()
        }(originID, originCursor)
    }
    wg.Wait()

    // Initialize heap with first item from each buffer
    for originID, buffer := range originBuffers {
        if len(buffer.Items) > 0 {
            heap.Push(&HeapItem{
                Item:     buffer.Items[0],
                OriginID: originID,
                Index:    0,
            })
        }
    }

    // Merge-sort to get next `limit` items
    var results []Item
    newCursor := cursor.Clone()
    
    for len(results) < limit && heap.Len() > 0 {
        // Pop smallest/largest item (depending on sort order)
        heapItem := heap.Pop()
        item := heapItem.Item
        originID := heapItem.OriginID
        
        // Deduplication check
        itemKey := item.Collection + ":" + item.ID
        if newCursor.SeenItems.Contains(itemKey) {
            // Skip duplicate, but continue processing
            h.advanceBuffer(heap, originBuffers, originID, heapItem.Index)
            continue
        }
        
        // Add to results
        results = append(results, item)
        newCursor.SeenItems.Add(itemKey)
        newCursor.LastValue = getSortValue(item, cursor.SortField)
        newCursor.LastItemID = item.ID
        
        // Advance this origin's buffer
        h.advanceBuffer(heap, originBuffers, originID, heapItem.Index)
    }

    // Update origin cursors
    for originID, buffer := range originBuffers {
        oc := newCursor.OriginCursors[originID]
        oc.NextLink = buffer.NextLink
        oc.Exhausted = buffer.Exhausted && buffer.Index >= len(buffer.Items)
        oc.BufferedCount = len(buffer.Items) - buffer.Index
    }

    // Check if all origins exhausted
    allExhausted := true
    for _, oc := range newCursor.OriginCursors {
        if !oc.Exhausted {
            allExhausted = false
            break
        }
    }
    
    if allExhausted {
        return results, nil, nil // No next cursor = last page
    }

    return results, newCursor, nil
}

// advanceBuffer moves to next item in origin buffer, fetching more if needed
func (h *FederationHandler) advanceBuffer(heap *MergeHeap, 
    buffers map[string]*OriginBuffer, originID string, currentIndex int) {
    
    buffer := buffers[originID]
    nextIndex := currentIndex + 1
    
    if nextIndex < len(buffer.Items) {
        // More items in buffer
        heap.Push(&HeapItem{
            Item:     buffer.Items[nextIndex],
            OriginID: originID,
            Index:    nextIndex,
        })
        buffer.Index = nextIndex
    } else if buffer.NextLink != "" && !buffer.Exhausted {
        // Need to fetch next page from origin
        // In practice, this is done lazily or with prefetching
        buffer.Index = nextIndex
    }
}

// MergeHeap implements a min/max heap for merge-sort across origins
type MergeHeap struct {
    items     []*HeapItem
    sortField string
    sortOrder string // "asc" or "desc"
}

type HeapItem struct {
    Item     Item
    OriginID string
    Index    int
}

func (h *MergeHeap) Len() int { return len(h.items) }

func (h *MergeHeap) Less(i, j int) bool {
    vi := getSortValue(h.items[i].Item, h.sortField)
    vj := getSortValue(h.items[j].Item, h.sortField)
    
    if h.sortOrder == "desc" {
        return vi > vj
    }
    return vi < vj
}

func (h *MergeHeap) Swap(i, j int) {
    h.items[i], h.items[j] = h.items[j], h.items[i]
}

func (h *MergeHeap) Push(x interface{}) {
    h.items = append(h.items, x.(*HeapItem))
    heap.Fix(h, len(h.items)-1)
}

func (h *MergeHeap) Pop() *HeapItem {
    n := len(h.items)
    item := h.items[0]
    h.items[0] = h.items[n-1]
    h.items = h.items[:n-1]
    if len(h.items) > 0 {
        heap.Fix(h, 0)
    }
    return item
}
```

**Deduplication with Bloom Filters:**

```go
package federation

// BloomFilter provides space-efficient probabilistic duplicate detection
// False positives possible (item skipped when it shouldn't be)
// False negatives impossible (duplicate never emitted twice)
type BloomFilter struct {
    bits    []uint64
    size    uint64
    hashFns int
}

func NewBloomFilter(expectedItems int, falsePositiveRate float64) *BloomFilter {
    // Calculate optimal size and hash functions
    m := optimalM(expectedItems, falsePositiveRate)
    k := optimalK(m, expectedItems)
    
    return &BloomFilter{
        bits:    make([]uint64, (m+63)/64),
        size:    m,
        hashFns: k,
    }
}

func (bf *BloomFilter) Add(item string) {
    for i := 0; i < bf.hashFns; i++ {
        idx := bf.hash(item, i) % bf.size
        bf.bits[idx/64] |= 1 << (idx % 64)
    }
}

func (bf *BloomFilter) Contains(item string) bool {
    for i := 0; i < bf.hashFns; i++ {
        idx := bf.hash(item, i) % bf.size
        if bf.bits[idx/64]&(1<<(idx%64)) == 0 {
            return false
        }
    }
    return true
}

// For very large result sets, use a rolling bloom filter that
// only tracks recent items (relies on sort order for correctness)
type RollingBloomFilter struct {
    current  *BloomFilter
    previous *BloomFilter
    count    int
    maxItems int
}

func (rbf *RollingBloomFilter) Add(item string) {
    rbf.current.Add(item)
    rbf.count++
    
    if rbf.count >= rbf.maxItems {
        // Rotate filters
        rbf.previous = rbf.current
        rbf.current = NewBloomFilter(rbf.maxItems, 0.001)
        rbf.count = 0
    }
}

func (rbf *RollingBloomFilter) Contains(item string) bool {
    return rbf.current.Contains(item) || 
           (rbf.previous != nil && rbf.previous.Contains(item))
}
```

**Consistent Sorting Across Origins:**

```go
package federation

// SortConfig defines how results are sorted across origins
type SortConfig struct {
    Field     string // "properties.datetime", "id", "properties.created"
    Order     string // "asc" or "desc"
    Tiebreaker string // Secondary sort field (usually "id")
}

// DefaultSort returns the default sort configuration
func DefaultSort() SortConfig {
    return SortConfig{
        Field:      "properties.datetime",
        Order:      "desc",
        Tiebreaker: "id",
    }
}

// getSortValue extracts the sort value from an item
func getSortValue(item Item, field string) string {
    switch field {
    case "properties.datetime":
        return item.Properties.DateTime.Format(time.RFC3339Nano)
    case "id":
        return item.ID
    case "properties.created":
        if created, ok := item.Properties.Extra["created"].(string); ok {
            return created
        }
        return ""
    default:
        // Handle nested properties
        parts := strings.Split(field, ".")
        val := getNestedValue(item, parts)
        if s, ok := val.(string); ok {
            return s
        }
        return fmt.Sprintf("%v", val)
    }
}

// When requesting from origins, ensure consistent sort order
func (h *FederationHandler) adaptSortForOrigin(req *SearchRequest, 
    origin *Origin, cursor *FederatedCursor) *SearchRequest {
    
    adapted := req.Clone()
    
    // Force consistent sort across all origins
    adapted.Sortby = []SortSpec{
        {Field: cursor.SortField, Direction: cursor.SortOrder},
        {Field: "id", Direction: "asc"}, // Tiebreaker
    }
    
    // If continuing pagination, filter by sort value
    if cursor.LastValue != "" {
        adapted.Filter = appendTemporalFilter(adapted.Filter, 
            cursor.SortField, cursor.SortOrder, cursor.LastValue)
    }
    
    return adapted
}
```

**Pagination Response Format:**

```go
func (h *FederationHandler) buildPaginatedResponse(items []Item, 
    nextCursor *FederatedCursor, req *SearchRequest) (*STACResponse, error) {
    
    fc := FeatureCollection{
        Type:     "FeatureCollection",
        Features: items,
        Context: &SearchContext{
            Returned: len(items),
            Limit:    req.Limit,
        },
        Links: []Link{
            {Rel: "self", Href: h.buildSearchURL(req, ""), Type: "application/geo+json"},
            {Rel: "root", Href: h.proxyBaseURL, Type: "application/json"},
        },
    }
    
    // Add next link if more results available
    if nextCursor != nil {
        fc.Links = append(fc.Links, Link{
            Rel:    "next",
            Href:   h.buildSearchURL(req, nextCursor.Encode()),
            Type:   "application/geo+json",
            Method: "GET",
        })
    }
    
    // Add pagination metadata
    fc.Context.Next = nextCursor != nil
    
    body, _ := json.Marshal(fc)
    
    return &STACResponse{
        StatusCode: http.StatusOK,
        Headers: http.Header{
            "Content-Type": []string{"application/geo+json"},
        },
        Body: body,
    }, nil
}
```

**Pagination Guarantees:**

| Guarantee | How It's Achieved |
|-----------|-------------------|
| No duplicates | Bloom filter tracks emitted item IDs |
| No skipped items | Merge-sort ensures global ordering; cursor stores exact position |
| Consistency | Cursor includes request hash; rejects mismatched cursors |
| Resumability | Full state encoded in cursor; can resume after any delay |
| Origin failure tolerance | Failed origins excluded; pagination continues with remaining |
```

### 4.4 Response Transformation

#### 4.4.1 Link Rewriting

All STAC responses contain links that must be rewritten to route through the proxy.

```go
package transform

type LinkRewriter struct {
    proxyBaseURL string
    pathMappings map[string]string
}

func (r *LinkRewriter) RewriteLinks(resp *STACResponse, 
    originID string) *STACResponse {
    
    var data map[string]interface{}
    json.Unmarshal(resp.Body, &data)
    
    // Rewrite "links" array
    if links, ok := data["links"].([]interface{}); ok {
        for i, link := range links {
            if linkMap, ok := link.(map[string]interface{}); ok {
                if href, ok := linkMap["href"].(string); ok {
                    linkMap["href"] = r.rewriteURL(href, originID)
                }
            }
            links[i] = link
        }
    }
    
    // Rewrite asset hrefs (handled by RemapMiddleware if configured)
    
    body, _ := json.Marshal(data)
    resp.Body = body
    
    return resp
}
```

### 4.5 Configuration

#### 4.5.1 Configuration Schema

```yaml
# stac-proxy.yaml

server:
  host: "0.0.0.0"
  port: 8080
  tls:
    enabled: true
    cert_file: "/etc/ssl/certs/proxy.crt"
    key_file: "/etc/ssl/private/proxy.key"
  timeouts:
    read: 30s
    write: 60s
    idle: 120s

logging:
  level: "info"
  format: "json"
  output: "stdout"

metrics:
  enabled: true
  path: "/metrics"
  port: 9090

# Middleware configuration (order matters)
middleware:
  - name: logging
    config:
      include_body: false
      
  - name: auth
    config:
      allow_anonymous: false
      providers:
        - type: bearer
          jwks_url: "https://auth.example.com/.well-known/jwks.json"
          issuer: "https://auth.example.com"
          audience: "stac-proxy"
        - type: api_key
          header: "X-API-Key"
          keys_file: "/etc/stac-proxy/api-keys.yaml"
          
  - name: authz
    config:
      policy_source: "opa"  # "file", "opa", or "both"
      default_effect: "deny"
      
      # OPA configuration
      opa:
        embedded: true  # Run OPA in-process (no external server)
        rego_files:
          - "/etc/stac-proxy/policies/stac_authz.rego"
        data_files:
          - "/etc/stac-proxy/policies/data.json"
        # Or use external OPA server:
        # url: "http://opa:8181"
        # policy_path: "v1/data/stac/authz"
        cache_decisions: true
        cache_ttl: 5m
        timeout: 100ms
      
      # Geofencing configuration  
      geofencing:
        enabled: true
        regions_file: "/etc/stac-proxy/regions.geojson"
        refresh_interval: 1h
        default_allow: false
        enforce_on_search: true
        enforce_on_items: true
        user_fence_source: "jwt_claim"
        user_fence_claim: "allowed_geometry"
        exclusion_zones:
          - "restricted_military"
          - "classified_sites"
      
  - name: rate_limit
    config:
      default_quota:
        requests: 1000
        window: 1h
      burst: 50
      
  - name: cache
    config:
      store: redis
      redis_url: "redis://localhost:6379"
      collection_ttl: 5m
      item_ttl: 1m
      search_ttl: 30s
      
  - name: url_remap
    config:
      rules:
        - match: "^https://internal-storage.example.com/(.*)$"
          replace: "https://cdn.example.com/$1"
        - match: "^s3://bucket-name/(.*)$"
          replace: "https://cdn.example.com/assets/$1"
          sign: true
          sign_ttl: 1h

# Upstream configuration
mode: federation  # "single" or "federation"

# Single origin mode
upstream:
  url: "https://stac.example.com"
  timeout: 30s

# Federation mode
federation:
  search_strategy: parallel
  max_concurrent: 10
  aggregate_timeout: 60s
  conflict_strategy: priority
  
  origins:
    - id: primary
      name: "Primary STAC Server"
      base_url: "https://stac-primary.example.com"
      priority: 1
      enabled: true
      
    - id: archive
      name: "Archive Server"
      base_url: "https://stac-archive.example.com"
      priority: 2
      enabled: true
      collections:
        - "landsat-8"
        - "sentinel-2"
      auth:
        type: bearer
        token: "${ARCHIVE_TOKEN}"
        
    - id: partner
      name: "Partner Catalog"
      base_url: "https://partner-stac.example.org"
      priority: 3
      enabled: true
      exclude_collections:
        - "internal-only"
      headers:
        X-Partner-ID: "stac-proxy"

# Health check configuration
health:
  path: "/health"
  check_upstreams: true
  check_interval: 30s
```

#### 4.5.2 Configuration Loading

```go
package config

type Config struct {
    Server      ServerConfig      `yaml:"server"`
    Logging     LoggingConfig     `yaml:"logging"`
    Metrics     MetricsConfig     `yaml:"metrics"`
    Middleware  []MiddlewareConfig `yaml:"middleware"`
    Mode        string            `yaml:"mode"`
    Upstream    *UpstreamConfig   `yaml:"upstream"`
    Federation  *FederationConfig `yaml:"federation"`
    Health      HealthConfig      `yaml:"health"`
}

func Load(path string) (*Config, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return nil, err
    }
    
    // Expand environment variables
    data = []byte(os.ExpandEnv(string(data)))
    
    var cfg Config
    if err := yaml.Unmarshal(data, &cfg); err != nil {
        return nil, err
    }
    
    if err := cfg.Validate(); err != nil {
        return nil, err
    }
    
    return &cfg, nil
}

// Watch for config changes
func (c *Config) Watch(ctx context.Context, onChange func(*Config)) error {
    watcher, err := fsnotify.NewWatcher()
    if err != nil {
        return err
    }
    
    go func() {
        for {
            select {
            case event := <-watcher.Events:
                if event.Op&fsnotify.Write == fsnotify.Write {
                    newCfg, err := Load(c.path)
                    if err != nil {
                        log.Error("config reload failed", "error", err)
                        continue
                    }
                    onChange(newCfg)
                }
            case <-ctx.Done():
                return
            }
        }
    }()
    
    return watcher.Add(c.path)
}
```

---

## 5. API Design

### 5.1 Unified Federation Experience

From a client's perspective, the federated proxy appears as a single STAC API. Clients make standard STAC API requests and receive aggregated responses without needing to know about the underlying origins.

**Example: Unified Search Across Multiple Providers**

```bash
# Client searches for Sentinel-2 data - proxy handles routing to 
# whichever backends serve Sentinel-2 with their respective auth
curl -X POST https://stac-proxy.example.com/search \
  -H "Authorization: Bearer <client-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "collections": ["sentinel-2-l2a"],
    "datetime": "2024-01-01/2024-01-31",
    "bbox": [-122.5, 37.5, -122.0, 38.0],
    "limit": 100
  }'

# Response includes items from ALL origins serving sentinel-2-l2a,
# transparently merged with origin metadata
{
  "type": "FeatureCollection",
  "features": [
    {
      "id": "S2A_MSIL2A_20240115...",
      "collection": "sentinel-2-l2a",
      "properties": {
        "datetime": "2024-01-15T18:45:00Z",
        "stac_proxy:origin": "copernicus-dataspace",
        ...
      },
      "assets": {...}
    },
    {
      "id": "S2B_MSIL2A_20240118...",
      "collection": "sentinel-2-l2a", 
      "properties": {
        "datetime": "2024-01-18T18:42:00Z",
        "stac_proxy:origin": "aws-earth-search",
        ...
      },
      "assets": {...}
    }
  ],
  "context": {
    "matched": 47,
    "returned": 47
  }
}
```

**Key Federation Behaviors:**

1. **Transparent Routing**: Proxy routes requests to origins based on collection mapping
2. **Auth Isolation**: Each origin's auth is handled independently; clients only need proxy credentials
3. **Result Merging**: Items from multiple origins merged into single response
4. **Origin Tagging**: Each item tagged with `stac_proxy:origin` for provenance
5. **Link Rewriting**: All links rewritten to route through proxy

### 5.2 Proxy Endpoints

The proxy transparently forwards all STAC API endpoints:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Landing page |
| `/conformance` | GET | Conformance classes |
| `/collections` | GET | List collections |
| `/collections/{collectionId}` | GET | Get collection |
| `/collections/{collectionId}/items` | GET | List items |
| `/collections/{collectionId}/items/{itemId}` | GET | Get item |
| `/search` | GET, POST | Search items |
| `/queryables` | GET | Global queryables |
| `/collections/{collectionId}/queryables` | GET | Collection queryables |

### 5.3 Management Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/health/live` | GET | Liveness probe |
| `/health/ready` | GET | Readiness probe |
| `/metrics` | GET | Prometheus metrics |
| `/_admin/config` | GET | Current configuration |
| `/_admin/origins` | GET | Federation origin status |
| `/_admin/origins/{id}/health` | GET | Specific origin health |
| `/_admin/cache/clear` | POST | Clear cache |
| `/_admin/collections/refresh` | POST | Refresh collection discovery |

### 5.4 Federation-Specific Behavior

When in federation mode, the proxy aggregates data from multiple downstream servers:

**GET /collections**
- Fetches collections from all enabled origins in parallel
- Each origin uses its own configured authentication
- Merges results, applying deduplication based on collection ID
- Adds `stac_proxy:origin` and `stac_proxy:origin_name` to each collection
- Collections can be prefixed per-origin to avoid ID collisions

**GET /collections/{collectionId}**
- Routes to the origin(s) serving that collection
- If multiple origins serve it, returns from highest priority origin
- Rewrites all links to route through the proxy

**POST /search**
- Parses `collections` parameter to determine target origins
- Fans out search to all applicable origins in parallel
- Each origin request includes origin-specific authentication
- Merges results using configured conflict resolution strategy
- Handles pagination across federated results
- Supports all STAC search parameters (bbox, datetime, intersects, etc.)

**GET /collections/{collectionId}/items/{itemId}**
- Routes to the origin serving that collection
- If namespacing is enabled, strips origin prefix from item ID

### 5.5 Error Handling in Federation

The proxy implements graceful degradation when origins fail:

- If all origins fail → Return 502 Bad Gateway with error details
- If some origins fail → Return partial results with `X-STAC-Proxy-Partial: true` header
- Individual origin errors are logged but don't fail entire request
- `/_admin/origins` endpoint shows current health status of each origin

---

## 6. Implementation Plan

### 6.1 Project Structure

```
stac-proxy/
├── cmd/
│   └── stac-proxy/
│       └── main.go
├── internal/
│   ├── config/
│   │   ├── config.go
│   │   └── validation.go
│   ├── server/
│   │   ├── server.go
│   │   ├── router.go
│   │   └── handlers.go
│   ├── middleware/
│   │   ├── chain.go
│   │   ├── logging.go
│   │   ├── auth/
│   │   │   ├── middleware.go
│   │   │   ├── bearer.go
│   │   │   ├── apikey.go
│   │   │   ├── oauth2.go
│   │   │   └── oidc.go
│   │   ├── authz/
│   │   │   ├── middleware.go
│   │   │   ├── enforcer.go
│   │   │   ├── opa.go              # OPA integration
│   │   │   ├── opa_embedded.go     # Embedded OPA engine
│   │   │   ├── geofence.go         # Geofencing logic
│   │   │   ├── geofence_spatial.go # Spatial operations
│   │   │   └── policy.go           # File-based policies
│   │   ├── cache/
│   │   │   ├── middleware.go
│   │   │   ├── memory.go
│   │   │   └── redis.go
│   │   ├── ratelimit/
│   │   │   ├── middleware.go
│   │   │   └── sliding_window.go
│   │   └── remap/
│   │       ├── middleware.go
│   │       └── signer.go
│   ├── proxy/
│   │   ├── handler.go
│   │   └── client.go
│   ├── federation/
│   │   ├── handler.go
│   │   ├── router.go           # Collection routing
│   │   ├── origin.go           # Origin client with auth
│   │   ├── merger.go           # Result merging
│   │   ├── pagination.go       # Federated pagination
│   │   ├── cursor.go           # Cursor encoding/decoding
│   │   └── bloom.go            # Bloom filter for dedup
│   ├── transform/
│   │   ├── links.go
│   │   └── assets.go
│   ├── geo/
│   │   ├── geometry.go         # Geometry operations
│   │   ├── geojson.go          # GeoJSON parsing
│   │   └── spatial_index.go    # R-tree indexing
│   └── stac/
│       ├── types.go
│       ├── parser.go
│       └── validator.go
├── pkg/
│   └── stacproxy/
│       └── client.go           # Client library for embedding
├── policies/
│   ├── stac_authz.rego         # Example OPA policies
│   ├── geofence.rego
│   └── data.json               # Policy data
├── configs/
│   ├── example.yaml
│   └── regions.geojson         # Example region definitions
├── deployments/
│   ├── docker/
│   │   └── Dockerfile
│   └── kubernetes/
│       ├── deployment.yaml
│       ├── service.yaml
│       ├── configmap.yaml
│       └── opa-sidecar.yaml    # OPA as sidecar option
├── docs/
│   └── ...
├── go.mod
├── go.sum
└── README.md
```

### 6.2 Dependencies

```go
// go.mod
module github.com/exergy-dev/stac-proxy

go 1.22

require (
    // Web framework
    github.com/go-chi/chi/v5 v5.0.10
    
    // Authentication
    github.com/golang-jwt/jwt/v5 v5.0.0
    github.com/coreos/go-oidc/v3 v3.6.0
    golang.org/x/oauth2 v0.12.0
    
    // Authorization - OPA
    github.com/open-policy-agent/opa v0.57.0
    
    // Geospatial
    github.com/twpayne/go-geom v1.5.0           // Geometry types
    github.com/peterstace/simplefeatures v0.44.0 // Spatial operations
    github.com/tidwall/rtree v1.10.0            // Spatial indexing
    github.com/paulmach/orb v0.10.0             // GeoJSON support
    
    // Storage
    github.com/redis/go-redis/v9 v9.0.5
    
    // Observability
    github.com/prometheus/client_golang v1.16.0
    go.opentelemetry.io/otel v1.19.0
    go.opentelemetry.io/otel/trace v1.19.0
    
    // Configuration
    github.com/spf13/viper v1.16.0
    github.com/fsnotify/fsnotify v1.6.0
    gopkg.in/yaml.v3 v3.0.1
    
    // Utilities
    // logging via stdlib log/slog (no third-party dep)
    golang.org/x/sync v0.3.0
    golang.org/x/time v0.3.0
    github.com/golang/snappy v0.0.4             // Cursor compression
    github.com/bits-and-blooms/bloom/v3 v3.5.0  // Bloom filters
)
```

### 6.3 Development Phases

| Phase | Duration | Deliverables |
|-------|----------|--------------|
| **Phase 1: Core Proxy** | 4 weeks | Basic proxy, routing, config loading |
| **Phase 2: Middleware Framework** | 3 weeks | Middleware chain, logging, metrics |
| **Phase 3: Authentication** | 3 weeks | Auth providers, JWT validation |
| **Phase 4: Authorization** | 2 weeks | Policy engine, spatial/temporal filters |
| **Phase 5: Federation** | 4 weeks | Multi-origin support, aggregation |
| **Phase 6: Advanced Features** | 3 weeks | Caching, rate limiting, URL remapping |
| **Phase 7: Hardening** | 3 weeks | Testing, documentation, performance |

---

## 7. Operational Considerations

### 7.1 Deployment

**Docker**
```dockerfile
FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY . .
RUN CGO_ENABLED=0 go build -o stac-proxy ./cmd/stac-proxy

FROM alpine:3.18
RUN apk add --no-cache ca-certificates
COPY --from=builder /app/stac-proxy /usr/local/bin/
ENTRYPOINT ["stac-proxy"]
CMD ["--config", "/etc/stac-proxy/config.yaml"]
```

**Kubernetes**
- Deploy as a Deployment with HPA for auto-scaling
- Use ConfigMaps for configuration
- Use Secrets for API keys and certificates
- Expose via Service + Ingress

### 7.2 Monitoring

**Metrics (Prometheus)**
- `stac_proxy_requests_total{method, path, status}`
- `stac_proxy_request_duration_seconds{method, path}`
- `stac_proxy_upstream_requests_total{origin, status}`
- `stac_proxy_upstream_latency_seconds{origin}`
- `stac_proxy_cache_hits_total`
- `stac_proxy_cache_misses_total`
- `stac_proxy_auth_failures_total{provider, reason}`
- `stac_proxy_rate_limit_exceeded_total`

**Logging**
- Structured JSON logging
- Request ID propagation
- Configurable log levels

**Tracing**
- OpenTelemetry support
- Trace propagation to upstreams

### 7.3 Security Considerations

1. **TLS**: Always terminate TLS at the proxy or load balancer
2. **Secrets**: Use environment variables or secret management systems
3. **Input Validation**: Validate all incoming STAC parameters
4. **Rate Limiting**: Protect upstreams from abuse
5. **Audit Logging**: Log all authentication and authorization decisions
6. **Dependency Scanning**: Regular vulnerability scanning of dependencies

---

## 8. Testing Strategy

### 8.1 Unit Tests

- Test each middleware in isolation
- Mock upstream responses
- Test configuration parsing and validation

### 8.2 Integration Tests

- Spin up actual STAC servers (e.g., stac-fastapi) in containers
- Test federation across multiple origins
- Test authentication flows

### 8.3 Load Testing

- Use k6 or similar for load testing
- Target: 10,000 requests/second with <100ms p99 latency
- Test cache effectiveness under load

### 8.4 Conformance Testing

- Run official STAC API conformance tests through proxy
- Ensure all STAC API behaviors are preserved

---

## 9. Future Enhancements

1. **WebSocket Support**: Real-time notifications for catalog updates
2. **GraphQL Interface**: Alternative query interface
3. **Asset Proxy**: Proxy asset downloads with transformation
4. **Query Rewriting**: Translate between STAC API versions
5. **Multi-tenancy**: Virtual catalogs per tenant
6. **Plugin System**: Dynamic middleware loading via Go plugins

---

## 10. References

- [STAC Specification](https://stacspec.org/)
- [STAC API Specification](https://github.com/radiantearth/stac-api-spec)
- [Open Policy Agent (OPA)](https://www.openpolicyagent.org/)
- [Rego Policy Language](https://www.openpolicyagent.org/docs/latest/policy-language/)
- [OPA Go SDK](https://www.openpolicyagent.org/docs/latest/integration/#integrating-with-the-go-sdk)
- [GeoJSON RFC 7946](https://datatracker.ietf.org/doc/html/rfc7946)
- [Go HTTP Middleware Patterns](https://www.alexedwards.net/blog/making-and-using-middleware)
- [Bloom Filters Explained](https://llimllib.github.io/bloomfilter-tutorial/)
- [Merge-Sort Based Pagination](https://engineering.fb.com/2013/10/29/core-data/graphql-a-query-language/)

---

## Appendix A: Glossary

| Term | Definition |
|------|------------|
| **STAC** | SpatioTemporal Asset Catalog |
| **Item** | A STAC Item representing a single spatiotemporal asset |
| **Collection** | A group of related STAC Items |
| **Catalog** | A container for Collections and Items |
| **Origin** | An upstream STAC server in federation mode |
| **Federation** | Aggregating multiple STAC servers into one view |
| **Middleware** | A component that processes requests/responses in a chain |
| **OPA** | Open Policy Agent - a general-purpose policy engine |
| **Rego** | OPA's declarative policy language |
| **Geofencing** | Restricting access based on geographic boundaries |
| **Principal** | The authenticated entity (user or service) making a request |
| **Cursor** | Encoded pagination state for resumable queries |
| **Bloom Filter** | Probabilistic data structure for duplicate detection |

---

## Appendix B: Configuration Examples

### B.1 Simple Single-Origin Proxy

```yaml
server:
  port: 8080

mode: single

upstream:
  url: "https://earth-search.aws.element84.com/v1"

middleware:
  - name: logging
```

### B.2 Federated Multi-Provider Setup with Per-Origin Auth

```yaml
server:
  port: 8080
  tls:
    enabled: true
    cert_file: "/etc/ssl/certs/proxy.crt"
    key_file: "/etc/ssl/private/proxy.key"

mode: federation

federation:
  search_strategy: parallel
  max_concurrent: 10
  aggregate_timeout: 60s
  conflict_strategy: priority  # Lower priority number wins

  origins:
    # Public STAC server - no auth required
    - id: aws-earth-search
      name: "AWS Earth Search"
      base_url: "https://earth-search.aws.element84.com/v1"
      enabled: true
      priority: 1
      auto_discover: true
      discovery_interval: 1h
      timeout: 30s
      # No auth block - public API

    # API Key authentication
    - id: planet-nicfi
      name: "Planet NICFI Basemaps"
      base_url: "https://api.planet.com/basemaps/v1/mosaics"
      enabled: true
      priority: 2
      collections:
        - "planet-nicfi"
      auth:
        type: api_key
        api_key_header: "Authorization"
        api_key_value: "api-key ${PLANET_API_KEY}"
      timeout: 45s
      retry:
        max_retries: 3
        initial_backoff: 1s
        max_backoff: 10s

    # OAuth2 client credentials
    - id: copernicus-dataspace
      name: "Copernicus Data Space"
      base_url: "https://catalogue.dataspace.copernicus.eu/stac"
      enabled: true
      priority: 3
      collections:
        - "sentinel-2-l2a"
        - "sentinel-1-grd"
      auth:
        type: oauth2
        oauth2:
          token_url: "https://identity.dataspace.copernicus.eu/auth/realms/CDSE/protocol/openid-connect/token"
          client_id: "${COPERNICUS_CLIENT_ID}"
          client_secret: "${COPERNICUS_CLIENT_SECRET}"
          scopes: ["openid"]
      timeout: 60s

    # Bearer token (static)
    - id: maxar-securewatch
      name: "Maxar SecureWatch"
      base_url: "https://securewatch.maxar.com/catalogservice/stac/v1"
      enabled: true
      priority: 4
      auth:
        type: bearer
        token: "${MAXAR_ACCESS_TOKEN}"
      timeout: 30s

    # AWS SigV4 signing (for AWS-hosted private STAC)
    - id: internal-aws-stac
      name: "Internal AWS STAC"
      base_url: "https://stac.internal.example.com/v1"
      enabled: true
      priority: 5
      collection_prefix: "internal:"  # Prefix all collection IDs
      auth:
        type: aws_sig_v4
        aws_sig_v4:
          region: "us-west-2"
          service: "execute-api"
          use_iam_role: true  # Use EC2/ECS instance role
      timeout: 30s

    # Basic auth with mTLS
    - id: partner-secure-catalog
      name: "Partner Secure Catalog"
      base_url: "https://stac.partner.example.org/api"
      enabled: true
      priority: 6
      auth:
        type: basic
        username: "${PARTNER_USERNAME}"
        password: "${PARTNER_PASSWORD}"
        client_cert:
          cert_file: "/etc/ssl/client/partner.crt"
          key_file: "/etc/ssl/client/partner.key"
          ca_file: "/etc/ssl/client/partner-ca.crt"
      timeout: 45s
      collections:
        - "partner-imagery"
      exclude_collections:
        - "partner-internal-only"

    # Custom headers for proprietary systems
    - id: legacy-catalog
      name: "Legacy Internal Catalog"
      base_url: "https://legacy.internal.example.com/stac"
      enabled: true
      priority: 10
      auth:
        type: custom
        custom_headers:
          X-API-Version: "2.0"
          X-Tenant-ID: "production"
          X-Auth-Token: "${LEGACY_AUTH_TOKEN}"
      collection_mapping:
        "sat-imagery": "satellite_imagery_collection"  # Map public name to internal name
        "drone-data": "uav_captures"
      timeout: 60s

middleware:
  - name: logging
    config:
      include_body: false

  - name: cache
    config:
      store: redis
      redis_url: "redis://localhost:6379"
      collection_ttl: 5m
      item_ttl: 1m
      search_ttl: 30s

  - name: url_remap
    config:
      rules:
        # Remap internal S3 URLs to CloudFront
        - match: "^s3://internal-bucket/(.*)$"
          replace: "https://cdn.example.com/assets/$1"
          sign: true
          sign_ttl: 1h
```

### B.3 Enterprise Setup with Full Auth Stack

```yaml
server:
  host: "0.0.0.0"
  port: 8443
  tls:
    enabled: true
    cert_file: "/etc/ssl/certs/stac-proxy.crt"
    key_file: "/etc/ssl/private/stac-proxy.key"

mode: federation

# Client-facing authentication (who can access the proxy)
middleware:
  - name: auth
    config:
      allow_anonymous: false
      providers:
        - type: oidc
          issuer: "https://sso.example.com"
          audience: "stac-proxy"
          jwks_url: "https://sso.example.com/.well-known/jwks.json"
        - type: api_key
          header: "X-API-Key"
          keys_file: "/etc/stac-proxy/api-keys.yaml"

  - name: authz
    config:
      policy_source: "opa"
      
      opa:
        # External OPA server for enterprise deployment
        url: "http://opa.internal:8181"
        policy_path: "v1/data/stac/authz/allow"
        timeout: 200ms
        cache_decisions: true
        cache_ttl: 1m
        
      geofencing:
        enabled: true
        regions_file: "/etc/stac-proxy/regions.geojson"
        default_allow: false
        enforce_on_search: true
        enforce_on_items: true
        # Geofence comes from user's JWT claims
        user_fence_source: "jwt_claim"
        user_fence_claim: "stac_allowed_regions"  # Claim contains region names
        exclusion_zones:
          - "classified_zones"

  - name: rate_limit
    config:
      default_quota:
        requests: 10000
        window: 1h
      quotas_by_role:
        premium:
          requests: 100000
          window: 1h
        trial:
          requests: 100
          window: 1h

federation:
  # ... origins with their own downstream auth as shown above
```

### B.4 Geofencing by User Identity Example

```yaml
# Example: Different users/organizations have different geographic access

server:
  port: 8443

middleware:
  - name: auth
    config:
      providers:
        - type: oidc
          issuer: "https://auth.example.com"
          # JWT contains claims like:
          # {
          #   "sub": "user123",
          #   "org": "acme-corp",
          #   "roles": ["analyst"],
          #   "stac_regions": ["conus", "europe"],  # Named regions
          #   "stac_geometry": { "type": "Polygon", ... }  # Or explicit geometry
          # }

  - name: authz
    config:
      policy_source: "opa"
      
      opa:
        embedded: true
        rego_files:
          - "/etc/stac-proxy/geofence_policy.rego"
        data_files:
          - "/etc/stac-proxy/org_regions.json"
        
      geofencing:
        enabled: true
        
        # Named regions that can be referenced in policies/claims
        regions_file: "/etc/stac-proxy/regions.geojson"
        # regions.geojson contains:
        # {
        #   "type": "FeatureCollection",
        #   "features": [
        #     {"type": "Feature", "properties": {"name": "conus"}, "geometry": {...}},
        #     {"type": "Feature", "properties": {"name": "europe"}, "geometry": {...}},
        #     {"type": "Feature", "properties": {"name": "apac"}, "geometry": {...}}
        #   ]
        # }
        
        # How to get user's allowed regions
        user_fence_source: "jwt_claim"
        user_fence_claim: "stac_regions"  # References named regions
        
        # Global exclusions (applied to everyone)
        exclusion_zones:
          - "military_bases"
          - "sensitive_infrastructure"
        
        # If user has no geofence defined, deny by default
        default_allow: false
        
        # Apply geofencing to both search queries and result filtering
        enforce_on_search: true  # Modify search bbox/intersects
        enforce_on_items: true   # Filter items in results

mode: federation

federation:
  origins:
    - id: global-imagery
      base_url: "https://imagery.example.com/stac"
      enabled: true
```

**Example OPA Policy for Organization-Based Geofencing:**

```rego
# /etc/stac-proxy/geofence_policy.rego
package stac.authz

import future.keywords.if
import future.keywords.in

default allow := false

# Main authorization decision
allow := decision if {
    is_authenticated
    org_has_access
    decision := {
        "allow": true,
        "spatial_filter": user_geofence,
        "collection_filter": org_collections,
    }
}

is_authenticated if {
    input.principal.id != ""
    input.principal.type != "anonymous"
}

# Organization-based access control
org_has_access if {
    org := input.principal.attributes.org
    org in data.authorized_orgs
}

# Get geofence from JWT claim or org default
user_geofence := geom if {
    # First try user-specific geometry from JWT
    geom := input.principal.allowed_geometry
} else := geom if {
    # Fall back to regions from JWT claim
    regions := input.principal.allowed_regions
    geom := merge_named_regions(regions)
} else := geom if {
    # Fall back to organization default regions
    org := input.principal.attributes.org
    regions := data.org_regions[org]
    geom := merge_named_regions(regions)
}

# Collections allowed for this organization
org_collections := colls if {
    org := input.principal.attributes.org
    colls := data.org_collections[org]
}

merge_named_regions(region_names) := merged if {
    geometries := [data.regions[name] | some name in region_names]
    merged := geo.union(geometries)
}
```

**Organization Region Data:**

```json
// /etc/stac-proxy/org_regions.json
{
  "authorized_orgs": ["acme-corp", "globex", "initech", "umbrella"],
  
  "org_regions": {
    "acme-corp": ["conus", "europe"],
    "globex": ["conus", "apac"],
    "initech": ["conus"],
    "umbrella": ["global"]
  },
  
  "org_collections": {
    "acme-corp": ["sentinel-2-l2a", "landsat-c2-l2", "planet-nicfi"],
    "globex": ["sentinel-2-l2a", "landsat-c2-l2"],
    "initech": ["landsat-c2-l2"],
    "umbrella": ["*"]
  },
  
  "regions": {
    "conus": {
      "type": "Polygon",
      "coordinates": [[[-125, 24], [-66, 24], [-66, 50], [-125, 50], [-125, 24]]]
    },
    "europe": {
      "type": "Polygon",
      "coordinates": [[[-10, 35], [40, 35], [40, 72], [-10, 72], [-10, 35]]]
    },
    "apac": {
      "type": "Polygon",
      "coordinates": [[[100, -10], [180, -10], [180, 50], [100, 50], [100, -10]]]
    },
    "global": {
      "type": "Polygon",
      "coordinates": [[[-180, -90], [180, -90], [180, 90], [-180, 90], [-180, -90]]]
    }
  }
}
```
