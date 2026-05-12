# Writing OPA policies for stac-proxy

stac-proxy delegates every authorization decision to an [OPA](https://www.openpolicyagent.org/)
policy. The embedded enforcer loads `.rego` files at startup, builds a
prepared query, and evaluates it on every request. Your policy returns
both an allow decision and (optionally) a set of constraints that the
proxy enforces against the upstream STAC API.

## The contract

Your policy lives in package `stac.authz` and exposes a `result`
binding:

```rego
package stac.authz

default allow := false

result := {
    "allow": allow,
    "reasons": reasons,        # optional, []string
    "constraints": constraints  # optional, see schema below
}
```

The proxy queries `data.stac.authz` and unwraps `result` from the
returned map.

## AuthzInput schema

Every rule sees an `input` document with this shape:

```json
{
  "principal": {
    "id": "user-42",
    "type": "user",
    "roles": ["analyst"],
    "groups": ["geo-team"],
    "attributes": {"dept": "research", "region": "us", "auth_method": "bearer"},
    "auth_method": "bearer"
  },
  "request": {
    "method": "GET",
    "path": "/search",
    "request_type": "search",
    "query": {"limit": ["10"]},
    "headers": {"User-Agent": "curl/8.5.0"},
    "client_ip": "203.0.113.4",
    "request_id": "5e2fcae5-2a6a-4ec3-..."
  },
  "resource": {
    "type": "search",
    "collection": "sentinel-2-l2a",
    "item_id": ""
  }
}
```

`request_type` is one of `landing`, `conformance`, `collections`,
`collection`, `items`, `item`, `search`, `queryables`,
`collection_queryables`.

`principal` is absent for anonymous requests when the auth middleware
allows them. Sensitive headers (`Authorization`, `Cookie`,
`X-Api-Key`) are stripped before the policy sees them.

## Allow

Whatever sets `allow := true` in your package is the allow decision.
Standard idiom:

```rego
allow if {
    input.principal
    "admin" in input.principal.roles
}

allow if {
    input.request.request_type in ["landing", "conformance"]
}
```

## Constraints

`constraints` is an object the proxy understands key-by-key:

| Key | Type | Effect |
|---|---|---|
| `allowed_collections` | `[]string` | Whitelist; proxy intersects with the request's collections |
| `denied_collections` | `[]string` | Blacklist applied after allow-list |
| `max_results` | `int` | Caps the request's `limit` |
| `geofence.allowed_area` | GeoJSON | Item geometry must intersect this (push-down `S_INTERSECTS` if upstream supports Filter Extension, else response post-filter) |
| `geofence.denied_area` | GeoJSON | Item geometry must NOT intersect this (push-down `NOT S_INTERSECTS`, else post-filter) |
| `geofence.filter_mode` | `bool` | `true` filters responses; `false` rejects the whole request when the request bbox escapes the allowed area |
| `cql2_filter` | string | A cql2-text predicate; AND-combined with any client filter and forwarded |
| `cql2_filter_json` | object | cql2-json equivalent; wins over `cql2_filter` if both set |
| `required_filters` | object | STAC `query`-extension filters (deprecated but still wired) |

The proxy only emits `cql2_filter` / push-down geofence to upstream when
`authz.cql2_injection.enabled: true` in the YAML config AND the target
upstream advertises the Filter Extension (auto-probed at boot).

## Worked examples

### 1. Role-gated collections

```rego
package stac.authz

import future.keywords.if
import future.keywords.in

default allow := false

allow if {
    input.principal
    not input.request.method in ["DELETE", "PUT", "PATCH"]
}

allowed_collections := ["sentinel-2-l2a", "landsat-c2-l2"] if {
    "analyst" in input.principal.roles
}

allowed_collections := ["*"] if {
    "admin" in input.principal.roles
}

result := {
    "allow": allow,
    "reasons": [],
    "constraints": {"allowed_collections": allowed_collections},
}
```

### 2. Per-tenant geofence from a JWT claim

```rego
tenant_polygons := {
    "tenant-a": {"type": "Polygon", "coordinates": [[[-125, 24], [-66, 24], [-66, 50], [-125, 50], [-125, 24]]]},
    "tenant-b": {"type": "Polygon", "coordinates": [[[-10, 35], [40, 35], [40, 60], [-10, 60], [-10, 35]]]},
}

tenant := input.principal.attributes.tenant

result := {
    "allow": allow,
    "constraints": {
        "geofence": {
            "allowed_area": tenant_polygons[tenant],
            "filter_mode": true,
        },
    },
}
```

When the upstream supports the Filter Extension, the geofence becomes
`S_INTERSECTS(geometry, <polygon>)`; otherwise the proxy filters items
in the response body.

### 3. Cloud-cover cap for non-premium users on `/search`

```rego
cql2_filter := "eo:cloud_cover < 20" if {
    input.principal
    not "premium" in input.principal.roles
    input.request.request_type == "search"
}

cql2_filter := "" if {
    "premium" in input.principal.roles
}

result := {
    "allow": allow,
    "constraints": {"cql2_filter": cql2_filter},
}
```

### 4. Per-method branching (read vs. write)

```rego
allow if {
    input.principal
    input.request.method == "GET"
}

allow if {
    input.principal
    input.request.method == "POST"
    input.request.request_type == "search"
}

# DELETE/PUT/PATCH currently aren't routed (v0.1 is read-only); future
# transaction support will require explicit allow rules here.
```

### 5. Combining conditions (time-window + IP allowlist)

`stac-proxy` also supports policy-engine-agnostic "conditions" — a
secondary file-policy enforcer not driven by OPA. See
`internal/middleware/authz/policy.go` `Condition` types (`time_range`,
`ip_range`, `attribute`). OPA users typically express the same logic
directly in Rego:

```rego
business_hours if {
    now := time.now_ns()
    hour := time.weekday(now)
    not hour == "Saturday"
    not hour == "Sunday"
}

allow if {
    business_hours
    net.cidr_contains("10.0.0.0/8", input.request.client_ip)
    "analyst" in input.principal.roles
}
```

## Testing your policy

OPA ships an excellent test framework. Drop tests next to your `.rego`:

```rego
# policy_test.rego
package stac.authz

test_admin_allow if {
    allow with input as {
        "principal": {"roles": ["admin"]},
        "request":   {"method": "GET", "request_type": "search"},
        "resource":  {"type": "search"},
    }
}
```

Run with:

```bash
opa test policies/
```

When wiring a new policy, validate via the proxy too:

```bash
./stac-proxy --validate --config configs/example.yaml
```

## Debugging

Set `logging.level: debug` in YAML to see per-request policy input.
The proxy logs `authz_decision` with `allowed`, `reasons`, and a
short hash of `constraints` so you can diff between requests.

For policy-side debugging, OPA's `print()` writes to stderr; the
embedded enforcer surfaces those at info level.
