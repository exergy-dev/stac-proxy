# STAC Proxy Authorization Policy
# This policy controls access to STAC resources based on user identity,
# roles, and resource attributes.

package stac.authz

import future.keywords.if
import future.keywords.in

# Default deny
default allow := false

# Result structure for the proxy
result := {
    "allow": allow,
    "reasons": reasons,
    "constraints": constraints
}

# Collect all reasons
reasons[msg] {
    allow
    msg := "access granted"
}

reasons[msg] {
    not allow
    not input.principal
    msg := "authentication required"
}

reasons[msg] {
    not allow
    input.principal
    msg := "insufficient permissions"
}

# Allow admin users full access
allow if {
    input.principal
    "admin" in input.principal.roles
}

# Allow read access for authenticated users
allow if {
    input.principal
    is_read_request
}

# Allow anonymous access to landing page and conformance
allow if {
    input.request.request_type in ["landing", "conformance"]
}

# Allow anonymous access to public collections
allow if {
    input.request.request_type == "collections"
}

allow if {
    input.request.request_type == "collection"
    is_public_collection(input.resource.collection)
}

# Check if request is a read operation
is_read_request if {
    input.request.method == "GET"
}

is_read_request if {
    input.request.method == "POST"
    input.request.request_type == "search"
}

# Public collections (customize for your environment)
public_collections := {
    "sentinel-2-l2a",
    "landsat-c2-l2",
    "cop-dem-glo-30",
    "cop-dem-glo-90"
}

is_public_collection(collection_id) if {
    collection_id in public_collections
}

# Collection access control
allowed_collections := collections if {
    input.principal
    "data_scientist" in input.principal.roles
    collections := ["*"]
}

allowed_collections := collections if {
    input.principal
    not "data_scientist" in input.principal.roles
    not "admin" in input.principal.roles
    collections := public_collections
}

# Build constraints
#
# Additional keys understood by the proxy:
#   cql2_filter      (string) — a cql2-text expression AND-combined with
#                               any client-supplied filter and pushed to
#                               the upstream STAC API.
#   cql2_filter_json (object) — same effect, but as cql2-json. If both
#                               are set, the JSON variant wins.
#   geofence.allowed_area (GeoJSON) — when the proxy's CQL2 injection
#                               is enabled and the upstream supports the
#                               Filter Extension, the geofence is pushed
#                               down as S_INTERSECTS rather than
#                               post-filtered.
constraints := c if {
    allow
    c := {
        "allowed_collections": allowed_collections,
        "max_results": max_results,
        "cql2_filter": cql2_filter,
    }
}

# Example: clamp cloud cover for non-premium users so the upstream
# returns clearer scenes only. Premium users get an empty filter.
cql2_filter := "eo:cloud_cover < 20" if {
    input.principal
    not "premium" in input.principal.roles
}

cql2_filter := "" if {
    not input.principal
}

cql2_filter := "" if {
    input.principal
    "premium" in input.principal.roles
}

constraints := {} if {
    not allow
}

# Rate limit based on role
max_results := 1000 if {
    input.principal
    "premium" in input.principal.roles
}

max_results := 100 if {
    input.principal
    not "premium" in input.principal.roles
}

max_results := 10 if {
    not input.principal
}

# Geofencing rules (example)
# Restrict certain users to specific geographic areas
user_geofences := {
    "user123": {
        "type": "Polygon",
        "coordinates": [[[-125, 24], [-66, 24], [-66, 50], [-125, 50], [-125, 24]]]
    }
}

geofence := fence if {
    input.principal
    fence := user_geofences[input.principal.id]
}

geofence := null if {
    not input.principal
}

geofence := null if {
    input.principal
    not user_geofences[input.principal.id]
}
