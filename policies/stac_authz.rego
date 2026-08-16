# STAC Proxy Authorization Policy
# This policy controls access to STAC resources based on user identity,
# roles, and resource attributes.
#
# Requires stac-proxy >= 0.4.0: anonymous requests reach the policy
# with input.principal UNDEFINED (not null), so `not input.principal`
# is the correct anonymous guard and `input.principal.<field>` rules
# are simply undefined (never matched) for anonymous callers.

package stac.authz

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# Default deny
default allow := false

# Result structure for the proxy
result := {
    "allow": allow,
    "reasons": reasons,
    "constraints": constraints,
}

# --- Reasons -----------------------------------------------------------

reasons contains "access granted" if allow

reasons contains "authentication required" if {
    not allow
    not input.principal
}

reasons contains "insufficient permissions" if {
    not allow
    input.principal
}

# --- Allow rules -------------------------------------------------------

# Admin users get full access. (For anonymous callers
# input.principal.roles is undefined, so this rule simply never
# matches — no explicit principal check needed.)
allow if {
    "admin" in input.principal.roles
}

# Authenticated users get read access.
allow if {
    input.principal
    is_read_request
}

# Anonymous access to the catalog surface — reads only. The proxy's
# routes are read-only today, but the method guard keeps these rules
# fail-closed if transaction endpoints ever appear.
allow if {
    input.request.method == "GET"
    input.request.request_type in ["landing", "conformance", "collections"]
}

allow if {
    input.request.method == "GET"
    input.request.request_type == "collection"
    is_public_collection(input.resource.collection)
}

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
    "cop-dem-glo-90",
}

is_public_collection(collection_id) if {
    collection_id in public_collections
}

# --- Constraints -------------------------------------------------------
#
# Keys understood by the proxy (all optional):
#   allowed_collections ([]string) — literal intersection with the
#                               request's collections. There is NO "*"
#                               wildcard: full-access roles must OMIT
#                               this key entirely (omission means
#                               unrestricted).
#   denied_collections  ([]string) — removed from the request.
#   max_results         (int)    — clamps the search limit.
#   cql2_filter         (string) — a cql2-text expression AND-combined
#                               with any client-supplied filter and
#                               pushed to the upstream STAC API.
#   cql2_filter_json    (object) — same effect, as cql2-json. If both
#                               are set, the JSON variant wins.
#   required_filters    (object) — property equality filters, also
#                               AND-combined.
#   geofence            (object) — {"allowed_area": <GeoJSON>,
#                               "filter_mode": true, ...}. Pushed down
#                               as S_INTERSECTS when the upstream
#                               advertises CQL2 spatial conformance;
#                               post-filtered otherwise.
#
# Composition style: each concern contributes a small object that is
# {} when not applicable, folded with object.union_n. This is
# deliberate — a single object literal referencing every rule would
# become undefined (collapsing ALL constraints) whenever any one
# member is undefined for the current input.
constraints := c if {
    allow
    c := object.union_n([collections_part, limits_part, filter_part, geofence_part])
} else := {}

# Collection scoping. admin and data_scientist omit the key entirely
# (full access); everyone else is limited to the public set.
default collections_part := {}

collections_part := {"allowed_collections": public_collections} if {
    input.principal
    not "admin" in input.principal.roles
    not "data_scientist" in input.principal.roles
}

# Result-size clamp by role.
default limits_part := {}

limits_part := {"max_results": 1000} if {
    "premium" in input.principal.roles
}

limits_part := {"max_results": 100} if {
    input.principal
    not "premium" in input.principal.roles
}

limits_part := {"max_results": 10} if {
    not input.principal
}

# Example: clamp cloud cover for non-premium users so the upstream
# returns clearer scenes only. Branch on input.request.method,
# input.request.request_type, and input.resource.collection when
# different collections or verbs need different filters.
default filter_part := {}

filter_part := {"cql2_filter": "eo:cloud_cover < 20"} if {
    input.principal
    not "premium" in input.principal.roles
    input.request.method == "GET"
    input.resource.collection == "sentinel-2-l2a"
}

filter_part := {"cql2_filter": "eo:cloud_cover < 20"} if {
    input.principal
    not "premium" in input.principal.roles
    input.request.method == "POST"
    input.request.request_type == "search"
}

# Geofencing: restrict listed users to a geographic area. The value
# must be a member of constraints (this object), in the proxy's
# geofence shape — a bare package-level rule is never read.
user_geofences := {"user123": {
    "type": "Polygon",
    "coordinates": [[[-125, 24], [-66, 24], [-66, 50], [-125, 50], [-125, 24]]],
}}

default geofence_part := {}

geofence_part := {"geofence": {
    "allowed_area": fence,
    "filter_mode": true,
}} if {
    fence := user_geofences[input.principal.id]
}
