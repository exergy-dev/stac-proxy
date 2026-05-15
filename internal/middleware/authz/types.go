// Package authz provides authorization middleware.
package authz

import (
	"context"
	"net/http"

	"github.com/yourorg/stac-proxy/internal/middleware"
	"github.com/yourorg/stac-proxy/internal/middleware/auth"
)

// AuthzInput contains all information for authorization decisions.
type AuthzInput struct {
	// Principal information
	Principal *PrincipalInfo `json:"principal"`

	// Request information
	Request *RequestInfo `json:"request"`

	// Resource information
	Resource *ResourceInfo `json:"resource"`
}

// PrincipalInfo contains identity information for authorization.
type PrincipalInfo struct {
	ID         string                 `json:"id"`
	Type       string                 `json:"type"`
	Roles      []string               `json:"roles"`
	Groups     []string               `json:"groups"`
	Attributes map[string]interface{} `json:"attributes"`
	AuthMethod string                 `json:"auth_method"`
}

// RequestInfo contains request context for authorization.
type RequestInfo struct {
	Method      string                 `json:"method"`
	Path        string                 `json:"path"`
	RequestType string                 `json:"request_type"`
	Query       map[string][]string    `json:"query"`
	Headers     map[string]string      `json:"headers"`
	Body        map[string]interface{} `json:"body,omitempty"`
	ClientIP    string                 `json:"client_ip"`
	RequestID   string                 `json:"request_id"`
}

// ResourceInfo contains resource context for authorization.
type ResourceInfo struct {
	Type       string   `json:"type"` // collection, item, search
	Collection string   `json:"collection,omitempty"`
	ItemID     string   `json:"item_id,omitempty"`
	Origins    []string `json:"origins,omitempty"`
}

// AuthzDecision represents an authorization decision.
type AuthzDecision struct {
	Allowed bool     `json:"allowed"`
	Reasons []string `json:"reasons,omitempty"`

	// Optional constraints on the allowed request
	Constraints *AuthzConstraints `json:"constraints,omitempty"`
}

// HasConstraints reports whether the decision carries any
// row-level or content-filtering constraint that would make the
// response specific to this principal. The response cache uses this
// to bypass caching entirely when constraints are present, since the
// same URL can produce different filtered responses for different
// principals.
func (d *AuthzDecision) HasConstraints() bool {
	if d == nil || d.Constraints == nil {
		return false
	}
	c := d.Constraints
	if len(c.AllowedCollections) > 0 {
		return true
	}
	if len(c.DeniedCollections) > 0 {
		return true
	}
	if c.Geofence != nil && c.Geofence.AllowedArea != nil {
		return true
	}
	if c.MaxResults > 0 {
		return true
	}
	if len(c.RequiredFilters) > 0 {
		return true
	}
	if c.CQL2Filter != "" {
		return true
	}
	if c.CQL2FilterJSON != nil {
		return true
	}
	return false
}

// AuthzConstraints provides optional restrictions on allowed requests.
type AuthzConstraints struct {
	// Collections the user is allowed to access
	AllowedCollections []string `json:"allowed_collections,omitempty"`

	// Collections explicitly denied
	DeniedCollections []string `json:"denied_collections,omitempty"`

	// Geofence restriction
	Geofence *GeofenceConstraint `json:"geofence,omitempty"`

	// Maximum results allowed
	MaxResults int `json:"max_results,omitempty"`

	// Required filters to apply
	RequiredFilters map[string]interface{} `json:"required_filters,omitempty"`

	// CQL2Filter is a cql2-text expression the policy wants AND-combined
	// with any client-supplied filter and pushed to the upstream STAC API.
	CQL2Filter string `json:"cql2_filter,omitempty"`

	// CQL2FilterJSON is the cql2-json equivalent; if both are set, the
	// JSON form wins. Stored as an interface{} since it may be any JSON
	// object shape.
	CQL2FilterJSON interface{} `json:"cql2_filter_json,omitempty"`

	// GeofencePushedDown is set by the authz middleware when the geofence
	// has been pushed down as a CQL2 S_INTERSECTS predicate. When true,
	// the response-time post-filter is skipped.
	GeofencePushedDown bool `json:"-"`
}

// GeofenceConstraint specifies spatial access restrictions.
type GeofenceConstraint struct {
	// GeoJSON geometry defining allowed area
	AllowedArea interface{} `json:"allowed_area,omitempty"`

	// GeoJSON geometry defining denied area
	DeniedArea interface{} `json:"denied_area,omitempty"`

	// Whether to filter results or reject entire requests
	FilterMode bool `json:"filter_mode"`
}

// Enforcer is the interface for authorization decision makers.
type Enforcer interface {
	// Authorize makes an authorization decision for the given input.
	Authorize(ctx context.Context, input *AuthzInput) (*AuthzDecision, error)

	// Name returns the enforcer name for logging/metrics.
	Name() string
}

// BuildAuthzInput creates AuthzInput from an http.Request plus the
// parsed STAC info and authenticated principal. info may be nil for
// non-STAC routes; in that case Resource is left empty.
func BuildAuthzInput(r *http.Request, info *middleware.STACInfo, principal *auth.Principal) *AuthzInput {
	input := &AuthzInput{
		Request: &RequestInfo{
			Method:   r.Method,
			Path:     r.URL.Path,
			Query:    r.URL.Query(),
			Headers:  extractHeaders(r.Header),
			ClientIP: r.RemoteAddr,
		},
		Resource: &ResourceInfo{},
	}
	if info != nil {
		input.Request.RequestType = info.RequestType.String()
		input.Resource.Type = resourceTypeFromRequest(info.RequestType)
		input.Resource.Collection = info.Collection
		input.Resource.ItemID = info.ItemID
	}

	if principal != nil {
		attrs := make(map[string]interface{}, len(principal.Attributes))
		for k, v := range principal.Attributes {
			attrs[k] = v
		}
		input.Principal = &PrincipalInfo{
			ID:         principal.ID,
			Type:       principal.Type,
			Roles:      principal.Roles,
			Groups:     principal.Groups,
			Attributes: attrs,
			AuthMethod: principal.Attributes["auth_method"],
		}
	}

	if reqID, ok := r.Context().Value(middleware.RequestIDKey).(string); ok {
		input.Request.RequestID = reqID
	}

	return input
}

// extractHeaders extracts headers for authorization context.
func extractHeaders(headers map[string][]string) map[string]string {
	result := make(map[string]string)
	for key, values := range headers {
		if len(values) > 0 {
			// Skip sensitive headers
			switch key {
			case "Authorization", "Cookie", "X-Api-Key":
				continue
			}
			result[key] = values[0]
		}
	}
	return result
}

// resourceTypeFromRequest maps request type to resource type.
func resourceTypeFromRequest(rt middleware.RequestType) string {
	switch rt {
	case middleware.RequestTypeCollection, middleware.RequestTypeCollections:
		return "collection"
	case middleware.RequestTypeItem, middleware.RequestTypeItems:
		return "item"
	case middleware.RequestTypeSearch:
		return "search"
	default:
		return rt.String()
	}
}
