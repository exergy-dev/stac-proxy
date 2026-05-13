// Package middleware provides the core middleware interfaces and types.
package middleware

import (
	"context"
	"net/http"

	"github.com/yourorg/stac-proxy/internal/stac"
)

// RequestType identifies the type of STAC API request.
type RequestType int

const (
	RequestTypeUnknown RequestType = iota
	RequestTypeLanding
	RequestTypeConformance
	RequestTypeCollections
	RequestTypeCollection
	RequestTypeItems
	RequestTypeItem
	RequestTypeSearch
	RequestTypeQueryables
	RequestTypeCollectionQueryables
)

// String returns a string representation of the request type.
func (rt RequestType) String() string {
	switch rt {
	case RequestTypeLanding:
		return "landing"
	case RequestTypeConformance:
		return "conformance"
	case RequestTypeCollections:
		return "collections"
	case RequestTypeCollection:
		return "collection"
	case RequestTypeItems:
		return "items"
	case RequestTypeItem:
		return "item"
	case RequestTypeSearch:
		return "search"
	case RequestTypeQueryables:
		return "queryables"
	case RequestTypeCollectionQueryables:
		return "collection_queryables"
	default:
		return "unknown"
	}
}

// MiddlewarePriorities defines standard priority levels for middleware.
//
// Ordering rationale: Auth runs first so we have a Principal. Cache runs
// before Authz and RateLimit so that a cache hit does not consume a
// rate-limit token AND is gated by Auth (an unauthenticated caller
// cannot fish for cached content), but does not bother Authz which can
// be expensive (OPA). Authorization still runs on hits via the
// `cacheHit` context value; per-principal cache keys are required when
// authorization decisions vary by principal.
const (
	PriorityFirst     = 0
	PriorityLogging   = 100
	PriorityAuth      = 200
	PriorityCache     = 250
	PriorityAuthz     = 300
	PriorityRateLimit = 400
	PriorityTransform = 600
	PriorityLast      = 1000
)

// Context keys for storing values in context.
type contextKey string

const (
	// PrincipalKey is the context key for the authenticated principal.
	PrincipalKey contextKey = "principal"

	// RequestIDKey is the context key for the request ID.
	RequestIDKey contextKey = "request_id"

	// AuthzDecisionKey is the context key for authorization decision.
	AuthzDecisionKey contextKey = "authz_decision"

	// GeofenceKey is the context key for the effective geofence.
	GeofenceKey contextKey = "geofence"

	// OriginIDKey is the context key for the upstream origin ID.
	OriginIDKey contextKey = "origin_id"

	// stacInfoKey carries the parsed STAC request shape (collection,
	// item ID, request type, search request) through the chi middleware
	// chain. Set by the router before any middleware runs.
	stacInfoKey contextKey = "stac_info"
)

// STACInfo is the parsed STAC shape attached to every request's context
// by the router. Chi middlewares read it to specialize cache keys,
// authorize collection access, and inject filters.
type STACInfo struct {
	Collection  string
	ItemID      string
	RequestType RequestType
	SearchReq   *stac.SearchRequest
}

// WithSTACInfo attaches info to ctx. Returns the new context.
func WithSTACInfo(ctx context.Context, info *STACInfo) context.Context {
	return context.WithValue(ctx, stacInfoKey, info)
}

// STACInfoFromContext returns the STACInfo attached to ctx, or nil.
// Middleware that needs the parsed STAC shape pulls it via this helper.
func STACInfoFromContext(ctx context.Context) *STACInfo {
	if v, ok := ctx.Value(stacInfoKey).(*STACInfo); ok {
		return v
	}
	return nil
}

// ForwardRequestID copies the inbound request ID (if any) from ctx
// onto an outbound HTTP request as the standard X-Request-ID header.
// No-op when ctx carries no request ID.
func ForwardRequestID(ctx context.Context, req *http.Request) {
	if rid, ok := ctx.Value(RequestIDKey).(string); ok && rid != "" {
		req.Header.Set("X-Request-ID", rid)
	}
}

// Error types for middleware.

// AuthError represents an authentication error.
type AuthError struct {
	Message string
	Code    string // "invalid_token", "expired_token", "missing_token", etc.
}

func (e *AuthError) Error() string {
	return e.Message
}

// ForbiddenError represents an authorization failure.
type ForbiddenError struct {
	Reason    string
	Principal string
}

func (e *ForbiddenError) Error() string {
	return e.Reason
}

// RateLimitError represents a rate limit exceeded error.
type RateLimitError struct {
	RetryAfter int // Seconds until retry is allowed
}

func (e *RateLimitError) Error() string {
	return "rate limit exceeded"
}

// InternalError represents an internal server error.
type InternalError struct {
	Message string
	Cause   error
}

func (e *InternalError) Error() string {
	if e.Cause != nil {
		return e.Message + ": " + e.Cause.Error()
	}
	return e.Message
}

func (e *InternalError) Unwrap() error {
	return e.Cause
}
