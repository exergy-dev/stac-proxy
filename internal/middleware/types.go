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

// STACRequest wraps an HTTP request with STAC-specific context.
type STACRequest struct {
	*http.Request
	Context     context.Context
	Params      map[string]interface{} // Parsed STAC query parameters
	Collection  string                 // Target collection (if applicable)
	ItemID      string                 // Target item ID (if applicable)
	RequestType RequestType            // Type of STAC request
	SearchReq   *stac.SearchRequest    // Parsed search request (if applicable)
}

// Clone creates a shallow copy of the STACRequest.
func (r *STACRequest) Clone() *STACRequest {
	clone := *r
	if r.Params != nil {
		clone.Params = make(map[string]interface{}, len(r.Params))
		for k, v := range r.Params {
			clone.Params[k] = v
		}
	}
	return &clone
}

// STACResponse wraps an HTTP response. The body is the canonical
// payload; downstream middleware reads/mutates Body directly rather
// than going through any parallel parsed-data field.
type STACResponse struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
}

// Middleware defines the interface for all middleware components.
type Middleware interface {
	// Name returns a unique identifier for this middleware.
	Name() string

	// ProcessRequest handles incoming requests before upstream.
	// Return modified request, or error to short-circuit.
	ProcessRequest(ctx context.Context, req *STACRequest) (*STACRequest, error)

	// ProcessResponse handles responses before returning to client.
	ProcessResponse(ctx context.Context, req *STACRequest, resp *STACResponse) (*STACResponse, error)

	// Priority determines ordering (lower = earlier in chain).
	Priority() int
}

// BaseMiddleware provides a default implementation that can be embedded.
type BaseMiddleware struct {
	name     string
	priority int
}

// NewBaseMiddleware creates a new BaseMiddleware.
func NewBaseMiddleware(name string, priority int) BaseMiddleware {
	return BaseMiddleware{name: name, priority: priority}
}

// Name returns the middleware name.
func (m BaseMiddleware) Name() string {
	return m.name
}

// Priority returns the middleware priority.
func (m BaseMiddleware) Priority() int {
	return m.priority
}

// ProcessRequest is a no-op that passes through the request.
func (m BaseMiddleware) ProcessRequest(ctx context.Context, req *STACRequest) (*STACRequest, error) {
	return req, nil
}

// ProcessResponse is a no-op that passes through the response.
func (m BaseMiddleware) ProcessResponse(ctx context.Context, req *STACRequest, resp *STACResponse) (*STACResponse, error) {
	return resp, nil
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

// Handler is the interface for the core request handler (proxy or federation).
type Handler interface {
	// Handle processes a STAC request and returns a response.
	Handle(ctx context.Context, req *STACRequest) (*STACResponse, error)
}

// HandlerFunc is an adapter to allow the use of ordinary functions as Handlers.
type HandlerFunc func(ctx context.Context, req *STACRequest) (*STACResponse, error)

// Handle calls f(ctx, req).
func (f HandlerFunc) Handle(ctx context.Context, req *STACRequest) (*STACResponse, error) {
	return f(ctx, req)
}

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
)

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
