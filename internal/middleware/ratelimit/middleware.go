// Package ratelimit provides rate limiting middleware.
package ratelimit

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	"github.com/yourorg/stac-proxy/internal/middleware"
	"github.com/yourorg/stac-proxy/internal/middleware/auth"
)

// Middleware implements rate limiting for incoming requests.
type Middleware struct {
	middleware.BaseMiddleware
	limiter     Limiter
	keyFunc     KeyFunc
	quotaFunc   QuotaFunc
	defaultQuota Quota
}

// Config contains configuration for the rate limit middleware.
type Config struct {
	Limiter      Limiter
	KeyFunc      KeyFunc
	QuotaFunc    QuotaFunc
	DefaultQuota Quota
}

// NewMiddleware creates a new rate limit middleware.
func NewMiddleware(cfg Config) *Middleware {
	limiter := cfg.Limiter
	if limiter == nil {
		limiter = NewSlidingWindowLimiter()
	}

	keyFunc := cfg.KeyFunc
	if keyFunc == nil {
		keyFunc = DefaultKeyFunc
	}

	quotaFunc := cfg.QuotaFunc
	if quotaFunc == nil {
		quotaFunc = DefaultQuotaFunc
	}

	return &Middleware{
		BaseMiddleware: middleware.NewBaseMiddleware("ratelimit", middleware.PriorityRateLimit),
		limiter:        limiter,
		keyFunc:        keyFunc,
		quotaFunc:      quotaFunc,
		defaultQuota:   cfg.DefaultQuota,
	}
}

// ProcessRequest checks rate limits for the incoming request.
func (m *Middleware) ProcessRequest(ctx context.Context, req *middleware.STACRequest) (*middleware.STACRequest, error) {
	// Get principal for rate limit key
	principal := auth.PrincipalFromContext(ctx)
	principalID := ""
	var roles []string
	if principal != nil {
		principalID = principal.ID
		roles = principal.Roles
	}

	// Get client IP
	clientIP := req.RemoteAddr

	// Generate rate limit key
	key := m.keyFunc(ctx, principalID, clientIP)

	// Get quota for this request
	quota := m.quotaFunc(roles, m.defaultQuota)

	// Check rate limit
	allowed, info, err := m.limiter.Allow(ctx, key, quota)
	if err != nil {
		// On error, allow the request but log
		return req, nil
	}

	// Store rate limit info for response headers
	ctx = context.WithValue(ctx, rateLimitInfoKey, info)
	req.Context = ctx

	if !allowed {
		return nil, &middleware.RateLimitError{
			RetryAfter: info.RetryAfter,
		}
	}

	return req, nil
}

// ProcessResponse adds rate limit headers to the response.
func (m *Middleware) ProcessResponse(ctx context.Context, req *middleware.STACRequest,
	resp *middleware.STACResponse) (*middleware.STACResponse, error) {

	info, ok := ctx.Value(rateLimitInfoKey).(Info)
	if !ok {
		return resp, nil
	}

	// Add rate limit headers
	if resp.Headers == nil {
		resp.Headers = make(http.Header)
	}

	resp.Headers.Set("X-RateLimit-Limit", strconv.Itoa(info.Limit))
	resp.Headers.Set("X-RateLimit-Remaining", strconv.Itoa(info.Remaining))
	resp.Headers.Set("X-RateLimit-Reset", strconv.FormatInt(info.ResetAt, 10))

	return resp, nil
}

// Context key for rate limit info
type contextKeyType string

const rateLimitInfoKey contextKeyType = "ratelimit_info"

// RoleBasedQuotaFunc creates a quota function that uses role-based quotas.
func RoleBasedQuotaFunc(quotasByRole map[string]Quota, defaultQuota Quota) QuotaFunc {
	return func(roles []string, _ Quota) Quota {
		// Check roles in order, return first matching quota
		for _, role := range roles {
			if quota, ok := quotasByRole[role]; ok {
				return quota
			}
		}
		return defaultQuota
	}
}

// ErrorResponse creates an HTTP response for rate limit errors.
func ErrorResponse(err *middleware.RateLimitError) *middleware.STACResponse {
	return &middleware.STACResponse{
		StatusCode: http.StatusTooManyRequests,
		Headers: http.Header{
			"Content-Type":  []string{"application/json"},
			"Retry-After":   []string{strconv.Itoa(err.RetryAfter)},
		},
		Body: []byte(fmt.Sprintf(`{"code": "RateLimitExceeded", "description": "Rate limit exceeded. Retry after %d seconds"}`, err.RetryAfter)),
	}
}
