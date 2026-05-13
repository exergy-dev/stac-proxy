// Package ratelimit provides rate limiting middleware.
//
// Ratelimit is a chi-style http middleware (func(http.Handler) http.Handler)
// rather than going through the buffered middleware.Middleware contract:
// it operates only on the inbound *http.Request and writes either the
// X-RateLimit-* headers + a 200 (allowed) or a 429 response (denied).
package ratelimit

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/yourorg/stac-proxy/internal/middleware/auth"
	"github.com/yourorg/stac-proxy/internal/observability"
)

// Config contains configuration for the rate limit middleware.
type Config struct {
	Limiter      Limiter
	KeyFunc      KeyFunc
	QuotaFunc    QuotaFunc
	DefaultQuota Quota
}

// NewHTTPMiddleware returns chi-compatible rate-limit middleware.
//
//   - Builds the rate-limit key via cfg.KeyFunc (principalID falls back
//     to client IP). Principal comes from the auth middleware's context
//     value, so auth MUST be wired before ratelimit at the chi level.
//   - Looks up the quota via cfg.QuotaFunc (default falls through).
//   - Sets X-RateLimit-Limit/Remaining/Reset on every response.
//   - On deny: writes Retry-After and a 429 JSON error; the inner handler
//     does not run.
func NewHTTPMiddleware(cfg Config) func(http.Handler) http.Handler {
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

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			var principalID string
			var roles []string
			if p := auth.PrincipalFromContext(ctx); p != nil {
				principalID = p.ID
				roles = p.Roles
			}
			key := keyFunc(ctx, principalID, r.RemoteAddr)
			quota := quotaFunc(roles, cfg.DefaultQuota)

			allowed, info, err := limiter.Allow(ctx, key, quota)
			if err != nil {
				// Fail open: allow through, no headers added.
				next.ServeHTTP(w, r)
				return
			}

			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(info.Limit))
			w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(info.Remaining))
			w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(info.ResetAt, 10))

			if !allowed {
				if m := observability.Default(); m != nil {
					keyType := "principal"
					if principalID == "" {
						keyType = "ip"
					}
					m.RateLimitExceeded.WithLabelValues(keyType).Inc()
				}
				w.Header().Set("Retry-After", strconv.Itoa(info.RetryAfter))
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"code":        "RateLimitExceeded",
					"description": "Rate limit exceeded",
				})
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RoleBasedQuotaFunc returns a QuotaFunc that picks the first matching
// per-role quota from quotasByRole, falling back to defaultQuota.
func RoleBasedQuotaFunc(quotasByRole map[string]Quota, defaultQuota Quota) QuotaFunc {
	return func(roles []string, _ Quota) Quota {
		for _, role := range roles {
			if quota, ok := quotasByRole[role]; ok {
				return quota
			}
		}
		return defaultQuota
	}
}
