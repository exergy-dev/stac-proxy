// Package ratelimit provides rate limiting middleware.
//
// Ratelimit is a chi-style http middleware (func(http.Handler) http.Handler):
// it inspects the inbound *http.Request, sets X-RateLimit-* response
// headers, and either lets the request through or short-circuits with 429.
package ratelimit

import (
	"net"
	"net/http"
	"strconv"

	"github.com/yourorg/stac-proxy/internal/middleware"
	"github.com/yourorg/stac-proxy/internal/middleware/auth"
)

// Config contains configuration for the rate limit middleware.
type Config struct {
	Limiter      Limiter
	DefaultQuota Quota

	// FailClosed selects the failure mode when the limiter errors —
	// only reachable with a remote limiter (Redis); the in-memory one
	// never errors. Default false: fail open, because making the
	// rate-limit backend a hard availability dependency turns a
	// cache-tier outage into a full proxy outage, and an edge LB can
	// backstop-limit meanwhile. Operators with strict quota/billing
	// contracts opt into true: requests are refused with 503 while
	// the backend is unreachable.
	FailClosed bool
}

// NewHTTPMiddleware returns chi-compatible rate-limit middleware.
//
//   - Builds the rate-limit key via DefaultKeyFunc (principalID falls
//     back to client IP). Principal comes from the auth middleware's
//     context value, so auth MUST be wired before ratelimit at the chi
//     level.
//   - Sets X-RateLimit-Limit/Remaining/Reset on every response.
//   - On deny: writes Retry-After and a 429 JSON error; the inner handler
//     does not run.
func NewHTTPMiddleware(cfg Config) func(http.Handler) http.Handler {
	limiter := cfg.Limiter
	if limiter == nil {
		limiter = NewTokenBucketLimiter(0)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			var principalID string
			if p := auth.PrincipalFromContext(ctx); p != nil {
				principalID = p.ID
			}
			// r.RemoteAddr is already the best client IP — chi's
			// RealIP middleware overwrites it from X-Real-IP /
			// X-Forwarded-For / True-Client-IP when present, and
			// otherwise it's the TCP peer. Strip the port so all
			// requests from a given host share one bucket.
			clientIP := r.RemoteAddr
			if host, _, err := net.SplitHostPort(clientIP); err == nil {
				clientIP = host
			}
			key := DefaultKeyFunc(ctx, principalID, clientIP)

			allowed, info, err := limiter.Allow(ctx, key, cfg.DefaultQuota)
			if err != nil {
				// The limiter itself logs the (throttled) warning.
				if cfg.FailClosed {
					w.Header().Set("Retry-After", "1")
					middleware.WriteJSONError(w, http.StatusServiceUnavailable,
						"RateLimiterUnavailable",
						"Rate limiting backend unavailable; refusing request (failure_mode: closed)")
					return
				}
				// Fail open: allow through, no headers added.
				next.ServeHTTP(w, r)
				return
			}

			// X-RateLimit-* header semantics (M-ratelimit-2):
			//  - Limit: the configured Quota.Requests.
			//  - Remaining: pre-reservation available capacity. The
			//    caller observes "tokens you had before this call",
			//    matching GitHub/Twitter convention. A successful
			//    request that drained the bucket can therefore still
			//    show Remaining > 0.
			//  - Reset: unix timestamp at which the bucket refills to
			//    full given current state — useful for clients
			//    timing their backoff. Constant for the lifetime of
			//    a fully-drained bucket only.
			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(info.Limit))
			w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(info.Remaining))
			w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(info.ResetAt, 10))

			if !allowed {
				w.Header().Set("Retry-After", strconv.Itoa(info.RetryAfter))
				middleware.WriteJSONError(w, http.StatusTooManyRequests,
					"RateLimitExceeded", "Rate limit exceeded")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
