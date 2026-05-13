// Package auth provides authentication middleware.
//
// Auth is a chi-style http middleware (func(http.Handler) http.Handler):
// it operates on the inbound *http.Request and writes either a Principal
// into context or a 401 response.
package auth

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/yourorg/stac-proxy/internal/middleware"
	"github.com/yourorg/stac-proxy/internal/observability"
)

// Config contains configuration for the auth middleware.
type Config struct {
	AllowAnonymous bool
	Providers      []Provider
}

// PrincipalFromContext retrieves the authenticated principal from context.
func PrincipalFromContext(ctx context.Context) *Principal {
	if p, ok := ctx.Value(middleware.PrincipalKey).(*Principal); ok {
		return p
	}
	return nil
}

// NewHTTPMiddleware returns chi-compatible middleware that walks the
// configured providers, stores the Principal in context, and either
// proceeds to the next handler or writes a 401 when no provider
// authenticated and AllowAnonymous is false.
//
// Provider semantics:
//   - (Principal, nil): authenticated — next handler runs with Principal in context.
//   - (nil, nil): provider doesn't apply to this request — try the next one.
//   - (nil, err): provider errored — try the next one (errored providers don't deny).
func NewHTTPMiddleware(cfg Config) func(http.Handler) http.Handler {
	anonPrincipal := AnonymousPrincipal()
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			var authed *Principal
			for _, provider := range cfg.Providers {
				p, err := provider.Authenticate(ctx, r)
				if err != nil {
					if m := observability.Default(); m != nil {
						m.AuthFailures.WithLabelValues(provider.Name(), "error").Inc()
					}
					continue
				}
				if p != nil {
					authed = p
					if m := observability.Default(); m != nil {
						m.AuthSuccesses.WithLabelValues(provider.Name(), p.Type).Inc()
					}
					break
				}
			}
			if authed == nil {
				if !cfg.AllowAnonymous {
					if m := observability.Default(); m != nil {
						m.AuthFailures.WithLabelValues("none", "missing_credentials").Inc()
					}
					writeAuthError(w, "authentication required")
					return
				}
				authed = anonPrincipal
				if m := observability.Default(); m != nil {
					m.AuthSuccesses.WithLabelValues("anonymous", "anonymous").Inc()
				}
			}
			ctx = context.WithValue(ctx, middleware.PrincipalKey, authed)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func writeAuthError(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"code":        "Unauthorized",
		"description": msg,
	})
}
