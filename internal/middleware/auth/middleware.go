// Package auth provides authentication middleware.
//
// Auth is a chi-style http middleware (func(http.Handler) http.Handler):
// it operates on the inbound *http.Request and writes either a Principal
// into context or a 401 response.
package auth

import (
	"context"
	"net/http"

	"github.com/yourorg/stac-proxy/internal/middleware"
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
//   - (nil, err): provider errored.
//     If the provider implements CredentialClaimer and reported
//     ClaimsCredential(req) == true, the chain MUST fail closed with a
//     401 — the request presented this provider's credential type
//     and it was invalid. Falling through here is a critical auth
//     bypass: a Bearer token with a bad signature would otherwise be
//     downgraded to anonymous when AllowAnonymous=true.
//     Otherwise (no claim signal), the legacy fall-through behaviour
//     is preserved for diagnostic / best-effort providers.
func NewHTTPMiddleware(cfg Config) func(http.Handler) http.Handler {
	anonPrincipal := AnonymousPrincipal()
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			var authed *Principal
			for _, provider := range cfg.Providers {
				// Snapshot the credential-claim signal BEFORE calling
				// Authenticate so a misbehaving provider can't change
				// its mind about owning the credential after erroring.
				claimed := false
				if cc, ok := provider.(CredentialClaimer); ok {
					claimed = cc.ClaimsCredential(r)
				}
				p, err := provider.Authenticate(ctx, r)
				if err != nil {
					if claimed {
						// Fail closed: the request bore this
						// provider's credential type and it was
						// rejected. Do NOT try later providers and
						// do NOT downgrade to anonymous.
						middleware.WriteJSONError(w, http.StatusUnauthorized, "Unauthorized", "authentication required")
						return
					}
					continue
				}
				if p != nil {
					authed = p
					break
				}
			}
			if authed == nil {
				if !cfg.AllowAnonymous {
					middleware.WriteJSONError(w, http.StatusUnauthorized, "Unauthorized", "authentication required")
					return
				}
				authed = anonPrincipal
			}
			ctx = context.WithValue(ctx, middleware.PrincipalKey, authed)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
