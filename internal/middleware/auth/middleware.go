// Package auth provides authentication middleware.
package auth

import (
	"context"

	"github.com/yourorg/stac-proxy/internal/middleware"
)

// Middleware handles authentication for incoming requests.
type Middleware struct {
	middleware.BaseMiddleware
	providers      []Provider
	allowAnonymous bool
	anonPrincipal  *Principal
}

// Config contains configuration for the auth middleware.
type Config struct {
	AllowAnonymous bool
	Providers      []Provider
}

// NewMiddleware creates a new authentication middleware.
func NewMiddleware(cfg Config) *Middleware {
	return &Middleware{
		BaseMiddleware: middleware.NewBaseMiddleware("auth", middleware.PriorityAuth),
		providers:      cfg.Providers,
		allowAnonymous: cfg.AllowAnonymous,
		anonPrincipal:  AnonymousPrincipal(),
	}
}

// ProcessRequest attempts to authenticate the request using configured providers.
func (m *Middleware) ProcessRequest(ctx context.Context, req *middleware.STACRequest) (*middleware.STACRequest, error) {
	// Try each provider in order
	for _, provider := range m.providers {
		principal, err := provider.Authenticate(ctx, req.Request)
		if err != nil {
			// Authentication failed with this provider
			continue
		}
		if principal != nil {
			// Successfully authenticated
			ctx = context.WithValue(ctx, middleware.PrincipalKey, principal)
			req.Context = ctx
			return req, nil
		}
		// Provider doesn't apply to this request, try next
	}

	// No provider authenticated the request
	if m.allowAnonymous {
		ctx = context.WithValue(ctx, middleware.PrincipalKey, m.anonPrincipal)
		req.Context = ctx
		return req, nil
	}

	return nil, &middleware.AuthError{
		Message: "authentication required",
		Code:    "missing_credentials",
	}
}

// PrincipalFromContext retrieves the authenticated principal from context.
func PrincipalFromContext(ctx context.Context) *Principal {
	if p, ok := ctx.Value(middleware.PrincipalKey).(*Principal); ok {
		return p
	}
	return nil
}

// AddProvider adds a new authentication provider.
func (m *Middleware) AddProvider(provider Provider) {
	m.providers = append(m.providers, provider)
}

// Providers returns the configured providers.
func (m *Middleware) Providers() []Provider {
	return m.providers
}
