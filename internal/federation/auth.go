// Package federation provides authentication for upstream origins.
package federation

import (
	"context"
	"net/http"
)

// AuthProvider handles authentication for a specific origin.
type AuthProvider interface {
	// ApplyAuth modifies the request with appropriate credentials.
	ApplyAuth(ctx context.Context, req *http.Request) error

	// Refresh updates credentials if needed (e.g., OAuth2 token refresh).
	Refresh(ctx context.Context) error
}

// NoOpAuthProvider provides no authentication.
type NoOpAuthProvider struct{}

// ApplyAuth does nothing.
func (p *NoOpAuthProvider) ApplyAuth(ctx context.Context, req *http.Request) error {
	return nil
}

// Refresh does nothing.
func (p *NoOpAuthProvider) Refresh(ctx context.Context) error {
	return nil
}

// BasicAuthProvider provides HTTP Basic authentication.
type BasicAuthProvider struct {
	Username string
	Password string
}

// ApplyAuth adds Basic auth header to the request.
func (p *BasicAuthProvider) ApplyAuth(ctx context.Context, req *http.Request) error {
	req.SetBasicAuth(p.Username, p.Password)
	return nil
}

// Refresh does nothing for basic auth.
func (p *BasicAuthProvider) Refresh(ctx context.Context) error {
	return nil
}

// BearerAuthProvider provides static Bearer token authentication.
type BearerAuthProvider struct {
	Token string
}

// ApplyAuth adds Bearer token to the request.
func (p *BearerAuthProvider) ApplyAuth(ctx context.Context, req *http.Request) error {
	req.Header.Set("Authorization", "Bearer "+p.Token)
	return nil
}

// Refresh does nothing for static bearer tokens.
func (p *BearerAuthProvider) Refresh(ctx context.Context) error {
	return nil
}

// APIKeyAuthProvider provides API key authentication.
type APIKeyAuthProvider struct {
	Header  string
	Value   string
	InQuery bool
}

// ApplyAuth adds API key to the request.
func (p *APIKeyAuthProvider) ApplyAuth(ctx context.Context, req *http.Request) error {
	if p.InQuery {
		q := req.URL.Query()
		q.Set(p.Header, p.Value)
		req.URL.RawQuery = q.Encode()
	} else {
		req.Header.Set(p.Header, p.Value)
	}
	return nil
}

// Refresh does nothing for API keys.
func (p *APIKeyAuthProvider) Refresh(ctx context.Context) error {
	return nil
}

// CustomHeadersProvider provides custom header injection.
type CustomHeadersProvider struct {
	Headers map[string]string
}

// ApplyAuth adds custom headers to the request.
func (p *CustomHeadersProvider) ApplyAuth(ctx context.Context, req *http.Request) error {
	for k, v := range p.Headers {
		req.Header.Set(k, v)
	}
	return nil
}

// Refresh does nothing for custom headers.
func (p *CustomHeadersProvider) Refresh(ctx context.Context) error {
	return nil
}

// ChainedAuthProvider combines multiple auth providers.
type ChainedAuthProvider struct {
	Providers []AuthProvider
}

// ApplyAuth applies all providers in order.
func (p *ChainedAuthProvider) ApplyAuth(ctx context.Context, req *http.Request) error {
	for _, provider := range p.Providers {
		if err := provider.ApplyAuth(ctx, req); err != nil {
			return err
		}
	}
	return nil
}

// Refresh refreshes all providers.
func (p *ChainedAuthProvider) Refresh(ctx context.Context) error {
	for _, provider := range p.Providers {
		if err := provider.Refresh(ctx); err != nil {
			return err
		}
	}
	return nil
}

// BuildAuthProvider creates an AuthProvider from configuration.
func BuildAuthProvider(cfg AuthConfig) (AuthProvider, error) {
	if cfg.Type == "" || cfg.Type == "none" {
		return &NoOpAuthProvider{}, nil
	}

	var providers []AuthProvider

	switch cfg.Type {
	case "basic":
		providers = append(providers, &BasicAuthProvider{
			Username: cfg.Username,
			Password: cfg.Password,
		})

	case "bearer":
		providers = append(providers, &BearerAuthProvider{
			Token: cfg.Token,
		})

	case "api_key":
		providers = append(providers, &APIKeyAuthProvider{
			Header:  cfg.APIKeyHeader,
			Value:   cfg.APIKeyValue,
			InQuery: cfg.APIKeyInQuery,
		})

	case "oauth2":
		if cfg.OAuth2 != nil {
			oauth2Provider, err := NewOAuth2AuthProvider(cfg.OAuth2)
			if err != nil {
				return nil, err
			}
			providers = append(providers, oauth2Provider)
		}

	case "aws_sig_v4":
		if cfg.AWSSigV4 != nil {
			sigv4Provider, err := NewAWSSigV4Provider(cfg.AWSSigV4)
			if err != nil {
				return nil, err
			}
			providers = append(providers, sigv4Provider)
		}

	case "custom":
		if len(cfg.CustomHeaders) > 0 {
			providers = append(providers, &CustomHeadersProvider{
				Headers: cfg.CustomHeaders,
			})
		}
	}

	if len(providers) == 0 {
		return &NoOpAuthProvider{}, nil
	}

	if len(providers) == 1 {
		return providers[0], nil
	}

	return &ChainedAuthProvider{Providers: providers}, nil
}
