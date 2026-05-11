// Package auth provides authentication middleware and providers.
package auth

import (
	"context"
	"net/http"
)

// Provider defines the interface for authentication providers.
type Provider interface {
	// Name returns a unique identifier for this provider.
	Name() string

	// Authenticate attempts to authenticate the request.
	// Returns a Principal if successful, nil if this provider doesn't apply,
	// or an error if authentication failed.
	Authenticate(ctx context.Context, req *http.Request) (*Principal, error)
}

// Principal represents an authenticated entity (user or service).
type Principal struct {
	ID          string            // Unique identifier
	Type        string            // "user", "service", "anonymous"
	Email       string            // Email address (if available)
	Name        string            // Display name (if available)
	Groups      []string          // Group memberships
	Roles       []string          // Assigned roles
	Attributes  map[string]string // Additional attributes
	Collections []string          // Allowed collections (empty = all)
	Token       string            // Original token (for forwarding)
	ExpiresAt   int64             // Token expiration (Unix timestamp)
}

// IsAnonymous returns true if this is an anonymous principal.
func (p *Principal) IsAnonymous() bool {
	return p.Type == "anonymous"
}

// HasRole checks if the principal has a specific role.
func (p *Principal) HasRole(role string) bool {
	for _, r := range p.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// HasGroup checks if the principal is a member of a specific group.
func (p *Principal) HasGroup(group string) bool {
	for _, g := range p.Groups {
		if g == group {
			return true
		}
	}
	return false
}

// CanAccessCollection checks if the principal can access a collection.
func (p *Principal) CanAccessCollection(collection string) bool {
	if len(p.Collections) == 0 {
		return true // No restrictions
	}
	for _, c := range p.Collections {
		if c == collection || c == "*" {
			return true
		}
	}
	return false
}

// Clone creates a copy of the principal.
func (p *Principal) Clone() *Principal {
	clone := *p
	if p.Groups != nil {
		clone.Groups = make([]string, len(p.Groups))
		copy(clone.Groups, p.Groups)
	}
	if p.Roles != nil {
		clone.Roles = make([]string, len(p.Roles))
		copy(clone.Roles, p.Roles)
	}
	if p.Attributes != nil {
		clone.Attributes = make(map[string]string, len(p.Attributes))
		for k, v := range p.Attributes {
			clone.Attributes[k] = v
		}
	}
	if p.Collections != nil {
		clone.Collections = make([]string, len(p.Collections))
		copy(clone.Collections, p.Collections)
	}
	return &clone
}

// AnonymousPrincipal creates a default anonymous principal.
func AnonymousPrincipal() *Principal {
	return &Principal{
		ID:         "anonymous",
		Type:       "anonymous",
		Attributes: make(map[string]string),
	}
}

// ProviderFunc is an adapter for functions to implement Provider.
type ProviderFunc func(ctx context.Context, req *http.Request) (*Principal, error)

// Authenticate calls the function.
func (f ProviderFunc) Authenticate(ctx context.Context, req *http.Request) (*Principal, error) {
	return f(ctx, req)
}

// Name returns "func".
func (f ProviderFunc) Name() string {
	return "func"
}
