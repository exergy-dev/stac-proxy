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

// IsAnonymous reports whether this principal represents an unauthenticated caller.
func (p *Principal) IsAnonymous() bool {
	return p.Type == "anonymous"
}

// HasGroup reports whether the principal is a member of group.
func (p *Principal) HasGroup(group string) bool {
	for _, g := range p.Groups {
		if g == group {
			return true
		}
	}
	return false
}

// HasRole reports whether the principal carries role.
func (p *Principal) HasRole(role string) bool {
	for _, r := range p.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// CanAccessCollection reports whether the principal is allowed to touch
// the named collection. An empty Collections slice means "all".
func (p *Principal) CanAccessCollection(collection string) bool {
	if len(p.Collections) == 0 {
		return true
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
