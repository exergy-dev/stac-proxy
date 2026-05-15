// Package auth provides authentication middleware and providers.
package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// BasicAuthProvider validates HTTP Basic authentication.
type BasicAuthProvider struct {
	name     string
	users    map[string]hashedUser
	realm    string
	cacheTTL time.Duration
}

type hashedUser struct {
	passwordHash []byte
	roles        []string
	attributes   map[string]interface{}
}

// BasicAuthConfig configures the basic auth provider.
type BasicAuthConfig struct {
	Name     string
	Realm    string
	Users    []BasicUser
	CacheTTL time.Duration
}

// BasicUser represents a user for basic auth.
type BasicUser struct {
	Username     string
	PasswordHash string // bcrypt hash
	Roles        []string
	Attributes   map[string]interface{}
}

// NewBasicAuthProvider creates a new basic auth provider.
func NewBasicAuthProvider(cfg BasicAuthConfig) (*BasicAuthProvider, error) {
	users := make(map[string]hashedUser)
	for _, u := range cfg.Users {
		users[u.Username] = hashedUser{
			passwordHash: decodePasswordHash(u.PasswordHash),
			roles:        u.Roles,
			attributes:   u.Attributes,
		}
	}

	return &BasicAuthProvider{
		name:     cfg.Name,
		users:    users,
		realm:    cfg.Realm,
		cacheTTL: cfg.CacheTTL,
	}, nil
}

// decodePasswordHash returns the raw bcrypt digest bytes for the
// configured PasswordHash. Bcrypt hashes use the OpenBSD modular crypt
// format and always begin with one of the version prefixes "$2a$",
// "$2b$" or "$2y$"; when present we MUST treat the input as a literal
// bcrypt hash rather than try to base64-decode it. (A bcrypt hash can
// happen to be valid base64 — silently decoding then storing the
// wrong bytes corrupts the credential and breaks every login.)
//
// When no recognised prefix is present we fall back to base64 decoding
// for backward compatibility with operators who stored hashes in
// base64-wrapped form.
func decodePasswordHash(s string) []byte {
	if isBcryptHash(s) {
		return []byte(s)
	}
	if decoded, err := base64.StdEncoding.DecodeString(s); err == nil {
		return decoded
	}
	return []byte(s)
}

// isBcryptHash reports whether s starts with a recognised bcrypt
// version prefix.
func isBcryptHash(s string) bool {
	return strings.HasPrefix(s, "$2a$") ||
		strings.HasPrefix(s, "$2b$") ||
		strings.HasPrefix(s, "$2y$")
}

// Name returns the provider name.
func (p *BasicAuthProvider) Name() string {
	return p.name
}

// ClaimsCredential reports whether the request bears a Basic
// Authorization header. See CredentialClaimer for the fail-closed
// contract.
func (p *BasicAuthProvider) ClaimsCredential(req *http.Request) bool {
	return strings.HasPrefix(req.Header.Get("Authorization"), "Basic ")
}

// Authenticate validates Basic auth credentials.
func (p *BasicAuthProvider) Authenticate(ctx context.Context, req *http.Request) (*Principal, error) {
	// Extract basic auth from Authorization header
	authHeader := req.Header.Get("Authorization")
	if authHeader == "" {
		return nil, nil // No auth header
	}

	if !strings.HasPrefix(authHeader, "Basic ") {
		return nil, nil // Not Basic auth
	}

	// Parse basic auth header
	username, password, ok := parseBasicAuth(authHeader)
	if !ok {
		return nil, errors.New("invalid basic auth format")
	}

	user, exists := p.users[username]
	if !exists {
		return nil, errors.New("invalid credentials")
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword(user.passwordHash, []byte(password)); err != nil {
		return nil, errors.New("invalid credentials")
	}

	// Convert user.attributes from map[string]interface{} to map[string]string
	attrs := make(map[string]string)
	for k, v := range user.attributes {
		if s, ok := v.(string); ok {
			attrs[k] = s
		}
	}

	return &Principal{
		ID:         username,
		Type:       "user",
		Roles:      user.roles,
		Attributes: attrs,
	}, nil
}

// parseBasicAuth parses an HTTP Basic Authentication string.
func parseBasicAuth(auth string) (username, password string, ok bool) {
	// Remove "Basic " prefix if present
	auth = strings.TrimPrefix(auth, "Basic ")

	c, err := base64.StdEncoding.DecodeString(auth)
	if err != nil {
		return "", "", false
	}
	cs := string(c)
	idx := strings.IndexByte(cs, ':')
	if idx < 0 {
		return "", "", false
	}
	return cs[:idx], cs[idx+1:], true
}

// HashPassword creates a bcrypt hash of a password.
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}
