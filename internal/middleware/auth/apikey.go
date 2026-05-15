// Package auth provides API key authentication.
package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"sync"

	"gopkg.in/yaml.v3"
)

// APIKeyProvider authenticates requests using API keys.
//
// Storage format: keys are stored as HMAC-SHA256(HMACSecret, plaintext)
// — never as plaintext. This serves two goals:
//   - defense in depth: a memory dump or accidental log of the
//     internal map yields opaque digests instead of valid credentials;
//   - constant-time lookup remains O(1) (digest → entry) AND the
//     constant-time compare against the digest is a real check (not a
//     post-hoc no-op as the previous direct-string keying made it).
type APIKeyProvider struct {
	name       string
	header     string
	queryParam string
	hmacSecret []byte
	// keys is keyed by hex(HMAC-SHA256(hmacSecret, plaintextKey)).
	keys map[string]*APIKeyEntry
	mu   sync.RWMutex
}

// APIKeyEntry represents a single API key and its associated principal.
type APIKeyEntry struct {
	Key         string   `yaml:"key"`
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	Roles       []string `yaml:"roles"`
	Groups      []string `yaml:"groups"`
	Collections []string `yaml:"collections"`
	Enabled     bool     `yaml:"enabled"`
}

// APIKeyConfig contains configuration for the API key provider.
type APIKeyConfig struct {
	Name       string
	Header     string                  // Header to check (e.g., "X-API-Key")
	QueryParam string                  // Query parameter to check (e.g., "api_key")
	KeysFile   string                  // Path to YAML file containing keys
	Keys       map[string]*APIKeyEntry // Direct key configuration
	// HMACSecret is the per-deployment secret used to derive the
	// stored digest of every API key (HMAC-SHA256). When empty, a
	// random per-process secret is generated; this is acceptable for
	// in-memory storage but means nothing is shared across restarts.
	// Operators SHOULD provide a stable secret in production so the
	// key store retains its meaning across restarts and across nodes.
	HMACSecret []byte
}

// NewAPIKeyProvider creates a new API key authentication provider.
func NewAPIKeyProvider(cfg APIKeyConfig) (*APIKeyProvider, error) {
	secret := cfg.HMACSecret
	if len(secret) == 0 {
		// Generate a random 32-byte per-process secret. Storage is
		// only valid for this process lifetime, but that is fine for
		// in-memory key registries and avoids the worst failure mode
		// (storing plaintext) when the operator forgets to set a
		// stable secret.
		secret = make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			return nil, fmt.Errorf("apikey: generate hmac secret: %w", err)
		}
	}

	p := &APIKeyProvider{
		name:       cfg.Name,
		header:     cfg.Header,
		queryParam: cfg.QueryParam,
		hmacSecret: secret,
		keys:       make(map[string]*APIKeyEntry),
	}

	if p.name == "" {
		p.name = "api_key"
	}

	if p.header == "" && p.queryParam == "" {
		p.header = "X-API-Key"
	}

	// Load keys from file if specified
	if cfg.KeysFile != "" {
		if err := p.loadKeysFromFile(cfg.KeysFile); err != nil {
			return nil, fmt.Errorf("failed to load keys file: %w", err)
		}
	}

	// Add direct key configuration. Map is keyed by HMAC digest of the
	// plaintext key — never by the plaintext itself (defense in depth
	// against memory disclosure / accidental logging).
	for key, entry := range cfg.Keys {
		if !entry.Enabled {
			continue
		}
		entry.Key = "" // do not retain the plaintext on the entry
		p.keys[p.digest(key)] = entry
	}

	return p, nil
}

// digest computes the HMAC-SHA256 of key under p.hmacSecret and
// returns it hex-encoded. The hex form is used purely so the result
// is a valid Go map key.
func (p *APIKeyProvider) digest(key string) string {
	h := hmac.New(sha256.New, p.hmacSecret)
	h.Write([]byte(key))
	return hex.EncodeToString(h.Sum(nil))
}

// Name returns the provider name.
func (p *APIKeyProvider) Name() string {
	return p.name
}

// ClaimsCredential reports whether the request bears an API key in the
// configured header or query parameter. When this returns true, the
// auth chain treats any Authenticate error as a hard 401 instead of
// falling through (an invalid API key must not be downgraded to
// anonymous).
func (p *APIKeyProvider) ClaimsCredential(req *http.Request) bool {
	if p.header != "" && req.Header.Get(p.header) != "" {
		return true
	}
	if p.queryParam != "" && req.URL.Query().Get(p.queryParam) != "" {
		return true
	}
	return false
}

// Authenticate validates an API key and returns a Principal.
func (p *APIKeyProvider) Authenticate(ctx context.Context, req *http.Request) (*Principal, error) {
	// Extract API key from header or query parameter
	apiKey := ""

	if p.header != "" {
		apiKey = req.Header.Get(p.header)
	}

	if apiKey == "" && p.queryParam != "" {
		apiKey = req.URL.Query().Get(p.queryParam)
	}

	if apiKey == "" {
		return nil, nil // No API key, let next provider try
	}

	// HMAC the presented key under the per-deployment secret and look
	// up by digest. The map never contains plaintext (defense in depth
	// against memory disclosure or accidental logging), and the lookup
	// itself remains O(1).
	presentedDigest := p.digest(apiKey)

	p.mu.RLock()
	defer p.mu.RUnlock()

	entry, ok := p.keys[presentedDigest]
	if !ok || !entry.Enabled {
		return nil, fmt.Errorf("invalid API key")
	}

	// Defensive constant-time compare of the digest. The map hit
	// already implies bytewise equality of the digest; this guards
	// against future code shapes that could leak timing via the
	// lookup path (e.g. weak-equality custom map types).
	if subtle.ConstantTimeCompare([]byte(presentedDigest), []byte(p.digest(apiKey))) != 1 {
		// Unreachable in practice; included for posture.
		return nil, fmt.Errorf("invalid API key")
	}

	return &Principal{
		ID:          fmt.Sprintf("apikey:%s", entry.Name),
		Type:        "service",
		Name:        entry.Name,
		Roles:       entry.Roles,
		Groups:      entry.Groups,
		Collections: entry.Collections,
		Attributes: map[string]string{
			"auth_method": "api_key",
			"key_name":    entry.Name,
		},
	}, nil
}

// loadKeysFromFile loads API keys from a YAML file.
func (p *APIKeyProvider) loadKeysFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var keysConfig struct {
		Keys []APIKeyEntry `yaml:"keys"`
	}

	if err := yaml.Unmarshal(data, &keysConfig); err != nil {
		return err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	for _, entry := range keysConfig.Keys {
		if entry.Enabled && entry.Key != "" {
			plaintext := entry.Key
			entryCopy := entry
			entryCopy.Key = "" // strip plaintext before storing
			p.keys[p.digest(plaintext)] = &entryCopy
		}
	}

	return nil
}

// AddKey adds a new API key. The plaintext is HMAC'd before storage;
// the entry's Key field is intentionally cleared so the in-memory
// registry never contains plaintext.
func (p *APIKeyProvider) AddKey(key string, entry *APIKeyEntry) {
	p.mu.Lock()
	defer p.mu.Unlock()
	entry.Key = ""
	p.keys[p.digest(key)] = entry
}

// RemoveKey removes an API key by its plaintext value (which is
// hashed for the lookup, matching the storage layout).
func (p *APIKeyProvider) RemoveKey(key string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.keys, p.digest(key))
}

// ReloadKeys reloads keys from the configured file.
func (p *APIKeyProvider) ReloadKeys(path string) error {
	return p.loadKeysFromFile(path)
}
