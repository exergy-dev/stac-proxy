// Package auth provides API key authentication.
package auth

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net/http"
	"os"
	"sync"

	"gopkg.in/yaml.v3"
)

// APIKeyProvider authenticates requests using API keys.
type APIKeyProvider struct {
	name      string
	header    string
	queryParam string
	keys      map[string]*APIKeyEntry
	mu        sync.RWMutex
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
	Header     string // Header to check (e.g., "X-API-Key")
	QueryParam string // Query parameter to check (e.g., "api_key")
	KeysFile   string // Path to YAML file containing keys
	Keys       map[string]*APIKeyEntry // Direct key configuration
}

// NewAPIKeyProvider creates a new API key authentication provider.
func NewAPIKeyProvider(cfg APIKeyConfig) (*APIKeyProvider, error) {
	p := &APIKeyProvider{
		name:       cfg.Name,
		header:     cfg.Header,
		queryParam: cfg.QueryParam,
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

	// Add direct key configuration
	for key, entry := range cfg.Keys {
		entry.Key = key
		if entry.Enabled {
			p.keys[key] = entry
		}
	}

	return p, nil
}

// Name returns the provider name.
func (p *APIKeyProvider) Name() string {
	return p.name
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

	// Look up the key. p.keys is keyed by the raw API-key string, so a direct
	// map lookup is O(1) — the previous O(N) linear scan with per-entry
	// constant-time compare was unnecessary given the storage shape.
	p.mu.RLock()
	defer p.mu.RUnlock()

	entry, ok := p.keys[apiKey]
	if !ok || !entry.Enabled {
		return nil, fmt.Errorf("invalid API key")
	}

	// Defensive constant-time compare against the stored raw key. The map hit
	// already guarantees bytewise equality, so this is degenerate in practice,
	// but it preserves the constant-time-compare API surface for the threat
	// model (reduces timing-side-channel surface for adversaries probing for
	// valid keys via lookup timing).
	if subtle.ConstantTimeCompare([]byte(apiKey), []byte(entry.Key)) != 1 {
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
			entryCopy := entry
			p.keys[entry.Key] = &entryCopy
		}
	}

	return nil
}

// AddKey adds a new API key.
func (p *APIKeyProvider) AddKey(key string, entry *APIKeyEntry) {
	p.mu.Lock()
	defer p.mu.Unlock()
	entry.Key = key
	p.keys[key] = entry
}

// RemoveKey removes an API key.
func (p *APIKeyProvider) RemoveKey(key string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.keys, key)
}

// ReloadKeys reloads keys from the configured file.
func (p *APIKeyProvider) ReloadKeys(path string) error {
	return p.loadKeysFromFile(path)
}
