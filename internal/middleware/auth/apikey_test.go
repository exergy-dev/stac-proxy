package auth

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAPIKeyProvider(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		config   APIKeyConfig
		wantErr  bool
		validate func(*testing.T, *APIKeyProvider)
	}{
		{
			name: "valid config with direct keys",
			config: APIKeyConfig{
				Name:   "test-apikey",
				Header: "X-API-Key",
				Keys: map[string]*APIKeyEntry{
					"key123": {
						Name:    "test-key",
						Enabled: true,
						Roles:   []string{"admin"},
						Groups:  []string{"engineering"},
					},
				},
			},
			wantErr: false,
			validate: func(t *testing.T, p *APIKeyProvider) {
				assert.Equal(t, "test-apikey", p.name, "name")
				assert.Equal(t, "X-API-Key", p.header, "header")
				assert.Len(t, p.keys, 1, "expected 1 key")
				assert.NotNil(t, p.keys[p.digest("key123")], "expected key123 to be present")
			},
		},
		{
			name: "default name when not provided",
			config: APIKeyConfig{
				Keys: map[string]*APIKeyEntry{
					"key1": {Enabled: true},
				},
			},
			wantErr: false,
			validate: func(t *testing.T, p *APIKeyProvider) {
				assert.Equal(t, "api_key", p.name, "expected default name")
			},
		},
		{
			name: "default header when neither header nor query param provided",
			config: APIKeyConfig{
				Keys: map[string]*APIKeyEntry{
					"key1": {Enabled: true},
				},
			},
			wantErr: false,
			validate: func(t *testing.T, p *APIKeyProvider) {
				assert.Equal(t, "X-API-Key", p.header, "expected default header")
			},
		},
		{
			name: "query parameter only",
			config: APIKeyConfig{
				QueryParam: "api_key",
				Keys: map[string]*APIKeyEntry{
					"key1": {Enabled: true},
				},
			},
			wantErr: false,
			validate: func(t *testing.T, p *APIKeyProvider) {
				assert.Equal(t, "", p.header, "expected empty header")
				assert.Equal(t, "api_key", p.queryParam, "queryParam")
			},
		},
		{
			name: "both header and query parameter",
			config: APIKeyConfig{
				Header:     "Authorization",
				QueryParam: "token",
				Keys: map[string]*APIKeyEntry{
					"key1": {Enabled: true},
				},
			},
			wantErr: false,
			validate: func(t *testing.T, p *APIKeyProvider) {
				assert.Equal(t, "Authorization", p.header, "header")
				assert.Equal(t, "token", p.queryParam, "queryParam")
			},
		},
		{
			name: "only enabled keys are loaded",
			config: APIKeyConfig{
				Keys: map[string]*APIKeyEntry{
					"enabled-key": {
						Name:    "enabled",
						Enabled: true,
					},
					"disabled-key": {
						Name:    "disabled",
						Enabled: false,
					},
				},
			},
			wantErr: false,
			validate: func(t *testing.T, p *APIKeyProvider) {
				assert.Len(t, p.keys, 1, "expected 1 enabled key")
				assert.NotNil(t, p.keys[p.digest("enabled-key")], "expected enabled-key to be present")
				assert.Nil(t, p.keys[p.digest("disabled-key")], "expected disabled-key to be absent")
			},
		},
		{
			name: "multiple enabled keys",
			config: APIKeyConfig{
				Keys: map[string]*APIKeyEntry{
					"key1": {Name: "first", Enabled: true, Roles: []string{"admin"}},
					"key2": {Name: "second", Enabled: true, Roles: []string{"user"}},
					"key3": {Name: "third", Enabled: true, Roles: []string{"viewer"}},
				},
			},
			wantErr: false,
			validate: func(t *testing.T, p *APIKeyProvider) {
				assert.Len(t, p.keys, 3, "expected 3 keys")
			},
		},
		{
			name: "keys with all attributes",
			config: APIKeyConfig{
				Keys: map[string]*APIKeyEntry{
					"full-key": {
						Name:        "full",
						Description: "Full featured key",
						Enabled:     true,
						Roles:       []string{"admin", "user"},
						Groups:      []string{"team-a", "team-b"},
						Collections: []string{"collection1", "collection2"},
					},
				},
			},
			wantErr: false,
			validate: func(t *testing.T, p *APIKeyProvider) {
				key := p.keys[p.digest("full-key")]
				require.NotNil(t, key, "expected full-key to be present")
				assert.Equal(t, "full", key.Name, "name")
				assert.Equal(t, "Full featured key", key.Description, "description")
				assert.Len(t, key.Roles, 2, "expected 2 roles")
				assert.Len(t, key.Groups, 2, "expected 2 groups")
				assert.Len(t, key.Collections, 2, "expected 2 collections")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			provider, err := NewAPIKeyProvider(tt.config)

			if tt.wantErr {
				require.Error(t, err, "expected error")
				return
			}

			require.NoError(t, err, "unexpected error")

			if tt.validate != nil {
				tt.validate(t, provider)
			}
		})
	}
}

func TestNewAPIKeyProvider_WithKeysFile(t *testing.T) {
	t.Parallel()

	// Create a temporary directory for test files
	tmpDir := t.TempDir()

	tests := []struct {
		name        string
		fileData    string
		config      APIKeyConfig
		wantErr     bool
		errContains string
		validate    func(*testing.T, *APIKeyProvider)
	}{
		{
			name: "valid keys file",
			fileData: `keys:
  - key: "file-key-1"
    name: "file-key-one"
    enabled: true
    roles:
      - admin
    groups:
      - engineering
  - key: "file-key-2"
    name: "file-key-two"
    enabled: true
    roles:
      - user
`,
			config:  APIKeyConfig{},
			wantErr: false,
			validate: func(t *testing.T, p *APIKeyProvider) {
				assert.Len(t, p.keys, 2, "expected 2 keys from file")
				assert.NotNil(t, p.keys[p.digest("file-key-1")], "expected file-key-1 to be present")
				assert.NotNil(t, p.keys[p.digest("file-key-2")], "expected file-key-2 to be present")
			},
		},
		{
			name: "disabled keys in file are not loaded",
			fileData: `keys:
  - key: "enabled-key"
    name: "enabled"
    enabled: true
  - key: "disabled-key"
    name: "disabled"
    enabled: false
`,
			config:  APIKeyConfig{},
			wantErr: false,
			validate: func(t *testing.T, p *APIKeyProvider) {
				assert.Len(t, p.keys, 1, "expected 1 key")
				assert.NotNil(t, p.keys[p.digest("enabled-key")], "expected enabled-key to be present")
			},
		},
		{
			name: "keys without key field are skipped",
			fileData: `keys:
  - key: "valid-key"
    name: "valid"
    enabled: true
  - name: "no-key-field"
    enabled: true
`,
			config:  APIKeyConfig{},
			wantErr: false,
			validate: func(t *testing.T, p *APIKeyProvider) {
				assert.Len(t, p.keys, 1, "expected 1 key")
			},
		},
		{
			name:        "invalid YAML file",
			fileData:    `invalid: yaml: content: [[[`,
			config:      APIKeyConfig{},
			wantErr:     true,
			errContains: "failed to load keys file",
		},
		{
			name:        "non-existent file",
			fileData:    "", // Don't create file
			config:      APIKeyConfig{},
			wantErr:     true,
			errContains: "failed to load keys file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var keysFile string
			if tt.name != "non-existent file" {
				keysFile = filepath.Join(tmpDir, tt.name+".yaml")
				err := os.WriteFile(keysFile, []byte(tt.fileData), 0644)
				require.NoError(t, err, "failed to create test file")
			} else {
				keysFile = filepath.Join(tmpDir, "nonexistent.yaml")
			}

			tt.config.KeysFile = keysFile
			provider, err := NewAPIKeyProvider(tt.config)

			if tt.wantErr {
				require.Error(t, err, "expected error")
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains, "expected error containing %q", tt.errContains)
				}
				return
			}

			require.NoError(t, err, "unexpected error")

			if tt.validate != nil {
				tt.validate(t, provider)
			}
		})
	}
}

func TestNewAPIKeyProvider_CombineFileAndDirectKeys(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	keysFile := filepath.Join(tmpDir, "keys.yaml")

	fileData := `keys:
  - key: "file-key"
    name: "from-file"
    enabled: true
    roles:
      - admin
`
	err := os.WriteFile(keysFile, []byte(fileData), 0644)
	require.NoError(t, err, "failed to create test file")

	provider, err := NewAPIKeyProvider(APIKeyConfig{
		KeysFile: keysFile,
		Keys: map[string]*APIKeyEntry{
			"direct-key": {
				Name:    "from-config",
				Enabled: true,
				Roles:   []string{"user"},
			},
		},
	})

	require.NoError(t, err, "unexpected error")

	assert.Len(t, provider.keys, 2, "expected 2 keys (file + direct)")

	assert.NotNil(t, provider.keys[provider.digest("file-key")], "expected file-key to be present")

	assert.NotNil(t, provider.keys[provider.digest("direct-key")], "expected direct-key to be present")
}

func TestAPIKeyProvider_Name(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		providerName string
		expected     string
	}{
		{
			name:         "custom name",
			providerName: "custom-apikey",
			expected:     "custom-apikey",
		},
		{
			name:         "default name",
			providerName: "",
			expected:     "api_key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			provider, err := NewAPIKeyProvider(APIKeyConfig{
				Name: tt.providerName,
				Keys: map[string]*APIKeyEntry{
					"test": {Enabled: true},
				},
			})
			require.NoError(t, err, "failed to create provider")

			assert.Equal(t, tt.expected, provider.Name(), "Name()")
		})
	}
}

func TestAPIKeyProvider_Authenticate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		config      APIKeyConfig
		setupReq    func() *http.Request
		wantNil     bool // true if we expect nil principal (not applicable)
		wantErr     bool
		errContains string
		validate    func(*testing.T, *Principal)
	}{
		{
			name: "valid API key from header",
			config: APIKeyConfig{
				Header: "X-API-Key",
				Keys: map[string]*APIKeyEntry{
					"valid-key-123": {
						Name:    "test-service",
						Enabled: true,
						Roles:   []string{"admin", "user"},
						Groups:  []string{"engineering"},
					},
				},
			},
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "/test", nil)
				req.Header.Set("X-API-Key", "valid-key-123")
				return req
			},
			wantErr: false,
			validate: func(t *testing.T, p *Principal) {
				require.NotNil(t, p, "expected non-nil principal")
				assert.Equal(t, "apikey:test-service", p.ID, "ID")
				assert.Equal(t, "service", p.Type, "Type")
				assert.Equal(t, "test-service", p.Name, "Name")
				assert.Len(t, p.Roles, 2, "expected 2 roles")
				assert.True(t, p.HasRole("admin"), "expected admin role")
				assert.True(t, p.HasRole("user"), "expected user role")
				assert.Len(t, p.Groups, 1, "expected 1 group")
				assert.True(t, p.HasGroup("engineering"), "expected engineering group")
				require.NotNil(t, p.Attributes, "expected attributes to be set")
				assert.Equal(t, "api_key", p.Attributes["auth_method"], "auth_method")
				assert.Equal(t, "test-service", p.Attributes["key_name"], "key_name")
			},
		},
		{
			name: "valid API key from query parameter",
			config: APIKeyConfig{
				QueryParam:      "api_key",
				AllowQueryParam: true,
				Keys: map[string]*APIKeyEntry{
					"query-key-456": {
						Name:    "query-service",
						Enabled: true,
						Roles:   []string{"viewer"},
					},
				},
			},
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "/test?api_key=query-key-456", nil)
				return req
			},
			wantErr: false,
			validate: func(t *testing.T, p *Principal) {
				require.NotNil(t, p, "expected non-nil principal")
				assert.Equal(t, "query-service", p.Name, "Name")
			},
		},
		{
			name: "header takes precedence over query parameter",
			config: APIKeyConfig{
				Header:          "X-API-Key",
				QueryParam:      "api_key",
				AllowQueryParam: true,
				Keys: map[string]*APIKeyEntry{
					"header-key": {
						Name:    "header-service",
						Enabled: true,
					},
					"query-key": {
						Name:    "query-service",
						Enabled: true,
					},
				},
			},
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "/test?api_key=query-key", nil)
				req.Header.Set("X-API-Key", "header-key")
				return req
			},
			wantErr: false,
			validate: func(t *testing.T, p *Principal) {
				assert.Equal(t, "header-service", p.Name, "expected header to take precedence")
			},
		},
		{
			name: "fallback to query parameter when header is empty",
			config: APIKeyConfig{
				Header:          "X-API-Key",
				QueryParam:      "api_key",
				AllowQueryParam: true,
				Keys: map[string]*APIKeyEntry{
					"query-key": {
						Name:    "query-service",
						Enabled: true,
					},
				},
			},
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "/test?api_key=query-key", nil)
				return req
			},
			wantErr: false,
			validate: func(t *testing.T, p *Principal) {
				assert.Equal(t, "query-service", p.Name, "expected query parameter to be used")
			},
		},
		{
			name: "invalid API key",
			config: APIKeyConfig{
				Header: "X-API-Key",
				Keys: map[string]*APIKeyEntry{
					"valid-key": {
						Name:    "service",
						Enabled: true,
					},
				},
			},
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "/test", nil)
				req.Header.Set("X-API-Key", "invalid-key")
				return req
			},
			wantErr:     true,
			errContains: "invalid API key",
		},
		{
			name: "no API key provided - returns nil",
			config: APIKeyConfig{
				Header: "X-API-Key",
				Keys: map[string]*APIKeyEntry{
					"valid-key": {Enabled: true},
				},
			},
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "/test", nil)
				return req
			},
			wantNil: true,
		},
		{
			name: "empty API key in header - returns nil",
			config: APIKeyConfig{
				Header: "X-API-Key",
				Keys: map[string]*APIKeyEntry{
					"valid-key": {Enabled: true},
				},
			},
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "/test", nil)
				req.Header.Set("X-API-Key", "")
				return req
			},
			wantNil: true,
		},
		{
			name: "disabled key is rejected",
			config: APIKeyConfig{
				Header: "X-API-Key",
				Keys: map[string]*APIKeyEntry{
					"disabled-key": {
						Name:    "disabled-service",
						Enabled: false,
					},
				},
			},
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "/test", nil)
				req.Header.Set("X-API-Key", "disabled-key")
				return req
			},
			wantErr:     true,
			errContains: "invalid API key",
		},
		{
			name: "key with collections",
			config: APIKeyConfig{
				Header: "X-API-Key",
				Keys: map[string]*APIKeyEntry{
					"collection-key": {
						Name:        "collection-service",
						Enabled:     true,
						Collections: []string{"collection1", "collection2"},
					},
				},
			},
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "/test", nil)
				req.Header.Set("X-API-Key", "collection-key")
				return req
			},
			wantErr: false,
			validate: func(t *testing.T, p *Principal) {
				assert.Len(t, p.Collections, 2, "expected 2 collections")
				assert.True(t, p.CanAccessCollection("collection1"), "expected access to collection1")
				assert.True(t, p.CanAccessCollection("collection2"), "expected access to collection2")
			},
		},
		{
			name: "case sensitive key matching",
			config: APIKeyConfig{
				Header: "X-API-Key",
				Keys: map[string]*APIKeyEntry{
					"CaseSensitiveKey": {
						Name:    "case-service",
						Enabled: true,
					},
				},
			},
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "/test", nil)
				req.Header.Set("X-API-Key", "casesensitivekey")
				return req
			},
			wantErr:     true,
			errContains: "invalid API key",
		},
		{
			name: "exact key match required",
			config: APIKeyConfig{
				Header: "X-API-Key",
				Keys: map[string]*APIKeyEntry{
					"exact-key": {
						Name:    "exact-service",
						Enabled: true,
					},
				},
			},
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "/test", nil)
				req.Header.Set("X-API-Key", "exact-key-plus-extra")
				return req
			},
			wantErr:     true,
			errContains: "invalid API key",
		},
		{
			name: "multiple keys - first matching key is used",
			config: APIKeyConfig{
				Header: "X-API-Key",
				Keys: map[string]*APIKeyEntry{
					"key1": {
						Name:    "service1",
						Enabled: true,
						Roles:   []string{"role1"},
					},
					"key2": {
						Name:    "service2",
						Enabled: true,
						Roles:   []string{"role2"},
					},
					"key3": {
						Name:    "service3",
						Enabled: true,
						Roles:   []string{"role3"},
					},
				},
			},
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "/test", nil)
				req.Header.Set("X-API-Key", "key2")
				return req
			},
			wantErr: false,
			validate: func(t *testing.T, p *Principal) {
				assert.Equal(t, "service2", p.Name, "expected service2")
				assert.True(t, p.HasRole("role2"), "expected role2")
			},
		},
		{
			name: "key with all attributes populated",
			config: APIKeyConfig{
				Header: "X-API-Key",
				Keys: map[string]*APIKeyEntry{
					"full-key": {
						Name:        "full-service",
						Description: "A fully featured key",
						Enabled:     true,
						Roles:       []string{"admin", "editor", "viewer"},
						Groups:      []string{"team-a", "team-b", "team-c"},
						Collections: []string{"col1", "col2"},
					},
				},
			},
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "/test", nil)
				req.Header.Set("X-API-Key", "full-key")
				return req
			},
			wantErr: false,
			validate: func(t *testing.T, p *Principal) {
				assert.Len(t, p.Roles, 3, "expected 3 roles")
				assert.Len(t, p.Groups, 3, "expected 3 groups")
				assert.Len(t, p.Collections, 2, "expected 2 collections")
			},
		},
		{
			name: "custom header name",
			config: APIKeyConfig{
				Header: "Authorization",
				Keys: map[string]*APIKeyEntry{
					"auth-key": {
						Name:    "auth-service",
						Enabled: true,
					},
				},
			},
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "/test", nil)
				req.Header.Set("Authorization", "auth-key")
				return req
			},
			wantErr: false,
			validate: func(t *testing.T, p *Principal) {
				assert.Equal(t, "auth-service", p.Name, "expected auth-service")
			},
		},
		{
			name: "custom query parameter name",
			config: APIKeyConfig{
				QueryParam:      "token",
				AllowQueryParam: true,
				Keys: map[string]*APIKeyEntry{
					"token-key": {
						Name:    "token-service",
						Enabled: true,
					},
				},
			},
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "/test?token=token-key", nil)
				return req
			},
			wantErr: false,
			validate: func(t *testing.T, p *Principal) {
				assert.Equal(t, "token-service", p.Name, "expected token-service")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			provider, err := NewAPIKeyProvider(tt.config)
			require.NoError(t, err, "failed to create provider")

			req := tt.setupReq()
			ctx := context.Background()

			principal, err := provider.Authenticate(ctx, req)

			if tt.wantNil {
				assert.Nil(t, principal, "expected nil principal")
				assert.NoError(t, err, "expected nil error for non-applicable auth")
				return
			}

			if tt.wantErr {
				require.Error(t, err, "expected error")
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains, "expected error containing %q", tt.errContains)
				}
				return
			}

			require.NoError(t, err, "unexpected error")

			if tt.validate != nil {
				tt.validate(t, principal)
			}
		})
	}
}

func TestAPIKeyProvider_AddKey(t *testing.T) {
	t.Parallel()

	provider, err := NewAPIKeyProvider(APIKeyConfig{
		Keys: map[string]*APIKeyEntry{
			"initial-key": {
				Name:    "initial",
				Enabled: true,
			},
		},
	})
	require.NoError(t, err, "failed to create provider")

	// Add a new key
	provider.AddKey("new-key", &APIKeyEntry{
		Name:    "new-service",
		Enabled: true,
		Roles:   []string{"admin"},
	})

	// Verify the key was added (looked up by HMAC digest, not plaintext)
	require.NotNil(t, provider.keys[provider.digest("new-key")], "expected new-key to be present")

	assert.Equal(t, "new-service", provider.keys[provider.digest("new-key")].Name, "Name")

	// Plaintext is intentionally cleared from the entry after storage
	// so the in-memory registry never contains plaintext credentials
	// (defense in depth against memory disclosure / accidental logging).
	assert.Equal(t, "", provider.keys[provider.digest("new-key")].Key, "expected stored Key field to be empty (plaintext stripped)")

	// Verify it can be used for authentication
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-API-Key", "new-key")
	principal, err := provider.Authenticate(context.Background(), req)

	require.NoError(t, err, "unexpected error")

	assert.Equal(t, "new-service", principal.Name, "expected principal name=new-service")
}

func TestAPIKeyProvider_RemoveKey(t *testing.T) {
	t.Parallel()

	provider, err := NewAPIKeyProvider(APIKeyConfig{
		Keys: map[string]*APIKeyEntry{
			"key-to-remove": {
				Name:    "removable",
				Enabled: true,
			},
			"key-to-keep": {
				Name:    "keepable",
				Enabled: true,
			},
		},
	})
	require.NoError(t, err, "failed to create provider")

	// Remove the key
	provider.RemoveKey("key-to-remove")

	// Verify the key was removed
	assert.Nil(t, provider.keys[provider.digest("key-to-remove")], "expected key-to-remove to be absent")

	// Verify the other key is still present
	assert.NotNil(t, provider.keys[provider.digest("key-to-keep")], "expected key-to-keep to still be present")

	// Verify removed key cannot be used for authentication
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-API-Key", "key-to-remove")
	_, err = provider.Authenticate(context.Background(), req)

	assert.Error(t, err, "expected error when using removed key")
}

func TestAPIKeyProvider_ReloadKeys(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	keysFile := filepath.Join(tmpDir, "reload-keys.yaml")

	// Create initial file
	initialData := `keys:
  - key: "initial-key"
    name: "initial"
    enabled: true
`
	err := os.WriteFile(keysFile, []byte(initialData), 0644)
	require.NoError(t, err, "failed to create initial file")

	provider, err := NewAPIKeyProvider(APIKeyConfig{
		KeysFile: keysFile,
	})
	require.NoError(t, err, "failed to create provider")

	// Verify initial key
	assert.NotNil(t, provider.keys[provider.digest("initial-key")], "expected initial-key to be present")

	// Update the file
	updatedData := `keys:
  - key: "updated-key"
    name: "updated"
    enabled: true
  - key: "new-key"
    name: "new"
    enabled: true
`
	err = os.WriteFile(keysFile, []byte(updatedData), 0644)
	require.NoError(t, err, "failed to update file")

	// Reload keys
	err = provider.ReloadKeys(keysFile)
	require.NoError(t, err, "failed to reload keys")

	// Verify updated keys
	assert.NotNil(t, provider.keys[provider.digest("updated-key")], "expected updated-key to be present after reload")
	assert.NotNil(t, provider.keys[provider.digest("new-key")], "expected new-key to be present after reload")
}

func TestAPIKeyProvider_TimingAttackResistance(t *testing.T) {
	t.Parallel()

	// This test verifies that the implementation uses constant-time comparison
	// We can't directly measure timing, but we can verify the code path is used
	provider, err := NewAPIKeyProvider(APIKeyConfig{
		Header: "X-API-Key",
		Keys: map[string]*APIKeyEntry{
			"secret-key-with-long-value-to-test-timing": {
				Name:    "timing-test",
				Enabled: true,
			},
		},
	})
	require.NoError(t, err, "failed to create provider")

	// Test with correct key
	req1 := httptest.NewRequest("GET", "/test", nil)
	req1.Header.Set("X-API-Key", "secret-key-with-long-value-to-test-timing")
	p1, err1 := provider.Authenticate(context.Background(), req1)
	if err1 != nil || p1 == nil {
		assert.Fail(t, "expected successful authentication with correct key")
	}

	// Test with incorrect key of same length
	req2 := httptest.NewRequest("GET", "/test", nil)
	req2.Header.Set("X-API-Key", "wrong--key-with-long-value-to-test-timing")
	p2, err2 := provider.Authenticate(context.Background(), req2)
	if err2 == nil || p2 != nil {
		assert.Fail(t, "expected authentication to fail with wrong key")
	}

	// Test with incorrect key of different length
	req3 := httptest.NewRequest("GET", "/test", nil)
	req3.Header.Set("X-API-Key", "short")
	p3, err3 := provider.Authenticate(context.Background(), req3)
	if err3 == nil || p3 != nil {
		assert.Fail(t, "expected authentication to fail with short wrong key")
	}
}

func TestAPIKeyProvider_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	provider, err := NewAPIKeyProvider(APIKeyConfig{
		Header: "X-API-Key",
		Keys: map[string]*APIKeyEntry{
			"concurrent-key": {
				Name:    "concurrent",
				Enabled: true,
			},
		},
	})
	require.NoError(t, err, "failed to create provider")

	// Simulate concurrent authentication requests
	const numGoroutines = 100
	done := make(chan bool, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set("X-API-Key", "concurrent-key")
			_, err := provider.Authenticate(context.Background(), req)
			assert.NoError(t, err, "unexpected error in concurrent auth")
			done <- true
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		<-done
	}
}

func TestAPIKeyProvider_ConcurrentModification(t *testing.T) {
	t.Parallel()

	provider, err := NewAPIKeyProvider(APIKeyConfig{
		Header: "X-API-Key",
		Keys: map[string]*APIKeyEntry{
			"initial-key": {
				Name:    "initial",
				Enabled: true,
			},
		},
	})
	require.NoError(t, err, "failed to create provider")

	// Simulate concurrent reads and writes
	const numGoroutines = 50
	done := make(chan bool, numGoroutines*3)

	// Readers
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set("X-API-Key", "initial-key")
			provider.Authenticate(context.Background(), req)
			done <- true
		}(i)
	}

	// Writers - adding keys
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			provider.AddKey("key-"+string(rune('a'+id)), &APIKeyEntry{
				Name:    "service-" + string(rune('a'+id)),
				Enabled: true,
			})
			done <- true
		}(i)
	}

	// Writers - removing keys
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			provider.RemoveKey("key-" + string(rune('a'+id)))
			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines*3; i++ {
		<-done
	}

	// Verify the provider is still functional
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-API-Key", "initial-key")
	principal, err := provider.Authenticate(context.Background(), req)
	assert.NoError(t, err, "provider not functional after concurrent modifications")
	assert.NotNil(t, principal, "expected non-nil principal after concurrent modifications")
}

func TestAPIKeyProvider_EmptyConfiguration(t *testing.T) {
	t.Parallel()

	// Provider with no keys
	provider, err := NewAPIKeyProvider(APIKeyConfig{})
	require.NoError(t, err, "unexpected error creating provider with no keys")

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-API-Key", "any-key")

	principal, err := provider.Authenticate(context.Background(), req)
	assert.Error(t, err, "expected error when no keys are configured")
	assert.Nil(t, principal, "expected nil principal when no keys are configured")
}

func TestAPIKeyProvider_Integration(t *testing.T) {
	t.Parallel()

	// Create a realistic scenario with file-based keys
	tmpDir := t.TempDir()
	keysFile := filepath.Join(tmpDir, "production-keys.yaml")

	keysData := `keys:
  - key: "prod-admin-key-123"
    name: "production-admin"
    description: "Admin access for production"
    enabled: true
    roles:
      - admin
      - operator
    groups:
      - platform-team
      - on-call
    collections:
      - production-data
      - monitoring-data
  - key: "prod-readonly-key-456"
    name: "production-readonly"
    description: "Read-only access"
    enabled: true
    roles:
      - viewer
    groups:
      - analytics-team
    collections:
      - production-data
  - key: "disabled-key-789"
    name: "disabled-service"
    enabled: false
`
	err := os.WriteFile(keysFile, []byte(keysData), 0644)
	require.NoError(t, err, "failed to create keys file")

	provider, err := NewAPIKeyProvider(APIKeyConfig{
		Name:            "production-api-keys",
		Header:          "X-API-Key",
		QueryParam:      "api_key",
		AllowQueryParam: true,
		KeysFile:        keysFile,
		Keys: map[string]*APIKeyEntry{
			"direct-dev-key": {
				Name:        "development-service",
				Description: "Development environment key",
				Enabled:     true,
				Roles:       []string{"developer"},
				Groups:      []string{"dev-team"},
			},
		},
	})
	require.NoError(t, err, "failed to create provider")

	// Test admin key from header
	req1 := httptest.NewRequest("GET", "/api/collections", nil)
	req1.Header.Set("X-API-Key", "prod-admin-key-123")
	p1, err := provider.Authenticate(context.Background(), req1)
	require.NoError(t, err, "admin key authentication failed")
	assert.True(t, p1.HasRole("admin"), "admin key should have admin role")
	assert.True(t, p1.HasRole("operator"), "admin key should have operator role")
	assert.True(t, p1.CanAccessCollection("production-data"), "admin key should have access to production-data")

	// Test readonly key from query parameter
	req2 := httptest.NewRequest("GET", "/api/search?api_key=prod-readonly-key-456", nil)
	p2, err := provider.Authenticate(context.Background(), req2)
	require.NoError(t, err, "readonly key authentication failed")
	assert.True(t, p2.HasRole("viewer"), "readonly key should have viewer role")
	assert.False(t, p2.HasRole("admin"), "readonly key should not have admin role")

	// Test disabled key is rejected
	req3 := httptest.NewRequest("GET", "/api/test", nil)
	req3.Header.Set("X-API-Key", "disabled-key-789")
	_, err = provider.Authenticate(context.Background(), req3)
	assert.Error(t, err, "disabled key should be rejected")

	// Test direct config key
	req4 := httptest.NewRequest("GET", "/api/test", nil)
	req4.Header.Set("X-API-Key", "direct-dev-key")
	p4, err := provider.Authenticate(context.Background(), req4)
	require.NoError(t, err, "dev key authentication failed")
	assert.True(t, p4.HasRole("developer"), "dev key should have developer role")

	// Test provider name
	assert.Equal(t, "production-api-keys", provider.Name(), "name")
}

// BenchmarkAuthenticate_1Key measures Authenticate cost with a single key.
func BenchmarkAuthenticate_1Key(b *testing.B) { benchmarkAuthenticateN(b, 1) }

// BenchmarkAuthenticate_100Keys measures Authenticate cost with 100 keys.
func BenchmarkAuthenticate_100Keys(b *testing.B) { benchmarkAuthenticateN(b, 100) }

// BenchmarkAuthenticate_10kKeys measures Authenticate cost with 10,000 keys.
func BenchmarkAuthenticate_10kKeys(b *testing.B) { benchmarkAuthenticateN(b, 10000) }

// benchmarkAuthenticateN builds a provider with n enabled keys and benchmarks
// Authenticate using the LAST key (worst case for the old linear scan; should
// be indistinguishable from any other key under the O(1) map lookup).
func benchmarkAuthenticateN(b *testing.B, n int) {
	keys := make(map[string]*APIKeyEntry, n)
	var lastKey string
	for i := 0; i < n; i++ {
		k := fmt.Sprintf("bench-key-%08d", i)
		keys[k] = &APIKeyEntry{
			Name:    fmt.Sprintf("svc-%d", i),
			Enabled: true,
		}
		lastKey = k
	}

	provider, err := NewAPIKeyProvider(APIKeyConfig{
		Header: "X-API-Key",
		Keys:   keys,
	})
	if err != nil {
		b.Fatalf("failed to create provider: %v", err)
	}

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-API-Key", lastKey)
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p, err := provider.Authenticate(ctx, req)
		if err != nil || p == nil {
			b.Fatalf("authenticate failed: p=%v err=%v", p, err)
		}
	}
}

// TestAPIKey_StorageDoesNotContainPlaintextKey verifies the
// HMAC-hashed-storage contract (HIGH H-auth-3): the in-memory key map
// must never contain the plaintext API key as either a key or a value.
// This is defense in depth — a memory dump or accidental log of the
// internal map yields opaque digests instead of valid credentials.
func TestAPIKey_StorageDoesNotContainPlaintextKey(t *testing.T) {
	t.Parallel()

	const plaintext = "my-secret-key"
	provider, err := NewAPIKeyProvider(APIKeyConfig{
		Header:     "X-API-Key",
		HMACSecret: []byte("test-deployment-secret"),
		Keys: map[string]*APIKeyEntry{
			plaintext: {
				Name:    "test-svc",
				Enabled: true,
			},
		},
	})
	require.NoError(t, err, "NewAPIKeyProvider")

	for k, entry := range provider.keys {
		require.NotEqual(t, plaintext, k, "internal map key contains plaintext API key %q", plaintext)
		require.NotEqual(t, plaintext, entry.Key, "internal entry.Key contains plaintext API key %q", plaintext)
	}

	// Sanity: the digest IS present (storage is keyed by HMAC).
	require.NotNil(t, provider.keys[provider.digest(plaintext)], "expected key to be stored under its HMAC digest")
}

// TestAPIKey_AcceptsCorrectKey is a focused regression test for the
// HMAC scheme: a configured plaintext key authenticates correctly
// after the storage migration to digests.
func TestAPIKey_AcceptsCorrectKey(t *testing.T) {
	t.Parallel()
	provider, err := NewAPIKeyProvider(APIKeyConfig{
		Header:     "X-API-Key",
		HMACSecret: []byte("deployment-secret"),
		Keys: map[string]*APIKeyEntry{
			"good-key": {Name: "svc", Enabled: true},
		},
	})
	require.NoError(t, err, "NewAPIKeyProvider")
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-API-Key", "good-key")
	princ, err := provider.Authenticate(context.Background(), req)
	require.NoError(t, err, "authenticate")
	require.NotNil(t, princ, "want principal name=svc")
	require.Equal(t, "svc", princ.Name, "want principal name=svc")
}

// TestAPIKey_RejectsWrongKey ensures a key not in the registry is
// rejected post-HMAC (and that the digest comparison does not
// accidentally collide).
func TestAPIKey_RejectsWrongKey(t *testing.T) {
	t.Parallel()
	provider, err := NewAPIKeyProvider(APIKeyConfig{
		Header:     "X-API-Key",
		HMACSecret: []byte("deployment-secret"),
		Keys: map[string]*APIKeyEntry{
			"good-key": {Name: "svc", Enabled: true},
		},
	})
	require.NoError(t, err, "NewAPIKeyProvider")
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-API-Key", "wrong-key")
	princ, err := provider.Authenticate(context.Background(), req)
	require.Error(t, err, "want error for wrong key")
	require.Nil(t, princ, "want nil principal")
}

// TestAPIKey_QueryParam_DisabledByDefault verifies that query-param
// authentication is gated behind the explicit AllowQueryParam opt-in
// (M-auth-5). With the default config a request that places the key in
// the URL gets no principal and no auth-chain hard-fail.
func TestAPIKey_QueryParam_DisabledByDefault(t *testing.T) {
	t.Parallel()

	provider, err := NewAPIKeyProvider(APIKeyConfig{
		QueryParam: "api_key",
		Keys: map[string]*APIKeyEntry{
			"q-key": {Name: "svc", Enabled: true},
		},
	})
	require.NoError(t, err, "NewAPIKeyProvider")

	req := httptest.NewRequest("GET", "/x?api_key=q-key", nil)
	princ, err := provider.Authenticate(context.Background(), req)
	require.NoError(t, err, "expected nil error when query-param auth is disabled")
	require.Nil(t, princ, "expected nil principal when query-param auth is disabled")

	// The chain must NOT treat query-only credentials as a presented
	// credential when query-param is disabled — otherwise an
	// invalid-key fall-through becomes a hard 401 against an opt-in
	// the operator declined.
	require.False(t, provider.ClaimsCredential(req), "ClaimsCredential should ignore the query parameter when disabled")
}

// TestAPIKey_QueryParam_WarnsWhenEnabled captures slog output and
// asserts the construction-time WARN fires when AllowQueryParam=true.
func TestAPIKey_QueryParam_WarnsWhenEnabled(t *testing.T) {
	t.Parallel()

	var buf apikeyLogBuffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	_, err := NewAPIKeyProvider(APIKeyConfig{
		Name:            "test",
		QueryParam:      "api_key",
		AllowQueryParam: true,
		Logger:          logger,
		Keys: map[string]*APIKeyEntry{
			"q-key": {Name: "svc", Enabled: true},
		},
	})
	require.NoError(t, err, "NewAPIKeyProvider")

	out := buf.String()
	assert.Contains(t, out, `"level":"WARN"`, "expected WARN-level log")
	assert.Contains(t, out, `"query_param":"api_key"`, "expected query_param attribute in warning")
	assert.Contains(t, out, "query-param authentication enabled", "expected security-implication wording in warning")
}

// TestAPIKey_QueryParam_AuthEmitsRateLimitedWarn covers the per-auth
// rate-limited warning path: every successful query-param login bumps
// the warning, but at most once per minute.
func TestAPIKey_QueryParam_AuthEmitsRateLimitedWarn(t *testing.T) {
	t.Parallel()

	var buf apikeyLogBuffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	provider, err := NewAPIKeyProvider(APIKeyConfig{
		Name:            "test",
		QueryParam:      "api_key",
		AllowQueryParam: true,
		Logger:          logger,
		Keys: map[string]*APIKeyEntry{
			"q-key": {Name: "svc", Enabled: true},
		},
	})
	require.NoError(t, err, "NewAPIKeyProvider")
	// Pin the clock so the rate-limit window is deterministic.
	now := time.Now()
	provider.now = func() time.Time { return now }

	// Drop the construction warning from the buffer for a focused
	// assertion below.
	buf.Reset()

	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("GET", "/x?api_key=q-key", nil)
		_, err := provider.Authenticate(context.Background(), req)
		require.NoError(t, err, "authenticate %d", i)
	}
	out1 := buf.String()
	warnCount := apiKeyCount(out1, "authenticated via query parameter")
	require.Equal(t, 1, warnCount, "expected exactly 1 query-auth warning across 5 requests in the same minute, got %d\n%s", warnCount, out1)

	// Advance past the window — the next request should warn again.
	now = now.Add(2 * time.Minute)
	req := httptest.NewRequest("GET", "/x?api_key=q-key", nil)
	_, err = provider.Authenticate(context.Background(), req)
	require.NoError(t, err, "authenticate after window")
	got := apiKeyCount(buf.String(), "authenticated via query parameter")
	require.Equal(t, 2, got, "expected 2 warnings across two windows, got %d", got)
}

// apikeyLogBuffer is a tiny io.Writer for collecting slog JSON output.
type apikeyLogBuffer struct {
	mu  sync.Mutex
	buf []byte
}

func (b *apikeyLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	b.buf = append(b.buf, p...)
	b.mu.Unlock()
	return len(p), nil
}

func (b *apikeyLogBuffer) Reset() {
	b.mu.Lock()
	b.buf = nil
	b.mu.Unlock()
}

func (b *apikeyLogBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(b.buf)
}

func apiKeyCount(s, sub string) int {
	if sub == "" {
		return 0
	}
	n := 0
	for i := 0; i+len(sub) <= len(s); {
		if s[i:i+len(sub)] == sub {
			n++
			i += len(sub)
			continue
		}
		i++
	}
	return n
}
