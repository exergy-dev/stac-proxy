package auth

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
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
				if p.name != "test-apikey" {
					t.Errorf("expected name=test-apikey, got %s", p.name)
				}
				if p.header != "X-API-Key" {
					t.Errorf("expected header=X-API-Key, got %s", p.header)
				}
				if len(p.keys) != 1 {
					t.Errorf("expected 1 key, got %d", len(p.keys))
				}
				if p.keys[p.digest("key123")] == nil {
					t.Error("expected key123 to be present")
				}
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
				if p.name != "api_key" {
					t.Errorf("expected default name=api_key, got %s", p.name)
				}
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
				if p.header != "X-API-Key" {
					t.Errorf("expected default header=X-API-Key, got %s", p.header)
				}
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
				if p.header != "" {
					t.Errorf("expected empty header, got %s", p.header)
				}
				if p.queryParam != "api_key" {
					t.Errorf("expected queryParam=api_key, got %s", p.queryParam)
				}
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
				if p.header != "Authorization" {
					t.Errorf("expected header=Authorization, got %s", p.header)
				}
				if p.queryParam != "token" {
					t.Errorf("expected queryParam=token, got %s", p.queryParam)
				}
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
				if len(p.keys) != 1 {
					t.Errorf("expected 1 enabled key, got %d", len(p.keys))
				}
				if p.keys[p.digest("enabled-key")] == nil {
					t.Error("expected enabled-key to be present")
				}
				if p.keys[p.digest("disabled-key")] != nil {
					t.Error("expected disabled-key to be absent")
				}
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
				if len(p.keys) != 3 {
					t.Errorf("expected 3 keys, got %d", len(p.keys))
				}
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
				if key == nil {
					t.Fatal("expected full-key to be present")
				}
				if key.Name != "full" {
					t.Errorf("expected name=full, got %s", key.Name)
				}
				if key.Description != "Full featured key" {
					t.Errorf("expected description, got %s", key.Description)
				}
				if len(key.Roles) != 2 {
					t.Errorf("expected 2 roles, got %d", len(key.Roles))
				}
				if len(key.Groups) != 2 {
					t.Errorf("expected 2 groups, got %d", len(key.Groups))
				}
				if len(key.Collections) != 2 {
					t.Errorf("expected 2 collections, got %d", len(key.Collections))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			provider, err := NewAPIKeyProvider(tt.config)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

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
				if len(p.keys) != 2 {
					t.Errorf("expected 2 keys from file, got %d", len(p.keys))
				}
				if p.keys[p.digest("file-key-1")] == nil {
					t.Error("expected file-key-1 to be present")
				}
				if p.keys[p.digest("file-key-2")] == nil {
					t.Error("expected file-key-2 to be present")
				}
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
				if len(p.keys) != 1 {
					t.Errorf("expected 1 key, got %d", len(p.keys))
				}
				if p.keys[p.digest("enabled-key")] == nil {
					t.Error("expected enabled-key to be present")
				}
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
				if len(p.keys) != 1 {
					t.Errorf("expected 1 key, got %d", len(p.keys))
				}
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
				if err := os.WriteFile(keysFile, []byte(tt.fileData), 0644); err != nil {
					t.Fatalf("failed to create test file: %v", err)
				}
			} else {
				keysFile = filepath.Join(tmpDir, "nonexistent.yaml")
			}

			tt.config.KeysFile = keysFile
			provider, err := NewAPIKeyProvider(tt.config)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errContains != "" && !apiKeyContains(err.Error(), tt.errContains) {
					t.Errorf("expected error containing %q, got %q", tt.errContains, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

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
	if err := os.WriteFile(keysFile, []byte(fileData), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

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

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(provider.keys) != 2 {
		t.Errorf("expected 2 keys (file + direct), got %d", len(provider.keys))
	}

	if provider.keys[provider.digest("file-key")] == nil {
		t.Error("expected file-key to be present")
	}

	if provider.keys[provider.digest("direct-key")] == nil {
		t.Error("expected direct-key to be present")
	}
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
			if err != nil {
				t.Fatalf("failed to create provider: %v", err)
			}

			if provider.Name() != tt.expected {
				t.Errorf("expected Name()=%s, got %s", tt.expected, provider.Name())
			}
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
				if p == nil {
					t.Fatal("expected non-nil principal")
				}
				if p.ID != "apikey:test-service" {
					t.Errorf("expected ID=apikey:test-service, got %s", p.ID)
				}
				if p.Type != "service" {
					t.Errorf("expected Type=service, got %s", p.Type)
				}
				if p.Name != "test-service" {
					t.Errorf("expected Name=test-service, got %s", p.Name)
				}
				if len(p.Roles) != 2 {
					t.Errorf("expected 2 roles, got %d", len(p.Roles))
				}
				if !p.HasRole("admin") {
					t.Error("expected admin role")
				}
				if !p.HasRole("user") {
					t.Error("expected user role")
				}
				if len(p.Groups) != 1 {
					t.Errorf("expected 1 group, got %d", len(p.Groups))
				}
				if !p.HasGroup("engineering") {
					t.Error("expected engineering group")
				}
				if p.Attributes == nil {
					t.Fatal("expected attributes to be set")
				}
				if p.Attributes["auth_method"] != "api_key" {
					t.Errorf("expected auth_method=api_key, got %s", p.Attributes["auth_method"])
				}
				if p.Attributes["key_name"] != "test-service" {
					t.Errorf("expected key_name=test-service, got %s", p.Attributes["key_name"])
				}
			},
		},
		{
			name: "valid API key from query parameter",
			config: APIKeyConfig{
				QueryParam: "api_key",
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
				if p == nil {
					t.Fatal("expected non-nil principal")
				}
				if p.Name != "query-service" {
					t.Errorf("expected Name=query-service, got %s", p.Name)
				}
			},
		},
		{
			name: "header takes precedence over query parameter",
			config: APIKeyConfig{
				Header:     "X-API-Key",
				QueryParam: "api_key",
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
				if p.Name != "header-service" {
					t.Errorf("expected header to take precedence, got %s", p.Name)
				}
			},
		},
		{
			name: "fallback to query parameter when header is empty",
			config: APIKeyConfig{
				Header:     "X-API-Key",
				QueryParam: "api_key",
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
				if p.Name != "query-service" {
					t.Errorf("expected query parameter to be used, got %s", p.Name)
				}
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
				if len(p.Collections) != 2 {
					t.Errorf("expected 2 collections, got %d", len(p.Collections))
				}
				if !p.CanAccessCollection("collection1") {
					t.Error("expected access to collection1")
				}
				if !p.CanAccessCollection("collection2") {
					t.Error("expected access to collection2")
				}
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
				if p.Name != "service2" {
					t.Errorf("expected service2, got %s", p.Name)
				}
				if !p.HasRole("role2") {
					t.Error("expected role2")
				}
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
				if len(p.Roles) != 3 {
					t.Errorf("expected 3 roles, got %d", len(p.Roles))
				}
				if len(p.Groups) != 3 {
					t.Errorf("expected 3 groups, got %d", len(p.Groups))
				}
				if len(p.Collections) != 2 {
					t.Errorf("expected 2 collections, got %d", len(p.Collections))
				}
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
				if p.Name != "auth-service" {
					t.Errorf("expected auth-service, got %s", p.Name)
				}
			},
		},
		{
			name: "custom query parameter name",
			config: APIKeyConfig{
				QueryParam: "token",
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
				if p.Name != "token-service" {
					t.Errorf("expected token-service, got %s", p.Name)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			provider, err := NewAPIKeyProvider(tt.config)
			if err != nil {
				t.Fatalf("failed to create provider: %v", err)
			}

			req := tt.setupReq()
			ctx := context.Background()

			principal, err := provider.Authenticate(ctx, req)

			if tt.wantNil {
				if principal != nil {
					t.Errorf("expected nil principal, got %+v", principal)
				}
				if err != nil {
					t.Errorf("expected nil error for non-applicable auth, got %v", err)
				}
				return
			}

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errContains != "" {
					if !apiKeyContains(err.Error(), tt.errContains) {
						t.Errorf("expected error containing %q, got %q", tt.errContains, err.Error())
					}
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

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
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	// Add a new key
	provider.AddKey("new-key", &APIKeyEntry{
		Name:    "new-service",
		Enabled: true,
		Roles:   []string{"admin"},
	})

	// Verify the key was added (looked up by HMAC digest, not plaintext)
	if provider.keys[provider.digest("new-key")] == nil {
		t.Error("expected new-key to be present")
	}

	if provider.keys[provider.digest("new-key")].Name != "new-service" {
		t.Errorf("expected Name=new-service, got %s", provider.keys[provider.digest("new-key")].Name)
	}

	// Plaintext is intentionally cleared from the entry after storage
	// so the in-memory registry never contains plaintext credentials
	// (defense in depth against memory disclosure / accidental logging).
	if got := provider.keys[provider.digest("new-key")].Key; got != "" {
		t.Errorf("expected stored Key field to be empty (plaintext stripped), got %q", got)
	}

	// Verify it can be used for authentication
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-API-Key", "new-key")
	principal, err := provider.Authenticate(context.Background(), req)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if principal.Name != "new-service" {
		t.Errorf("expected principal name=new-service, got %s", principal.Name)
	}
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
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	// Remove the key
	provider.RemoveKey("key-to-remove")

	// Verify the key was removed
	if provider.keys[provider.digest("key-to-remove")] != nil {
		t.Error("expected key-to-remove to be absent")
	}

	// Verify the other key is still present
	if provider.keys[provider.digest("key-to-keep")] == nil {
		t.Error("expected key-to-keep to still be present")
	}

	// Verify removed key cannot be used for authentication
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-API-Key", "key-to-remove")
	_, err = provider.Authenticate(context.Background(), req)

	if err == nil {
		t.Error("expected error when using removed key")
	}
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
	if err := os.WriteFile(keysFile, []byte(initialData), 0644); err != nil {
		t.Fatalf("failed to create initial file: %v", err)
	}

	provider, err := NewAPIKeyProvider(APIKeyConfig{
		KeysFile: keysFile,
	})
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	// Verify initial key
	if provider.keys[provider.digest("initial-key")] == nil {
		t.Error("expected initial-key to be present")
	}

	// Update the file
	updatedData := `keys:
  - key: "updated-key"
    name: "updated"
    enabled: true
  - key: "new-key"
    name: "new"
    enabled: true
`
	if err := os.WriteFile(keysFile, []byte(updatedData), 0644); err != nil {
		t.Fatalf("failed to update file: %v", err)
	}

	// Reload keys
	if err := provider.ReloadKeys(keysFile); err != nil {
		t.Fatalf("failed to reload keys: %v", err)
	}

	// Verify updated keys
	if provider.keys[provider.digest("updated-key")] == nil {
		t.Error("expected updated-key to be present after reload")
	}
	if provider.keys[provider.digest("new-key")] == nil {
		t.Error("expected new-key to be present after reload")
	}
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
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	// Test with correct key
	req1 := httptest.NewRequest("GET", "/test", nil)
	req1.Header.Set("X-API-Key", "secret-key-with-long-value-to-test-timing")
	p1, err1 := provider.Authenticate(context.Background(), req1)
	if err1 != nil || p1 == nil {
		t.Error("expected successful authentication with correct key")
	}

	// Test with incorrect key of same length
	req2 := httptest.NewRequest("GET", "/test", nil)
	req2.Header.Set("X-API-Key", "wrong--key-with-long-value-to-test-timing")
	p2, err2 := provider.Authenticate(context.Background(), req2)
	if err2 == nil || p2 != nil {
		t.Error("expected authentication to fail with wrong key")
	}

	// Test with incorrect key of different length
	req3 := httptest.NewRequest("GET", "/test", nil)
	req3.Header.Set("X-API-Key", "short")
	p3, err3 := provider.Authenticate(context.Background(), req3)
	if err3 == nil || p3 != nil {
		t.Error("expected authentication to fail with short wrong key")
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
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	// Simulate concurrent authentication requests
	const numGoroutines = 100
	done := make(chan bool, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set("X-API-Key", "concurrent-key")
			_, err := provider.Authenticate(context.Background(), req)
			if err != nil {
				t.Errorf("unexpected error in concurrent auth: %v", err)
			}
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
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

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
	if err != nil {
		t.Errorf("provider not functional after concurrent modifications: %v", err)
	}
	if principal == nil {
		t.Error("expected non-nil principal after concurrent modifications")
	}
}

func TestAPIKeyProvider_EmptyConfiguration(t *testing.T) {
	t.Parallel()

	// Provider with no keys
	provider, err := NewAPIKeyProvider(APIKeyConfig{})
	if err != nil {
		t.Fatalf("unexpected error creating provider with no keys: %v", err)
	}

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-API-Key", "any-key")

	principal, err := provider.Authenticate(context.Background(), req)
	if err == nil {
		t.Error("expected error when no keys are configured")
	}
	if principal != nil {
		t.Error("expected nil principal when no keys are configured")
	}
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
	if err := os.WriteFile(keysFile, []byte(keysData), 0644); err != nil {
		t.Fatalf("failed to create keys file: %v", err)
	}

	provider, err := NewAPIKeyProvider(APIKeyConfig{
		Name:       "production-api-keys",
		Header:     "X-API-Key",
		QueryParam: "api_key",
		KeysFile:   keysFile,
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
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	// Test admin key from header
	req1 := httptest.NewRequest("GET", "/api/collections", nil)
	req1.Header.Set("X-API-Key", "prod-admin-key-123")
	p1, err := provider.Authenticate(context.Background(), req1)
	if err != nil {
		t.Fatalf("admin key authentication failed: %v", err)
	}
	if !p1.HasRole("admin") || !p1.HasRole("operator") {
		t.Error("admin key should have admin and operator roles")
	}
	if !p1.CanAccessCollection("production-data") {
		t.Error("admin key should have access to production-data")
	}

	// Test readonly key from query parameter
	req2 := httptest.NewRequest("GET", "/api/search?api_key=prod-readonly-key-456", nil)
	p2, err := provider.Authenticate(context.Background(), req2)
	if err != nil {
		t.Fatalf("readonly key authentication failed: %v", err)
	}
	if !p2.HasRole("viewer") {
		t.Error("readonly key should have viewer role")
	}
	if p2.HasRole("admin") {
		t.Error("readonly key should not have admin role")
	}

	// Test disabled key is rejected
	req3 := httptest.NewRequest("GET", "/api/test", nil)
	req3.Header.Set("X-API-Key", "disabled-key-789")
	_, err = provider.Authenticate(context.Background(), req3)
	if err == nil {
		t.Error("disabled key should be rejected")
	}

	// Test direct config key
	req4 := httptest.NewRequest("GET", "/api/test", nil)
	req4.Header.Set("X-API-Key", "direct-dev-key")
	p4, err := provider.Authenticate(context.Background(), req4)
	if err != nil {
		t.Fatalf("dev key authentication failed: %v", err)
	}
	if !p4.HasRole("developer") {
		t.Error("dev key should have developer role")
	}

	// Test provider name
	if provider.Name() != "production-api-keys" {
		t.Errorf("expected name=production-api-keys, got %s", provider.Name())
	}
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
	if err != nil {
		t.Fatalf("NewAPIKeyProvider: %v", err)
	}

	for k, entry := range provider.keys {
		if k == plaintext {
			t.Fatalf("internal map key contains plaintext API key %q", plaintext)
		}
		if entry.Key == plaintext {
			t.Fatalf("internal entry.Key contains plaintext API key %q", plaintext)
		}
	}

	// Sanity: the digest IS present (storage is keyed by HMAC).
	if provider.keys[provider.digest(plaintext)] == nil {
		t.Fatal("expected key to be stored under its HMAC digest")
	}
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
	if err != nil {
		t.Fatalf("NewAPIKeyProvider: %v", err)
	}
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-API-Key", "good-key")
	princ, err := provider.Authenticate(context.Background(), req)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if princ == nil || princ.Name != "svc" {
		t.Fatalf("want principal name=svc, got %+v", princ)
	}
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
	if err != nil {
		t.Fatalf("NewAPIKeyProvider: %v", err)
	}
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-API-Key", "wrong-key")
	princ, err := provider.Authenticate(context.Background(), req)
	if err == nil {
		t.Fatal("want error for wrong key")
	}
	if princ != nil {
		t.Fatalf("want nil principal, got %+v", princ)
	}
}

// apiKeyContains checks if s contains substr
func apiKeyContains(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	if len(s) < len(substr) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
