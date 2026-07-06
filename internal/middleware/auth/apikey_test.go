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
