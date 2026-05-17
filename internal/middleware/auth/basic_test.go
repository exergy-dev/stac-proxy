package auth

import (
	"context"
	"encoding/base64"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

// TestBasicAuth_BcryptPrefixSkipsBase64 verifies that a bcrypt-formatted
// PasswordHash (which starts with $2a$/$2b$/$2y$) is stored verbatim and
// is *not* fed through base64.StdEncoding.DecodeString. A bcrypt hash
// can happen to be valid base64; the previous silent-fallback decoded
// it into garbage and corrupted the credential.
func TestBasicAuth_BcryptPrefixSkipsBase64(t *testing.T) {
	t.Parallel()

	const password = "correct-horse-battery-staple"
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	require.NoError(t, err, "bcrypt")
	hashStr := string(hashed)
	require.True(t, strings.HasPrefix(hashStr, "$2"), "sanity: expected bcrypt prefix on %q", hashStr)

	provider, err := NewBasicAuthProvider(BasicAuthConfig{
		Name: "basic",
		Users: []BasicUser{{
			Username:     "alice",
			PasswordHash: hashStr,
			Roles:        []string{"reader"},
		}},
	})
	require.NoError(t, err, "NewBasicAuthProvider")

	user, ok := provider.users["alice"]
	require.True(t, ok, "user alice not stored")
	require.Equal(t, hashStr, string(user.passwordHash), "expected stored hash to match input verbatim")

	// And the credential authenticates.
	req := httptest.NewRequest("GET", "/", nil)
	credential := base64.StdEncoding.EncodeToString([]byte("alice:" + password))
	req.Header.Set("Authorization", "Basic "+credential)
	princ, err := provider.Authenticate(context.Background(), req)
	require.NoError(t, err, "authenticate")
	require.NotNil(t, princ, "want principal alice")
	require.Equal(t, "alice", princ.ID, "want principal alice")
}

// TestBasicAuth_Base64FallbackPreserved exercises the legacy path: a
// PasswordHash that is *not* bcrypt-prefixed but IS valid base64 is
// still decoded for backward compatibility with operators who wrapped
// the bcrypt bytes themselves.
func TestBasicAuth_Base64FallbackPreserved(t *testing.T) {
	t.Parallel()

	const password = "password"
	rawHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	require.NoError(t, err, "bcrypt")
	// Pre-base64-encode the bcrypt bytes — this is the historical
	// configuration shape we still support.
	wrapped := base64.StdEncoding.EncodeToString(rawHash)
	require.False(t, strings.HasPrefix(wrapped, "$2"), "base64 output unexpectedly starts with bcrypt prefix: %s", wrapped)

	provider, err := NewBasicAuthProvider(BasicAuthConfig{
		Name: "basic",
		Users: []BasicUser{{
			Username:     "bob",
			PasswordHash: wrapped,
		}},
	})
	require.NoError(t, err, "NewBasicAuthProvider")

	got := provider.users["bob"].passwordHash
	require.Equal(t, string(rawHash), string(got), "expected base64-wrapped hash to be decoded back to raw bcrypt bytes")

	req := httptest.NewRequest("GET", "/", nil)
	cred := base64.StdEncoding.EncodeToString([]byte("bob:" + password))
	req.Header.Set("Authorization", "Basic "+cred)
	_, err = provider.Authenticate(context.Background(), req)
	require.NoError(t, err, "authenticate")
}
