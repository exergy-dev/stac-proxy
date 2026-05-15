package auth

import (
	"context"
	"encoding/base64"
	"net/http/httptest"
	"strings"
	"testing"

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
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	hashStr := string(hashed)
	if !strings.HasPrefix(hashStr, "$2") {
		t.Fatalf("sanity: expected bcrypt prefix on %q", hashStr)
	}

	provider, err := NewBasicAuthProvider(BasicAuthConfig{
		Name: "basic",
		Users: []BasicUser{{
			Username:     "alice",
			PasswordHash: hashStr,
			Roles:        []string{"reader"},
		}},
	})
	if err != nil {
		t.Fatalf("NewBasicAuthProvider: %v", err)
	}

	user, ok := provider.users["alice"]
	if !ok {
		t.Fatal("user alice not stored")
	}
	if string(user.passwordHash) != hashStr {
		t.Fatalf("expected stored hash to match input verbatim;\n want: %s\n got:  %s",
			hashStr, string(user.passwordHash))
	}

	// And the credential authenticates.
	req := httptest.NewRequest("GET", "/", nil)
	credential := base64.StdEncoding.EncodeToString([]byte("alice:" + password))
	req.Header.Set("Authorization", "Basic "+credential)
	princ, err := provider.Authenticate(context.Background(), req)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if princ == nil || princ.ID != "alice" {
		t.Fatalf("want principal alice, got %+v", princ)
	}
}

// TestBasicAuth_Base64FallbackPreserved exercises the legacy path: a
// PasswordHash that is *not* bcrypt-prefixed but IS valid base64 is
// still decoded for backward compatibility with operators who wrapped
// the bcrypt bytes themselves.
func TestBasicAuth_Base64FallbackPreserved(t *testing.T) {
	t.Parallel()

	const password = "password"
	rawHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	// Pre-base64-encode the bcrypt bytes — this is the historical
	// configuration shape we still support.
	wrapped := base64.StdEncoding.EncodeToString(rawHash)
	if strings.HasPrefix(wrapped, "$2") {
		t.Fatalf("base64 output unexpectedly starts with bcrypt prefix: %s", wrapped)
	}

	provider, err := NewBasicAuthProvider(BasicAuthConfig{
		Name: "basic",
		Users: []BasicUser{{
			Username:     "bob",
			PasswordHash: wrapped,
		}},
	})
	if err != nil {
		t.Fatalf("NewBasicAuthProvider: %v", err)
	}

	got := provider.users["bob"].passwordHash
	if string(got) != string(rawHash) {
		t.Fatalf("expected base64-wrapped hash to be decoded back to raw bcrypt bytes")
	}

	req := httptest.NewRequest("GET", "/", nil)
	cred := base64.StdEncoding.EncodeToString([]byte("bob:" + password))
	req.Header.Set("Authorization", "Basic "+cred)
	if _, err := provider.Authenticate(context.Background(), req); err != nil {
		t.Fatalf("authenticate: %v", err)
	}
}
