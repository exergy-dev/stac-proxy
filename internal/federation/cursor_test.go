package federation

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

var testCursorSecret = []byte("test-cursor-secret-32-bytes-long!")

func testAllowed(origins ...string) map[string]string {
	m := make(map[string]string, len(origins))
	for _, id := range origins {
		m[id] = "https://" + id + ".example.com"
	}
	return m
}

// TestNewFederatedCursor tests cursor creation
func TestNewFederatedCursor(t *testing.T) {
	t.Run("with default config", func(t *testing.T) {
		t.Parallel()

		queryHash := "test-query-hash"
		originIDs := []string{"origin1", "origin2", "origin3"}

		cursor := NewFederatedCursor(queryHash, "principal-hash", originIDs, nil)

		if cursor == nil {
			t.Fatal("expected cursor to be non-nil")
		}

		if cursor.Version != 1 {
			t.Errorf("expected version 1, got %d", cursor.Version)
		}

		if cursor.QueryHash != queryHash {
			t.Errorf("expected query hash %q, got %q", queryHash, cursor.QueryHash)
		}

		if cursor.PrincipalHash != "principal-hash" {
			t.Errorf("expected principal hash 'principal-hash', got %q", cursor.PrincipalHash)
		}

		if len(cursor.Origins) != len(originIDs) {
			t.Errorf("expected %d origins, got %d", len(originIDs), len(cursor.Origins))
		}

		for _, id := range originIDs {
			origin, ok := cursor.Origins[id]
			if !ok {
				t.Errorf("expected origin %q to exist", id)
				continue
			}
			if origin.ID != id {
				t.Errorf("expected origin ID %q, got %q", id, origin.ID)
			}
		}

		if cursor.CreatedAt == 0 {
			t.Error("expected created at to be set")
		}

		expectedExpiry := cursor.CreatedAt + int64(time.Hour.Seconds())
		if cursor.ExpiresAt != expectedExpiry {
			t.Errorf("expected expiry at %d, got %d", expectedExpiry, cursor.ExpiresAt)
		}
	})

	t.Run("with custom config", func(t *testing.T) {
		t.Parallel()

		cfg := &CursorConfig{DefaultTTL: 30 * time.Minute}
		cursor := NewFederatedCursor("hash", "", []string{"origin1"}, cfg)

		expectedExpiry := cursor.CreatedAt + int64((30 * time.Minute).Seconds())
		if cursor.ExpiresAt != expectedExpiry {
			t.Errorf("expected expiry at %d, got %d", expectedExpiry, cursor.ExpiresAt)
		}
	})

	t.Run("with nil origin list", func(t *testing.T) {
		t.Parallel()

		cursor := NewFederatedCursor("hash", "", nil, nil)
		if cursor.Origins == nil {
			t.Error("expected origins map to be initialized")
		}
		if len(cursor.Origins) != 0 {
			t.Errorf("expected 0 origins, got %d", len(cursor.Origins))
		}
	})
}

// TestCursor_RoundTripSigned verifies happy-path encode + decode with
// HMAC signing, including principal binding and the NextURL allowlist.
func TestCursor_RoundTripSigned(t *testing.T) {
	t.Parallel()

	cursor := NewFederatedCursor("query-hash", "abc123", []string{"origin1", "origin2"}, nil)
	cursor.Origins["origin1"].NextURL = "https://origin1.example.com/search?page=2"
	cursor.Origins["origin1"].ItemCount = 10
	cursor.Origins["origin2"].NextToken = "tok"
	cursor.TotalReturned = 10

	encoded, err := cursor.Encode(testCursorSecret)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}
	if !strings.Contains(encoded, ".") {
		t.Fatalf("encoded token must contain '.' separator: %q", encoded)
	}

	decoded, err := DecodeCursor(encoded, testCursorSecret, testAllowed("origin1", "origin2"), "abc123")
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	if decoded.QueryHash != cursor.QueryHash {
		t.Errorf("query hash mismatch: %q vs %q", decoded.QueryHash, cursor.QueryHash)
	}
	if decoded.PrincipalHash != cursor.PrincipalHash {
		t.Errorf("principal hash mismatch: %q vs %q", decoded.PrincipalHash, cursor.PrincipalHash)
	}
	if decoded.Origins["origin1"].NextURL != cursor.Origins["origin1"].NextURL {
		t.Errorf("origin1 NextURL mismatch")
	}
	if decoded.Origins["origin2"].NextToken != "tok" {
		t.Errorf("origin2 NextToken mismatch")
	}
}

// TestCursor_EmptySecretEncodeRejected verifies that Encode requires a secret.
func TestCursor_EmptySecretEncodeRejected(t *testing.T) {
	t.Parallel()

	cursor := NewFederatedCursor("h", "", []string{"o1"}, nil)
	if _, err := cursor.Encode(nil); err == nil {
		t.Error("expected error for nil secret")
	}
	if _, err := cursor.Encode([]byte{}); err == nil {
		t.Error("expected error for empty secret")
	}
}

// TestCursor_EmptySecretDecodeRejected verifies that DecodeCursor requires a secret.
func TestCursor_EmptySecretDecodeRejected(t *testing.T) {
	t.Parallel()

	cursor := NewFederatedCursor("h", "", []string{"o1"}, nil)
	encoded, err := cursor.Encode(testCursorSecret)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}
	if _, err := DecodeCursor(encoded, nil, testAllowed("o1"), ""); err == nil {
		t.Error("expected error for nil secret on decode")
	}
	if _, err := DecodeCursor(encoded, []byte{}, testAllowed("o1"), ""); err == nil {
		t.Error("expected error for empty secret on decode")
	}
}

// TestCursor_TamperedPayloadRejected verifies HMAC catches payload mutation.
func TestCursor_TamperedPayloadRejected(t *testing.T) {
	t.Parallel()

	cursor := NewFederatedCursor("h", "", []string{"o1"}, nil)
	encoded, err := cursor.Encode(testCursorSecret)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}

	parts := strings.SplitN(encoded, ".", 2)
	if len(parts) != 2 {
		t.Fatal("expected two parts")
	}
	// Flip one byte of the payload section deterministically.
	mutated := []byte(parts[0])
	for i := 0; i < len(mutated); i++ {
		// Find a base64url character we can swap to a different valid one.
		if mutated[i] != 'A' {
			mutated[i] = 'A'
			break
		} else {
			mutated[i] = 'B'
			break
		}
	}
	tampered := string(mutated) + "." + parts[1]

	_, err = DecodeCursor(tampered, testCursorSecret, testAllowed("o1"), "")
	if err == nil {
		t.Fatal("expected error for tampered payload")
	}
	// Could be invalid JSON OR tampered signature depending on which bit flipped;
	// either is acceptable as long as decoding fails.
	if !errors.Is(err, ErrCursorTampered) && !errors.Is(err, ErrCursorInvalid) {
		t.Errorf("expected tampered or invalid error, got %v", err)
	}
}

// TestCursor_TamperedSignatureRejected verifies HMAC catches signature mutation.
func TestCursor_TamperedSignatureRejected(t *testing.T) {
	t.Parallel()

	cursor := NewFederatedCursor("h", "", []string{"o1"}, nil)
	encoded, err := cursor.Encode(testCursorSecret)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}

	parts := strings.SplitN(encoded, ".", 2)
	if len(parts) != 2 {
		t.Fatal("expected two parts")
	}
	mutated := []byte(parts[1])
	if mutated[0] != 'A' {
		mutated[0] = 'A'
	} else {
		mutated[0] = 'B'
	}
	tampered := parts[0] + "." + string(mutated)

	_, err = DecodeCursor(tampered, testCursorSecret, testAllowed("o1"), "")
	if err == nil {
		t.Fatal("expected error for tampered signature")
	}
	if !errors.Is(err, ErrCursorTampered) {
		t.Errorf("expected ErrCursorTampered, got %v", err)
	}
}

// TestCursor_NextURLOutsideOriginBaseRejected verifies the SSRF guard.
func TestCursor_NextURLOutsideOriginBaseRejected(t *testing.T) {
	t.Parallel()

	cursor := NewFederatedCursor("h", "", []string{"o1"}, nil)
	cursor.Origins["o1"].NextURL = "https://attacker.example/x"

	encoded, err := cursor.Encode(testCursorSecret)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}

	allowed := map[string]string{"o1": "https://upstream.example"}
	_, err = DecodeCursor(encoded, testCursorSecret, allowed, "")
	if err == nil {
		t.Fatal("expected error for disallowed NextURL")
	}
	if !errors.Is(err, ErrCursorOriginURLNotAllowed) {
		t.Errorf("expected ErrCursorOriginURLNotAllowed, got %v", err)
	}
}

// TestCursor_NextURLEmptyAllowed verifies origins with no NextURL pass.
func TestCursor_NextURLEmptyAllowed(t *testing.T) {
	t.Parallel()

	cursor := NewFederatedCursor("h", "", []string{"o1"}, nil)
	// NextURL stays "" (default).
	encoded, err := cursor.Encode(testCursorSecret)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}

	if _, err := DecodeCursor(encoded, testCursorSecret, map[string]string{}, ""); err != nil {
		t.Errorf("expected success for empty NextURL with empty allowlist, got %v", err)
	}
}

// TestCursor_PrincipalBindingEnforced verifies the cursor is bound to a
// specific principal hash.
func TestCursor_PrincipalBindingEnforced(t *testing.T) {
	t.Parallel()

	cursor := NewFederatedCursor("h", "A", []string{"o1"}, nil)
	encoded, err := cursor.Encode(testCursorSecret)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}

	_, err = DecodeCursor(encoded, testCursorSecret, testAllowed("o1"), "B")
	if err == nil {
		t.Fatal("expected error for principal mismatch")
	}
	if !errors.Is(err, ErrCursorPrincipalMismatch) {
		t.Errorf("expected ErrCursorPrincipalMismatch, got %v", err)
	}

	if _, err := DecodeCursor(encoded, testCursorSecret, testAllowed("o1"), "A"); err != nil {
		t.Errorf("expected success with matching principal, got %v", err)
	}
}

// TestCursor_AnonymousRoundTrips verifies "" principal works both ends.
func TestCursor_AnonymousRoundTrips(t *testing.T) {
	t.Parallel()

	cursor := NewFederatedCursor("h", "", []string{"o1"}, nil)
	encoded, err := cursor.Encode(testCursorSecret)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}

	if _, err := DecodeCursor(encoded, testCursorSecret, testAllowed("o1"), ""); err != nil {
		t.Errorf("anonymous round-trip failed: %v", err)
	}
}

// TestCursor_ExpiredRejected verifies expiry enforcement.
func TestCursor_ExpiredRejected(t *testing.T) {
	t.Parallel()

	cursor := NewFederatedCursor("h", "", []string{"o1"}, nil)
	cursor.ExpiresAt = time.Now().Add(-1 * time.Hour).Unix()

	encoded, err := cursor.Encode(testCursorSecret)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}

	_, err = DecodeCursor(encoded, testCursorSecret, testAllowed("o1"), "")
	if err == nil {
		t.Fatal("expected expired error")
	}
	if !errors.Is(err, ErrCursorExpired) {
		t.Errorf("expected ErrCursorExpired, got %v", err)
	}
}

// TestCursor_InvalidFormatRejected verifies tokens missing the "." or with
// invalid base64 are rejected.
func TestCursor_InvalidFormatRejected(t *testing.T) {
	t.Parallel()

	allowed := testAllowed("o1")
	cases := []string{
		"",
		"no-dot-here",
		".only-sig",
		"only-payload.",
		"!!!.!!!",
	}
	for _, c := range cases {
		if _, err := DecodeCursor(c, testCursorSecret, allowed, ""); err == nil {
			t.Errorf("expected error for %q", c)
		}
	}
}

// TestPrincipalHash_DeterministicAndShort verifies the hashing helper.
func TestPrincipalHash_DeterministicAndShort(t *testing.T) {
	t.Parallel()

	if got := PrincipalHash(""); got != "" {
		t.Errorf("expected empty hash for empty input, got %q", got)
	}

	a := PrincipalHash("alice@example.com")
	a2 := PrincipalHash("alice@example.com")
	if a != a2 {
		t.Errorf("expected deterministic hash, got %q vs %q", a, a2)
	}
	if len(a) != 16 {
		t.Errorf("expected hash length 16, got %d (%q)", len(a), a)
	}

	b := PrincipalHash("bob@example.com")
	if a == b {
		t.Errorf("expected different hashes for different inputs")
	}
}

// TestEncodedFormatIsBase64URLDot verifies the token format.
func TestEncodedFormatIsBase64URLDot(t *testing.T) {
	t.Parallel()

	cursor := NewFederatedCursor("h", "", []string{"o1"}, nil)
	encoded, err := cursor.Encode(testCursorSecret)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}
	parts := strings.Split(encoded, ".")
	if len(parts) != 2 {
		t.Fatalf("expected two parts, got %d", len(parts))
	}
	if _, err := base64.RawURLEncoding.DecodeString(parts[0]); err != nil {
		t.Errorf("payload not valid base64url: %v", err)
	}
	if _, err := base64.RawURLEncoding.DecodeString(parts[1]); err != nil {
		t.Errorf("signature not valid base64url: %v", err)
	}
	if strings.ContainsAny(encoded, "+/=") {
		t.Errorf("encoded cursor must not contain '+', '/', or '=': %q", encoded)
	}
}

// TestIsExpired tests cursor expiration
func TestIsExpired(t *testing.T) {
	t.Run("not expired", func(t *testing.T) {
		t.Parallel()
		cursor := NewFederatedCursor("hash", "", []string{"origin1"}, nil)
		if cursor.IsExpired() {
			t.Error("newly created cursor should not be expired")
		}
	})

	t.Run("expired", func(t *testing.T) {
		t.Parallel()
		cursor := NewFederatedCursor("hash", "", []string{"origin1"}, nil)
		cursor.ExpiresAt = time.Now().Add(-1 * time.Hour).Unix()
		if !cursor.IsExpired() {
			t.Error("cursor with past expiry should be expired")
		}
	})

	t.Run("zero expiry", func(t *testing.T) {
		t.Parallel()
		cursor := NewFederatedCursor("hash", "", []string{"origin1"}, nil)
		cursor.ExpiresAt = 0
		if !cursor.IsExpired() {
			t.Error("cursor with zero expiry should be expired")
		}
	})
}

// TestHasMore tests whether cursor has more results
func TestHasMore(t *testing.T) {
	t.Run("all origins active", func(t *testing.T) {
		t.Parallel()
		cursor := NewFederatedCursor("hash", "", []string{"origin1", "origin2"}, nil)
		if !cursor.HasMore() {
			t.Error("cursor with active origins should have more")
		}
	})

	t.Run("all origins exhausted", func(t *testing.T) {
		t.Parallel()
		cursor := NewFederatedCursor("hash", "", []string{"origin1"}, nil)
		cursor.Origins["origin1"].Exhausted = true
		if cursor.HasMore() {
			t.Error("cursor with all exhausted origins should not have more")
		}
	})

	t.Run("all origins have errors", func(t *testing.T) {
		t.Parallel()
		cursor := NewFederatedCursor("hash", "", []string{"origin1"}, nil)
		cursor.Origins["origin1"].Error = true
		if cursor.HasMore() {
			t.Error("cursor with all error origins should not have more")
		}
	})
}

// TestActiveOrigins tests getting active origin IDs
func TestActiveOrigins(t *testing.T) {
	t.Run("sorted alphabetically", func(t *testing.T) {
		t.Parallel()
		cursor := NewFederatedCursor("hash", "", []string{"zebra", "alpha", "mike"}, nil)
		active := cursor.ActiveOrigins()
		expected := []string{"alpha", "mike", "zebra"}
		for i, id := range expected {
			if active[i] != id {
				t.Errorf("expected active[%d] = %q, got %q", i, id, active[i])
			}
		}
	})

	t.Run("excludes inactive", func(t *testing.T) {
		t.Parallel()
		cursor := NewFederatedCursor("hash", "", []string{"a", "b", "c"}, nil)
		cursor.Origins["b"].Exhausted = true
		cursor.Origins["c"].Error = true
		active := cursor.ActiveOrigins()
		if len(active) != 1 || active[0] != "a" {
			t.Errorf("expected [a], got %v", active)
		}
	})
}

// TestMarkExhausted tests marking origins as exhausted
func TestMarkExhausted(t *testing.T) {
	t.Parallel()
	cursor := NewFederatedCursor("hash", "", []string{"origin1"}, nil)
	cursor.Origins["origin1"].NextToken = "token"
	cursor.Origins["origin1"].NextURL = "url"

	cursor.MarkExhausted("origin1")
	origin := cursor.Origins["origin1"]
	if !origin.Exhausted {
		t.Error("origin should be marked exhausted")
	}
	if origin.NextToken != "" || origin.NextURL != "" {
		t.Error("next token/URL should be cleared")
	}
}

// TestMarkError tests marking origins as having errors
func TestMarkError(t *testing.T) {
	t.Parallel()
	cursor := NewFederatedCursor("hash", "", []string{"origin1"}, nil)
	cursor.MarkError("origin1")
	if !cursor.Origins["origin1"].Error {
		t.Error("origin should be marked with error")
	}
	// Non-existent should not panic.
	cursor.MarkError("missing")
}

// TestUpdateOrigin tests updating origin cursor state
func TestUpdateOrigin(t *testing.T) {
	t.Run("basic update", func(t *testing.T) {
		t.Parallel()
		cursor := NewFederatedCursor("hash", "", []string{"origin1"}, nil)
		cursor.UpdateOrigin("origin1", 10, "next-token", "next-url", "sort-value")
		origin := cursor.Origins["origin1"]
		if origin.ItemCount != 10 || origin.NextToken != "next-token" || origin.NextURL != "next-url" {
			t.Errorf("unexpected origin state: %+v", origin)
		}
		if origin.Exhausted {
			t.Error("origin should not be exhausted with next token")
		}
	})

	t.Run("marks exhausted when no next", func(t *testing.T) {
		t.Parallel()
		cursor := NewFederatedCursor("hash", "", []string{"origin1"}, nil)
		cursor.UpdateOrigin("origin1", 10, "", "", nil)
		if !cursor.Origins["origin1"].Exhausted {
			t.Error("origin should be marked exhausted")
		}
	})

	t.Run("increments item count", func(t *testing.T) {
		t.Parallel()
		cursor := NewFederatedCursor("hash", "", []string{"origin1"}, nil)
		cursor.UpdateOrigin("origin1", 10, "t", "", nil)
		cursor.UpdateOrigin("origin1", 5, "t2", "", nil)
		if cursor.Origins["origin1"].ItemCount != 15 {
			t.Errorf("expected item count 15, got %d", cursor.Origins["origin1"].ItemCount)
		}
	})
}

// TestClone tests deep copying of cursors
func TestClone(t *testing.T) {
	t.Run("preserves principal hash", func(t *testing.T) {
		t.Parallel()
		original := NewFederatedCursor("hash", "ph", []string{"origin1"}, nil)
		cloned := original.Clone()
		if cloned.PrincipalHash != "ph" {
			t.Errorf("clone should preserve principal hash, got %q", cloned.PrincipalHash)
		}
	})

	t.Run("no shared references", func(t *testing.T) {
		t.Parallel()
		original := NewFederatedCursor("hash", "", []string{"origin1"}, nil)
		original.Origins["origin1"].NextToken = "token"
		original.LastSortValues = []interface{}{"v"}

		cloned := original.Clone()
		original.Origins["origin1"].NextToken = "modified"
		original.LastSortValues[0] = "modified"

		if cloned.Origins["origin1"].NextToken == "modified" {
			t.Error("clone should not share origin state")
		}
		if cloned.LastSortValues[0] == "modified" {
			t.Error("clone should not share LastSortValues slice")
		}
	})
}

// TestString tests string representation
func TestString(t *testing.T) {
	t.Parallel()
	cursor := NewFederatedCursor("hash", "", []string{"origin1", "origin2"}, nil)
	cursor.TotalReturned = 50
	str := cursor.String()
	if !strings.Contains(str, "FederatedCursor") {
		t.Errorf("string missing prefix: %s", str)
	}
	if !strings.Contains(str, "returned=50") {
		t.Errorf("string missing returned: %s", str)
	}
}

// TestUnsignedBase64IsNotAcceptedAsCursor verifies that a plain
// base64-encoded JSON payload (i.e. an "old style" unsigned cursor) is
// rejected as malformed.
func TestUnsignedBase64IsNotAcceptedAsCursor(t *testing.T) {
	t.Parallel()
	cursor := NewFederatedCursor("h", "", []string{"o1"}, nil)
	data, _ := json.Marshal(cursor)
	plain := base64.RawURLEncoding.EncodeToString(data)
	if _, err := DecodeCursor(plain, testCursorSecret, testAllowed("o1"), ""); err == nil {
		t.Error("expected error for unsigned base64-only cursor")
	}
}

// TestDefaultCursorConfig tests default cursor configuration
func TestDefaultCursorConfig(t *testing.T) {
	t.Parallel()
	cfg := DefaultCursorConfig()
	if cfg.DefaultTTL != 1*time.Hour {
		t.Errorf("expected default TTL 1h, got %v", cfg.DefaultTTL)
	}
	if cfg.MaxTTL != 24*time.Hour {
		t.Errorf("expected max TTL 24h, got %v", cfg.MaxTTL)
	}
}
