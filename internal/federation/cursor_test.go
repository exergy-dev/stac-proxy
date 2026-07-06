package federation

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

		require.NotNil(t, cursor, "expected cursor to be non-nil")

		assert.Equalf(t, currentCursorVersion, cursor.Version, "expected version %d", currentCursorVersion)
		assert.Equalf(t, queryHash, cursor.QueryHash, "expected query hash %q", queryHash)
		assert.Equal(t, "principal-hash", cursor.PrincipalHash, "expected principal hash 'principal-hash'")
		assert.Lenf(t, cursor.Origins, len(originIDs), "expected %d origins", len(originIDs))

		for _, id := range originIDs {
			origin, ok := cursor.Origins[id]
			if !assert.Truef(t, ok, "expected origin %q to exist", id) {
				continue
			}
			assert.Equalf(t, id, origin.ID, "expected origin ID %q", id)
		}

		assert.NotZero(t, cursor.CreatedAt, "expected created at to be set")

		expectedExpiry := cursor.CreatedAt + int64(time.Hour.Seconds())
		assert.Equalf(t, expectedExpiry, cursor.ExpiresAt, "expected expiry at %d", expectedExpiry)
	})

	t.Run("with custom config", func(t *testing.T) {
		t.Parallel()

		cfg := &CursorConfig{DefaultTTL: 30 * time.Minute}
		cursor := NewFederatedCursor("hash", "", []string{"origin1"}, cfg)

		expectedExpiry := cursor.CreatedAt + int64((30 * time.Minute).Seconds())
		assert.Equalf(t, expectedExpiry, cursor.ExpiresAt, "expected expiry at %d", expectedExpiry)
	})

	t.Run("with nil origin list", func(t *testing.T) {
		t.Parallel()

		cursor := NewFederatedCursor("hash", "", nil, nil)
		assert.NotNil(t, cursor.Origins, "expected origins map to be initialized")
		assert.Empty(t, cursor.Origins, "expected 0 origins")
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
	require.NoError(t, err, "encode failed")
	require.Containsf(t, encoded, ".", "encoded token must contain '.' separator: %q", encoded)

	decoded, err := DecodeCursor(encoded, testCursorSecret, testAllowed("origin1", "origin2"), "abc123")
	require.NoError(t, err, "decode failed")

	assert.Equalf(t, cursor.QueryHash, decoded.QueryHash, "query hash mismatch")
	assert.Equalf(t, cursor.PrincipalHash, decoded.PrincipalHash, "principal hash mismatch")
	assert.Equal(t, cursor.Origins["origin1"].NextURL, decoded.Origins["origin1"].NextURL, "origin1 NextURL mismatch")
	assert.Equal(t, "tok", decoded.Origins["origin2"].NextToken, "origin2 NextToken mismatch")
}

// TestCursor_EmptySecretEncodeRejected verifies that Encode requires a secret.
func TestCursor_EmptySecretEncodeRejected(t *testing.T) {
	t.Parallel()

	cursor := NewFederatedCursor("h", "", []string{"o1"}, nil)
	_, err := cursor.Encode(nil)
	assert.Error(t, err, "expected error for nil secret")
	_, err = cursor.Encode([]byte{})
	assert.Error(t, err, "expected error for empty secret")
}

// TestCursor_EmptySecretDecodeRejected verifies that DecodeCursor requires a secret.
func TestCursor_EmptySecretDecodeRejected(t *testing.T) {
	t.Parallel()

	cursor := NewFederatedCursor("h", "", []string{"o1"}, nil)
	encoded, err := cursor.Encode(testCursorSecret)
	require.NoError(t, err, "encode failed")
	_, err = DecodeCursor(encoded, nil, testAllowed("o1"), "")
	assert.Error(t, err, "expected error for nil secret on decode")
	_, err = DecodeCursor(encoded, []byte{}, testAllowed("o1"), "")
	assert.Error(t, err, "expected error for empty secret on decode")
}

// TestCursor_TamperedRejected verifies HMAC catches both payload and signature mutation.
func TestCursor_TamperedRejected(t *testing.T) {
	t.Parallel()

	mutate := func(s string) string {
		b := []byte(s)
		if b[0] != 'A' {
			b[0] = 'A'
		} else {
			b[0] = 'B'
		}
		return string(b)
	}

	cases := []struct {
		name      string
		mutateIdx int // 0 = payload, 1 = sig
	}{
		{"payload", 0},
		{"signature", 1},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cursor := NewFederatedCursor("h", "", []string{"o1"}, nil)
			encoded, err := cursor.Encode(testCursorSecret)
			require.NoError(t, err, "encode failed")
			parts := strings.SplitN(encoded, ".", 2)
			require.Len(t, parts, 2)
			parts[tc.mutateIdx] = mutate(parts[tc.mutateIdx])
			_, err = DecodeCursor(parts[0]+"."+parts[1], testCursorSecret, testAllowed("o1"), "")
			require.Error(t, err)
			assert.Truef(t, errors.Is(err, ErrCursorTampered) || errors.Is(err, ErrCursorInvalid), "expected tampered or invalid error, got %v", err)
		})
	}
}

// TestCursor_NextURLOutsideOriginBaseRejected verifies the SSRF guard.
func TestCursor_NextURLOutsideOriginBaseRejected(t *testing.T) {
	t.Parallel()

	cursor := NewFederatedCursor("h", "", []string{"o1"}, nil)
	cursor.Origins["o1"].NextURL = "https://attacker.example/x"

	encoded, err := cursor.Encode(testCursorSecret)
	require.NoError(t, err, "encode failed")

	allowed := map[string]string{"o1": "https://upstream.example"}
	_, err = DecodeCursor(encoded, testCursorSecret, allowed, "")
	require.Error(t, err, "expected error for disallowed NextURL")
	assert.ErrorIsf(t, err, ErrCursorOriginURLNotAllowed, "expected ErrCursorOriginURLNotAllowed, got %v", err)
}

// TestCursor_NextURLEmptyAllowed verifies origins with no NextURL pass.
func TestCursor_NextURLEmptyAllowed(t *testing.T) {
	t.Parallel()

	cursor := NewFederatedCursor("h", "", []string{"o1"}, nil)
	// NextURL stays "" (default).
	encoded, err := cursor.Encode(testCursorSecret)
	require.NoError(t, err, "encode failed")

	_, err = DecodeCursor(encoded, testCursorSecret, map[string]string{}, "")
	assert.NoErrorf(t, err, "expected success for empty NextURL with empty allowlist")
}

// TestCursor_PrincipalBindingEnforced verifies the cursor is bound to a
// specific principal hash.
func TestCursor_PrincipalBindingEnforced(t *testing.T) {
	t.Parallel()

	cursor := NewFederatedCursor("h", "A", []string{"o1"}, nil)
	encoded, err := cursor.Encode(testCursorSecret)
	require.NoError(t, err, "encode failed")

	_, err = DecodeCursor(encoded, testCursorSecret, testAllowed("o1"), "B")
	require.Error(t, err, "expected error for principal mismatch")
	assert.ErrorIsf(t, err, ErrCursorPrincipalMismatch, "expected ErrCursorPrincipalMismatch, got %v", err)

	_, err = DecodeCursor(encoded, testCursorSecret, testAllowed("o1"), "A")
	assert.NoErrorf(t, err, "expected success with matching principal")
}

// TestCursor_AnonymousRoundTrips verifies "" principal works both ends.
func TestCursor_AnonymousRoundTrips(t *testing.T) {
	t.Parallel()

	cursor := NewFederatedCursor("h", "", []string{"o1"}, nil)
	encoded, err := cursor.Encode(testCursorSecret)
	require.NoError(t, err, "encode failed")

	_, err = DecodeCursor(encoded, testCursorSecret, testAllowed("o1"), "")
	assert.NoErrorf(t, err, "anonymous round-trip failed")
}

// TestCursor_ExpiredRejected verifies expiry enforcement.
func TestCursor_ExpiredRejected(t *testing.T) {
	t.Parallel()

	cursor := NewFederatedCursor("h", "", []string{"o1"}, nil)
	cursor.ExpiresAt = time.Now().Add(-1 * time.Hour).Unix()

	encoded, err := cursor.Encode(testCursorSecret)
	require.NoError(t, err, "encode failed")

	_, err = DecodeCursor(encoded, testCursorSecret, testAllowed("o1"), "")
	require.Error(t, err, "expected expired error")
	assert.ErrorIsf(t, err, ErrCursorExpired, "expected ErrCursorExpired, got %v", err)
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
		_, err := DecodeCursor(c, testCursorSecret, allowed, "")
		assert.Errorf(t, err, "expected error for %q", c)
	}
}

// TestPrincipalHash_DeterministicAndShort verifies the hashing helper.
func TestPrincipalHash_DeterministicAndShort(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "", PrincipalHash(""), "expected empty hash for empty input")

	a := PrincipalHash("alice@example.com")
	a2 := PrincipalHash("alice@example.com")
	assert.Equalf(t, a, a2, "expected deterministic hash")
	assert.Lenf(t, a, 16, "expected hash length 16, got %d (%q)", len(a), a)

	b := PrincipalHash("bob@example.com")
	assert.NotEqual(t, a, b, "expected different hashes for different inputs")
}

// TestEncodedFormatIsBase64URLDot verifies the token format.
func TestEncodedFormatIsBase64URLDot(t *testing.T) {
	t.Parallel()

	cursor := NewFederatedCursor("h", "", []string{"o1"}, nil)
	encoded, err := cursor.Encode(testCursorSecret)
	require.NoError(t, err, "encode failed")
	parts := strings.Split(encoded, ".")
	require.Lenf(t, parts, 2, "expected two parts, got %d", len(parts))
	_, err = base64.RawURLEncoding.DecodeString(parts[0])
	assert.NoErrorf(t, err, "payload not valid base64url")
	_, err = base64.RawURLEncoding.DecodeString(parts[1])
	assert.NoErrorf(t, err, "signature not valid base64url")
	assert.Falsef(t, strings.ContainsAny(encoded, "+/="), "encoded cursor must not contain '+', '/', or '=': %q", encoded)
}

// TestIsExpired tests cursor expiration (expired case; not-expired is
// covered by other round-trip tests).
func TestIsExpired(t *testing.T) {
	t.Parallel()
	cursor := NewFederatedCursor("hash", "", []string{"origin1"}, nil)
	cursor.ExpiresAt = time.Now().Add(-1 * time.Hour).Unix()
	assert.True(t, cursor.IsExpired(), "cursor with past expiry should be expired")
}

// TestHasMore tests whether cursor has more results
func TestHasMore(t *testing.T) {
	t.Run("all origins active", func(t *testing.T) {
		t.Parallel()
		cursor := NewFederatedCursor("hash", "", []string{"origin1", "origin2"}, nil)
		assert.True(t, cursor.HasMore(), "cursor with active origins should have more")
	})

	t.Run("all origins exhausted", func(t *testing.T) {
		t.Parallel()
		cursor := NewFederatedCursor("hash", "", []string{"origin1"}, nil)
		cursor.Origins["origin1"].Exhausted = true
		assert.False(t, cursor.HasMore(), "cursor with all exhausted origins should not have more")
	})

	t.Run("all origins have errors", func(t *testing.T) {
		t.Parallel()
		cursor := NewFederatedCursor("hash", "", []string{"origin1"}, nil)
		cursor.Origins["origin1"].Error = true
		assert.False(t, cursor.HasMore(), "cursor with all error origins should not have more")
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
			assert.Equalf(t, id, active[i], "expected active[%d] = %q", i, id)
		}
	})

	t.Run("excludes inactive", func(t *testing.T) {
		t.Parallel()
		cursor := NewFederatedCursor("hash", "", []string{"a", "b", "c"}, nil)
		cursor.Origins["b"].Exhausted = true
		cursor.Origins["c"].Error = true
		active := cursor.ActiveOrigins()
		assert.Equalf(t, []string{"a"}, active, "expected [a], got %v", active)
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
	assert.True(t, origin.Exhausted, "origin should be marked exhausted")
	assert.Empty(t, origin.NextToken, "next token should be cleared")
	assert.Empty(t, origin.NextURL, "next URL should be cleared")
}

// TestMarkError tests marking origins as having errors
func TestMarkError(t *testing.T) {
	t.Parallel()
	cursor := NewFederatedCursor("hash", "", []string{"origin1"}, nil)
	cursor.MarkError("origin1")
	assert.True(t, cursor.Origins["origin1"].Error, "origin should be marked with error")
	// Non-existent should not panic.
	cursor.MarkError("missing")
}

// TestClone tests deep copying of cursors
func TestClone(t *testing.T) {
	t.Run("preserves principal hash", func(t *testing.T) {
		t.Parallel()
		original := NewFederatedCursor("hash", "ph", []string{"origin1"}, nil)
		cloned := original.Clone()
		assert.Equalf(t, "ph", cloned.PrincipalHash, "clone should preserve principal hash")
	})

	t.Run("no shared references", func(t *testing.T) {
		t.Parallel()
		original := NewFederatedCursor("hash", "", []string{"origin1"}, nil)
		original.Origins["origin1"].NextToken = "token"
		original.LastSortValues = []interface{}{"v"}

		cloned := original.Clone()
		original.Origins["origin1"].NextToken = "modified"
		original.LastSortValues[0] = "modified"

		assert.NotEqual(t, "modified", cloned.Origins["origin1"].NextToken, "clone should not share origin state")
		assert.NotEqual(t, "modified", cloned.LastSortValues[0], "clone should not share LastSortValues slice")
	})
}

// TestUnsignedBase64IsNotAcceptedAsCursor verifies that a plain
// base64-encoded JSON payload (i.e. an "old style" unsigned cursor) is
// rejected as malformed.
func TestUnsignedBase64IsNotAcceptedAsCursor(t *testing.T) {
	t.Parallel()
	cursor := NewFederatedCursor("h", "", []string{"o1"}, nil)
	data, _ := json.Marshal(cursor)
	plain := base64.RawURLEncoding.EncodeToString(data)
	_, err := DecodeCursor(plain, testCursorSecret, testAllowed("o1"), "")
	assert.Error(t, err, "expected error for unsigned base64-only cursor")
}

// TestDefaultCursorConfig tests default cursor configuration
func TestDefaultCursorConfig(t *testing.T) {
	t.Parallel()
	cfg := DefaultCursorConfig()
	assert.Equalf(t, 1*time.Hour, cfg.DefaultTTL, "expected default TTL 1h")
	assert.Equalf(t, 24*time.Hour, cfg.MaxTTL, "expected max TTL 24h")
}
