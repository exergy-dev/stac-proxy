package federation

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/yourorg/stac-proxy/internal/stac"
)

// flipLastByte returns s with its final byte XOR-flipped. Used to build
// a tampered-signature seed (and, in the fuzz body, to prove that
// corrupting the signature of an otherwise-valid cursor is rejected).
func flipLastByte(s string) string {
	if s == "" {
		return s
	}
	b := []byte(s)
	b[len(b)-1] ^= 0xFF
	return string(b)
}

// FuzzDecodeCursor drives DecodeCursor — the attacker-controllable entry
// point that takes a base64 cursor string from a query param and performs
// HMAC verification, JSON decode, and per-origin state rehydration
// (NextURL/NextBody/Stash) — against arbitrary input.
//
// Invariants:
//   - DecodeCursor never panics, whatever the input bytes.
//   - A successful decode implies the HMAC over the payload verified: we
//     independently recompute HMAC(secret, payload) and require it equals
//     the signature carried by the input.
//   - Corrupting the signature of any input that decoded successfully
//     makes DecodeCursor reject it (a tampered cursor is never accepted).
func FuzzDecodeCursor(f *testing.F) {
	secret := []byte("fuzz-cursor-secret-32-bytes-long!")
	// The allowlist a real request would pass: origin ID -> base URL.
	// Seeded valid cursors keep their NextURLs under these prefixes so
	// they survive the SSRF allowlist check and exercise rehydration.
	allowed := map[string]string{
		"origin1": "https://origin1.example.com",
		"origin2": "https://origin2.example.com",
	}
	const principalHash = "" // anonymous; matches the seeds below

	// Seed 1: a plain valid cursor (anonymous, two origins).
	c1 := NewFederatedCursor("query-hash-1", principalHash, []string{"origin1", "origin2"}, nil)
	enc1, err := c1.Encode(secret)
	require.NoError(f, err)
	f.Add(enc1)

	// Seed 2: a valid cursor exercising per-origin rehydration —
	// NextURL (allowlisted), a verbatim POST NextBody, and a stashed item.
	c2 := NewFederatedCursor("query-hash-2", principalHash, []string{"origin1"}, nil)
	oc := c2.Origins["origin1"]
	oc.NextURL = "https://origin1.example.com/search?token=abc"
	oc.NextBody = []byte(`{"token":"abc"}`)
	oc.Stash = []*stac.Item{{Version: "1.0.0", ID: "item-1", Collection: "c1"}}
	enc2, err := c2.Encode(secret)
	require.NoError(f, err)
	f.Add(enc2)

	// Malformed seeds.
	f.Add("")                 // empty
	f.Add("not-base64!!")     // not two base64 parts
	f.Add(flipLastByte(enc1)) // valid cursor, last byte flipped (tampered)
	f.Add(enc1[:len(enc1)/2]) // truncated

	f.Fuzz(func(t *testing.T, data string) {
		// Primary invariant: must not panic for any input.
		cursor, err := DecodeCursor(data, secret, allowed, principalHash)
		if err != nil {
			return // rejected input carries no further obligations
		}

		// A successful decode must return a usable cursor...
		require.NotNil(t, cursor, "nil cursor returned without an error")

		// ...and must have passed HMAC verification. Recompute it
		// independently from the raw token to prove the guarantee.
		parts := strings.Split(data, ".")
		require.Len(t, parts, 2, "decoded token was not two dot-separated parts")
		payload, derr := base64.RawURLEncoding.DecodeString(parts[0])
		require.NoError(t, derr, "decoded token had non-base64 payload")
		sig, derr := base64.RawURLEncoding.DecodeString(parts[1])
		require.NoError(t, derr, "decoded token had non-base64 signature")
		mac := hmac.New(sha256.New, secret)
		mac.Write(payload)
		require.True(t, hmac.Equal(mac.Sum(nil), sig),
			"DecodeCursor accepted a cursor whose HMAC does not verify")

		// Tampering with the (valid) signature must be rejected.
		tampered := parts[0] + "." + base64.RawURLEncoding.EncodeToString(flipBytes(sig))
		_, terr := DecodeCursor(tampered, secret, allowed, principalHash)
		require.Error(t, terr, "tampered signature must be rejected")
	})
}

// flipBytes returns a copy of b with its last byte flipped (b unchanged).
func flipBytes(b []byte) []byte {
	out := append([]byte(nil), b...)
	if len(out) > 0 {
		out[len(out)-1] ^= 0xFF
	}
	return out
}
