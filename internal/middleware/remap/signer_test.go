package remap

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHMACSigner_SignVerify_RoundTrip(t *testing.T) {
	s := NewHMACSigner("secret")
	signed := s.Sign(context.Background(), "https://stac.example.com/items/abc?role=read&foo=bar", time.Hour)
	ok, err := s.Verify(signed)
	require.NoError(t, err, "round-trip Verify failed")
	require.True(t, ok, "round-trip Verify failed")
}

func TestHMACSigner_TamperWithQueryFails(t *testing.T) {
	s := NewHMACSigner("secret")
	signed := s.Sign(context.Background(), "https://stac.example.com/items/abc?role=read", time.Hour)

	u, err := url.Parse(signed)
	require.NoError(t, err, "parse signed URL")
	q := u.Query()
	q.Set("role", "admin") // attacker swaps the query parameter
	u.RawQuery = q.Encode()

	ok, err := s.Verify(u.String())
	require.False(t, ok, "tampered query must fail verification")
	require.Error(t, err, "tampered query must fail verification")
}

// TestNewSigner_RejectsUnknownTypes guards against signer-type typos
// (and re-introduction of the deleted cloudfront / s3_presigned stubs,
// which performed no real RSA / SigV4 signing).
func TestNewSigner_RejectsUnknownTypes(t *testing.T) {
	for _, typ := range []string{"cloudfront", "s3_presigned", "bogus"} {
		typ := typ
		t.Run(typ, func(t *testing.T) {
			s, err := NewSigner(typ, "ignored")
			require.Error(t, err, "expected error for type %q", typ)
			require.Nil(t, s, "expected nil signer for type %q", typ)
			assert.Contains(t, err.Error(), "unknown signer type",
				"expected 'unknown signer type' in error")
		})
	}
}

// TestSigner_DoubleSlashSameAsSingleSlash (M-remap-4): "/foo" and
// "//foo" resolve to the same resource on virtually every HTTP server,
// but pre-fix they produced different HMAC inputs because path.Clean
// wasn't applied. The fix canonicalizes the path on both Sign and
// Verify so the two forms verify against each other — closing an
// open-redirect-adjacent inconsistency.
func TestSigner_DoubleSlashSameAsSingleSlash(t *testing.T) {
	s := NewHMACSigner("secret")

	signed := s.Sign(context.Background(), "https://stac.example.com/foo?role=read", time.Hour)

	// Build the "//foo" variant by injecting an extra slash into
	// the path of the signed URL. The query (with sig + exp) stays
	// as-is.
	u, err := url.Parse(signed)
	require.NoError(t, err, "parse")
	u.Path = "//foo"
	doubled := u.String()

	ok, err := s.Verify(doubled)
	assert.NoError(t, err, "//foo should verify against /foo signature (path.Clean normalization)")
	assert.True(t, ok, "//foo should verify against /foo signature (path.Clean normalization)")

}

// TestSigningMessage_DoesNotMutateInput (M-remap-3): signingMessage
// historically called Del("sig") and Set("exp", …) on the caller's
// url.Values map. That behavior was a footgun — callers that wanted
// to log/inspect the original query after signing got a corrupted
// view. signingMessage now operates on a deep clone.
func TestSigningMessage_DoesNotMutateInput(t *testing.T) {
	in := url.Values{
		"sig":  {"caller-original-sig"},
		"exp":  {"100"},
		"role": {"read"},
		"foo":  {"bar", "baz"},
	}
	// Snapshot the values before the call.
	before := map[string][]string{}
	for k, vs := range in {
		before[k] = append([]string(nil), vs...)
	}

	_ = signingMessage("Host.Example", "/p", in, 999)

	for k, vs := range before {
		got, ok := in[k]
		if !ok {
			assert.Failf(t, "key deleted", "signingMessage deleted caller's key %q", k)
			continue
		}
		if len(got) != len(vs) {
			assert.Failf(t, "len changed", "key %q: len changed (was %d, now %d)", k, len(vs), len(got))
			continue
		}
		for i := range vs {
			assert.Equal(t, vs[i], got[i], "key %q[%d]", k, i)
		}
	}
	assert.Equal(t, len(before), len(in), "signingMessage added/removed keys")
}

// TestHMACSigner_RotationVerifiesOldSigs (M-remap-2): after rotating
// a new primary key in, signatures issued under the old key continue
// to verify and new signatures use the new key. This is the property
// that makes a key rotation operation safe to perform without
// invalidating in-flight signed URLs.
func TestHMACSigner_RotationVerifiesOldSigs(t *testing.T) {
	s := NewHMACSigner("secret-A")

	// Signature under A.
	signedA := s.Sign(context.Background(), "https://stac.example.com/items/abc?role=read", time.Hour)

	// Rotate: B becomes primary, A stays for verification only.
	s.RotateSecret([]byte("secret-B"))

	// Old A-signed URL still verifies.
	okA, errA := s.Verify(signedA)
	assert.NoError(t, errA, "old A-signed URL must still verify after rotation")
	assert.True(t, okA, "old A-signed URL must still verify after rotation")

	// New signature uses B.
	signedB := s.Sign(context.Background(), "https://stac.example.com/items/abc?role=read", time.Hour)
	assert.NotEqual(t, signedA, signedB, "after rotation, Sign should produce a new signature (B != A)")
	okB, errB := s.Verify(signedB)
	assert.NoError(t, errB, "new B-signed URL must verify")
	assert.True(t, okB, "new B-signed URL must verify")

	// A signer that knows ONLY B must reject the A-signed URL —
	// proves the A-signature/B-signature distinction is real.
	bOnly := NewHMACSigner("secret-B")
	okBOnly, _ := bOnly.Verify(signedA)
	assert.False(t, okBOnly, "A-signed URL should not verify under a B-only signer (sanity check)")
}

// TestHMACSigner_VerifyRejectsBadExpiryFormats covers the strconv
// upgrade: fmt.Sscanf("%d") used to silently accept negatives,
// trailing junk, and leading whitespace.
func TestHMACSigner_VerifyRejectsBadExpiryFormats(t *testing.T) {
	s := NewHMACSigner("test-secret")

	for _, badExp := range []string{"-1", "12abc", "abc", " 12", "9999999999999999999999"} {
		raw := "https://example.com/x?exp=" + badExp + "&sig=AAAA"
		ok, err := s.Verify(raw)
		assert.False(t, ok, "expected reject for exp=%q", badExp)
		assert.Error(t, err, "expected reject for exp=%q", badExp)
	}
}
