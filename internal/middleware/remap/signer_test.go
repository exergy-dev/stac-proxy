package remap

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestHMACSigner_SignVerify_RoundTrip(t *testing.T) {
	s := NewHMACSigner("secret")
	signed := s.Sign(context.Background(), "https://stac.example.com/items/abc?role=read&foo=bar", time.Hour)
	ok, err := s.Verify(signed)
	if err != nil || !ok {
		t.Fatalf("round-trip Verify failed: ok=%v err=%v", ok, err)
	}
}

func TestHMACSigner_TamperWithQueryFails(t *testing.T) {
	s := NewHMACSigner("secret")
	signed := s.Sign(context.Background(), "https://stac.example.com/items/abc?role=read", time.Hour)

	u, err := url.Parse(signed)
	if err != nil {
		t.Fatalf("parse signed URL: %v", err)
	}
	q := u.Query()
	q.Set("role", "admin") // attacker swaps the query parameter
	u.RawQuery = q.Encode()

	if ok, err := s.Verify(u.String()); ok || err == nil {
		t.Fatalf("tampered query must fail verification (ok=%v err=%v)", ok, err)
	}
}

func TestHMACSigner_TamperWithHostFails(t *testing.T) {
	s := NewHMACSigner("secret")
	signed := s.Sign(context.Background(), "https://real.example.com/items/abc", time.Hour)

	tampered := strings.Replace(signed, "real.example.com", "evil.example.com", 1)
	if ok, err := s.Verify(tampered); ok || err == nil {
		t.Fatalf("host swap must fail verification (ok=%v err=%v)", ok, err)
	}
}

// TestNewSigner_RejectsUnknownTypes guards against signer-type typos
// (and re-introduction of the deleted cloudfront / s3_presigned stubs,
// which performed no real RSA / SigV4 signing).
func TestNewSigner_RejectsUnknownTypes(t *testing.T) {
	for _, typ := range []string{"cloudfront", "s3_presigned", "bogus"} {
		typ := typ
		t.Run(typ, func(t *testing.T) {
			s, err := NewSigner(typ, "ignored")
			if err == nil {
				t.Fatalf("expected error for type %q, got signer=%v", typ, s)
			}
			if s != nil {
				t.Fatalf("expected nil signer for type %q, got %v", typ, s)
			}
			if !strings.Contains(err.Error(), "unknown signer type") {
				t.Errorf("expected 'unknown signer type' in error, got: %v", err)
			}
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
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	u.Path = "//foo"
	doubled := u.String()

	if ok, err := s.Verify(doubled); !ok || err != nil {
		t.Errorf("//foo should verify against /foo signature (path.Clean normalization): ok=%v err=%v", ok, err)
	}

	// Also confirm /a//b//c canonicalizes to /a/b/c equivalently.
	signed2 := s.Sign(context.Background(), "https://stac.example.com/a/b/c?role=read", time.Hour)
	u2, _ := url.Parse(signed2)
	u2.Path = "/a//b//c"
	if ok, err := s.Verify(u2.String()); !ok || err != nil {
		t.Errorf("/a//b//c should verify against /a/b/c signature: ok=%v err=%v", ok, err)
	}
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
			t.Errorf("signingMessage deleted caller's key %q", k)
			continue
		}
		if len(got) != len(vs) {
			t.Errorf("key %q: len changed (was %d, now %d)", k, len(vs), len(got))
			continue
		}
		for i := range vs {
			if got[i] != vs[i] {
				t.Errorf("key %q[%d]: was %q, now %q", k, i, vs[i], got[i])
			}
		}
	}
	if len(in) != len(before) {
		t.Errorf("signingMessage added/removed keys: was %d, now %d", len(before), len(in))
	}
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
	if ok, err := s.Verify(signedA); !ok || err != nil {
		t.Errorf("old A-signed URL must still verify after rotation: ok=%v err=%v", ok, err)
	}

	// New signature uses B.
	signedB := s.Sign(context.Background(), "https://stac.example.com/items/abc?role=read", time.Hour)
	if signedB == signedA {
		t.Errorf("after rotation, Sign should produce a new signature (B != A)")
	}
	if ok, err := s.Verify(signedB); !ok || err != nil {
		t.Errorf("new B-signed URL must verify: ok=%v err=%v", ok, err)
	}

	// A signer that knows ONLY B must reject the A-signed URL —
	// proves the A-signature/B-signature distinction is real.
	bOnly := NewHMACSigner("secret-B")
	if ok, _ := bOnly.Verify(signedA); ok {
		t.Errorf("A-signed URL should not verify under a B-only signer (sanity check)")
	}
}

func TestNewSigner_HMACAndNoOp(t *testing.T) {
	s, err := NewSigner("hmac", "secret")
	if err != nil {
		t.Fatalf("hmac: unexpected error: %v", err)
	}
	if _, ok := s.(*HMACSigner); !ok {
		t.Fatalf("expected *HMACSigner, got %T", s)
	}

	if _, err := NewSigner("hmac", ""); err == nil {
		t.Fatal("expected error for hmac with empty secret")
	}

	for _, typ := range []string{"noop", ""} {
		s, err := NewSigner(typ, "")
		if err != nil {
			t.Fatalf("noop (%q): unexpected error: %v", typ, err)
		}
		if _, ok := s.(*NoOpSigner); !ok {
			t.Fatalf("expected *NoOpSigner for %q, got %T", typ, s)
		}
	}

	if _, err := NewSigner("bogus", ""); err == nil {
		t.Fatal("expected error for unknown signer type")
	}
}

// TestHMACSigner_VerifyRejectsBadExpiryFormats covers the strconv
// upgrade: fmt.Sscanf("%d") used to silently accept negatives,
// trailing junk, and leading whitespace.
func TestHMACSigner_VerifyRejectsBadExpiryFormats(t *testing.T) {
	s := NewHMACSigner("test-secret")

	for _, badExp := range []string{"-1", "12abc", "abc", " 12", "9999999999999999999999"} {
		raw := "https://example.com/x?exp=" + badExp + "&sig=AAAA"
		ok, err := s.Verify(raw)
		if ok || err == nil {
			t.Errorf("expected reject for exp=%q; ok=%v err=%v", badExp, ok, err)
		}
	}
}
