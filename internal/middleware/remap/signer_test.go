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

// TestNewSigner_RejectsCloudFrontAndS3 guards against re-introducing
// the deleted CloudFront and S3-presigned signers, which were stubs
// that performed no real RSA / SigV4 signing and thus silently shipped
// URLs with no integrity protection.
func TestNewSigner_RejectsCloudFrontAndS3(t *testing.T) {
	for _, typ := range []string{"cloudfront", "s3_presigned"} {
		typ := typ
		t.Run(typ, func(t *testing.T) {
			s, err := NewSigner(typ, "ignored")
			if err == nil {
				t.Fatalf("expected error for type %q, got signer=%v", typ, s)
			}
			if s != nil {
				t.Fatalf("expected nil signer for type %q, got %v", typ, s)
			}
			if !strings.Contains(err.Error(), "not implemented") {
				t.Errorf("expected 'not implemented' in error, got: %v", err)
			}
		})
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
