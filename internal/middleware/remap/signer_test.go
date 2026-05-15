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
