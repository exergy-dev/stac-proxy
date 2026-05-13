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
