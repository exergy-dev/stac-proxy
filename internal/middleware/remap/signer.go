// Package remap provides URL signing for remapped URLs.
package remap

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Signer defines the interface for URL signing.
type Signer interface {
	// Sign adds a signature to the URL with the given TTL.
	Sign(ctx context.Context, rawURL string, ttl time.Duration) string
}

// HMACSigner signs URLs using HMAC-SHA256.
type HMACSigner struct {
	secret []byte
}

// NewHMACSigner creates a new HMAC signer.
func NewHMACSigner(secret string) *HMACSigner {
	return &HMACSigner{
		secret: []byte(secret),
	}
}

// signingMessage builds the canonical bytes the HMAC covers. Host, path
// and query (sorted, exp included) are all bound so an attacker cannot
// swap query parameters or hostnames while keeping the signature.
func signingMessage(host, path string, q url.Values, expiry int64) string {
	// Remove the signature itself before canonicalizing; everything
	// else, including the expiry, is part of the signed input.
	q.Del("sig")
	q.Set("exp", fmt.Sprintf("%d", expiry))
	return strings.ToLower(host) + "\n" + path + "\n" + q.Encode()
}

// Sign adds an HMAC signature and expiry to the URL.
func (s *HMACSigner) Sign(ctx context.Context, rawURL string, ttl time.Duration) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}

	expiry := time.Now().Add(ttl).Unix()

	q := parsed.Query()
	message := signingMessage(parsed.Host, parsed.Path, q, expiry)
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(message))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	q.Set("exp", fmt.Sprintf("%d", expiry))
	q.Set("sig", signature)
	parsed.RawQuery = q.Encode()

	return parsed.String()
}

// Verify validates an HMAC-signed URL.
func (s *HMACSigner) Verify(rawURL string) (bool, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false, err
	}

	q := parsed.Query()
	expStr := q.Get("exp")
	sig := q.Get("sig")

	if expStr == "" || sig == "" {
		return false, fmt.Errorf("missing signature parameters")
	}

	var expiry int64
	if _, err := fmt.Sscanf(expStr, "%d", &expiry); err != nil {
		return false, fmt.Errorf("invalid expiry format")
	}

	if time.Now().Unix() > expiry {
		return false, fmt.Errorf("signature expired")
	}

	message := signingMessage(parsed.Host, parsed.Path, q, expiry)
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(message))
	expectedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(sig), []byte(expectedSig)) {
		return false, fmt.Errorf("invalid signature")
	}

	return true, nil
}

// NoOpSigner is a signer that doesn't modify URLs.
type NoOpSigner struct{}

// Sign returns the URL unchanged.
func (s *NoOpSigner) Sign(ctx context.Context, rawURL string, ttl time.Duration) string {
	return rawURL
}

// NewSigner constructs a Signer of the given type.
//
// Supported types:
//   - "hmac"  — HMAC-SHA256 signing using `secret` (see HMACSigner).
//   - "noop"  — no-op signer (returns URLs unchanged).
//
// The "cloudfront" and "s3_presigned" types are explicitly rejected:
// previous implementations in this package were stubs that did not
// perform real RSA / SigV4 signing — they merely base64-encoded a
// policy or appended unsigned query parameters. Shipping them in a
// production binary was a credential-leak / auth-bypass trap, and they
// have been removed. Use a real upstream signer (the AWS SDK) at the
// origin instead, or use the HMAC signer for proxy-issued URLs.
func NewSigner(typ, secret string) (Signer, error) {
	switch typ {
	case "hmac":
		if secret == "" {
			return nil, fmt.Errorf("remap: hmac signer requires a non-empty secret")
		}
		return NewHMACSigner(secret), nil
	case "noop", "":
		return &NoOpSigner{}, nil
	case "cloudfront", "s3_presigned":
		return nil, fmt.Errorf("remap: signer type %q is not implemented; use hmac", typ)
	default:
		return nil, fmt.Errorf("remap: unknown signer type %q", typ)
	}
}
