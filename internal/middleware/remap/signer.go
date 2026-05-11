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

// Sign adds an HMAC signature and expiry to the URL.
func (s *HMACSigner) Sign(ctx context.Context, rawURL string, ttl time.Duration) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}

	// Calculate expiry
	expiry := time.Now().Add(ttl).Unix()

	// Create signature
	message := fmt.Sprintf("%s:%d", parsed.Path, expiry)
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(message))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	// Add to query string
	q := parsed.Query()
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

	// Check expiry
	if time.Now().Unix() > expiry {
		return false, fmt.Errorf("signature expired")
	}

	// Verify signature
	message := fmt.Sprintf("%s:%s", parsed.Path, expStr)
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(message))
	expectedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(sig), []byte(expectedSig)) {
		return false, fmt.Errorf("invalid signature")
	}

	return true, nil
}

// CloudFrontSigner signs URLs for AWS CloudFront.
type CloudFrontSigner struct {
	keyPairID  string
	privateKey []byte
}

// NewCloudFrontSigner creates a new CloudFront signer.
func NewCloudFrontSigner(keyPairID string, privateKey []byte) *CloudFrontSigner {
	return &CloudFrontSigner{
		keyPairID:  keyPairID,
		privateKey: privateKey,
	}
}

// Sign creates a CloudFront signed URL.
func (s *CloudFrontSigner) Sign(ctx context.Context, rawURL string, ttl time.Duration) string {
	// Simplified implementation - in production use AWS SDK
	expiry := time.Now().Add(ttl).Unix()

	// Create policy
	policy := fmt.Sprintf(`{"Statement":[{"Resource":"%s","Condition":{"DateLessThan":{"AWS:EpochTime":%d}}}]}`,
		rawURL, expiry)

	// Sign policy (simplified - use proper RSA signing in production)
	signature := base64.RawURLEncoding.EncodeToString([]byte(policy))
	signature = strings.ReplaceAll(signature, "+", "-")
	signature = strings.ReplaceAll(signature, "=", "_")
	signature = strings.ReplaceAll(signature, "/", "~")

	// Build signed URL
	separator := "?"
	if strings.Contains(rawURL, "?") {
		separator = "&"
	}

	return fmt.Sprintf("%s%sExpires=%d&Signature=%s&Key-Pair-Id=%s",
		rawURL, separator, expiry, signature, s.keyPairID)
}

// NoOpSigner is a signer that doesn't modify URLs.
type NoOpSigner struct{}

// Sign returns the URL unchanged.
func (s *NoOpSigner) Sign(ctx context.Context, rawURL string, ttl time.Duration) string {
	return rawURL
}

// S3PresignedSigner creates pre-signed S3 URLs.
type S3PresignedSigner struct {
	accessKey string
	secretKey string
	region    string
}

// NewS3PresignedSigner creates a new S3 pre-signed URL signer.
func NewS3PresignedSigner(accessKey, secretKey, region string) *S3PresignedSigner {
	return &S3PresignedSigner{
		accessKey: accessKey,
		secretKey: secretKey,
		region:    region,
	}
}

// Sign creates an S3 pre-signed URL.
func (s *S3PresignedSigner) Sign(ctx context.Context, rawURL string, ttl time.Duration) string {
	// This is a simplified implementation
	// In production, use the AWS SDK to generate proper pre-signed URLs
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}

	// Only sign S3 URLs
	if !strings.HasPrefix(rawURL, "s3://") && !strings.Contains(parsed.Host, "s3") {
		return rawURL
	}

	// Add expiry and simplified signature
	expiry := time.Now().Add(ttl).Unix()
	q := parsed.Query()
	q.Set("X-Amz-Expires", fmt.Sprintf("%d", int(ttl.Seconds())))
	q.Set("X-Amz-Date", time.Now().UTC().Format("20060102T150405Z"))
	parsed.RawQuery = q.Encode()

	_ = expiry // In real implementation, use this for signature

	return parsed.String()
}
