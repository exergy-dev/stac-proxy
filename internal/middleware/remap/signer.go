// Package remap provides URL signing for remapped URLs.
package remap

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"
)

// Signer defines the interface for URL signing.
type Signer interface {
	// Sign adds a signature to the URL with the given TTL.
	Sign(ctx context.Context, rawURL string, ttl time.Duration) string
}

// HMACSigner signs URLs using HMAC-SHA256.
//
// HMACSigner holds a *slice* of secrets to support key rotation
// without breaking in-flight signed URLs (M-remap-2):
//
//   - Sign always uses secrets[0] (the primary).
//   - Verify tries every secret in order; first match wins.
//   - RotateSecret prepends a new primary and demotes the previous
//     primaries; the rotation operator can then expire the trailing
//     entries on whatever overlap window matches the longest in-
//     flight signed-URL TTL.
//
// Concurrent calls to Sign/Verify are safe; concurrent rotation is
// serialized via the embedded mutex. The secrets slice is copied on
// rotation rather than mutated in place so live readers retain a
// consistent snapshot.
type HMACSigner struct {
	mu      sync.RWMutex
	secrets [][]byte
}

// NewHMACSigner creates a new HMAC signer with a single primary secret.
func NewHMACSigner(secret string) *HMACSigner {
	return &HMACSigner{
		secrets: [][]byte{[]byte(secret)},
	}
}

// RotateSecret prepends a new primary secret and demotes the previous
// primary. After rotation:
//   - new signatures are produced with `next`.
//   - previously-issued signatures (under any older secret) continue
//     to verify until the operator drops them by re-rotating.
//
// The slice grows unbounded; callers that perform many rotations
// should call CompactSecrets (or build a new HMACSigner) once they
// are confident no in-flight signed URLs reference an older key.
func (s *HMACSigner) RotateSecret(next []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make([][]byte, 0, len(s.secrets)+1)
	cp = append(cp, append([]byte(nil), next...))
	cp = append(cp, s.secrets...)
	s.secrets = cp
}

// snapshotSecrets returns a copy-of-pointers slice safe to iterate
// without holding the lock. The underlying byte slices are immutable
// once stored.
func (s *HMACSigner) snapshotSecrets() [][]byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([][]byte, len(s.secrets))
	copy(out, s.secrets)
	return out
}

// signingMessage builds the canonical bytes the HMAC covers. Host, path
// and query (sorted, exp included) are all bound so an attacker cannot
// swap query parameters or hostnames while keeping the signature.
//
// Side-effect-free contract (M-remap-3): the caller's url.Values is
// NOT mutated. The previous implementation deleted "sig" and reset
// "exp" on the passed map, which silently corrupted the caller's
// query (e.g. the verification path lost the original sig and could
// not log/diagnose; the sign path was lucky because it then re-set
// the values). Internally we work on a deep clone.
func signingMessage(host, urlPath string, q url.Values, expiry int64) string {
	clone := make(url.Values, len(q))
	for k, vs := range q {
		// Reuse the slice header is fine — we only call Del/Set,
		// never append to a shared slice.
		clone[k] = append([]string(nil), vs...)
	}
	// Remove the signature itself before canonicalizing; everything
	// else, including the expiry, is part of the signed input.
	clone.Del("sig")
	clone.Set("exp", fmt.Sprintf("%d", expiry))
	return strings.ToLower(host) + "\n" + canonicalPath(urlPath) + "\n" + clone.Encode()
}

// canonicalPath normalizes the URL path for signing so that
// equivalent representations produce identical signatures (M-remap-4).
//
// Without this, "/foo" and "//foo" — which most HTTP servers treat as
// the same resource — yielded different HMAC inputs. An attacker
// could not forge a *new* signature, but the inconsistency was
// confusing and adjacent to open-redirect classes of bug. Aligning
// the canonical form on path.Clean gives:
//
//   - "//foo"     -> "/foo"
//   - "/a//b"     -> "/a/b"
//   - "/a/./b"    -> "/a/b"
//   - "/a/b/.."   -> "/a"
//   - ""          -> "/" (empty path canonicalizes to root)
//
// path.Clean operates on the raw byte sequence (not URL semantics);
// percent-encoding is preserved, which matches what url.URL.Path
// stores. Trailing slash semantics are preserved (path.Clean strips
// trailing "/" only on roots, which is what we want).
func canonicalPath(p string) string {
	if p == "" {
		return "/"
	}
	cleaned := path.Clean(p)
	// path.Clean does not preserve a trailing slash on non-root
	// paths. URL semantics frequently distinguish them, but for
	// signing we treat them as equivalent — both Sign and Verify
	// pass through this function so the round-trip is consistent.
	return cleaned
}

// Sign adds an HMAC signature and expiry to the URL using the primary
// secret (secrets[0]).
func (s *HMACSigner) Sign(ctx context.Context, rawURL string, ttl time.Duration) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}

	expiry := time.Now().Add(ttl).Unix()

	q := parsed.Query()
	message := signingMessage(parsed.Host, parsed.Path, q, expiry)

	primary := s.snapshotSecrets()[0]
	mac := hmac.New(sha256.New, primary)
	mac.Write([]byte(message))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	q.Set("exp", fmt.Sprintf("%d", expiry))
	q.Set("sig", signature)
	parsed.RawQuery = q.Encode()

	return parsed.String()
}

// Verify validates an HMAC-signed URL.
//
// During key rotation Verify accepts a signature produced by ANY
// secret currently held by the signer (M-remap-2). The first match
// wins; absence of a match is reported as a single "invalid
// signature" error rather than per-key detail to avoid leaking the
// rotation history.
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

	for _, secret := range s.snapshotSecrets() {
		mac := hmac.New(sha256.New, secret)
		mac.Write([]byte(message))
		expectedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
		if hmac.Equal([]byte(sig), []byte(expectedSig)) {
			return true, nil
		}
	}
	return false, fmt.Errorf("invalid signature")
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
