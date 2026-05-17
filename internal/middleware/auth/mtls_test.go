package auth

import (
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestMTLSProvider_ConstructorRejectsNilCAs guards the safety contract
// (HIGH H-auth-4): NewMTLSProvider must refuse a nil trustedCAs pool.
// The previous implementation silently skipped certificate
// verification when trustedCAs was nil, which is the worst possible
// failure mode for an mTLS check (any presented client cert
// authenticates).
func TestMTLSProvider_ConstructorRejectsNilCAs(t *testing.T) {
	t.Parallel()

	_, err := NewMTLSProvider(MTLSConfig{
		Name:       "mtls",
		TrustedCAs: nil,
	})
	require.Error(t, err, "expected error for nil trustedCAs")
}

// TestMTLSProvider_ConstructorAcceptsEmptyButNonNilCAs documents the
// boundary: an empty pool is a *configured* empty trust set (every
// cert will fail verification), which is safe — only nil is refused.
func TestMTLSProvider_ConstructorAcceptsEmptyButNonNilCAs(t *testing.T) {
	t.Parallel()

	p, err := NewMTLSProvider(MTLSConfig{
		Name:       "mtls",
		TrustedCAs: x509.NewCertPool(),
	})
	require.NoError(t, err, "unexpected error for empty (but non-nil) pool")
	require.NotNil(t, p, "expected provider")
}
