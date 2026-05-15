// Package auth provides authentication middleware and providers.
package auth

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"strings"
)

// MTLSProvider validates client certificates for mTLS authentication.
type MTLSProvider struct {
	name            string
	trustedCAs      *x509.CertPool
	requireClientCA bool
	subjectMapper   SubjectMapper
}

// MTLSConfig configures the mTLS provider.
type MTLSConfig struct {
	Name            string
	TrustedCAs      *x509.CertPool
	RequireClientCA bool
	SubjectMapper   SubjectMapper
}

// SubjectMapper maps certificate subject to principal attributes.
type SubjectMapper interface {
	MapSubject(cert *x509.Certificate) (*Principal, error)
}

// DefaultSubjectMapper provides default certificate to principal mapping.
type DefaultSubjectMapper struct{}

// NewMTLSProvider creates a new mTLS authentication provider.
func NewMTLSProvider(cfg MTLSConfig) (*MTLSProvider, error) {
	return &MTLSProvider{
		name:            cfg.Name,
		trustedCAs:      cfg.TrustedCAs,
		requireClientCA: cfg.RequireClientCA,
		subjectMapper:   cfg.SubjectMapper,
	}, nil
}

// Name returns the provider name.
func (p *MTLSProvider) Name() string {
	return p.name
}

// ClaimsCredential reports whether the request presented a client
// certificate via TLS. See CredentialClaimer for the fail-closed
// contract — a presented but unverifiable client cert must not be
// downgraded to anonymous.
func (p *MTLSProvider) ClaimsCredential(req *http.Request) bool {
	return req.TLS != nil && len(req.TLS.PeerCertificates) > 0
}

// Authenticate validates a client certificate.
func (p *MTLSProvider) Authenticate(ctx context.Context, req *http.Request) (*Principal, error) {
	// Extract client certificate from TLS connection state
	if req.TLS == nil || len(req.TLS.PeerCertificates) == 0 {
		return nil, nil // No client certificate
	}

	cert := req.TLS.PeerCertificates[0]

	// Verify the certificate if we have trusted CAs
	if p.trustedCAs != nil {
		opts := x509.VerifyOptions{
			Roots:     p.trustedCAs,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}

		if _, err := cert.Verify(opts); err != nil {
			return nil, errors.New("certificate verification failed")
		}
	}

	// Map certificate to principal
	if p.subjectMapper != nil {
		return p.subjectMapper.MapSubject(cert)
	}

	// Default mapping
	return defaultMapSubject(cert), nil
}

// MapSubject implements default certificate subject mapping.
func (m *DefaultSubjectMapper) MapSubject(cert *x509.Certificate) (*Principal, error) {
	return defaultMapSubject(cert), nil
}

// defaultMapSubject creates a principal from certificate subject.
func defaultMapSubject(cert *x509.Certificate) *Principal {
	principal := &Principal{
		Type:       "certificate",
		Attributes: make(map[string]string),
	}

	// Use subject CN as ID
	if cert.Subject.CommonName != "" {
		principal.ID = cert.Subject.CommonName
	} else if len(cert.EmailAddresses) > 0 {
		principal.ID = cert.EmailAddresses[0]
	} else if len(cert.DNSNames) > 0 {
		principal.ID = cert.DNSNames[0]
	}

	// Extract organization as roles
	if len(cert.Subject.Organization) > 0 {
		principal.Roles = cert.Subject.Organization
	}

	// Add certificate metadata to attributes
	principal.Attributes["subject_dn"] = cert.Subject.String()
	principal.Attributes["issuer_dn"] = cert.Issuer.String()
	principal.Attributes["serial_number"] = cert.SerialNumber.String()
	principal.Attributes["not_before"] = cert.NotBefore.Format("2006-01-02T15:04:05Z")
	principal.Attributes["not_after"] = cert.NotAfter.Format("2006-01-02T15:04:05Z")

	if len(cert.EmailAddresses) > 0 {
		principal.Attributes["email"] = cert.EmailAddresses[0]
	}

	if len(cert.Subject.OrganizationalUnit) > 0 {
		principal.Attributes["ou"] = strings.Join(cert.Subject.OrganizationalUnit, ",")
	}

	// Extract SANs
	var sans []string
	sans = append(sans, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		sans = append(sans, ip.String())
	}
	for _, uri := range cert.URIs {
		sans = append(sans, uri.String())
	}
	if len(sans) > 0 {
		principal.Attributes["sans"] = strings.Join(sans, ",")
	}

	return principal
}

// CertificateFromPEM parses a PEM-encoded certificate.
func CertificateFromPEM(pemData []byte) (*x509.Certificate, error) {
	return x509.ParseCertificate(pemData)
}

// LoadCertPool loads certificates from PEM data into a cert pool.
func LoadCertPool(pemData []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemData) {
		return nil, errors.New("failed to parse any certificates")
	}
	return pool, nil
}

// ExtractSPIFFEID extracts SPIFFE ID from certificate URIs.
func ExtractSPIFFEID(cert *x509.Certificate) string {
	for _, uri := range cert.URIs {
		if strings.HasPrefix(uri.String(), "spiffe://") {
			return uri.String()
		}
	}
	return ""
}

// SPIFFESubjectMapper maps SPIFFE IDs to principals.
type SPIFFESubjectMapper struct {
	TrustDomains []string
}

// MapSubject maps a SPIFFE certificate to a principal.
func (m *SPIFFESubjectMapper) MapSubject(cert *x509.Certificate) (*Principal, error) {
	spiffeID := ExtractSPIFFEID(cert)
	if spiffeID == "" {
		return nil, errors.New("no SPIFFE ID found in certificate")
	}

	// Validate trust domain if configured
	if len(m.TrustDomains) > 0 {
		trusted := false
		for _, td := range m.TrustDomains {
			if strings.HasPrefix(spiffeID, "spiffe://"+td+"/") {
				trusted = true
				break
			}
		}
		if !trusted {
			return nil, errors.New("SPIFFE ID not from trusted domain")
		}
	}

	// Parse SPIFFE ID for workload identity
	parts := strings.SplitN(spiffeID, "/", 4)
	var workload string
	if len(parts) >= 4 {
		workload = parts[3]
	}

	return &Principal{
		ID:   spiffeID,
		Type: "spiffe",
		Attributes: map[string]string{
			"spiffe_id": spiffeID,
			"workload":  workload,
		},
	}, nil
}
