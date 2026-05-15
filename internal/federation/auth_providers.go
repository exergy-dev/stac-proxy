// Package federation provides OAuth2 and AWS SigV4 auth providers.
package federation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"golang.org/x/sync/singleflight"
)

// authRoundTripper applies an AuthProvider to every outbound request
// before delegating to the wrapped RoundTripper. OAuth2 token refresh
// happens inside ApplyAuth as before.
type authRoundTripper struct {
	auth AuthProvider
	next http.RoundTripper
}

// RoundTrip implements http.RoundTripper.
func (a *authRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := a.auth.ApplyAuth(req.Context(), req); err != nil {
		return nil, err
	}
	return a.next.RoundTrip(req)
}

// OAuth2AuthProvider handles OAuth2 client credentials flow.
//
// Concurrency: token reads/writes are protected by mu, and concurrent
// refreshes collapse onto a single in-flight request via the
// singleflight group keyed by client_id. The HTTP POST runs WITHOUT
// holding mu so other callers (e.g. requests with a still-valid cached
// token) are not serialised behind the network round-trip.
type OAuth2AuthProvider struct {
	config      *OAuth2Config
	token       string
	tokenExpiry time.Time
	mu          sync.RWMutex
	httpClient  *http.Client
	refreshSF   singleflight.Group
}

// NewOAuth2AuthProvider creates a new OAuth2 auth provider.
func NewOAuth2AuthProvider(config *OAuth2Config) (*OAuth2AuthProvider, error) {
	if config.TokenURL == "" {
		return nil, fmt.Errorf("token_url is required")
	}
	if config.ClientID == "" {
		return nil, fmt.Errorf("client_id is required")
	}

	return &OAuth2AuthProvider{
		config: config,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}, nil
}

// ApplyAuth adds OAuth2 bearer token to the request.
func (p *OAuth2AuthProvider) ApplyAuth(ctx context.Context, req *http.Request) error {
	token, err := p.getToken(ctx)
	if err != nil {
		return fmt.Errorf("failed to get OAuth2 token: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return nil
}

// Refresh forces a token refresh. Concurrent Refresh / getToken callers
// share a single in-flight HTTP round-trip via singleflight.
func (p *OAuth2AuthProvider) Refresh(ctx context.Context) error {
	_, err := p.refreshOnce(ctx)
	return err
}

// getToken returns a valid token, refreshing if necessary. Returns the
// freshly-published token (never an empty string with a nil error).
func (p *OAuth2AuthProvider) getToken(ctx context.Context) (string, error) {
	p.mu.RLock()
	if p.token != "" && time.Now().Before(p.tokenExpiry.Add(-30*time.Second)) {
		token := p.token
		p.mu.RUnlock()
		return token, nil
	}
	p.mu.RUnlock()

	// Trigger (or join) a single in-flight refresh. The fetched token is
	// returned directly so the caller cannot race a concurrent Refresh
	// that overwrites p.token before we read it back.
	tok, err := p.refreshOnce(ctx)
	if err != nil {
		return "", err
	}
	return tok, nil
}

// refreshOnce coalesces concurrent refreshes into a single HTTP fetch
// keyed by client_id. The HTTP round-trip runs WITHOUT holding p.mu so
// requests with a still-valid token are not serialised behind it. On
// success the new token is published under the write lock.
func (p *OAuth2AuthProvider) refreshOnce(ctx context.Context) (string, error) {
	v, err, _ := p.refreshSF.Do(p.config.ClientID, func() (interface{}, error) {
		// Re-check under read lock — another caller may have just
		// published a fresh token while we were waiting to enter the
		// singleflight slot.
		p.mu.RLock()
		if p.token != "" && time.Now().Before(p.tokenExpiry.Add(-30*time.Second)) {
			tok := p.token
			p.mu.RUnlock()
			return tok, nil
		}
		p.mu.RUnlock()
		return p.fetchToken(ctx)
	})
	if err != nil {
		return "", err
	}
	tok, _ := v.(string)
	return tok, nil
}

// fetchToken performs the HTTP token request without holding any lock,
// then publishes the result under the write lock. Callers must already
// be inside the singleflight group so only one fetchToken runs at a
// time per client.
func (p *OAuth2AuthProvider) fetchToken(ctx context.Context) (string, error) {
	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", p.config.ClientID)
	data.Set("client_secret", p.config.ClientSecret)

	if len(p.config.Scopes) > 0 {
		data.Set("scope", joinStrings(p.config.Scopes, " "))
	}
	if p.config.Audience != "" {
		data.Set("audience", p.config.Audience)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", p.config.TokenURL,
		bytes.NewBufferString(data.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("token request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("failed to parse token response: %w", err)
	}

	expiry := time.Now().Add(1 * time.Hour)
	if tokenResp.ExpiresIn > 0 {
		expiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	}

	p.mu.Lock()
	p.token = tokenResp.AccessToken
	p.tokenExpiry = expiry
	p.mu.Unlock()

	return tokenResp.AccessToken, nil
}

// AWSSigV4Provider handles AWS Signature V4 signing.
//
// The actual canonicalisation, signing-key derivation, and header
// emission are delegated to github.com/aws/aws-sdk-go-v2/aws/signer/v4.
// The previous hand-rolled implementation forced the Host header
// without honouring non-default ports, did not URI-encode the path
// (silently failing on spaces, `+`, or non-ASCII), and only signed
// host;x-amz-date — all of which produced 403 SignatureDoesNotMatch
// from real AWS endpoints.
type AWSSigV4Provider struct {
	config *AWSSigV4Config
	signer *v4.Signer
}

// NewAWSSigV4Provider creates a new AWS SigV4 auth provider.
func NewAWSSigV4Provider(config *AWSSigV4Config) (*AWSSigV4Provider, error) {
	if config.Region == "" {
		return nil, fmt.Errorf("region is required")
	}
	if config.Service == "" {
		config.Service = "execute-api"
	}

	return &AWSSigV4Provider{
		config: config,
		signer: v4.NewSigner(),
	}, nil
}

// ApplyAuth signs the request with AWS Signature V4 via aws-sdk-go-v2.
func (p *AWSSigV4Provider) ApplyAuth(ctx context.Context, req *http.Request) error {
	// Get credentials. UseIAMRole is not yet supported (the previous
	// hand-rolled impl carried a TODO with the same behaviour); when an
	// IAM-role provider is wired in, this is the place to substitute it.
	if p.config.AccessKey == "" || p.config.SecretKey == "" {
		return fmt.Errorf("AWS credentials not configured")
	}
	// Session token is not currently exposed on AWSSigV4Config; pass
	// empty so SDK signs without an X-Amz-Security-Token header. If
	// short-lived credentials become a configuration option, plumb it
	// here.
	credProvider := credentials.NewStaticCredentialsProvider(
		p.config.AccessKey,
		p.config.SecretKey,
		"",
	)
	awsCreds, err := credProvider.Retrieve(ctx)
	if err != nil {
		return fmt.Errorf("resolve AWS credentials: %w", err)
	}

	// Buffer the body so (a) we can compute its SHA256 for the
	// X-Amz-Content-Sha256 / payload-hash inputs the signer needs, and
	// (b) downstream RoundTrip can still read it. SignHTTP does not read
	// req.Body itself.
	var bodyBytes []byte
	if req.Body != nil {
		bodyBytes, err = io.ReadAll(req.Body)
		if err != nil {
			return err
		}
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}
	sum := sha256.Sum256(bodyBytes)
	payloadHash := hex.EncodeToString(sum[:])

	// Set the content hash header explicitly. SignHTTP itself does not
	// set X-Amz-Content-Sha256 (it is a service-specific concern), but
	// S3 and several other services require it on the wire and many
	// services include it in SignedHeaders when present. Setting it
	// before signing keeps the canonical request consistent.
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)

	return p.signer.SignHTTP(
		ctx,
		awsCreds,
		req,
		payloadHash,
		p.config.Service,
		p.config.Region,
		time.Now(),
	)
}

// Refresh does nothing for SigV4 (credentials refreshed per-request).
func (p *AWSSigV4Provider) Refresh(ctx context.Context) error {
	return nil
}

// Helper functions

func joinStrings(strs []string, sep string) string {
	if len(strs) == 0 {
		return ""
	}
	result := strs[0]
	for _, s := range strs[1:] {
		result += sep + s
	}
	return result
}
