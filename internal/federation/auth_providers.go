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
)

// OAuth2AuthProvider handles OAuth2 client credentials flow.
type OAuth2AuthProvider struct {
	config      *OAuth2Config
	token       string
	tokenExpiry time.Time
	mu          sync.RWMutex
	httpClient  *http.Client
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

// Refresh forces a token refresh.
func (p *OAuth2AuthProvider) Refresh(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.refreshToken(ctx)
}

// getToken returns a valid token, refreshing if necessary.
func (p *OAuth2AuthProvider) getToken(ctx context.Context) (string, error) {
	p.mu.RLock()
	if p.token != "" && time.Now().Before(p.tokenExpiry.Add(-30*time.Second)) {
		token := p.token
		p.mu.RUnlock()
		return token, nil
	}
	p.mu.RUnlock()

	p.mu.Lock()
	defer p.mu.Unlock()

	// Double-check after acquiring write lock
	if p.token != "" && time.Now().Before(p.tokenExpiry.Add(-30*time.Second)) {
		return p.token, nil
	}

	return p.token, p.refreshToken(ctx)
}

// refreshToken fetches a new token from the OAuth2 server.
func (p *OAuth2AuthProvider) refreshToken(ctx context.Context) error {
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
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("token request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return fmt.Errorf("failed to parse token response: %w", err)
	}

	p.token = tokenResp.AccessToken
	if tokenResp.ExpiresIn > 0 {
		p.tokenExpiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	} else {
		p.tokenExpiry = time.Now().Add(1 * time.Hour)
	}

	return nil
}

// AWSSigV4Provider handles AWS Signature V4 signing.
type AWSSigV4Provider struct {
	config *AWSSigV4Config
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
	}, nil
}

// ApplyAuth signs the request with AWS Signature V4.
func (p *AWSSigV4Provider) ApplyAuth(ctx context.Context, req *http.Request) error {
	// Read the body if present
	var bodyBytes []byte
	if req.Body != nil {
		var err error
		bodyBytes, err = io.ReadAll(req.Body)
		if err != nil {
			return err
		}
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}

	// Get credentials
	accessKey := p.config.AccessKey
	secretKey := p.config.SecretKey

	if p.config.UseIAMRole {
		// TODO: Implement IAM role credential fetching
		// For now, fall back to configured credentials
	}

	if accessKey == "" || secretKey == "" {
		return fmt.Errorf("AWS credentials not configured")
	}

	// Sign the request
	now := time.Now().UTC()
	dateStamp := now.Format("20060102")
	amzDate := now.Format("20060102T150405Z")

	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("Host", req.URL.Host)

	// Create canonical request
	canonicalURI := req.URL.Path
	if canonicalURI == "" {
		canonicalURI = "/"
	}
	canonicalQueryString := req.URL.RawQuery

	signedHeaders := "host;x-amz-date"
	canonicalHeaders := fmt.Sprintf("host:%s\nx-amz-date:%s\n", req.URL.Host, amzDate)

	payloadHash := sha256Hash(bodyBytes)
	canonicalRequest := fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s",
		req.Method,
		canonicalURI,
		canonicalQueryString,
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	)

	// Create string to sign
	algorithm := "AWS4-HMAC-SHA256"
	credentialScope := fmt.Sprintf("%s/%s/%s/aws4_request", dateStamp, p.config.Region, p.config.Service)
	stringToSign := fmt.Sprintf("%s\n%s\n%s\n%s",
		algorithm,
		amzDate,
		credentialScope,
		sha256Hash([]byte(canonicalRequest)),
	)

	// Calculate signature
	signingKey := getSignatureKey(secretKey, dateStamp, p.config.Region, p.config.Service)
	signature := hex.EncodeToString(hmacSHA256(signingKey, []byte(stringToSign)))

	// Add authorization header
	authHeader := fmt.Sprintf("%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		algorithm,
		accessKey,
		credentialScope,
		signedHeaders,
		signature,
	)
	req.Header.Set("Authorization", authHeader)

	return nil
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

func sha256Hash(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func hmacSHA256(key, data []byte) []byte {
	// Simple HMAC-SHA256 implementation
	// In production, use crypto/hmac
	h := sha256.New()

	// Pad key
	if len(key) > 64 {
		h.Write(key)
		key = h.Sum(nil)
		h.Reset()
	}
	if len(key) < 64 {
		padded := make([]byte, 64)
		copy(padded, key)
		key = padded
	}

	// Inner hash
	ipad := make([]byte, 64)
	opad := make([]byte, 64)
	for i := 0; i < 64; i++ {
		ipad[i] = key[i] ^ 0x36
		opad[i] = key[i] ^ 0x5c
	}

	h.Write(ipad)
	h.Write(data)
	inner := h.Sum(nil)

	h.Reset()
	h.Write(opad)
	h.Write(inner)
	return h.Sum(nil)
}

func getSignatureKey(secretKey, dateStamp, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secretKey), []byte(dateStamp))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))
	return kSigning
}
