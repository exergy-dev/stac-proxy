// Package federation provides multi-origin STAC federation.
package federation

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Sentinel errors for cursor decoding. Callers can use errors.Is to
// distinguish a malformed cursor from a tampered one from a
// principal/origin mismatch.
var (
	// ErrCursorInvalid is returned when the cursor token is structurally
	// malformed (not two base64 parts, invalid base64, invalid JSON).
	ErrCursorInvalid = errors.New("cursor: invalid")

	// ErrCursorTampered is returned when the HMAC signature does not
	// match the payload (key mismatch or payload was modified).
	ErrCursorTampered = errors.New("cursor: signature mismatch")

	// ErrCursorExpired is returned when the cursor's ExpiresAt is in the
	// past.
	ErrCursorExpired = errors.New("cursor: expired")

	// ErrCursorPrincipalMismatch is returned when the cursor was issued
	// for a different principal than the one making the current request.
	ErrCursorPrincipalMismatch = errors.New("cursor: principal mismatch")

	// ErrCursorOriginURLNotAllowed is returned when an OriginCursor's
	// NextURL does not begin with the configured origin BaseURL. This
	// guards against SSRF/authz bypass via tampered NextURLs.
	ErrCursorOriginURLNotAllowed = errors.New("cursor: origin NextURL not allowed")

	// ErrCursorSecretMissing is returned when Encode or DecodeCursor is
	// called with an empty secret.
	ErrCursorSecretMissing = errors.New("cursor: secret required")
)

// FederatedCursor tracks pagination state across multiple origins.
type FederatedCursor struct {
	// Version for cursor format compatibility
	Version int `json:"v"`

	// Original search parameters hash
	QueryHash string `json:"q"`

	// PrincipalHash binds the cursor to the principal that originally
	// requested it. Empty == anonymous. See PrincipalHash().
	PrincipalHash string `json:"ph,omitempty"`

	// Per-origin cursor state
	Origins map[string]*OriginCursor `json:"o"`

	// Global state
	TotalReturned int   `json:"tr"`
	CreatedAt     int64 `json:"ca"`
	ExpiresAt     int64 `json:"ea"`

	// Sort state for merge-sort pagination
	LastSortValues []interface{} `json:"lsv,omitempty"`
}

// OriginCursor tracks pagination state for a single origin.
type OriginCursor struct {
	// Origin ID
	ID string `json:"id"`

	// Next page token/URL from the origin
	NextToken string `json:"nt,omitempty"`
	NextURL   string `json:"nu,omitempty"`

	// Offset-based pagination
	Offset int `json:"off,omitempty"`

	// State
	Exhausted bool `json:"ex"`
	Error     bool `json:"err"`

	// Items returned so far from this origin
	ItemCount int `json:"ic"`

	// Last sort value for merge-sort
	LastSortValue interface{} `json:"lsv,omitempty"`
}

// CursorConfig contains cursor configuration.
type CursorConfig struct {
	DefaultTTL time.Duration
	MaxTTL     time.Duration
	SecretKey  []byte // For HMAC signing
}

// DefaultCursorConfig returns default cursor configuration.
func DefaultCursorConfig() *CursorConfig {
	return &CursorConfig{
		DefaultTTL: 1 * time.Hour,
		MaxTTL:     24 * time.Hour,
	}
}

// PrincipalHash returns a short stable hash binding a cursor to a
// principal. Empty input returns empty output (anonymous). The output
// is 16 hex chars of sha256(principalID)[:8].
func PrincipalHash(principalID string) string {
	if principalID == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(principalID))
	return hex.EncodeToString(sum[:8])
}

// NewFederatedCursor creates a new federated cursor bound to the given
// principal hash. queryHash should be the output of hashSearchRequest;
// principalHash should be the output of PrincipalHash (or "" for
// anonymous).
func NewFederatedCursor(queryHash, principalHash string, originIDs []string, cfg *CursorConfig) *FederatedCursor {
	if cfg == nil {
		cfg = DefaultCursorConfig()
	}

	now := time.Now()
	cursor := &FederatedCursor{
		Version:       1,
		QueryHash:     queryHash,
		PrincipalHash: principalHash,
		Origins:       make(map[string]*OriginCursor),
		CreatedAt:     now.Unix(),
		ExpiresAt:     now.Add(cfg.DefaultTTL).Unix(),
	}

	for _, id := range originIDs {
		cursor.Origins[id] = &OriginCursor{
			ID: id,
		}
	}

	return cursor
}

// Encode serializes and signs the cursor. The token format is:
//
//	base64url(payload-json) + "." + base64url(hmac-sha256(payload-json, secret))
//
// secret must be non-empty.
func (c *FederatedCursor) Encode(secret []byte) (string, error) {
	if len(secret) == 0 {
		return "", ErrCursorSecretMissing
	}
	data, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("cursor: marshal: %w", err)
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(data)
	sig := mac.Sum(nil)

	payload := base64.RawURLEncoding.EncodeToString(data)
	signature := base64.RawURLEncoding.EncodeToString(sig)
	return payload + "." + signature, nil
}

// DecodeCursor parses, verifies HMAC, and validates the cursor against
// the calling principal and the configured origin allowlist. It checks:
//  1. token format (two base64url parts separated by ".")
//  2. HMAC over the payload matches signature
//  3. cursor not expired
//  4. cursor.PrincipalHash matches the supplied principalHash
//  5. for each OriginCursor.NextURL: either empty OR prefixed by allowed[OriginCursor.ID]
//
// allowed is originID -> originBaseURL. principalHash empty == anonymous request.
func DecodeCursor(encoded string, secret []byte, allowed map[string]string, principalHash string) (*FederatedCursor, error) {
	if encoded == "" {
		return nil, fmt.Errorf("%w: empty cursor", ErrCursorInvalid)
	}
	if len(secret) == 0 {
		return nil, ErrCursorSecretMissing
	}

	parts := strings.Split(encoded, ".")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return nil, fmt.Errorf("%w: token must have payload and signature", ErrCursorInvalid)
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: payload base64: %v", ErrCursorInvalid, err)
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: signature base64: %v", ErrCursorInvalid, err)
	}

	mac := hmac.New(sha256.New, secret)
	mac.Write(payload)
	expected := mac.Sum(nil)
	if !hmac.Equal(expected, signature) {
		return nil, ErrCursorTampered
	}

	var cursor FederatedCursor
	if err := json.Unmarshal(payload, &cursor); err != nil {
		return nil, fmt.Errorf("%w: payload JSON: %v", ErrCursorInvalid, err)
	}

	if time.Now().Unix() > cursor.ExpiresAt {
		return nil, ErrCursorExpired
	}

	if cursor.PrincipalHash != principalHash {
		return nil, ErrCursorPrincipalMismatch
	}

	for _, oc := range cursor.Origins {
		if oc == nil || oc.NextURL == "" {
			continue
		}
		base, ok := allowed[oc.ID]
		if !ok || base == "" || !strings.HasPrefix(oc.NextURL, base) {
			return nil, fmt.Errorf("%w: origin=%s url=%s", ErrCursorOriginURLNotAllowed, oc.ID, oc.NextURL)
		}
	}

	return &cursor, nil
}

// IsExpired checks if the cursor has expired. A cursor is considered
// expired at the boundary (now >= ExpiresAt) so callers don't need
// sub-second precision to detect the transition.
func (c *FederatedCursor) IsExpired() bool {
	return time.Now().Unix() >= c.ExpiresAt
}

// HasMore returns true if any origin has more results.
func (c *FederatedCursor) HasMore() bool {
	for _, origin := range c.Origins {
		if !origin.Exhausted && !origin.Error {
			return true
		}
	}
	return false
}

// ActiveOrigins returns origins that have more results.
func (c *FederatedCursor) ActiveOrigins() []string {
	var active []string
	for id, origin := range c.Origins {
		if !origin.Exhausted && !origin.Error {
			active = append(active, id)
		}
	}
	sort.Strings(active)
	return active
}

// MarkExhausted marks an origin as having no more results.
func (c *FederatedCursor) MarkExhausted(originID string) {
	if origin, ok := c.Origins[originID]; ok {
		origin.Exhausted = true
		origin.NextToken = ""
		origin.NextURL = ""
	}
}

// MarkError marks an origin as having encountered an error.
func (c *FederatedCursor) MarkError(originID string) {
	if origin, ok := c.Origins[originID]; ok {
		origin.Error = true
	}
}

// UpdateOrigin updates cursor state for an origin after fetching results.
func (c *FederatedCursor) UpdateOrigin(originID string, itemCount int, nextToken, nextURL string, lastSortValue interface{}) {
	origin, ok := c.Origins[originID]
	if !ok {
		origin = &OriginCursor{ID: originID}
		c.Origins[originID] = origin
	}

	origin.ItemCount += itemCount
	origin.NextToken = nextToken
	origin.NextURL = nextURL
	origin.LastSortValue = lastSortValue

	if nextToken == "" && nextURL == "" {
		origin.Exhausted = true
	}
}

// UpdateOffset updates offset-based pagination for an origin.
func (c *FederatedCursor) UpdateOffset(originID string, newOffset int) {
	if origin, ok := c.Origins[originID]; ok {
		origin.Offset = newOffset
	}
}

// Clone creates a deep copy of the cursor.
func (c *FederatedCursor) Clone() *FederatedCursor {
	clone := &FederatedCursor{
		Version:       c.Version,
		QueryHash:     c.QueryHash,
		PrincipalHash: c.PrincipalHash,
		Origins:       make(map[string]*OriginCursor),
		TotalReturned: c.TotalReturned,
		CreatedAt:     c.CreatedAt,
		ExpiresAt:     c.ExpiresAt,
	}

	for id, origin := range c.Origins {
		clone.Origins[id] = &OriginCursor{
			ID:            origin.ID,
			NextToken:     origin.NextToken,
			NextURL:       origin.NextURL,
			Offset:        origin.Offset,
			Exhausted:     origin.Exhausted,
			Error:         origin.Error,
			ItemCount:     origin.ItemCount,
			LastSortValue: origin.LastSortValue,
		}
	}

	if c.LastSortValues != nil {
		clone.LastSortValues = make([]interface{}, len(c.LastSortValues))
		copy(clone.LastSortValues, c.LastSortValues)
	}

	return clone
}

// GetOriginCursor returns the cursor for a specific origin.
func (c *FederatedCursor) GetOriginCursor(originID string) *OriginCursor {
	return c.Origins[originID]
}

// String returns a human-readable representation.
func (c *FederatedCursor) String() string {
	active := c.ActiveOrigins()
	return fmt.Sprintf("FederatedCursor{version=%d, active=%d/%d, returned=%d}",
		c.Version, len(active), len(c.Origins), c.TotalReturned)
}
