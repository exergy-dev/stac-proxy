// Package federation provides multi-origin STAC federation.
package federation

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
)

// FederatedCursor tracks pagination state across multiple origins.
type FederatedCursor struct {
	// Version for cursor format compatibility
	Version int `json:"v"`

	// Original search parameters hash
	QueryHash string `json:"q"`

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

// NewFederatedCursor creates a new federated cursor.
func NewFederatedCursor(queryHash string, originIDs []string, cfg *CursorConfig) *FederatedCursor {
	if cfg == nil {
		cfg = DefaultCursorConfig()
	}

	now := time.Now()
	cursor := &FederatedCursor{
		Version:   1,
		QueryHash: queryHash,
		Origins:   make(map[string]*OriginCursor),
		CreatedAt: now.Unix(),
		ExpiresAt: now.Add(cfg.DefaultTTL).Unix(),
	}

	for _, id := range originIDs {
		cursor.Origins[id] = &OriginCursor{
			ID: id,
		}
	}

	return cursor
}

// Encode serializes the cursor to a URL-safe string.
func (c *FederatedCursor) Encode() (string, error) {
	data, err := json.Marshal(c)
	if err != nil {
		return "", err
	}

	// Base64 URL-safe encoding
	return base64.RawURLEncoding.EncodeToString(data), nil
}

// DecodeCursor deserializes a cursor from a string.
func DecodeCursor(encoded string) (*FederatedCursor, error) {
	if encoded == "" {
		return nil, errors.New("empty cursor")
	}

	data, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("invalid cursor encoding: %w", err)
	}

	var cursor FederatedCursor
	if err := json.Unmarshal(data, &cursor); err != nil {
		return nil, fmt.Errorf("invalid cursor data: %w", err)
	}

	// Check expiration
	if time.Now().Unix() > cursor.ExpiresAt {
		return nil, errors.New("cursor expired")
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
