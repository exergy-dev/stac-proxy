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

	"github.com/yourorg/stac-proxy/internal/stac"
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

// currentCursorVersion is the format version stamped onto every cursor
// the proxy mints. Decoders accept any version that round-trips
// through encoding/json without unknown-field errors — we bump the
// version when adding new semantic state (v1 → v2 added prev/first
// link plumbing) so logs / dashboards / future migrations can tell
// cursor generations apart, not because we reject old shapes.
const currentCursorVersion = 2

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

	// PrevCursor is the encoded cursor that produced THIS page. When
	// the response is the first page (no incoming cursor), this is
	// empty. The proxy uses it to emit `rel: prev` links and to key
	// the page cache for backwards-navigation lookups.
	PrevCursor string `json:"pc,omitempty"`

	// FirstCursor is the encoded cursor for page 0 of this chain.
	// Fixed for the lifetime of a pagination session so `rel: first`
	// links keep working from any page. Empty on page 0 itself
	// (there's nothing to navigate "first" to from the first page).
	FirstCursor string `json:"fc,omitempty"`

	// PageSeq is the 0-indexed page number for this cursor. Used by
	// the link emitter to decide whether `rel: first` is meaningful
	// (only when PageSeq > 0).
	PageSeq int `json:"ps,omitempty"`
}

// OriginCursor tracks pagination state for a single origin.
type OriginCursor struct {
	// Origin ID
	ID string `json:"id"`

	// Next page token/URL from the origin
	NextToken string `json:"nt,omitempty"`
	NextURL   string `json:"nu,omitempty"`

	// NextBody is the verbatim POST body captured from upstream's
	// rel=next link by the post_body adapter. When set (alongside
	// NextURL), the next page POSTs NextURL with this body instead of
	// GETting NextURL or POSTing /search with the proxy-rebuilt body.
	NextBody []byte `json:"nb,omitempty"`

	// Offset-based pagination
	Offset int `json:"off,omitempty"`

	// AdapterName locks this origin's pagination convention for the
	// cursor's lifetime. Populated by the `auto` pagination adapter
	// after its first successful probe; empty for origins configured
	// with an explicit named adapter (those don't need locking).
	// Subsequent pages route to the named adapter directly.
	AdapterName string `json:"ad,omitempty"`

	// State
	Exhausted bool `json:"ex"`
	Error     bool `json:"err"`
	// ErrorCount is the number of pages on which this origin's fetch
	// failed. Errored origins are retried on subsequent pages until
	// maxOriginErrorRetries — a transient blip (or a circuit breaker
	// in its open window) must not silently drop an origin from the
	// rest of a paginated session, but an origin that fails every
	// page must not keep the session alive forever either.
	ErrorCount int `json:"ec,omitempty"`

	// Items returned so far from this origin
	ItemCount int `json:"ic"`

	// Last sort value for merge-sort
	LastSortValue interface{} `json:"lsv,omitempty"`

	// Stash holds items that were fetched from this origin on a
	// previous page but not emitted because the merge-sort trim
	// favored items from another origin with newer datetimes. The
	// next page consumes Stash first, BEFORE re-fetching from
	// upstream, so the items aren't lost. Without this, the per-origin
	// cursor (NextToken/NextURL/NextBody) advances past the
	// already-fetched items, dropping the un-emitted ones forever.
	Stash []*stac.Item `json:"st,omitempty"`
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
		Version:       currentCursorVersion,
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

// maxOriginErrorRetries bounds how many pages an origin may fail on
// before it is permanently dropped from the session. Retrying at all
// matters because origin failures are frequently transient (breaker
// open window, deploy blip); the bound matters because a dead origin
// must not emit `rel: next` links forever.
const maxOriginErrorRetries = 3

// retired reports whether an origin is permanently out of the
// session: it failed on maxOriginErrorRetries pages.
func (o *OriginCursor) retired() bool {
	return o.Error && o.ErrorCount >= maxOriginErrorRetries
}

// HasMore returns true if any origin has more results — either
// un-fetched upstream pages remain, or a stash of previously-fetched
// items is queued for emit on the next page. Errored-but-not-retired
// origins count: they are retried on the next page.
func (c *FederatedCursor) HasMore() bool {
	for _, origin := range c.Origins {
		if origin.retired() {
			continue
		}
		if !origin.Exhausted || len(origin.Stash) > 0 {
			return true
		}
	}
	return false
}

// ActiveOrigins returns origins that have more results — same rule
// as HasMore. An origin whose upstream is exhausted but whose stash
// still has items is "active" for the merge phase (mergeResults will
// consume from its Stash); it just won't be fetched again.
func (c *FederatedCursor) ActiveOrigins() []string {
	var active []string
	for id, origin := range c.Origins {
		if origin.retired() {
			continue
		}
		if !origin.Exhausted || len(origin.Stash) > 0 {
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
		origin.NextBody = nil
	}
}

// MarkError marks an origin as having encountered an error on this
// page. The origin is retried on subsequent pages until ErrorCount
// reaches maxOriginErrorRetries.
func (c *FederatedCursor) MarkError(originID string) {
	if origin, ok := c.Origins[originID]; ok {
		origin.Error = true
		origin.ErrorCount++
	}
}

// UpdateOrigin updates cursor state for an origin after fetching results.
func (c *FederatedCursor) UpdateOrigin(originID string, itemCount int, nextToken, nextURL string, lastSortValue interface{}) {
	c.UpdateOriginState(originID, OriginUpdate{
		ItemCount:     itemCount,
		NextToken:     nextToken,
		NextURL:       nextURL,
		LastSortValue: lastSortValue,
	})
}

// OriginUpdate carries the fields UpdateOriginState applies to an
// OriginCursor. New fields go here rather than on UpdateOrigin's
// argument list so subsequent additions don't ripple through every
// caller — and so callers can supply only the fields they know about
// (zero values are skipped where the distinction matters).
type OriginUpdate struct {
	ItemCount     int
	NextToken     string
	NextURL       string
	NextBody      []byte
	Offset        int
	AdapterName   string // only written when non-empty (auto's lock decision)
	LastSortValue interface{}
}

// UpdateOriginState is the rich-argument form of UpdateOrigin. Pagination
// adapters that need to record an offset or lock an adapter name use
// this; the simpler UpdateOrigin remains for token-style updates.
func (c *FederatedCursor) UpdateOriginState(originID string, u OriginUpdate) {
	origin, ok := c.Origins[originID]
	if !ok {
		origin = &OriginCursor{ID: originID}
		c.Origins[originID] = origin
	}

	origin.ItemCount += u.ItemCount
	origin.NextToken = u.NextToken
	origin.NextURL = u.NextURL
	origin.NextBody = u.NextBody
	origin.Offset = u.Offset
	origin.LastSortValue = u.LastSortValue
	// A successful fetch clears the transient-error state — the retry
	// budget is for consecutive-page failures, not lifetime ones.
	origin.Error = false
	origin.ErrorCount = 0
	// AdapterName is sticky: once locked (auto's choice), don't
	// overwrite on subsequent updates with an empty string. The named
	// adapter's response will not re-emit the adapter name.
	if u.AdapterName != "" {
		origin.AdapterName = u.AdapterName
	}

	if u.NextToken == "" && u.NextURL == "" && u.Offset == 0 && len(u.NextBody) == 0 {
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
		PrevCursor:    c.PrevCursor,
		FirstCursor:   c.FirstCursor,
		PageSeq:       c.PageSeq,
	}

	for id, origin := range c.Origins {
		oc := &OriginCursor{
			ID:            origin.ID,
			NextToken:     origin.NextToken,
			NextURL:       origin.NextURL,
			Offset:        origin.Offset,
			AdapterName:   origin.AdapterName,
			Exhausted:     origin.Exhausted,
			Error:         origin.Error,
			ItemCount:     origin.ItemCount,
			LastSortValue: origin.LastSortValue,
		}
		if len(origin.NextBody) > 0 {
			oc.NextBody = append([]byte(nil), origin.NextBody...)
		}
		if len(origin.Stash) > 0 {
			oc.Stash = append([]*stac.Item(nil), origin.Stash...)
		}
		clone.Origins[id] = oc
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
