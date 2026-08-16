// Package pagecache stores rendered federated-search pages keyed by
// the proxy-issued cursor that produced them. The federation paginator
// uses it to serve backwards navigation (`rel: prev`, `rel: first`)
// without re-executing the upstream fan-out: when a client follows a
// prev link, the proxy looks up the previous page's bytes here.
//
// # Keying
//
// Entries are keyed by:
//
//	hmac(secret, signaturePart(cursor) || principalHash)
//
// where signaturePart is the second component of the encoded cursor
// (`<payload>.<signature>` — the HMAC of the payload, already
// principal-bound by the cursor encoder). Using the signature as the
// keying material means:
//
//   - The cache key is a stable opaque token derived from the
//     authenticated cursor, never from raw user input.
//   - A tampered cursor that fails HMAC verification at the cursor
//     decoder will never reach the cache (the paginator only calls
//     Get after DecodeCursor succeeds).
//   - Mixing in the principalHash defends against a cache key that
//     is otherwise identical for two principals with disjoint
//     visibility — even though the existing cursor encoder already
//     binds to principal, the second-pass HMAC here means a leaked
//     cache key cannot be replayed against a different principal.
//
// # Invalidation
//
// Cache TTL is bounded by the cursor's remaining lifetime — entries
// can never outlive the cursor that keys them. The paginator computes
// `min(configured TTL, cursor.ExpiresAt - now)` and passes it to Put.
//
// # Correctness role
//
// The cache is purely an optimisation. A cache miss falls through to
// a fresh paginator execution, which produces the same items given the
// same cursor (federated pagination is deterministic per cursor).
// Correctness never depends on the cache having an entry.
package pagecache

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/exergy-dev/stac-proxy/internal/stac"
)

// SearchResult is a JSON-serializable carrier for the federated
// search result the paginator hands to the handler. It mirrors
// federation.SearchResult but lives here so this package doesn't
// import federation (which would be a cycle: federation imports
// pagecache). The paginator converts between the two at the cache
// boundary.
type SearchResult struct {
	Items       []*stac.Item `json:"items"`
	TotalCount  int          `json:"tc,omitempty"`
	NextCursor  string       `json:"nc,omitempty"`
	PrevCursor  string       `json:"pc,omitempty"`
	FirstCursor string       `json:"fc,omitempty"`
	SelfCursor  string       `json:"sc,omitempty"`
	// Context is the per-origin status block; preserved as a raw
	// JSON message so this package doesn't need to model every
	// federation.OriginStatus field (those evolve independently).
	Context json.RawMessage `json:"ctx,omitempty"`
}

// Store is the byte-store abstraction this package consumes. It
// matches the existing cache.Store shape so an operator can plug the
// HTTP middleware cache's MemoryStore into pagecache or use a
// dedicated one. Re-declared here so this package doesn't import the
// cache middleware package.
type Store interface {
	Get(ctx context.Context, key string) ([]byte, bool)
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
}

// Cache is the typed page cache.
type Cache struct {
	store  Store
	ttl    time.Duration
	secret []byte
}

// New constructs a Cache backed by store with the given default TTL.
// secret must be non-empty — Cache keys are HMAC-derived to defend
// against cross-principal key collisions.
//
// Returns nil when store is nil; callers should pass the nil result
// straight through (Get and Put on a nil *Cache are no-ops, the
// paginator treats a nil cache as "feature disabled").
func New(store Store, ttl time.Duration, secret []byte) (*Cache, error) {
	if store == nil {
		return nil, nil //nolint:nilnil // caller treats nil as "disabled"
	}
	if len(secret) == 0 {
		return nil, errors.New("pagecache: secret is required")
	}
	if ttl <= 0 {
		return nil, errors.New("pagecache: ttl must be positive")
	}
	return &Cache{store: store, ttl: ttl, secret: secret}, nil
}

// TTL returns the cache's configured TTL, or 0 when the cache is
// disabled. The paginator caps actual TTLs against the cursor's
// remaining lifetime — see Put.
func (c *Cache) TTL() time.Duration {
	if c == nil {
		return 0
	}
	return c.ttl
}

// Get looks up the cached page for cursorSig under principalHash.
// Returns nil, false on miss. Safe to call on a nil *Cache (returns
// nil, false), so callers can use the value-or-disabled pattern
// without a nil check on every call.
func (c *Cache) Get(ctx context.Context, cursorSig, principalHash string) (*SearchResult, bool) {
	if c == nil {
		return nil, false
	}
	key := c.key(cursorSig, principalHash)
	raw, ok := c.store.Get(ctx, key)
	if !ok {
		return nil, false
	}
	var r SearchResult
	if err := json.Unmarshal(raw, &r); err != nil {
		// A decode failure is treated as a miss — the entry will be
		// overwritten or evicted on its own TTL.
		return nil, false
	}
	return &r, true
}

// Put stores result under cursorSig + principalHash with min(c.ttl,
// remaining) as the entry TTL. When remaining is non-positive (cursor
// already expired or near-expiry), Put is a no-op.
func (c *Cache) Put(ctx context.Context, cursorSig, principalHash string, result *SearchResult, remaining time.Duration) error {
	if c == nil || result == nil {
		return nil
	}
	if remaining <= 0 {
		// Cursor already expired or has zero lifetime — storing
		// would create an entry no follow-up call can consume.
		return nil
	}
	ttl := c.ttl
	if remaining < ttl {
		ttl = remaining
	}
	raw, err := json.Marshal(result)
	if err != nil {
		return err
	}
	return c.store.Set(ctx, c.key(cursorSig, principalHash), raw, ttl)
}

// key derives the storage key from the cursor signature and principal
// hash. Output is fixed-length base64url — short enough for any
// store's key budget, opaque, never log-noisy.
func (c *Cache) key(cursorSig, principalHash string) string {
	mac := hmac.New(sha256.New, c.secret)
	mac.Write([]byte(cursorSig))
	mac.Write([]byte{0}) // separator so sig + principal don't collide
	mac.Write([]byte(principalHash))
	return "pg:" + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// SignatureOf returns the signature half of an encoded cursor
// (`<payload>.<signature>`). The paginator uses this to derive the
// key on both Get and Put — the signature is already an HMAC over
// payload+principal, so it's a fixed-length opaque identifier of the
// exact cursor.
//
// Returns "" when encoded is malformed; the caller should treat that
// as "no cache lookup possible" and proceed without the cache.
func SignatureOf(encoded string) string {
	idx := strings.LastIndex(encoded, ".")
	if idx < 0 || idx == len(encoded)-1 {
		return ""
	}
	return encoded[idx+1:]
}
