// Package federation provides multi-origin STAC server federation.
package federation

import (
	"context"
	"net/http"
	"time"

	"github.com/yourorg/stac-proxy/internal/middleware"
	"github.com/yourorg/stac-proxy/internal/stac"
)

// request is federation's internal carrier for the parsed STAC shape
// alongside the inbound *http.Request. The per-route handlers
// (handleSearch, handleGetItem, etc.) and reverseProxyOnce read from it
// directly. Chi-style middleware uses middleware.STACInfo on the
// request context; ServeHTTP translates STACInfo → *request.
type request struct {
	Request     *http.Request
	Context     context.Context
	Collection  string
	ItemID      string
	RequestType middleware.RequestType
	SearchReq   *stac.SearchRequest
}

// response is federation's internal buffered response. ServeHTTP and
// the per-route handlers compose one of these, then the outermost
// caller writes it to the wire ResponseWriter.
type response struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
}

// Origin represents configuration for a single upstream STAC server.
type Origin struct {
	// Identity
	ID          string
	Name        string
	Description string

	// Connection
	BaseURL             string
	Enabled             bool
	Timeout             time.Duration
	Retry               *RetryPolicy
	MaxIdleConnsPerHost int

	// Authentication for this downstream server
	Auth AuthConfig

	// Collection routing
	Collections        []string
	ExcludeCollections []string

	// Behavior
	Priority   int
	ReadOnly   bool
	Searchable bool

	// Collection discovery
	AutoDiscover      bool
	DiscoveryInterval time.Duration

	// Transformations
	CollectionPrefix  string
	CollectionMapping map[string]string
	StripPathPrefix   string

	// SupportsFilterExtension indicates this origin's STAC API supports
	// the Filter Extension (cql2-text / cql2-json). When true, the
	// authz middleware may push down CQL2 predicates to this origin
	// instead of post-filtering. When false (default), the post-filter
	// remains responsible.
	SupportsFilterExtension bool

	// RewriteAssets controls how assets[*].href is rewritten in
	// responses from this origin. One of:
	//   ""      — same as "never" (default).
	//   "never" — asset hrefs pass through unchanged.
	//   "sign"  — the asset href is HMAC-signed via the remap signer
	//             so direct fetches require a valid signature.
	//   "proxy" — the asset href is replaced with a proxy URL of the
	//             form {proxyBaseURL}/assets/{originId}/{base64url-href}
	//             that streams the upstream asset through the proxy's
	//             authz + ratelimit chain.
	RewriteAssets string

	// AssetSignTTL is the TTL applied when RewriteAssets=="sign".
	// Defaults to 15 minutes when zero.
	AssetSignTTL time.Duration

	// ForwardUserIdentity controls whether the inbound request's
	// Authorization / Cookie / X-API-Key headers are forwarded to
	// this origin. The DEFAULT is false: those headers are stripped
	// before fan-out so end-user credentials never leak to upstreams
	// the proxy talks to on its own behalf. Set to true ONLY when
	// the origin specifically wants OIDC-token-pass-through and the
	// operator understands the confused-deputy risk that creates.
	ForwardUserIdentity bool

	// MaxResponseBytes caps the size of an upstream response body
	// that this origin will decode in a single call (Search,
	// GetCollections, etc.). Zero or negative falls back to the
	// per-package default (32 MiB). Useful to keep one buggy or
	// malicious origin from OOMing the proxy by streaming a multi-GB
	// response into memory.
	MaxResponseBytes int64
}

// RetryPolicy defines retry behavior for an origin.
type RetryPolicy struct {
	MaxRetries     int
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
	RetryOn        []int // HTTP status codes to retry
}

// AuthConfig defines authentication for an upstream origin.
type AuthConfig struct {
	Type string // none, basic, bearer, api_key, oauth2, aws_sig_v4, custom

	// Basic Auth
	Username string
	Password string

	// Bearer Token (static)
	Token string

	// API Key
	APIKeyHeader  string
	APIKeyValue   string
	APIKeyInQuery bool

	// OAuth2 Client Credentials Flow
	OAuth2 *OAuth2Config

	// AWS Signature V4
	AWSSigV4 *AWSSigV4Config

	// Custom header injection
	CustomHeaders map[string]string

	// mTLS client certificate
	ClientCert *ClientCertConfig
}

// OAuth2Config contains OAuth2 settings.
type OAuth2Config struct {
	TokenURL     string
	ClientID     string
	ClientSecret string
	Scopes       []string
	Audience     string
}

// AWSSigV4Config contains AWS Signature V4 settings.
type AWSSigV4Config struct {
	Region     string
	Service    string
	AccessKey  string
	SecretKey  string
	UseIAMRole bool
}

// ClientCertConfig contains mTLS settings.
type ClientCertConfig struct {
	CertFile string
	KeyFile  string
	CAFile   string
}

// ConflictStrategy defines how to handle item ID collisions.
type ConflictStrategy int

const (
	// ConflictFirstWins - First origin's item wins (based on response time)
	ConflictFirstWins ConflictStrategy = iota
	// ConflictPriorityWins - Highest priority origin wins
	ConflictPriorityWins
	// ConflictMerge - Merge items with same ID (combine assets, keep latest properties)
	ConflictMerge
	// ConflictNamespace - Prefix item IDs with origin ID (no conflicts possible)
	ConflictNamespace
	// ConflictRejectDuplicates - Return error if duplicates found
	ConflictRejectDuplicates
)

// String returns the string representation of the conflict strategy.
func (s ConflictStrategy) String() string {
	switch s {
	case ConflictFirstWins:
		return "first_wins"
	case ConflictPriorityWins:
		return "priority"
	case ConflictMerge:
		return "merge"
	case ConflictNamespace:
		return "namespace"
	case ConflictRejectDuplicates:
		return "reject_duplicates"
	default:
		return "unknown"
	}
}

// ParseConflictStrategy parses a string to ConflictStrategy.
func ParseConflictStrategy(s string) ConflictStrategy {
	switch s {
	case "first_wins":
		return ConflictFirstWins
	case "priority":
		return ConflictPriorityWins
	case "merge":
		return ConflictMerge
	case "namespace":
		return ConflictNamespace
	case "reject_duplicates":
		return ConflictRejectDuplicates
	default:
		return ConflictPriorityWins
	}
}

// SearchStrategy defines how to search across origins.
type SearchStrategy int

const (
	// SearchParallel - Query all origins in parallel
	SearchParallel SearchStrategy = iota
	// SearchSequential - Query origins one at a time
	SearchSequential
	// SearchPriority - Query highest priority origins first
	SearchPriority
)

// OriginSearchResult contains search results from a single origin.
//
// OriginURL is the origin's configured BaseURL, surfaced here so the
// merger can attach a stac_proxy:origin link (href = OriginURL,
// title = OriginID) to each merged item without having to look the
// origin up in a separate registry.
type OriginSearchResult struct {
	OriginID  string
	OriginURL string
	Priority  int
	Items     []*stac.Item
	Context   *stac.SearchContext
	Links     []*stac.Link
	Error     error
}

// OriginCollectionsResult contains collections from a single origin.
// OriginURL has the same role as in OriginSearchResult.
type OriginCollectionsResult struct {
	OriginID    string
	OriginURL   string
	Collections []*stac.Collection
	Error       error
}

// FederationStats contains statistics about federated operations.
type FederationStats struct {
	OriginsQueried   int
	OriginsSucceeded int
	OriginsFailed    int
	TotalItems       int
	DuplicatesFound  int
	Duration         time.Duration
}
