// Package federation provides multi-origin STAC server federation.
package federation

import (
	"time"

	"github.com/yourorg/stac-proxy/internal/stac"
)

// Origin represents configuration for a single upstream STAC server.
type Origin struct {
	// Identity
	ID          string
	Name        string
	Description string

	// Connection
	BaseURL string
	Enabled bool
	Timeout time.Duration
	Retry   *RetryPolicy

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
type OriginSearchResult struct {
	OriginID string
	Priority int
	Items    []stac.Item
	Context  *stac.SearchContext
	Links    []stac.Link
	Error    error
}

// OriginCollectionsResult contains collections from a single origin.
type OriginCollectionsResult struct {
	OriginID    string
	Collections []stac.Collection
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
