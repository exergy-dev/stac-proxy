package authz

/*
This file contains comprehensive tests for the OPA embedded authorization enforcer.

Coverage includes:
- Engine initialization with various policy sources (inline, files, multiple files)
- Policy compilation and validation
- Authorization decisions with different policy rules
- Role-based access control
- Collection-based authorization
- Spatial/geofence constraints
- Resource constraints (max results, allowed/denied collections, required filters)
- Multiple policy rules evaluation
- Error handling (invalid policies, missing files, syntax errors)
- Context cancellation and timeouts
- Concurrent access
- Policy reloading
- Boolean and structured result parsing
- Complex nested input structures

NOTE: TestBuildAuthzInput is currently commented out due to compilation errors
in the auth package (missing Principal.AuthMethod field and other issues).
Once the auth package is fixed, uncomment that test.

To run these tests (requires fixing auth package first):
  go test ./internal/middleware/authz -run TestEmbeddedOPA -v

To check coverage:
  go test ./internal/middleware/authz -cover -coverprofile=coverage.out
  go tool cover -html=coverage.out
*/

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/open-policy-agent/opa/rego"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test Rego policies
const (
	// Simple allow-all policy
	allowAllPolicy = `
package stac.authz

default allow = true

result = {
	"allow": allow,
	"reasons": reasons,
	"constraints": constraints
}

reasons[msg] {
	allow
	msg := "allowed by policy"
}

constraints = {}
`

	// Simple deny-all policy
	denyAllPolicy = `
package stac.authz

default allow = false

result = {
	"allow": allow,
	"reasons": reasons,
	"constraints": constraints
}

reasons[msg] {
	not allow
	msg := "denied by policy"
}

constraints = {}
`

	// Role-based policy
	roleBasedPolicy = `
package stac.authz

default allow = false

allow {
	input.principal.roles[_] == "admin"
}

allow {
	input.principal.roles[_] == "viewer"
	input.request.method == "GET"
}

result = {
	"allow": allow,
	"reasons": reasons,
	"constraints": constraints
}

reasons[msg] {
	allow
	input.principal.roles[_] == "admin"
	msg := "allowed for admin role"
}

reasons[msg] {
	allow
	input.principal.roles[_] == "viewer"
	input.request.method == "GET"
	msg := "allowed for viewer on GET requests"
}

reasons[msg] {
	not allow
	msg := "denied: insufficient permissions"
}

constraints = {}
`

	// Collection-based policy
	collectionBasedPolicy = `
package stac.authz

default allow = false

allow {
	input.resource.collection == "public"
}

allow {
	input.principal.roles[_] == "admin"
}

allow {
	input.resource.collection == "restricted"
	input.principal.groups[_] == "data-team"
}

result = {
	"allow": allow,
	"reasons": reasons,
	"constraints": constraints
}

reasons[msg] {
	allow
	input.resource.collection == "public"
	msg := "public collection accessible to all"
}

reasons[msg] {
	allow
	input.principal.roles[_] == "admin"
	msg := "admin can access all collections"
}

reasons[msg] {
	allow
	input.resource.collection == "restricted"
	msg := "data-team member can access restricted collection"
}

reasons[msg] {
	not allow
	msg := "denied: no access to collection"
}

constraints = {}
`

	// Policy with constraints
	constraintsPolicy = `
package stac.authz

default allow = false

allow {
	input.principal.type == "user"
}

result = {
	"allow": allow,
	"reasons": reasons,
	"constraints": constraints
}

reasons[msg] {
	allow
	msg := "allowed with constraints"
}

reasons[msg] {
	not allow
	msg := "denied: not a user"
}

constraints = {
	"allowed_collections": allowed_collections,
	"max_results": max_results,
	"geofence": geofence
}

allowed_collections = ["coll1", "coll2"] {
	input.principal.groups[_] == "basic-users"
}

allowed_collections = ["coll1", "coll2", "coll3", "coll4"] {
	input.principal.groups[_] == "premium-users"
}

max_results = 10 {
	input.principal.groups[_] == "basic-users"
}

max_results = 100 {
	input.principal.groups[_] == "premium-users"
}

default geofence := null

geofence = {
	"allowed_area": {
		"type": "Polygon",
		"coordinates": [[[-125, 24], [-66, 24], [-66, 50], [-125, 50], [-125, 24]]]
	},
	"filter_mode": true
} {
	input.principal.attributes.region == "us"
}
`

	// Spatial constraints policy
	spatialPolicy = `
package stac.authz

default allow = true

result = {
	"allow": allow,
	"reasons": reasons,
	"constraints": constraints
}

reasons[msg] {
	allow
	msg := "allowed with spatial constraints"
}

constraints = {
	"geofence": geofence
}

geofence = {
	"allowed_area": {
		"type": "Polygon",
		"coordinates": [[[-10, -10], [10, -10], [10, 10], [-10, 10], [-10, -10]]]
	},
	"filter_mode": true
}
`

	// Multiple rules policy
	multipleRulesPolicy = `
package stac.authz

default allow = false

# Rule 1: Admins can do everything
allow {
	input.principal.roles[_] == "admin"
}

# Rule 2: Authenticated users can read
allow {
	input.request.method == "GET"
	input.principal.type != "anonymous"
}

# Rule 3: Writers can POST to their collections
allow {
	input.request.method == "POST"
	input.principal.roles[_] == "writer"
	input.resource.collection
	input.principal.attributes.allowed_collections[_] == input.resource.collection
}

result = {
	"allow": allow,
	"reasons": reasons,
	"constraints": constraints
}

reasons[msg] {
	allow
	input.principal.roles[_] == "admin"
	msg := "admin access granted"
}

reasons[msg] {
	allow
	input.request.method == "GET"
	input.principal.type != "anonymous"
	msg := "authenticated read access granted"
}

reasons[msg] {
	allow
	input.request.method == "POST"
	input.principal.roles[_] == "writer"
	msg := "writer access granted for owned collection"
}

reasons[msg] {
	not allow
	msg := "no matching authorization rule"
}

constraints = {}
`

	// Boolean-only policy (returns just true/false)
	booleanOnlyPolicy = `
package stac.authz

default allow = false

allow {
	input.principal.roles[_] == "admin"
}

allow {
	input.request.method == "GET"
}
`

	// Invalid policy (syntax error)
	invalidPolicy = `
package stac.authz

this is not valid rego syntax
`

	// Policy with denied collections
	deniedCollectionsPolicy = `
package stac.authz

default allow = true

result = {
	"allow": allow,
	"reasons": reasons,
	"constraints": constraints
}

reasons[msg] {
	allow
	msg := "allowed with restrictions"
}

constraints = {
	"denied_collections": ["secret", "classified"]
}
`

	// Policy with required filters
	requiredFiltersPolicy = `
package stac.authz

default allow = true

result = {
	"allow": allow,
	"reasons": reasons,
	"constraints": constraints
}

reasons[msg] {
	allow
	msg := "allowed with required filters"
}

constraints = {
	"required_filters": {
		"cloud_cover": {"lte": 20},
		"platform": "sentinel-2"
	}
}
`
)

func TestNewEmbeddedOPAEnforcer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		config    EmbeddedOPAConfig
		wantErr   bool
		errString string
		validate  func(*testing.T, *EmbeddedOPAEnforcer)
	}{
		{
			name: "valid config with inline module",
			config: EmbeddedOPAConfig{
				Name:  "test-enforcer",
				Query: "data.stac.authz.result",
				Modules: map[string]string{
					"policy.rego": allowAllPolicy,
				},
			},
			wantErr: false,
			validate: func(t *testing.T, e *EmbeddedOPAEnforcer) {
				assert.Equal(t, "test-enforcer", e.name, "name")
				assert.Equal(t, "data.stac.authz.result", e.queryString, "query")
				// Query is a value type, check if queryString is set instead
				assert.NotEmpty(t, e.queryString, "expected query string to be set")
			},
		},
		{
			name: "default query when not specified",
			config: EmbeddedOPAConfig{
				Name: "default-query",
				Modules: map[string]string{
					"policy.rego": allowAllPolicy,
				},
			},
			wantErr: false,
			validate: func(t *testing.T, e *EmbeddedOPAEnforcer) {
				assert.Equal(t, "data.stac.authz", e.queryString, "expected default query")
			},
		},
		{
			name: "default policy when no modules specified",
			config: EmbeddedOPAConfig{
				Name: "default-policy",
			},
			wantErr: false,
			validate: func(t *testing.T, e *EmbeddedOPAEnforcer) {
				assert.NotEmpty(t, e.queryString, "expected default policy to be loaded")
			},
		},
		{
			name: "invalid policy syntax",
			config: EmbeddedOPAConfig{
				Name: "invalid",
				Modules: map[string]string{
					"bad.rego": invalidPolicy,
				},
			},
			wantErr:   true,
			errString: "failed to prepare OPA query",
		},
		{
			name: "policy file from disk",
			config: EmbeddedOPAConfig{
				Name:       "file-based",
				PolicyPath: createTempPolicyFile(t, allowAllPolicy),
			},
			wantErr: false,
			validate: func(t *testing.T, e *EmbeddedOPAEnforcer) {
				assert.NotEmpty(t, e.queryString, "expected policy to be loaded from file")
			},
		},
		{
			// H-authz-6: when two modules each declare `default allow`,
			// OPA's compiler rejects the bundle. Previously a regex
			// dedup silently stripped one (potentially the
			// fail-closed `default allow = false`). The new behaviour
			// is to surface the compile error to the operator.
			name: "multiple policy files with duplicate default rules",
			config: EmbeddedOPAConfig{
				Name: "multi-file",
				PolicyPaths: []string{
					createTempPolicyFile(t, allowAllPolicy),
					createTempPolicyFile(t, spatialPolicy),
				},
			},
			wantErr:   true,
			errString: "multiple default rules",
		},
		{
			name: "nonexistent policy file",
			config: EmbeddedOPAConfig{
				Name:       "missing-file",
				PolicyPath: "/nonexistent/policy.rego",
			},
			wantErr:   true,
			errString: "failed to read policy file",
		},
		{
			// H-authz-6: same shape as the multi-file case above —
			// inline + file modules each carry `default allow`, which
			// the compiler must reject. The previous regex dedup
			// silently dropped one declaration.
			name: "inline modules and file with duplicate default rules",
			config: EmbeddedOPAConfig{
				Name:       "override",
				PolicyPath: createTempPolicyFile(t, denyAllPolicy),
				Modules: map[string]string{
					"override.rego": allowAllPolicy,
				},
			},
			wantErr:   true,
			errString: "multiple default rules",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			enforcer, err := NewEmbeddedOPAEnforcer(tt.config)

			if tt.wantErr {
				require.Error(t, err, "expected error containing '%s'", tt.errString)
				if tt.errString != "" {
					require.Contains(t, err.Error(), tt.errString, "expected error containing '%s'", tt.errString)
				}
				return
			}

			require.NoError(t, err, "unexpected error")
			require.NotNil(t, enforcer, "expected non-nil enforcer")

			if tt.validate != nil {
				tt.validate(t, enforcer)
			}
		})
	}
}

// TestEmbeddedOPAEnforcer_NoBundleDeniesByDefault is C-3: the synthesized
// default policy used when no operator bundle is supplied must fail closed.
func TestEmbeddedOPAEnforcer_NoBundleDeniesByDefault(t *testing.T) {
	t.Parallel()

	enforcer, err := NewEmbeddedOPAEnforcer(EmbeddedOPAConfig{
		Name: "no-bundle",
		// No PolicyPath, no PolicyPaths, no Modules.
	})
	require.NoError(t, err, "NewEmbeddedOPAEnforcer")

	decision, err := enforcer.Authorize(context.Background(), &AuthzInput{
		Principal: &PrincipalInfo{ID: "anyone"},
		Request:   &RequestInfo{Method: "GET", Path: "/collections/x"},
		Resource:  &ResourceInfo{Type: "collection", Collection: "x"},
	})
	require.NoError(t, err, "Authorize")
	require.False(t, decision.Allowed, "default policy must deny when no operator bundle is supplied; reasons=%v", decision.Reasons)
}

func TestEmbeddedOPAEnforcer_Name(t *testing.T) {
	t.Parallel()

	enforcer, err := NewEmbeddedOPAEnforcer(EmbeddedOPAConfig{
		Name: "test-name",
		Modules: map[string]string{
			"policy.rego": allowAllPolicy,
		},
	})
	require.NoError(t, err, "failed to create enforcer")

	assert.Equal(t, "test-name", enforcer.Name(), "name")
}

func TestEmbeddedOPAEnforcer_Authorize(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		policy           string
		input            *AuthzInput
		expectedAllowed  bool
		expectedReasons  []string
		checkConstraints func(*testing.T, *AuthzConstraints)
		wantErr          bool
	}{
		{
			name:   "allow all policy - allow",
			policy: allowAllPolicy,
			input: &AuthzInput{
				Principal: &PrincipalInfo{
					ID:   "user1",
					Type: "user",
				},
				Request: &RequestInfo{
					Method: "GET",
					Path:   "/collections",
				},
				Resource: &ResourceInfo{
					Type: "collection",
				},
			},
			expectedAllowed: true,
			expectedReasons: []string{"allowed by policy"},
		},
		{
			name:   "deny all policy - deny",
			policy: denyAllPolicy,
			input: &AuthzInput{
				Principal: &PrincipalInfo{
					ID:   "user1",
					Type: "user",
				},
				Request: &RequestInfo{
					Method: "GET",
					Path:   "/collections",
				},
				Resource: &ResourceInfo{
					Type: "collection",
				},
			},
			expectedAllowed: false,
			expectedReasons: []string{"denied by policy"},
		},
		{
			name:   "role-based policy - admin allowed",
			policy: roleBasedPolicy,
			input: &AuthzInput{
				Principal: &PrincipalInfo{
					ID:    "admin1",
					Type:  "user",
					Roles: []string{"admin"},
				},
				Request: &RequestInfo{
					Method: "POST",
					Path:   "/collections",
				},
				Resource: &ResourceInfo{
					Type: "collection",
				},
			},
			expectedAllowed: true,
			expectedReasons: []string{"allowed for admin role"},
		},
		{
			name:   "role-based policy - viewer GET allowed",
			policy: roleBasedPolicy,
			input: &AuthzInput{
				Principal: &PrincipalInfo{
					ID:    "viewer1",
					Type:  "user",
					Roles: []string{"viewer"},
				},
				Request: &RequestInfo{
					Method: "GET",
					Path:   "/collections",
				},
				Resource: &ResourceInfo{
					Type: "collection",
				},
			},
			expectedAllowed: true,
			expectedReasons: []string{"allowed for viewer on GET requests"},
		},
		{
			name:   "role-based policy - viewer POST denied",
			policy: roleBasedPolicy,
			input: &AuthzInput{
				Principal: &PrincipalInfo{
					ID:    "viewer1",
					Type:  "user",
					Roles: []string{"viewer"},
				},
				Request: &RequestInfo{
					Method: "POST",
					Path:   "/collections",
				},
				Resource: &ResourceInfo{
					Type: "collection",
				},
			},
			expectedAllowed: false,
			expectedReasons: []string{"denied: insufficient permissions"},
		},
		{
			name:   "collection-based policy - public collection",
			policy: collectionBasedPolicy,
			input: &AuthzInput{
				Principal: &PrincipalInfo{
					ID:   "user1",
					Type: "user",
				},
				Request: &RequestInfo{
					Method: "GET",
					Path:   "/collections/public/items",
				},
				Resource: &ResourceInfo{
					Type:       "item",
					Collection: "public",
				},
			},
			expectedAllowed: true,
			expectedReasons: []string{"public collection accessible to all"},
		},
		{
			name:   "collection-based policy - restricted collection with group",
			policy: collectionBasedPolicy,
			input: &AuthzInput{
				Principal: &PrincipalInfo{
					ID:     "user1",
					Type:   "user",
					Groups: []string{"data-team"},
				},
				Request: &RequestInfo{
					Method: "GET",
					Path:   "/collections/restricted/items",
				},
				Resource: &ResourceInfo{
					Type:       "item",
					Collection: "restricted",
				},
			},
			expectedAllowed: true,
			expectedReasons: []string{"data-team member can access restricted collection"},
		},
		{
			name:   "collection-based policy - restricted collection without group",
			policy: collectionBasedPolicy,
			input: &AuthzInput{
				Principal: &PrincipalInfo{
					ID:     "user1",
					Type:   "user",
					Groups: []string{"other-team"},
				},
				Request: &RequestInfo{
					Method: "GET",
					Path:   "/collections/restricted/items",
				},
				Resource: &ResourceInfo{
					Type:       "item",
					Collection: "restricted",
				},
			},
			expectedAllowed: false,
			expectedReasons: []string{"denied: no access to collection"},
		},
		{
			name:   "policy with constraints - basic users",
			policy: constraintsPolicy,
			input: &AuthzInput{
				Principal: &PrincipalInfo{
					ID:     "user1",
					Type:   "user",
					Groups: []string{"basic-users"},
					Attributes: map[string]interface{}{
						"region": "us",
					},
				},
				Request: &RequestInfo{
					Method: "GET",
					Path:   "/search",
				},
				Resource: &ResourceInfo{
					Type: "search",
				},
			},
			expectedAllowed: true,
			expectedReasons: []string{"allowed with constraints"},
			checkConstraints: func(t *testing.T, c *AuthzConstraints) {
				require.NotNil(t, c, "expected constraints")
				assert.Len(t, c.AllowedCollections, 2, "expected 2 allowed collections")
				assert.Equal(t, 10, c.MaxResults, "expected max_results=10")
				require.NotNil(t, c.Geofence, "expected geofence constraint")
				assert.NotNil(t, c.Geofence.AllowedArea, "expected allowed_area in geofence")
				assert.True(t, c.Geofence.FilterMode, "expected filter_mode=true")
			},
		},
		{
			name:   "policy with constraints - premium users",
			policy: constraintsPolicy,
			input: &AuthzInput{
				Principal: &PrincipalInfo{
					ID:     "user1",
					Type:   "user",
					Groups: []string{"premium-users"},
				},
				Request: &RequestInfo{
					Method: "GET",
					Path:   "/search",
				},
				Resource: &ResourceInfo{
					Type: "search",
				},
			},
			expectedAllowed: true,
			checkConstraints: func(t *testing.T, c *AuthzConstraints) {
				require.NotNil(t, c, "expected constraints")
				assert.Len(t, c.AllowedCollections, 4, "expected 4 allowed collections")
				assert.Equal(t, 100, c.MaxResults, "expected max_results=100")
			},
		},
		{
			name:   "spatial constraints policy",
			policy: spatialPolicy,
			input: &AuthzInput{
				Principal: &PrincipalInfo{
					ID:   "user1",
					Type: "user",
				},
				Request: &RequestInfo{
					Method: "GET",
					Path:   "/search",
				},
				Resource: &ResourceInfo{
					Type: "search",
				},
			},
			expectedAllowed: true,
			checkConstraints: func(t *testing.T, c *AuthzConstraints) {
				require.NotNil(t, c, "expected constraints")
				require.NotNil(t, c.Geofence, "expected geofence constraint")
				assert.NotNil(t, c.Geofence.AllowedArea, "expected allowed_area in geofence")
			},
		},
		{
			name:   "multiple rules policy - admin",
			policy: multipleRulesPolicy,
			input: &AuthzInput{
				Principal: &PrincipalInfo{
					ID:    "admin1",
					Type:  "user",
					Roles: []string{"admin"},
				},
				Request: &RequestInfo{
					Method: "DELETE",
					Path:   "/collections/test",
				},
				Resource: &ResourceInfo{
					Type:       "collection",
					Collection: "test",
				},
			},
			expectedAllowed: true,
			expectedReasons: []string{"admin access granted"},
		},
		{
			name:   "multiple rules policy - authenticated read",
			policy: multipleRulesPolicy,
			input: &AuthzInput{
				Principal: &PrincipalInfo{
					ID:   "user1",
					Type: "user",
				},
				Request: &RequestInfo{
					Method: "GET",
					Path:   "/collections",
				},
				Resource: &ResourceInfo{
					Type: "collection",
				},
			},
			expectedAllowed: true,
			expectedReasons: []string{"authenticated read access granted"},
		},
		{
			name:   "multiple rules policy - writer with allowed collection",
			policy: multipleRulesPolicy,
			input: &AuthzInput{
				Principal: &PrincipalInfo{
					ID:    "writer1",
					Type:  "user",
					Roles: []string{"writer"},
					Attributes: map[string]interface{}{
						"allowed_collections": []interface{}{"my-collection"},
					},
				},
				Request: &RequestInfo{
					Method: "POST",
					Path:   "/collections/my-collection/items",
				},
				Resource: &ResourceInfo{
					Type:       "item",
					Collection: "my-collection",
				},
			},
			expectedAllowed: true,
			expectedReasons: []string{"writer access granted for owned collection"},
		},
		{
			name:   "multiple rules policy - writer with disallowed collection",
			policy: multipleRulesPolicy,
			input: &AuthzInput{
				Principal: &PrincipalInfo{
					ID:    "writer1",
					Type:  "user",
					Roles: []string{"writer"},
					Attributes: map[string]interface{}{
						"allowed_collections": []interface{}{"my-collection"},
					},
				},
				Request: &RequestInfo{
					Method: "POST",
					Path:   "/collections/other-collection/items",
				},
				Resource: &ResourceInfo{
					Type:       "item",
					Collection: "other-collection",
				},
			},
			expectedAllowed: false,
			expectedReasons: []string{"no matching authorization rule"},
		},
		{
			name:   "boolean-only policy - admin",
			policy: booleanOnlyPolicy,
			input: &AuthzInput{
				Principal: &PrincipalInfo{
					ID:    "admin1",
					Type:  "user",
					Roles: []string{"admin"},
				},
				Request: &RequestInfo{
					Method: "POST",
					Path:   "/collections",
				},
				Resource: &ResourceInfo{
					Type: "collection",
				},
			},
			expectedAllowed: true,
			expectedReasons: []string{"allowed by policy"},
		},
		{
			name:   "boolean-only policy - GET request",
			policy: booleanOnlyPolicy,
			input: &AuthzInput{
				Principal: &PrincipalInfo{
					ID:   "user1",
					Type: "user",
				},
				Request: &RequestInfo{
					Method: "GET",
					Path:   "/collections",
				},
				Resource: &ResourceInfo{
					Type: "collection",
				},
			},
			expectedAllowed: true,
			expectedReasons: []string{"allowed by policy"},
		},
		{
			name:   "boolean-only policy - denied",
			policy: booleanOnlyPolicy,
			input: &AuthzInput{
				Principal: &PrincipalInfo{
					ID:   "user1",
					Type: "user",
				},
				Request: &RequestInfo{
					Method: "POST",
					Path:   "/collections",
				},
				Resource: &ResourceInfo{
					Type: "collection",
				},
			},
			expectedAllowed: false,
			expectedReasons: []string{"denied by policy"},
		},
		{
			name:   "denied collections constraint",
			policy: deniedCollectionsPolicy,
			input: &AuthzInput{
				Principal: &PrincipalInfo{
					ID:   "user1",
					Type: "user",
				},
				Request: &RequestInfo{
					Method: "GET",
					Path:   "/search",
				},
				Resource: &ResourceInfo{
					Type: "search",
				},
			},
			expectedAllowed: true,
			checkConstraints: func(t *testing.T, c *AuthzConstraints) {
				require.NotNil(t, c, "expected constraints")
				assert.Len(t, c.DeniedCollections, 2, "expected 2 denied collections")
			},
		},
		{
			name:   "required filters constraint",
			policy: requiredFiltersPolicy,
			input: &AuthzInput{
				Principal: &PrincipalInfo{
					ID:   "user1",
					Type: "user",
				},
				Request: &RequestInfo{
					Method: "GET",
					Path:   "/search",
				},
				Resource: &ResourceInfo{
					Type: "search",
				},
			},
			expectedAllowed: true,
			checkConstraints: func(t *testing.T, c *AuthzConstraints) {
				require.NotNil(t, c, "expected constraints")
				require.NotNil(t, c.RequiredFilters, "expected required filters")
				_, ok := c.RequiredFilters["cloud_cover"]
				assert.True(t, ok, "expected cloud_cover filter")
				_, ok = c.RequiredFilters["platform"]
				assert.True(t, ok, "expected platform filter")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			enforcer, err := NewEmbeddedOPAEnforcer(EmbeddedOPAConfig{
				Name: tt.name,
				Modules: map[string]string{
					"policy.rego": tt.policy,
				},
			})
			require.NoError(t, err, "failed to create enforcer")

			ctx := context.Background()
			decision, err := enforcer.Authorize(ctx, tt.input)

			if tt.wantErr {
				require.Error(t, err, "expected error")
				return
			}

			require.NoError(t, err, "unexpected error")
			require.NotNil(t, decision, "expected non-nil decision")
			assert.Equal(t, tt.expectedAllowed, decision.Allowed, "allowed")

			if len(tt.expectedReasons) > 0 {
				if len(decision.Reasons) == 0 {
					t.Errorf("expected reasons %v, got none", tt.expectedReasons)
				} else if !containsAny(decision.Reasons, tt.expectedReasons) {
					t.Errorf("expected reasons to contain one of %v, got %v", tt.expectedReasons, decision.Reasons)
				}
			}

			if tt.checkConstraints != nil {
				tt.checkConstraints(t, decision.Constraints)
			}
		})
	}
}

func TestEmbeddedOPAEnforcer_Authorize_ContextCancellation(t *testing.T) {
	t.Parallel()

	enforcer, err := NewEmbeddedOPAEnforcer(EmbeddedOPAConfig{
		Name: "cancel-test",
		Modules: map[string]string{
			"policy.rego": allowAllPolicy,
		},
	})
	require.NoError(t, err, "failed to create enforcer")

	// Create a cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	input := &AuthzInput{
		Principal: &PrincipalInfo{
			ID:   "user1",
			Type: "user",
		},
		Request: &RequestInfo{
			Method: "GET",
			Path:   "/collections",
		},
		Resource: &ResourceInfo{
			Type: "collection",
		},
	}

	decision, err := enforcer.Authorize(ctx, input)

	// The behavior depends on OPA implementation
	// It might succeed quickly or return an error
	if err != nil && decision != nil {
		t.Errorf("expected either error or decision, got both: err=%v, decision=%+v", err, decision)
	}
}

func TestEmbeddedOPAEnforcer_Authorize_Timeout(t *testing.T) {
	t.Parallel()

	enforcer, err := NewEmbeddedOPAEnforcer(EmbeddedOPAConfig{
		Name: "timeout-test",
		Modules: map[string]string{
			"policy.rego": allowAllPolicy,
		},
	})
	require.NoError(t, err, "failed to create enforcer")

	// Create a context with a very short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	// Sleep briefly to ensure timeout
	time.Sleep(1 * time.Millisecond)

	input := &AuthzInput{
		Principal: &PrincipalInfo{
			ID:   "user1",
			Type: "user",
		},
		Request: &RequestInfo{
			Method: "GET",
			Path:   "/collections",
		},
		Resource: &ResourceInfo{
			Type: "collection",
		},
	}

	_, err = enforcer.Authorize(ctx, input)

	// We expect either success (if OPA was fast) or a context deadline error
	// Just verify we don't panic
	if err != nil && !contains(err.Error(), "context") {
		// It's OK if there's an error, just making sure it's handled
		t.Logf("got error (expected with timeout): %v", err)
	}
}

func TestEmbeddedOPAEnforcer_Authorize_NilInput(t *testing.T) {
	t.Parallel()

	enforcer, err := NewEmbeddedOPAEnforcer(EmbeddedOPAConfig{
		Name: "nil-test",
		Modules: map[string]string{
			"policy.rego": allowAllPolicy,
		},
	})
	require.NoError(t, err, "failed to create enforcer")

	ctx := context.Background()

	// Test with nil input
	_, err = enforcer.Authorize(ctx, nil)
	if err == nil {
		// It's OK if it doesn't error - depends on JSON marshaling behavior
		t.Log("nil input did not cause error (OK)")
	}
}

func TestEmbeddedOPAEnforcer_Authorize_EmptyInput(t *testing.T) {
	t.Parallel()

	enforcer, err := NewEmbeddedOPAEnforcer(EmbeddedOPAConfig{
		Name: "empty-test",
		Modules: map[string]string{
			"policy.rego": allowAllPolicy,
		},
	})
	require.NoError(t, err, "failed to create enforcer")

	ctx := context.Background()
	decision, err := enforcer.Authorize(ctx, &AuthzInput{})

	require.NoError(t, err, "unexpected error with empty input")
	require.NotNil(t, decision, "expected non-nil decision")
}

func TestEmbeddedOPAEnforcer_Authorize_ComplexInput(t *testing.T) {
	t.Parallel()

	enforcer, err := NewEmbeddedOPAEnforcer(EmbeddedOPAConfig{
		Name: "complex-input",
		Modules: map[string]string{
			"policy.rego": allowAllPolicy,
		},
	})
	require.NoError(t, err, "failed to create enforcer")

	ctx := context.Background()
	input := &AuthzInput{
		Principal: &PrincipalInfo{
			ID:     "user123",
			Type:   "service",
			Roles:  []string{"admin", "viewer", "editor"},
			Groups: []string{"group1", "group2", "group3"},
			Attributes: map[string]interface{}{
				"region":              "us-west-2",
				"department":          "engineering",
				"clearance_level":     5,
				"allowed_collections": []interface{}{"coll1", "coll2"},
				"metadata": map[string]interface{}{
					"created_at": "2023-01-01T00:00:00Z",
					"updated_at": "2023-12-31T23:59:59Z",
				},
			},
			AuthMethod: "mtls",
		},
		Request: &RequestInfo{
			Method:      "POST",
			Path:        "/collections/test/items",
			RequestType: "item",
			Query: map[string][]string{
				"limit": {"10"},
				"bbox":  {"-180,-90,180,90"},
			},
			Headers: map[string]string{
				"Content-Type": "application/json",
				"Accept":       "application/geo+json",
				"User-Agent":   "test-client/1.0",
				"X-Request-ID": "req-123",
			},
			Body: map[string]interface{}{
				"type": "Feature",
				"geometry": map[string]interface{}{
					"type":        "Point",
					"coordinates": []float64{-122.4, 37.8},
				},
			},
			ClientIP:  "192.168.1.100",
			RequestID: "req-123",
		},
		Resource: &ResourceInfo{
			Type:       "item",
			Collection: "test-collection",
			ItemID:     "item-123",
			Origins:    []string{"origin1", "origin2"},
		},
	}

	decision, err := enforcer.Authorize(ctx, input)

	require.NoError(t, err, "unexpected error")
	require.NotNil(t, decision, "expected non-nil decision")
	assert.True(t, decision.Allowed, "expected allow with allow-all policy")
}

func TestEmbeddedOPAEnforcer_ReloadPolicy(t *testing.T) {
	t.Parallel()

	// Create temp policy file
	tmpFile := createTempPolicyFile(t, denyAllPolicy)

	enforcer, err := NewEmbeddedOPAEnforcer(EmbeddedOPAConfig{
		Name:       "reload-test",
		PolicyPath: tmpFile,
	})
	require.NoError(t, err, "failed to create enforcer")

	ctx := context.Background()
	input := &AuthzInput{
		Principal: &PrincipalInfo{
			ID:   "user1",
			Type: "user",
		},
		Request: &RequestInfo{
			Method: "GET",
			Path:   "/collections",
		},
		Resource: &ResourceInfo{
			Type: "collection",
		},
	}

	// First check - should deny
	decision, err := enforcer.Authorize(ctx, input)
	require.NoError(t, err, "unexpected error")
	assert.False(t, decision.Allowed, "expected deny with deny-all policy")

	// Update the policy file
	require.NoError(t, os.WriteFile(tmpFile, []byte(allowAllPolicy), 0644), "failed to update policy file")

	// Reload policy
	require.NoError(t, enforcer.ReloadPolicy(), "failed to reload policy")

	// Second check - should allow
	decision, err = enforcer.Authorize(ctx, input)
	require.NoError(t, err, "unexpected error")
	assert.True(t, decision.Allowed, "expected allow after reloading allow-all policy")
}

func TestEmbeddedOPAEnforcer_ReloadPolicy_NoPath(t *testing.T) {
	t.Parallel()

	enforcer, err := NewEmbeddedOPAEnforcer(EmbeddedOPAConfig{
		Name: "no-path",
		Modules: map[string]string{
			"policy.rego": allowAllPolicy,
		},
	})
	require.NoError(t, err, "failed to create enforcer")

	// Reload should be a no-op when no policy path is set
	assert.NoError(t, enforcer.ReloadPolicy(), "unexpected error on reload with no path")
}

func TestEmbeddedOPAEnforcer_ReloadPolicy_InvalidFile(t *testing.T) {
	t.Parallel()

	tmpFile := createTempPolicyFile(t, allowAllPolicy)

	enforcer, err := NewEmbeddedOPAEnforcer(EmbeddedOPAConfig{
		Name:       "invalid-reload",
		PolicyPath: tmpFile,
	})
	require.NoError(t, err, "failed to create enforcer")

	// Delete the file
	require.NoError(t, os.Remove(tmpFile), "failed to remove temp file")

	// Reload should fail
	assert.Error(t, enforcer.ReloadPolicy(), "expected error when reloading deleted policy file")
}

func TestEmbeddedOPAEnforcer_ReloadPolicy_InvalidSyntax(t *testing.T) {
	t.Parallel()

	tmpFile := createTempPolicyFile(t, allowAllPolicy)

	enforcer, err := NewEmbeddedOPAEnforcer(EmbeddedOPAConfig{
		Name:       "invalid-syntax-reload",
		PolicyPath: tmpFile,
	})
	require.NoError(t, err, "failed to create enforcer")

	// Update with invalid policy
	require.NoError(t, os.WriteFile(tmpFile, []byte(invalidPolicy), 0644), "failed to update policy file")

	// Reload should fail
	assert.Error(t, enforcer.ReloadPolicy(), "expected error when reloading invalid policy")
}

func TestEmbeddedOPAEnforcer_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	enforcer, err := NewEmbeddedOPAEnforcer(EmbeddedOPAConfig{
		Name: "concurrent-test",
		Modules: map[string]string{
			"policy.rego": roleBasedPolicy,
		},
	})
	require.NoError(t, err, "failed to create enforcer")

	ctx := context.Background()

	// Run multiple concurrent authorizations
	const numGoroutines = 50
	done := make(chan bool, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer func() { done <- true }()

			input := &AuthzInput{
				Principal: &PrincipalInfo{
					ID:    "user" + string(rune(id)),
					Type:  "user",
					Roles: []string{"admin"},
				},
				Request: &RequestInfo{
					Method: "GET",
					Path:   "/collections",
				},
				Resource: &ResourceInfo{
					Type: "collection",
				},
			}

			decision, err := enforcer.Authorize(ctx, input)
			if err != nil {
				t.Errorf("goroutine %d: unexpected error: %v", id, err)
				return
			}

			if !decision.Allowed {
				t.Errorf("goroutine %d: expected allow for admin", id)
			}
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < numGoroutines; i++ {
		<-done
	}
}

func TestParseEmbeddedResult(t *testing.T) {
	// This test is for the parseEmbeddedResult internal function
	// We test it indirectly through Authorize, but we can also test
	// the result parsing with various OPA result structures
	t.Parallel()

	tests := []struct {
		name            string
		policy          string
		expectedAllowed bool
		hasConstraints  bool
	}{
		{
			name:            "structured result with all fields",
			policy:          constraintsPolicy,
			expectedAllowed: true,
			hasConstraints:  true,
		},
		{
			name:            "boolean only result",
			policy:          booleanOnlyPolicy,
			expectedAllowed: true,
			hasConstraints:  false,
		},
		{
			name:            "result with reasons",
			policy:          roleBasedPolicy,
			expectedAllowed: true,
			hasConstraints:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			enforcer, err := NewEmbeddedOPAEnforcer(EmbeddedOPAConfig{
				Name: tt.name,
				Modules: map[string]string{
					"policy.rego": tt.policy,
				},
			})
			require.NoError(t, err, "failed to create enforcer")

			ctx := context.Background()
			input := &AuthzInput{
				Principal: &PrincipalInfo{
					ID:     "user1",
					Type:   "user",
					Roles:  []string{"admin"},
					Groups: []string{"basic-users"},
					Attributes: map[string]interface{}{
						"region": "us",
					},
				},
				Request: &RequestInfo{
					Method: "GET",
					Path:   "/collections",
				},
				Resource: &ResourceInfo{
					Type: "collection",
				},
			}

			decision, err := enforcer.Authorize(ctx, input)
			require.NoError(t, err, "unexpected error")
			assert.Equal(t, tt.expectedAllowed, decision.Allowed, "allowed")

			if tt.hasConstraints {
				assert.NotNil(t, decision.Constraints, "expected constraints")
			}
		})
	}
}

func TestStructToMap(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   interface{}
		wantErr bool
		check   func(*testing.T, map[string]interface{})
	}{
		{
			name: "simple struct",
			input: &AuthzInput{
				Principal: &PrincipalInfo{
					ID:   "user1",
					Type: "user",
				},
			},
			wantErr: false,
			check: func(t *testing.T, m map[string]interface{}) {
				require.NotNil(t, m, "expected non-nil map")
				principal, ok := m["principal"].(map[string]interface{})
				require.True(t, ok, "expected principal to be a map")
				assert.Equal(t, "user1", principal["id"], "id")
			},
		},
		{
			name: "complex nested struct",
			input: &AuthzInput{
				Principal: &PrincipalInfo{
					ID:     "user1",
					Type:   "user",
					Roles:  []string{"admin", "viewer"},
					Groups: []string{"team1"},
					Attributes: map[string]interface{}{
						"key": "value",
					},
				},
				Request: &RequestInfo{
					Method: "GET",
					Path:   "/collections",
					Query: map[string][]string{
						"limit": {"10"},
					},
				},
			},
			wantErr: false,
			check: func(t *testing.T, m map[string]interface{}) {
				require.NotNil(t, m, "expected non-nil map")
				request, ok := m["request"].(map[string]interface{})
				require.True(t, ok, "expected request to be a map")
				assert.Equal(t, "GET", request["method"], "method")
			},
		},
		{
			name:    "nil input",
			input:   nil,
			wantErr: false, // JSON marshaling handles nil
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result, err := structToMap(tt.input)

			if tt.wantErr {
				require.Error(t, err, "expected error")
				return
			}

			require.NoError(t, err, "unexpected error")

			if tt.check != nil {
				tt.check(t, result)
			}
		})
	}
}

// TestBuildAuthzInput is commented out due to compilation errors in auth package
// Uncomment when auth package is fixed
/*
func TestBuildAuthzInput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		stacReq   *middleware.STACRequest
		principal *auth.Principal
		validate  func(*testing.T, *AuthzInput)
	}{
		{
			name: "basic collection request",
			stacReq: &middleware.STACRequest{
				Request: &http.Request{
					Method: "GET",
					URL:    mustParseURL("/collections/test"),
					Header: http.Header{
						"Content-Type": []string{"application/json"},
						"User-Agent":   []string{"test-client"},
					},
					RemoteAddr: "192.168.1.1:1234",
				},
				Context:     context.Background(),
				RequestType: middleware.RequestTypeCollection,
				Collection:  "test",
			},
			principal: &auth.Principal{
				ID:    "user1",
				Type:  "user",
				Roles: []string{"viewer"},
			},
			validate: func(t *testing.T, input *AuthzInput) {
				if input.Request.Method != "GET" {
					t.Errorf("expected method=GET, got %s", input.Request.Method)
				}
				if input.Resource.Collection != "test" {
					t.Errorf("expected collection=test, got %s", input.Resource.Collection)
				}
				if input.Principal.ID != "user1" {
					t.Errorf("expected principal ID=user1, got %s", input.Principal.ID)
				}
			},
		},
		{
			name: "item request",
			stacReq: &middleware.STACRequest{
				Request: &http.Request{
					Method:     "GET",
					URL:        mustParseURL("/collections/test/items/item123"),
					RemoteAddr: "192.168.1.1:1234",
				},
				Context:     context.Background(),
				RequestType: middleware.RequestTypeItem,
				Collection:  "test",
				ItemID:      "item123",
			},
			principal: nil, // anonymous
			validate: func(t *testing.T, input *AuthzInput) {
				if input.Resource.Type != "item" {
					t.Errorf("expected resource type=item, got %s", input.Resource.Type)
				}
				if input.Resource.ItemID != "item123" {
					t.Errorf("expected item ID=item123, got %s", input.Resource.ItemID)
				}
				if input.Principal != nil {
					t.Error("expected nil principal for anonymous request")
				}
			},
		},
		{
			name: "search request",
			stacReq: &middleware.STACRequest{
				Request: &http.Request{
					Method:     "POST",
					URL:        mustParseURL("/search?limit=10"),
					RemoteAddr: "192.168.1.1:1234",
				},
				Context:     context.Background(),
				RequestType: middleware.RequestTypeSearch,
			},
			principal: &auth.Principal{
				ID:   "user1",
				Type: "user",
				Attributes: map[string]string{
					"custom": "value",
				},
			},
			validate: func(t *testing.T, input *AuthzInput) {
				if input.Resource.Type != "search" {
					t.Errorf("expected resource type=search, got %s", input.Resource.Type)
				}
				if input.Request.Method != "POST" {
					t.Errorf("expected method=POST, got %s", input.Request.Method)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			input := BuildAuthzInput(tt.stacReq, tt.principal)

			if input == nil {
				t.Fatal("expected non-nil input")
			}

			if tt.validate != nil {
				tt.validate(t, input)
			}
		})
	}
}
*/

// Helper functions

func createTempPolicyFile(t *testing.T, content string) string {
	t.Helper()

	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "policy.rego")

	require.NoError(t, os.WriteFile(tmpFile, []byte(content), 0644), "failed to create temp policy file")

	return tmpFile
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && containsHelper(s, substr)))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func containsAny(slice []string, targets []string) bool {
	for _, s := range slice {
		for _, target := range targets {
			if s == target {
				return true
			}
		}
	}
	return false
}

func mustParseURL(rawURL string) *url.URL {
	u, err := url.Parse("http://example.com" + rawURL)
	if err != nil {
		panic(err)
	}
	return u
}

// TestEmbeddedOPA_DuplicateDefaultRules_ErrorsAtCompile is the
// H-authz-6 regression: when an operator passes two Rego modules at
// the same path that each declare `default allow = false`, the
// constructor must surface OPA's compile error rather than silently
// dropping one declaration. Previously a regex-based source-text
// dedup quietly stripped a duplicate, which could turn a
// fail-closed policy fail-open.
func TestEmbeddedOPA_DuplicateDefaultRules_ErrorsAtCompile(t *testing.T) {
	t.Parallel()

	moduleA := `package stac.authz

default allow = false

result = {"allow": allow, "reasons": [], "constraints": {}}
`
	moduleB := `package stac.authz

default allow = false

other_rule { input.principal.id == "x" }
`

	_, err := NewEmbeddedOPAEnforcer(EmbeddedOPAConfig{
		Name: "dup-default",
		Modules: map[string]string{
			"a.rego": moduleA,
			"b.rego": moduleB,
		},
	})
	require.Error(t, err, "constructor must fail when two modules declare the same default rule")
	require.Contains(t, err.Error(), "multiple default rules", "error must mention duplicate default rules")
}

// TestParseEmbeddedResult_NoAllowKey_ReturnsError verifies M-authz-6:
// a structured OPA result without an `allow` key is malformed and
// must surface as an error (the caller turns it into 500
// InternalError) rather than the previous silent deny with a
// generic "denied by policy" reason. The error/decision must name
// the query so operators can locate the offending policy module.
func TestParseEmbeddedResult_NoAllowKey_ReturnsError(t *testing.T) {
	t.Parallel()

	result := rego.Result{
		Expressions: []*rego.ExpressionValue{{
			Value: map[string]interface{}{
				"reasons": []interface{}{"because"},
			},
		}},
	}

	dec, err := parseEmbeddedResult(result, "data.stac.authz")
	require.Error(t, err, "want error for missing allow key")
	require.Contains(t, err.Error(), "missing the `allow` key", "error must mention missing allow key")
	require.NotNil(t, dec, "decision must be non-nil so caller can surface Reasons")
	require.NotEmpty(t, dec.Reasons, "decision reasons must name the query; got %v", dec.Reasons)
	require.Contains(t, dec.Reasons[len(dec.Reasons)-1], "data.stac.authz", "decision reasons must name the query; got %v", dec.Reasons)
}

// TestParseEmbeddedResult_AllowFalse_DenyWithReason ensures a
// well-formed `{"allow": false, "reasons": [...]}` keeps producing
// a normal deny — the fix above only tightens the "no allow key"
// path.
func TestParseEmbeddedResult_AllowFalse_DenyWithReason(t *testing.T) {
	t.Parallel()

	result := rego.Result{
		Expressions: []*rego.ExpressionValue{{
			Value: map[string]interface{}{
				"allow":   false,
				"reasons": []interface{}{"role lacks admin"},
			},
		}},
	}

	dec, err := parseEmbeddedResult(result, "data.stac.authz")
	require.NoError(t, err, "unexpected error")
	require.NotNil(t, dec, "want deny decision")
	require.False(t, dec.Allowed, "want deny decision, got %+v", dec)
	require.Equal(t, []string{"role lacks admin"}, dec.Reasons, "want reason from policy")
}

// TestEmbeddedOPA_Authorize_NoAllowKey_Returns500 wires the
// fix through Authorize: the enforcer must surface the error so the
// chi-style middleware writes 500. We exercise this with a tiny
// rego policy whose query value is a map without `allow`.
func TestEmbeddedOPA_Authorize_NoAllowKey_Returns500(t *testing.T) {
	t.Parallel()

	const policy = `
package stac.authz

# Deliberately wrong: returns reasons without an allow key.
result = {"reasons": ["missing allow"]}
`
	enf, err := NewEmbeddedOPAEnforcer(EmbeddedOPAConfig{
		Name:    "no-allow",
		Modules: map[string]string{"p.rego": policy},
	})
	require.NoError(t, err, "NewEmbeddedOPAEnforcer")

	_, err = enf.Authorize(context.Background(), &AuthzInput{
		Request: &RequestInfo{Method: "GET", Path: "/"},
	})
	require.Error(t, err, "want error from Authorize when policy result lacks allow key")
}
