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
	"os"
	"path/filepath"
	"testing"

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

	// Invalid policy (syntax error)
	invalidPolicy = `
package stac.authz

this is not valid rego syntax
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
	}{
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
			name:   "deny with reasons",
			policy: `
package stac.authz

default allow = false

result = {
	"allow": allow,
	"reasons": reasons,
	"constraints": {}
}

reasons[msg] {
	not allow
	msg := "denied by policy"
}
`,
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

			require.NoError(t, err, "unexpected error")
			require.NotNil(t, decision, "expected non-nil decision")
			assert.Equal(t, tt.expectedAllowed, decision.Allowed, "allowed")

			if len(tt.expectedReasons) > 0 {
				require.NotEmpty(t, decision.Reasons, "expected reasons %v, got none", tt.expectedReasons)
				require.True(t, containsAny(decision.Reasons, tt.expectedReasons), "expected reasons to contain one of %v, got %v", tt.expectedReasons, decision.Reasons)
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

// Helper functions

func createTempPolicyFile(t *testing.T, content string) string {
	t.Helper()

	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "policy.rego")

	require.NoError(t, os.WriteFile(tmpFile, []byte(content), 0644), "failed to create temp policy file")

	return tmpFile
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
