package authz

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPolicyEnforcer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		config   PolicyConfig
		wantErr  bool
		validate func(*testing.T, *PolicyEnforcer)
	}{
		{
			name: "empty config",
			config: PolicyConfig{
				Name: "test-enforcer",
			},
			wantErr: false,
			validate: func(t *testing.T, e *PolicyEnforcer) {
				require.NotNil(t, e, "expected non-nil enforcer")
				assert.Equal(t, "test-enforcer", e.name, "name")
				assert.Empty(t, e.policies, "expected empty policies")
			},
		},
		{
			name: "with inline policies",
			config: PolicyConfig{
				Name: "inline-enforcer",
				Policies: []Policy{
					{
						ID:          "policy1",
						Description: "Allow admins",
						Effect:      PolicyEffectAllow,
						Priority:    100,
						Principals: &PrincipalMatcher{
							Roles: []string{"admin"},
						},
					},
					{
						ID:          "policy2",
						Description: "Deny guests",
						Effect:      PolicyEffectDeny,
						Priority:    50,
						Principals: &PrincipalMatcher{
							Roles: []string{"guest"},
						},
					},
				},
			},
			wantErr: false,
			validate: func(t *testing.T, e *PolicyEnforcer) {
				assert.Len(t, e.policies, 2, "expected 2 policies")
				// Policies should be sorted by priority descending
				assert.Equal(t, 100, e.policies[0].Priority, "first policy priority")
				assert.Equal(t, 50, e.policies[1].Priority, "second policy priority")
			},
		},
		{
			name: "policies sorted by priority",
			config: PolicyConfig{
				Name: "sorted-enforcer",
				Policies: []Policy{
					{ID: "low", Priority: 10, Effect: PolicyEffectAllow},
					{ID: "high", Priority: 100, Effect: PolicyEffectAllow},
					{ID: "medium", Priority: 50, Effect: PolicyEffectAllow},
				},
			},
			wantErr: false,
			validate: func(t *testing.T, e *PolicyEnforcer) {
				require.Len(t, e.policies, 3, "expected 3 policies")
				assert.Equal(t, "high", e.policies[0].ID, "first policy ID")
				assert.Equal(t, "medium", e.policies[1].ID, "second policy ID")
				assert.Equal(t, "low", e.policies[2].ID, "third policy ID")
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			e, err := NewPolicyEnforcer(tt.config)
			if tt.wantErr {
				require.Error(t, err, "NewPolicyEnforcer() expected error")
				return
			}
			require.NoError(t, err, "NewPolicyEnforcer() error")

			if tt.validate != nil {
				tt.validate(t, e)
			}
		})
	}
}

func TestNewPolicyEnforcer_FromFile(t *testing.T) {
	t.Parallel()

	t.Run("load policies from valid file", func(t *testing.T) {
		// Create a temporary policy file
		tmpDir := t.TempDir()
		policyFile := filepath.Join(tmpDir, "policies.json")

		policies := []Policy{
			{
				ID:          "file-policy-1",
				Description: "Allow viewers to read collections",
				Effect:      PolicyEffectAllow,
				Priority:    100,
				Principals: &PrincipalMatcher{
					Roles: []string{"viewer"},
				},
				Resources: &ResourceMatcher{
					Types: []string{"collection"},
				},
				Actions: []string{"get:collection"},
			},
			{
				ID:          "file-policy-2",
				Description: "Deny access to sensitive collections",
				Effect:      PolicyEffectDeny,
				Priority:    200,
				Resources: &ResourceMatcher{
					Collections: []string{"sensitive-*"},
				},
			},
		}

		data, err := json.Marshal(policies)
		require.NoError(t, err, "failed to marshal policies")

		require.NoError(t, os.WriteFile(policyFile, data, 0600), "failed to write policy file")

		config := PolicyConfig{
			Name:       "file-enforcer",
			PolicyFile: policyFile,
		}

		e, err := NewPolicyEnforcer(config)
		require.NoError(t, err, "NewPolicyEnforcer() error")

		assert.Len(t, e.policies, 2, "expected 2 policies")

		// Verify policies are sorted by priority
		assert.Equal(t, 200, e.policies[0].Priority, "first policy priority")
	})

	t.Run("load from file with inline policies", func(t *testing.T) {
		tmpDir := t.TempDir()
		policyFile := filepath.Join(tmpDir, "policies.json")

		filePolicies := []Policy{
			{ID: "file-policy", Priority: 50, Effect: PolicyEffectAllow},
		}

		data, err := json.Marshal(filePolicies)
		require.NoError(t, err, "failed to marshal policies")

		require.NoError(t, os.WriteFile(policyFile, data, 0600), "failed to write policy file")

		config := PolicyConfig{
			Name:       "combined-enforcer",
			PolicyFile: policyFile,
			Policies: []Policy{
				{ID: "inline-policy", Priority: 100, Effect: PolicyEffectAllow},
			},
		}

		e, err := NewPolicyEnforcer(config)
		require.NoError(t, err, "NewPolicyEnforcer() error")

		assert.Len(t, e.policies, 2, "expected 2 policies (inline + file)")
	})

	t.Run("error on nonexistent file", func(t *testing.T) {
		config := PolicyConfig{
			Name:       "error-enforcer",
			PolicyFile: "/nonexistent/path/policies.json",
		}

		_, err := NewPolicyEnforcer(config)
		assert.Error(t, err, "expected error for nonexistent file")
	})

	t.Run("error on invalid json", func(t *testing.T) {
		tmpDir := t.TempDir()
		policyFile := filepath.Join(tmpDir, "invalid.json")

		require.NoError(t, os.WriteFile(policyFile, []byte("invalid json"), 0600), "failed to write file")

		config := PolicyConfig{
			Name:       "invalid-enforcer",
			PolicyFile: policyFile,
		}

		_, err := NewPolicyEnforcer(config)
		assert.Error(t, err, "expected error for invalid JSON")
	})
}

func TestPolicyEnforcer_Name(t *testing.T) {
	t.Parallel()

	e, err := NewPolicyEnforcer(PolicyConfig{Name: "test-name"})
	require.NoError(t, err, "NewPolicyEnforcer() error")

	assert.Equal(t, "test-name", e.Name(), "Name()")
}

func TestPolicyEnforcer_Authorize(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		policies        []Policy
		input           *AuthzInput
		wantAllowed     bool
		wantReasons     []string
		wantConstraints bool
	}{
		{
			name: "matching allow policy",
			policies: []Policy{
				{
					ID:       "allow-admins",
					Effect:   PolicyEffectAllow,
					Priority: 100,
					Principals: &PrincipalMatcher{
						Roles: []string{"admin"},
					},
				},
			},
			input: &AuthzInput{
				Principal: &PrincipalInfo{
					ID:    "user1",
					Roles: []string{"admin"},
				},
				Request: &RequestInfo{
					Method:      "GET",
					RequestType: "collection",
				},
				Resource: &ResourceInfo{
					Type: "collection",
				},
			},
			wantAllowed: true,
			wantReasons: []string{"allowed by policy: allow-admins"},
		},
		{
			name: "matching deny policy",
			policies: []Policy{
				{
					ID:       "deny-guests",
					Effect:   PolicyEffectDeny,
					Priority: 100,
					Principals: &PrincipalMatcher{
						Roles: []string{"guest"},
					},
				},
			},
			input: &AuthzInput{
				Principal: &PrincipalInfo{
					ID:    "user1",
					Roles: []string{"guest"},
				},
				Request: &RequestInfo{
					Method:      "GET",
					RequestType: "collection",
				},
				Resource: &ResourceInfo{
					Type: "collection",
				},
			},
			wantAllowed: false,
			wantReasons: []string{"denied by policy: deny-guests"},
		},
		{
			name: "no matching policy - default deny",
			policies: []Policy{
				{
					ID:       "allow-admins",
					Effect:   PolicyEffectAllow,
					Priority: 100,
					Principals: &PrincipalMatcher{
						Roles: []string{"admin"},
					},
				},
			},
			input: &AuthzInput{
				Principal: &PrincipalInfo{
					ID:    "user1",
					Roles: []string{"viewer"},
				},
				Request: &RequestInfo{
					Method:      "GET",
					RequestType: "collection",
				},
				Resource: &ResourceInfo{
					Type: "collection",
				},
			},
			wantAllowed: false,
			wantReasons: []string{"no matching policy found"},
		},
		{
			name: "deny takes precedence at same priority",
			policies: []Policy{
				{
					ID:       "allow-all",
					Effect:   PolicyEffectAllow,
					Priority: 100,
					Principals: &PrincipalMatcher{
						Roles: []string{"*"},
					},
				},
				{
					ID:       "deny-specific",
					Effect:   PolicyEffectDeny,
					Priority: 100,
					Resources: &ResourceMatcher{
						Collections: []string{"sensitive"},
					},
				},
			},
			input: &AuthzInput{
				Principal: &PrincipalInfo{
					ID:    "user1",
					Roles: []string{"viewer"},
				},
				Request: &RequestInfo{
					Method:      "GET",
					RequestType: "item",
				},
				Resource: &ResourceInfo{
					Type:       "item",
					Collection: "sensitive",
				},
			},
			wantAllowed: false,
			wantReasons: []string{"denied by policy: deny-specific"},
		},
		{
			name: "higher priority deny overrides lower priority allow",
			policies: []Policy{
				{
					ID:       "low-priority-allow",
					Effect:   PolicyEffectAllow,
					Priority: 50,
					Principals: &PrincipalMatcher{
						Roles: []string{"*"},
					},
				},
				{
					ID:       "high-priority-deny",
					Effect:   PolicyEffectDeny,
					Priority: 100,
					Resources: &ResourceMatcher{
						Collections: []string{"restricted"},
					},
				},
			},
			input: &AuthzInput{
				Principal: &PrincipalInfo{
					ID:    "user1",
					Roles: []string{"viewer"},
				},
				Request: &RequestInfo{
					Method:      "GET",
					RequestType: "item",
				},
				Resource: &ResourceInfo{
					Type:       "item",
					Collection: "restricted",
				},
			},
			wantAllowed: false,
			wantReasons: []string{"denied by policy: high-priority-deny"},
		},
		{
			name: "higher priority allow overrides lower priority deny",
			policies: []Policy{
				{
					ID:       "low-priority-deny",
					Effect:   PolicyEffectDeny,
					Priority: 50,
					Resources: &ResourceMatcher{
						Collections: []string{"public"},
					},
				},
				{
					ID:       "high-priority-allow",
					Effect:   PolicyEffectAllow,
					Priority: 100,
					Principals: &PrincipalMatcher{
						Roles: []string{"admin"},
					},
				},
			},
			input: &AuthzInput{
				Principal: &PrincipalInfo{
					ID:    "admin1",
					Roles: []string{"admin"},
				},
				Request: &RequestInfo{
					Method:      "GET",
					RequestType: "item",
				},
				Resource: &ResourceInfo{
					Type:       "item",
					Collection: "public",
				},
			},
			wantAllowed: true,
			wantReasons: []string{"allowed by policy: high-priority-allow"},
		},
		{
			name: "policy with constraints",
			policies: []Policy{
				{
					ID:       "allow-with-constraints",
					Effect:   PolicyEffectAllow,
					Priority: 100,
					Principals: &PrincipalMatcher{
						Roles: []string{"viewer"},
					},
					Constraints: &AuthzConstraints{
						AllowedCollections: []string{"public-1", "public-2"},
						MaxResults:         100,
					},
				},
			},
			input: &AuthzInput{
				Principal: &PrincipalInfo{
					ID:    "user1",
					Roles: []string{"viewer"},
				},
				Request: &RequestInfo{
					Method:      "GET",
					RequestType: "search",
				},
				Resource: &ResourceInfo{
					Type: "search",
				},
			},
			wantAllowed:     true,
			wantReasons:     []string{"allowed by policy: allow-with-constraints"},
			wantConstraints: true,
		},
		{
			name:     "empty policies - default deny",
			policies: []Policy{},
			input: &AuthzInput{
				Principal: &PrincipalInfo{
					ID:    "user1",
					Roles: []string{"viewer"},
				},
				Request: &RequestInfo{
					Method:      "GET",
					RequestType: "collection",
				},
				Resource: &ResourceInfo{
					Type: "collection",
				},
			},
			wantAllowed: false,
			wantReasons: []string{"no matching policy found"},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			e, err := NewPolicyEnforcer(PolicyConfig{
				Name:     "test",
				Policies: tt.policies,
			})
			require.NoError(t, err, "NewPolicyEnforcer() error")

			decision, err := e.Authorize(context.Background(), tt.input)
			require.NoError(t, err, "Authorize() error")
			require.NotNil(t, decision, "expected non-nil decision")

			assert.Equal(t, tt.wantAllowed, decision.Allowed, "Allowed")

			if len(decision.Reasons) != len(tt.wantReasons) {
				t.Errorf("Reasons count = %d, want %d", len(decision.Reasons), len(tt.wantReasons))
			} else {
				for i, reason := range tt.wantReasons {
					assert.Equal(t, reason, decision.Reasons[i], "Reason[%d]", i)
				}
			}

			if tt.wantConstraints {
				assert.NotNil(t, decision.Constraints, "expected constraints to be set")
			}

			if !tt.wantConstraints && decision.Allowed {
				assert.Nil(t, decision.Constraints, "expected no constraints")
			}
		})
	}
}

func TestPrincipalMatcher(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		matcher   *PrincipalMatcher
		principal *PrincipalInfo
		wantMatch bool
	}{
		{
			name: "match by ID",
			matcher: &PrincipalMatcher{
				IDs: []string{"user123", "user456"},
			},
			principal: &PrincipalInfo{
				ID: "user123",
			},
			wantMatch: true,
		},
		{
			name: "no match by ID",
			matcher: &PrincipalMatcher{
				IDs: []string{"user123", "user456"},
			},
			principal: &PrincipalInfo{
				ID: "user789",
			},
			wantMatch: false,
		},
		{
			name: "match by wildcard ID",
			matcher: &PrincipalMatcher{
				IDs: []string{"*"},
			},
			principal: &PrincipalInfo{
				ID: "any-user",
			},
			wantMatch: true,
		},
		{
			name: "match by role",
			matcher: &PrincipalMatcher{
				Roles: []string{"admin", "editor"},
			},
			principal: &PrincipalInfo{
				ID:    "user1",
				Roles: []string{"editor", "viewer"},
			},
			wantMatch: true,
		},
		{
			name: "no match by role",
			matcher: &PrincipalMatcher{
				Roles: []string{"admin"},
			},
			principal: &PrincipalInfo{
				ID:    "user1",
				Roles: []string{"viewer"},
			},
			wantMatch: false,
		},
		{
			name: "match by wildcard role",
			matcher: &PrincipalMatcher{
				Roles: []string{"*"},
			},
			principal: &PrincipalInfo{
				ID:    "user1",
				Roles: []string{"any-role"},
			},
			wantMatch: true,
		},
		{
			name: "match by group",
			matcher: &PrincipalMatcher{
				Groups: []string{"team-a", "team-b"},
			},
			principal: &PrincipalInfo{
				ID:     "user1",
				Groups: []string{"team-a"},
			},
			wantMatch: true,
		},
		{
			name: "no match by group",
			matcher: &PrincipalMatcher{
				Groups: []string{"team-a"},
			},
			principal: &PrincipalInfo{
				ID:     "user1",
				Groups: []string{"team-c"},
			},
			wantMatch: false,
		},
		{
			name: "match by type",
			matcher: &PrincipalMatcher{
				Types: []string{"user", "service"},
			},
			principal: &PrincipalInfo{
				ID:   "user1",
				Type: "user",
			},
			wantMatch: true,
		},
		{
			name: "no match by type",
			matcher: &PrincipalMatcher{
				Types: []string{"service"},
			},
			principal: &PrincipalInfo{
				ID:   "user1",
				Type: "user",
			},
			wantMatch: false,
		},
		{
			name: "match by wildcard type",
			matcher: &PrincipalMatcher{
				Types: []string{"*"},
			},
			principal: &PrincipalInfo{
				ID:   "user1",
				Type: "any-type",
			},
			wantMatch: true,
		},
		{
			name: "match multiple criteria",
			matcher: &PrincipalMatcher{
				IDs:    []string{"user123"},
				Roles:  []string{"admin"},
				Groups: []string{"team-a"},
				Types:  []string{"user"},
			},
			principal: &PrincipalInfo{
				ID:     "user123",
				Type:   "user",
				Roles:  []string{"admin"},
				Groups: []string{"team-a"},
			},
			wantMatch: true,
		},
		{
			name: "fail if any criteria doesn't match",
			matcher: &PrincipalMatcher{
				IDs:   []string{"user123"},
				Roles: []string{"admin"},
			},
			principal: &PrincipalInfo{
				ID:    "user123",
				Roles: []string{"viewer"}, // Wrong role
			},
			wantMatch: false,
		},
		{
			name: "nil principal",
			matcher: &PrincipalMatcher{
				Roles: []string{"admin"},
			},
			principal: nil,
			wantMatch: false,
		},
		{
			// M-authz-3: a PrincipalMatcher whose every field is empty
			// must NOT match anything. Operators wanting "match all"
			// should omit the matcher (set to nil) instead.
			name:      "empty matcher matches nothing",
			matcher:   &PrincipalMatcher{},
			principal: &PrincipalInfo{ID: "user1"},
			wantMatch: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			policy := Policy{
				ID:         "test-policy",
				Effect:     PolicyEffectAllow,
				Priority:   100,
				Principals: tt.matcher,
			}

			e, err := NewPolicyEnforcer(PolicyConfig{
				Name:     "test",
				Policies: []Policy{policy},
			})
			require.NoError(t, err, "NewPolicyEnforcer() error")

			input := &AuthzInput{
				Principal: tt.principal,
				Request: &RequestInfo{
					Method:      "GET",
					RequestType: "collection",
				},
				Resource: &ResourceInfo{
					Type: "collection",
				},
			}

			matched := e.matches(&policy, input)
			assert.Equal(t, tt.wantMatch, matched, "matches()")
		})
	}
}

func TestResourceMatcher(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		matcher   *ResourceMatcher
		resource  *ResourceInfo
		wantMatch bool
	}{
		{
			name: "match by type",
			matcher: &ResourceMatcher{
				Types: []string{"collection", "item"},
			},
			resource: &ResourceInfo{
				Type: "collection",
			},
			wantMatch: true,
		},
		{
			name: "no match by type",
			matcher: &ResourceMatcher{
				Types: []string{"collection"},
			},
			resource: &ResourceInfo{
				Type: "search",
			},
			wantMatch: false,
		},
		{
			name: "match by wildcard type",
			matcher: &ResourceMatcher{
				Types: []string{"*"},
			},
			resource: &ResourceInfo{
				Type: "any-type",
			},
			wantMatch: true,
		},
		{
			name: "match by exact collection",
			matcher: &ResourceMatcher{
				Collections: []string{"public-data", "open-data"},
			},
			resource: &ResourceInfo{
				Type:       "item",
				Collection: "public-data",
			},
			wantMatch: true,
		},
		{
			name: "no match by collection",
			matcher: &ResourceMatcher{
				Collections: []string{"public-data"},
			},
			resource: &ResourceInfo{
				Type:       "item",
				Collection: "private-data",
			},
			wantMatch: false,
		},
		{
			name: "match by wildcard collection",
			matcher: &ResourceMatcher{
				Collections: []string{"*"},
			},
			resource: &ResourceInfo{
				Type:       "item",
				Collection: "any-collection",
			},
			wantMatch: true,
		},
		{
			name: "match by collection glob pattern",
			matcher: &ResourceMatcher{
				Collections: []string{"public-*"},
			},
			resource: &ResourceInfo{
				Type:       "item",
				Collection: "public-imagery",
			},
			wantMatch: true,
		},
		{
			name: "no match by collection glob pattern",
			matcher: &ResourceMatcher{
				Collections: []string{"public-*"},
			},
			resource: &ResourceInfo{
				Type:       "item",
				Collection: "private-imagery",
			},
			wantMatch: false,
		},
		{
			name: "match multiple criteria",
			matcher: &ResourceMatcher{
				Types:       []string{"item"},
				Collections: []string{"public-*"},
			},
			resource: &ResourceInfo{
				Type:       "item",
				Collection: "public-data",
			},
			wantMatch: true,
		},
		{
			name: "fail if any criteria doesn't match",
			matcher: &ResourceMatcher{
				Types:       []string{"collection"},
				Collections: []string{"public-*"},
			},
			resource: &ResourceInfo{
				Type:       "item", // Wrong type
				Collection: "public-data",
			},
			wantMatch: false,
		},
		{
			name: "nil resource",
			matcher: &ResourceMatcher{
				Types: []string{"collection"},
			},
			resource:  nil,
			wantMatch: false,
		},
		{
			name:      "empty matcher matches anything",
			matcher:   &ResourceMatcher{},
			resource:  &ResourceInfo{Type: "collection"},
			wantMatch: true,
		},
		{
			name: "collection matcher with empty collection",
			matcher: &ResourceMatcher{
				Collections: []string{"specific-collection"},
			},
			resource: &ResourceInfo{
				Type:       "collection",
				Collection: "",
			},
			wantMatch: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			policy := Policy{
				ID:        "test-policy",
				Effect:    PolicyEffectAllow,
				Priority:  100,
				Resources: tt.matcher,
			}

			e, err := NewPolicyEnforcer(PolicyConfig{
				Name:     "test",
				Policies: []Policy{policy},
			})
			require.NoError(t, err, "NewPolicyEnforcer() error")

			input := &AuthzInput{
				Principal: &PrincipalInfo{ID: "user1"},
				Request: &RequestInfo{
					Method:      "GET",
					RequestType: "collection",
				},
				Resource: tt.resource,
			}

			matched := e.matches(&policy, input)
			assert.Equal(t, tt.wantMatch, matched, "matches()")
		})
	}
}

func TestActionMatcher(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		actions   []string
		request   *RequestInfo
		wantMatch bool
	}{
		{
			name:    "exact action match",
			actions: []string{"get:collection", "post:search"},
			request: &RequestInfo{
				Method:      "GET",
				RequestType: "collection",
			},
			wantMatch: true,
		},
		{
			name:    "case insensitive match",
			actions: []string{"GET:COLLECTION"},
			request: &RequestInfo{
				Method:      "get",
				RequestType: "collection",
			},
			wantMatch: true,
		},
		{
			name:    "no match",
			actions: []string{"post:item"},
			request: &RequestInfo{
				Method:      "GET",
				RequestType: "collection",
			},
			wantMatch: false,
		},
		{
			name:    "wildcard matches all",
			actions: []string{"*"},
			request: &RequestInfo{
				Method:      "DELETE",
				RequestType: "item",
			},
			wantMatch: true,
		},
		{
			name:    "wildcard method",
			actions: []string{"*:collection"},
			request: &RequestInfo{
				Method:      "GET",
				RequestType: "collection",
			},
			wantMatch: true,
		},
		{
			name:    "wildcard request type",
			actions: []string{"get:*"},
			request: &RequestInfo{
				Method:      "GET",
				RequestType: "anything",
			},
			wantMatch: true,
		},
		{
			name:    "glob pattern with prefix",
			actions: []string{"get:*"},
			request: &RequestInfo{
				Method:      "GET",
				RequestType: "collection",
			},
			wantMatch: true,
		},
		{
			name:    "glob pattern with suffix",
			actions: []string{"*:search"},
			request: &RequestInfo{
				Method:      "POST",
				RequestType: "search",
			},
			wantMatch: true,
		},
		{
			name:    "multiple actions - one matches",
			actions: []string{"post:item", "get:collection", "delete:item"},
			request: &RequestInfo{
				Method:      "GET",
				RequestType: "collection",
			},
			wantMatch: true,
		},
		{
			name:      "nil request",
			actions:   []string{"get:collection"},
			request:   nil,
			wantMatch: false,
		},
		{
			name:    "empty actions list",
			actions: []string{},
			request: &RequestInfo{
				Method:      "GET",
				RequestType: "collection",
			},
			wantMatch: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			policy := Policy{
				ID:       "test-policy",
				Effect:   PolicyEffectAllow,
				Priority: 100,
				Actions:  tt.actions,
			}

			e, err := NewPolicyEnforcer(PolicyConfig{
				Name:     "test",
				Policies: []Policy{policy},
			})
			require.NoError(t, err, "NewPolicyEnforcer() error")

			input := &AuthzInput{
				Principal: &PrincipalInfo{ID: "user1"},
				Request:   tt.request,
				Resource:  &ResourceInfo{Type: "collection"},
			}

			matched := e.matches(&policy, input)
			assert.Equal(t, tt.wantMatch, matched, "matches()")
		})
	}
}

func TestMatchGlob(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		pattern string
		s       string
		want    bool
	}{
		{
			name:    "wildcard matches all",
			pattern: "*",
			s:       "anything",
			want:    true,
		},
		{
			name:    "exact match no wildcard",
			pattern: "exact",
			s:       "exact",
			want:    true,
		},
		{
			name:    "no match no wildcard",
			pattern: "exact",
			s:       "different",
			want:    false,
		},
		{
			name:    "prefix wildcard",
			pattern: "prefix-*",
			s:       "prefix-test",
			want:    true,
		},
		{
			name:    "prefix wildcard no match",
			pattern: "prefix-*",
			s:       "other-test",
			want:    false,
		},
		{
			name:    "suffix wildcard",
			pattern: "*-suffix",
			s:       "test-suffix",
			want:    true,
		},
		{
			name:    "suffix wildcard no match",
			pattern: "*-suffix",
			s:       "test-other",
			want:    false,
		},
		{
			name:    "prefix and suffix wildcard",
			pattern: "start-*-end",
			s:       "start-middle-end",
			want:    true,
		},
		{
			name:    "prefix and suffix wildcard no match",
			pattern: "start-*-end",
			s:       "start-middle-other",
			want:    false,
		},
		{
			name:    "empty string with wildcard",
			pattern: "*",
			s:       "",
			want:    true,
		},
		{
			name:    "empty pattern",
			pattern: "",
			s:       "test",
			want:    false,
		},
		{
			name:    "both empty",
			pattern: "",
			s:       "",
			want:    true,
		},
		{
			name:    "wildcard in middle matches anything",
			pattern: "a*z",
			s:       "abcdefghijklmnopqrstuvwxyz",
			want:    true,
		},
		{
			name:    "wildcard in middle no suffix match",
			pattern: "a*z",
			s:       "abcdefg",
			want:    false,
		},
		{
			name:    "wildcard in middle no prefix match",
			pattern: "a*z",
			s:       "xyzz",
			want:    false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := matchGlob(tt.pattern, tt.s)
			assert.Equal(t, tt.want, got, "matchGlob(%q, %q)", tt.pattern, tt.s)
		})
	}
}

func TestReloadPolicies(t *testing.T) {
	t.Parallel()

	t.Run("successful reload", func(t *testing.T) {
		tmpDir := t.TempDir()
		policyFile := filepath.Join(tmpDir, "policies.json")

		// Initial policies
		initialPolicies := []Policy{
			{ID: "policy1", Effect: PolicyEffectAllow, Priority: 100},
		}
		data, err := json.Marshal(initialPolicies)
		require.NoError(t, err, "failed to marshal policies")
		require.NoError(t, os.WriteFile(policyFile, data, 0600), "failed to write policy file")

		e, err := NewPolicyEnforcer(PolicyConfig{
			Name:       "test",
			PolicyFile: policyFile,
		})
		require.NoError(t, err, "NewPolicyEnforcer() error")

		assert.Len(t, e.policies, 1, "initial policies count")

		// Update policies
		updatedPolicies := []Policy{
			{ID: "policy1", Effect: PolicyEffectAllow, Priority: 100},
			{ID: "policy2", Effect: PolicyEffectDeny, Priority: 200},
			{ID: "policy3", Effect: PolicyEffectAllow, Priority: 50},
		}
		data, err = json.Marshal(updatedPolicies)
		require.NoError(t, err, "failed to marshal updated policies")
		require.NoError(t, os.WriteFile(policyFile, data, 0600), "failed to write updated policy file")

		// Reload
		require.NoError(t, e.ReloadPolicies(policyFile), "ReloadPolicies() error")

		assert.Len(t, e.policies, 3, "reloaded policies count")

		// Verify policies are sorted by priority
		assert.Equal(t, 200, e.policies[0].Priority, "first policy priority")
		assert.Equal(t, 100, e.policies[1].Priority, "second policy priority")
		assert.Equal(t, 50, e.policies[2].Priority, "third policy priority")
	})

	t.Run("reload from nonexistent file", func(t *testing.T) {
		e, err := NewPolicyEnforcer(PolicyConfig{Name: "test"})
		require.NoError(t, err, "NewPolicyEnforcer() error")

		err = e.ReloadPolicies("/nonexistent/policies.json")
		assert.Error(t, err, "expected error for nonexistent file")
	})

	t.Run("reload from invalid json", func(t *testing.T) {
		tmpDir := t.TempDir()
		policyFile := filepath.Join(tmpDir, "invalid.json")

		require.NoError(t, os.WriteFile(policyFile, []byte("invalid json"), 0600), "failed to write file")

		e, err := NewPolicyEnforcer(PolicyConfig{Name: "test"})
		require.NoError(t, err, "NewPolicyEnforcer() error")

		err = e.ReloadPolicies(policyFile)
		assert.Error(t, err, "expected error for invalid JSON")
	})
}

func TestValidatePolicies(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		policies []Policy
		wantErr  bool
		errMsg   string
	}{
		{
			name: "valid policies",
			policies: []Policy{
				{ID: "policy1", Effect: PolicyEffectAllow},
				{ID: "policy2", Effect: PolicyEffectDeny},
			},
			wantErr: false,
		},
		{
			name: "missing ID",
			policies: []Policy{
				{ID: "", Effect: PolicyEffectAllow},
			},
			wantErr: true,
			errMsg:  "policy missing ID",
		},
		{
			name: "duplicate ID",
			policies: []Policy{
				{ID: "duplicate", Effect: PolicyEffectAllow},
				{ID: "duplicate", Effect: PolicyEffectDeny},
			},
			wantErr: true,
			errMsg:  "duplicate policy ID: duplicate",
		},
		{
			name: "invalid effect",
			policies: []Policy{
				{ID: "policy1", Effect: "invalid"},
			},
			wantErr: true,
			errMsg:  "invalid policy effect: invalid",
		},
		{
			name: "empty effect treated as invalid",
			policies: []Policy{
				{ID: "policy1", Effect: ""},
			},
			wantErr: true,
			errMsg:  "invalid policy effect: ",
		},
		{
			name:     "empty policies list",
			policies: []Policy{},
			wantErr:  false,
		},
		{
			name: "valid effects allow and deny",
			policies: []Policy{
				{ID: "allow-policy", Effect: PolicyEffectAllow},
				{ID: "deny-policy", Effect: PolicyEffectDeny},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := ValidatePolicies(tt.policies)
			if tt.wantErr {
				require.Error(t, err, "ValidatePolicies() expected error")
				if tt.errMsg != "" {
					assert.Equal(t, tt.errMsg, err.Error(), "ValidatePolicies() error message")
				}
				return
			}
			require.NoError(t, err, "ValidatePolicies() error")
		})
	}
}

func TestPolicyEnforcer_ComplexScenarios(t *testing.T) {
	t.Parallel()

	t.Run("multi-tier authorization", func(t *testing.T) {
		policies := []Policy{
			{
				ID:       "deny-sensitive",
				Effect:   PolicyEffectDeny,
				Priority: 1000,
				Resources: &ResourceMatcher{
					Collections: []string{"classified-*"},
				},
			},
			{
				ID:       "allow-admin-sensitive",
				Effect:   PolicyEffectAllow,
				Priority: 2000,
				Principals: &PrincipalMatcher{
					Roles: []string{"admin"},
				},
				Resources: &ResourceMatcher{
					Collections: []string{"classified-*"},
				},
			},
			{
				ID:       "allow-viewer-public",
				Effect:   PolicyEffectAllow,
				Priority: 500,
				Principals: &PrincipalMatcher{
					Roles: []string{"viewer"},
				},
				Resources: &ResourceMatcher{
					Collections: []string{"public-*"},
				},
			},
		}

		e, err := NewPolicyEnforcer(PolicyConfig{
			Name:     "multi-tier",
			Policies: policies,
		})
		require.NoError(t, err, "NewPolicyEnforcer() error")

		// Admin can access classified data
		adminInput := &AuthzInput{
			Principal: &PrincipalInfo{
				ID:    "admin1",
				Roles: []string{"admin"},
			},
			Request: &RequestInfo{
				Method:      "GET",
				RequestType: "item",
			},
			Resource: &ResourceInfo{
				Type:       "item",
				Collection: "classified-military",
			},
		}

		decision, err := e.Authorize(context.Background(), adminInput)
		require.NoError(t, err, "Authorize() error")
		assert.True(t, decision.Allowed, "admin should be allowed to access classified data")

		// Viewer cannot access classified data
		viewerClassifiedInput := &AuthzInput{
			Principal: &PrincipalInfo{
				ID:    "viewer1",
				Roles: []string{"viewer"},
			},
			Request: &RequestInfo{
				Method:      "GET",
				RequestType: "item",
			},
			Resource: &ResourceInfo{
				Type:       "item",
				Collection: "classified-military",
			},
		}

		decision, err = e.Authorize(context.Background(), viewerClassifiedInput)
		require.NoError(t, err, "Authorize() error")
		assert.False(t, decision.Allowed, "viewer should not be allowed to access classified data")

		// Viewer can access public data
		viewerPublicInput := &AuthzInput{
			Principal: &PrincipalInfo{
				ID:    "viewer1",
				Roles: []string{"viewer"},
			},
			Request: &RequestInfo{
				Method:      "GET",
				RequestType: "item",
			},
			Resource: &ResourceInfo{
				Type:       "item",
				Collection: "public-imagery",
			},
		}

		decision, err = e.Authorize(context.Background(), viewerPublicInput)
		require.NoError(t, err, "Authorize() error")
		assert.True(t, decision.Allowed, "viewer should be allowed to access public data")
	})

	t.Run("action-based authorization", func(t *testing.T) {
		policies := []Policy{
			{
				ID:       "allow-read",
				Effect:   PolicyEffectAllow,
				Priority: 100,
				Principals: &PrincipalMatcher{
					Roles: []string{"reader"},
				},
				Actions: []string{"get:*"},
			},
			{
				ID:       "allow-write",
				Effect:   PolicyEffectAllow,
				Priority: 100,
				Principals: &PrincipalMatcher{
					Roles: []string{"writer"},
				},
				Actions: []string{"post:*", "put:*", "delete:*"},
			},
		}

		e, err := NewPolicyEnforcer(PolicyConfig{
			Name:     "action-based",
			Policies: policies,
		})
		require.NoError(t, err, "NewPolicyEnforcer() error")

		// Reader can GET
		readerGetInput := &AuthzInput{
			Principal: &PrincipalInfo{
				ID:    "reader1",
				Roles: []string{"reader"},
			},
			Request: &RequestInfo{
				Method:      "GET",
				RequestType: "collection",
			},
			Resource: &ResourceInfo{
				Type: "collection",
			},
		}

		decision, err := e.Authorize(context.Background(), readerGetInput)
		require.NoError(t, err, "Authorize() error")
		assert.True(t, decision.Allowed, "reader should be allowed to GET")

		// Reader cannot POST
		readerPostInput := &AuthzInput{
			Principal: &PrincipalInfo{
				ID:    "reader1",
				Roles: []string{"reader"},
			},
			Request: &RequestInfo{
				Method:      "POST",
				RequestType: "item",
			},
			Resource: &ResourceInfo{
				Type: "item",
			},
		}

		decision, err = e.Authorize(context.Background(), readerPostInput)
		require.NoError(t, err, "Authorize() error")
		assert.False(t, decision.Allowed, "reader should not be allowed to POST")

		// Writer can POST
		writerPostInput := &AuthzInput{
			Principal: &PrincipalInfo{
				ID:    "writer1",
				Roles: []string{"writer"},
			},
			Request: &RequestInfo{
				Method:      "POST",
				RequestType: "item",
			},
			Resource: &ResourceInfo{
				Type: "item",
			},
		}

		decision, err = e.Authorize(context.Background(), writerPostInput)
		require.NoError(t, err, "Authorize() error")
		assert.True(t, decision.Allowed, "writer should be allowed to POST")
	})
}

func TestPolicyEnforcer_Interface(t *testing.T) {
	t.Parallel()

	// Verify PolicyEnforcer implements Enforcer interface
	var _ Enforcer = (*PolicyEnforcer)(nil)
}

func TestPolicyEnforcer_Concurrency(t *testing.T) {
	t.Parallel()

	policies := []Policy{
		{
			ID:       "policy1",
			Effect:   PolicyEffectAllow,
			Priority: 100,
			Principals: &PrincipalMatcher{
				Roles: []string{"*"},
			},
		},
	}

	e, err := NewPolicyEnforcer(PolicyConfig{
		Name:     "concurrent",
		Policies: policies,
	})
	require.NoError(t, err, "NewPolicyEnforcer() error")

	// Test concurrent authorization
	done := make(chan bool)
	for i := 0; i < 100; i++ {
		go func(id int) {
			input := &AuthzInput{
				Principal: &PrincipalInfo{
					ID:    "user",
					Roles: []string{"viewer"},
				},
				Request: &RequestInfo{
					Method:      "GET",
					RequestType: "collection",
				},
				Resource: &ResourceInfo{
					Type: "collection",
				},
			}

			_, err := e.Authorize(context.Background(), input)
			if err != nil {
				t.Errorf("Authorize() error = %v", err)
			}
			done <- true
		}(i)
	}

	for i := 0; i < 100; i++ {
		<-done
	}
}

func TestPolicyEnforcer_ConcurrentReload(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "policies.json")

	initialPolicies := []Policy{
		{ID: "policy1", Effect: PolicyEffectAllow, Priority: 100},
	}
	data, err := json.Marshal(initialPolicies)
	require.NoError(t, err, "failed to marshal policies")
	require.NoError(t, os.WriteFile(policyFile, data, 0600), "failed to write policy file")

	e, err := NewPolicyEnforcer(PolicyConfig{
		Name:       "reload-test",
		PolicyFile: policyFile,
	})
	require.NoError(t, err, "NewPolicyEnforcer() error")

	done := make(chan bool)

	// Concurrent reads
	for i := 0; i < 50; i++ {
		go func() {
			input := &AuthzInput{
				Principal: &PrincipalInfo{ID: "user1", Roles: []string{"viewer"}},
				Request:   &RequestInfo{Method: "GET", RequestType: "collection"},
				Resource:  &ResourceInfo{Type: "collection"},
			}
			_, err := e.Authorize(context.Background(), input)
			if err != nil {
				t.Errorf("Authorize() error = %v", err)
			}
			done <- true
		}()
	}

	// Concurrent reload
	go func() {
		updatedPolicies := []Policy{
			{ID: "policy1", Effect: PolicyEffectAllow, Priority: 100},
			{ID: "policy2", Effect: PolicyEffectDeny, Priority: 200},
		}
		data, _ := json.Marshal(updatedPolicies)
		os.WriteFile(policyFile, data, 0600)
		e.ReloadPolicies(policyFile)
		done <- true
	}()

	for i := 0; i < 51; i++ {
		<-done
	}
}

func TestHelperFunctions(t *testing.T) {
	t.Parallel()

	t.Run("containsString", func(t *testing.T) {
		tests := []struct {
			name  string
			slice []string
			s     string
			want  bool
		}{
			{
				name:  "found",
				slice: []string{"a", "b", "c"},
				s:     "b",
				want:  true,
			},
			{
				name:  "not found",
				slice: []string{"a", "b", "c"},
				s:     "d",
				want:  false,
			},
			{
				name:  "empty slice",
				slice: []string{},
				s:     "a",
				want:  false,
			},
			{
				name:  "empty string",
				slice: []string{"a", "", "c"},
				s:     "",
				want:  true,
			},
		}

		for _, tt := range tests {
			tt := tt
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()
				got := containsString(tt.slice, tt.s)
				assert.Equal(t, tt.want, got, "containsString(%v, %q)", tt.slice, tt.s)
			})
		}
	})

	t.Run("hasAnyRole", func(t *testing.T) {
		tests := []struct {
			name string
			a    []string
			b    []string
			want bool
		}{
			{
				name: "has common role",
				a:    []string{"admin", "viewer"},
				b:    []string{"editor", "admin"},
				want: true,
			},
			{
				name: "no common role",
				a:    []string{"admin", "viewer"},
				b:    []string{"editor", "writer"},
				want: false,
			},
			{
				name: "empty a",
				a:    []string{},
				b:    []string{"admin"},
				want: false,
			},
			{
				name: "empty b",
				a:    []string{"admin"},
				b:    []string{},
				want: false,
			},
			{
				name: "both empty",
				a:    []string{},
				b:    []string{},
				want: false,
			},
		}

		for _, tt := range tests {
			tt := tt
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()
				got := hasAnyRole(tt.a, tt.b)
				assert.Equal(t, tt.want, got, "hasAnyRole(%v, %v)", tt.a, tt.b)
			})
		}
	})
}

func TestEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("nil principal info", func(t *testing.T) {
		policy := Policy{
			ID:       "test",
			Effect:   PolicyEffectAllow,
			Priority: 100,
			Principals: &PrincipalMatcher{
				Roles: []string{"admin"},
			},
		}

		e, err := NewPolicyEnforcer(PolicyConfig{
			Name:     "test",
			Policies: []Policy{policy},
		})
		require.NoError(t, err, "NewPolicyEnforcer() error")

		input := &AuthzInput{
			Principal: nil,
			Request: &RequestInfo{
				Method:      "GET",
				RequestType: "collection",
			},
			Resource: &ResourceInfo{
				Type: "collection",
			},
		}

		decision, err := e.Authorize(context.Background(), input)
		require.NoError(t, err, "Authorize() error")
		assert.False(t, decision.Allowed, "should not allow nil principal")
	})

	t.Run("nil resource info", func(t *testing.T) {
		policy := Policy{
			ID:       "test",
			Effect:   PolicyEffectAllow,
			Priority: 100,
			Resources: &ResourceMatcher{
				Types: []string{"collection"},
			},
		}

		e, err := NewPolicyEnforcer(PolicyConfig{
			Name:     "test",
			Policies: []Policy{policy},
		})
		require.NoError(t, err, "NewPolicyEnforcer() error")

		input := &AuthzInput{
			Principal: &PrincipalInfo{
				ID:    "user1",
				Roles: []string{"viewer"},
			},
			Request: &RequestInfo{
				Method:      "GET",
				RequestType: "collection",
			},
			Resource: nil,
		}

		decision, err := e.Authorize(context.Background(), input)
		require.NoError(t, err, "Authorize() error")
		assert.False(t, decision.Allowed, "should not allow nil resource")
	})

	t.Run("nil request info", func(t *testing.T) {
		policy := Policy{
			ID:       "test",
			Effect:   PolicyEffectAllow,
			Priority: 100,
			Actions:  []string{"get:collection"},
		}

		e, err := NewPolicyEnforcer(PolicyConfig{
			Name:     "test",
			Policies: []Policy{policy},
		})
		require.NoError(t, err, "NewPolicyEnforcer() error")

		input := &AuthzInput{
			Principal: &PrincipalInfo{
				ID:    "user1",
				Roles: []string{"viewer"},
			},
			Request: nil,
			Resource: &ResourceInfo{
				Type: "collection",
			},
		}

		decision, err := e.Authorize(context.Background(), input)
		require.NoError(t, err, "Authorize() error")
		assert.False(t, decision.Allowed, "should not allow nil request")
	})

	t.Run("policy with all matchers nil", func(t *testing.T) {
		policy := Policy{
			ID:       "test",
			Effect:   PolicyEffectAllow,
			Priority: 100,
			// All matchers nil
		}

		e, err := NewPolicyEnforcer(PolicyConfig{
			Name:     "test",
			Policies: []Policy{policy},
		})
		require.NoError(t, err, "NewPolicyEnforcer() error")

		input := &AuthzInput{
			Principal: &PrincipalInfo{
				ID:    "user1",
				Roles: []string{"viewer"},
			},
			Request: &RequestInfo{
				Method:      "GET",
				RequestType: "collection",
			},
			Resource: &ResourceInfo{
				Type: "collection",
			},
		}

		decision, err := e.Authorize(context.Background(), input)
		require.NoError(t, err, "Authorize() error")

		// Policy with no matchers should match everything
		assert.True(t, decision.Allowed, "policy with no matchers should match everything")
	})
}

// TestPolicy_EmptyPrincipalMatcherMatchesNothing verifies M-authz-3:
// `principals: {}` (an object with all fields empty) must NOT match
// any principal. The previous behaviour silently treated each empty
// field as wildcard, allowing or denying everyone — a footgun for an
// operator who expected `{}` to mean "no constraint".
func TestPolicy_EmptyPrincipalMatcherMatchesNothing(t *testing.T) {
	t.Parallel()

	policy := Policy{
		ID:         "empty-matcher",
		Effect:     PolicyEffectAllow,
		Priority:   100,
		Principals: &PrincipalMatcher{}, // explicit-empty object
	}

	e, err := NewPolicyEnforcer(PolicyConfig{
		Name:     "test",
		Policies: []Policy{policy},
	})
	require.NoError(t, err, "NewPolicyEnforcer")

	input := &AuthzInput{
		Principal: &PrincipalInfo{ID: "anyone"},
		Request:   &RequestInfo{Method: "GET", RequestType: "collection"},
		Resource:  &ResourceInfo{Type: "collection"},
	}

	decision, err := e.Authorize(context.Background(), input)
	require.NoError(t, err, "Authorize")
	require.False(t, decision.Allowed, "want deny (empty matcher matches nothing), got allow: %+v", decision)
}

// TestPolicy_NilPrincipalMatcherMatchesAll verifies that omitting the
// principals matcher entirely (nil) preserves the historical
// "no principal constraint" semantics. This is how an operator should
// state "this policy applies to every authenticated principal".
func TestPolicy_NilPrincipalMatcherMatchesAll(t *testing.T) {
	t.Parallel()

	policy := Policy{
		ID:         "nil-matcher",
		Effect:     PolicyEffectAllow,
		Priority:   100,
		Principals: nil, // omitted — match all
		Actions:    []string{"*"},
	}

	e, err := NewPolicyEnforcer(PolicyConfig{
		Name:     "test",
		Policies: []Policy{policy},
	})
	require.NoError(t, err, "NewPolicyEnforcer")

	input := &AuthzInput{
		Principal: &PrincipalInfo{ID: "anyone", Type: "user"},
		Request:   &RequestInfo{Method: "GET", RequestType: "collection"},
		Resource:  &ResourceInfo{Type: "collection"},
	}

	decision, err := e.Authorize(context.Background(), input)
	require.NoError(t, err, "Authorize")
	require.True(t, decision.Allowed, "want allow (nil matcher = no constraint), got deny: %+v", decision)
}
