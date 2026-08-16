package authz

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// exampleEnforcer compiles the shipped example policy
// (policies/stac_authz.rego). Before this test existed, the example
// was compiled by nothing — it shipped with a fail-open anonymous
// path, a dead geofence rule, a broken "*" wildcard, and an
// all-or-nothing constraints literal, none of which CI could see.
func exampleEnforcer(t *testing.T) *EmbeddedOPAEnforcer {
	t.Helper()
	path, err := filepath.Abs(filepath.Join("..", "..", "..", "policies", "stac_authz.rego"))
	require.NoError(t, err)
	enf, err := NewEmbeddedOPAEnforcer(context.Background(), EmbeddedOPAConfig{
		Name:        "example-policy",
		PolicyPaths: []string{path},
	})
	require.NoError(t, err, "the shipped example policy must compile")
	return enf
}

func TestExamplePolicy_Decisions(t *testing.T) {
	t.Parallel()
	enf := exampleEnforcer(t)

	principal := func(id string, roles ...string) *PrincipalInfo {
		return &PrincipalInfo{ID: id, Type: "user", Roles: roles}
	}
	input := func(p *PrincipalInfo, method, reqType, collection string) *AuthzInput {
		return &AuthzInput{
			Principal: p,
			Request:   &RequestInfo{Method: method, Path: "/" + reqType, RequestType: reqType},
			Resource:  &ResourceInfo{Collection: collection},
		}
	}
	decide := func(t *testing.T, in *AuthzInput) *AuthzDecision {
		t.Helper()
		dec, err := enf.Authorize(context.Background(), in)
		require.NoError(t, err)
		require.NotNil(t, dec)
		return dec
	}

	t.Run("anonymous search is denied with auth-required reason", func(t *testing.T) {
		t.Parallel()
		dec := decide(t, input(nil, "POST", "search", ""))
		assert.False(t, dec.Allowed)
		assert.Contains(t, dec.Reasons, "authentication required")
	})

	t.Run("anonymous landing allowed with clamped limit", func(t *testing.T) {
		t.Parallel()
		dec := decide(t, input(nil, "GET", "landing", ""))
		require.True(t, dec.Allowed)
		require.NotNil(t, dec.Constraints)
		assert.Equal(t, 10, dec.Constraints.MaxResults, "anonymous max_results clamp")
	})

	t.Run("anonymous write is denied", func(t *testing.T) {
		t.Parallel()
		dec := decide(t, input(nil, "POST", "collection", "sentinel-2-l2a"))
		assert.False(t, dec.Allowed)
	})

	t.Run("authenticated write is denied for non-admin", func(t *testing.T) {
		t.Parallel()
		dec := decide(t, input(principal("bob", "user"), "POST", "collection", "x"))
		assert.False(t, dec.Allowed)
		assert.Contains(t, dec.Reasons, "insufficient permissions")
	})

	t.Run("admin write allowed with no collection scoping", func(t *testing.T) {
		t.Parallel()
		dec := decide(t, input(principal("root", "admin"), "POST", "collection", "x"))
		require.True(t, dec.Allowed)
		require.NotNil(t, dec.Constraints)
		assert.Empty(t, dec.Constraints.AllowedCollections,
			"full-access roles omit allowed_collections (there is no '*' wildcard)")
	})

	t.Run("regular user search: public collections + limit + cloud filter", func(t *testing.T) {
		t.Parallel()
		dec := decide(t, input(principal("bob", "user"), "POST", "search", ""))
		require.True(t, dec.Allowed)
		require.NotNil(t, dec.Constraints)
		assert.ElementsMatch(t,
			[]string{"sentinel-2-l2a", "landsat-c2-l2", "cop-dem-glo-30", "cop-dem-glo-90"},
			dec.Constraints.AllowedCollections)
		assert.Equal(t, 100, dec.Constraints.MaxResults)
		assert.Equal(t, "eo:cloud_cover < 20", dec.Constraints.CQL2Filter,
			"non-premium search carries the cloud-cover clamp")
	})

	t.Run("premium search: bigger limit, no filter", func(t *testing.T) {
		t.Parallel()
		dec := decide(t, input(principal("carol", "premium"), "POST", "search", ""))
		require.True(t, dec.Allowed)
		require.NotNil(t, dec.Constraints)
		assert.Equal(t, 1000, dec.Constraints.MaxResults)
		assert.Empty(t, dec.Constraints.CQL2Filter, "premium users get no cloud-cover clamp")
	})

	t.Run("data_scientist: no collection scoping, standard limit", func(t *testing.T) {
		t.Parallel()
		dec := decide(t, input(principal("dana", "data_scientist"), "GET", "search", ""))
		require.True(t, dec.Allowed)
		require.NotNil(t, dec.Constraints)
		assert.Empty(t, dec.Constraints.AllowedCollections)
		assert.Equal(t, 100, dec.Constraints.MaxResults)
	})

	t.Run("geofenced user carries a real geofence constraint", func(t *testing.T) {
		t.Parallel()
		dec := decide(t, input(principal("user123", "user"), "GET", "search", ""))
		require.True(t, dec.Allowed)
		require.NotNil(t, dec.Constraints)
		require.NotNil(t, dec.Constraints.Geofence,
			"the geofence must be a member of constraints, not a bare package rule")
		assert.NotNil(t, dec.Constraints.Geofence.AllowedArea)
		assert.True(t, dec.Constraints.Geofence.FilterMode)
	})

	t.Run("non-geofenced user has no geofence", func(t *testing.T) {
		t.Parallel()
		dec := decide(t, input(principal("bob", "user"), "GET", "search", ""))
		require.True(t, dec.Allowed)
		require.NotNil(t, dec.Constraints)
		assert.Nil(t, dec.Constraints.Geofence)
	})
}
