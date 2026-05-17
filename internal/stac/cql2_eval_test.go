package stac

import (
	"testing"

	cql2 "github.com/exergy-dev/go-cql2"
	_ "github.com/exergy-dev/go-cql2/codecs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustParse(t *testing.T, s string) cql2.Node {
	t.Helper()
	n, err := cql2.Parse([]byte(s))
	require.NoErrorf(t, err, "parse %q", s)
	return n
}

func TestEvalCQL2_NumericComparison(t *testing.T) {
	item := map[string]interface{}{
		"properties": map[string]interface{}{
			"eo:cloud_cover": 12.5,
		},
	}
	got, err := EvalCQL2(mustParse(t, "eo:cloud_cover < 20"), item)
	require.NoError(t, err)
	require.True(t, got)
	got, err = EvalCQL2(mustParse(t, "eo:cloud_cover < 10"), item)
	require.NoError(t, err)
	require.False(t, got)
}

func TestEvalCQL2_AndOrNot(t *testing.T) {
	item := map[string]interface{}{
		"properties": map[string]interface{}{
			"eo:cloud_cover": 12.5,
			"platform":       "sentinel-2a",
		},
	}
	cases := []struct {
		expr string
		want bool
	}{
		{"eo:cloud_cover < 20 AND platform = 'sentinel-2a'", true},
		{"eo:cloud_cover < 20 AND platform = 'landsat-8'", false},
		{"eo:cloud_cover > 100 OR platform = 'sentinel-2a'", true},
		{"NOT eo:cloud_cover < 5", true},
	}
	for _, c := range cases {
		got, err := EvalCQL2(mustParse(t, c.expr), item)
		if !assert.NoErrorf(t, err, "%s", c.expr) {
			continue
		}
		assert.Equalf(t, c.want, got, "%s", c.expr)
	}
}

func TestEvalCQL2_TopLevelField(t *testing.T) {
	item := map[string]interface{}{
		"id":         "abc",
		"collection": "sentinel-2-l2a",
		"properties": map[string]interface{}{},
	}
	got, err := EvalCQL2(mustParse(t, "collection = 'sentinel-2-l2a'"), item)
	require.NoError(t, err)
	require.True(t, got)
}

func TestEvalCQL2_InOperator(t *testing.T) {
	item := map[string]interface{}{
		"properties": map[string]interface{}{
			"platform": "sentinel-2a",
		},
	}
	got, err := EvalCQL2(mustParse(t, "platform IN ('sentinel-2a','sentinel-2b')"), item)
	require.NoError(t, err)
	require.True(t, got)
	got, err = EvalCQL2(mustParse(t, "platform IN ('landsat-8','landsat-9')"), item)
	require.NoError(t, err)
	require.False(t, got)
}

func TestEvalCQL2_IsNull(t *testing.T) {
	item := map[string]interface{}{
		"properties": map[string]interface{}{},
	}
	got, err := EvalCQL2(mustParse(t, "platform IS NULL"), item)
	require.NoError(t, err)
	require.True(t, got)
}

// boxPolygon centred on (0,0) with the supplied half-extent.
func boxPolygon(half float64) map[string]interface{} {
	return map[string]interface{}{
		"type": "Polygon",
		"coordinates": []interface{}{
			[]interface{}{
				[]interface{}{-half, -half},
				[]interface{}{half, -half},
				[]interface{}{half, half},
				[]interface{}{-half, half},
				[]interface{}{-half, -half},
			},
		},
	}
}

func TestEvalCQL2_SIntersects_Match(t *testing.T) {
	// Item geometry is a small box well inside the polygon.
	item := map[string]interface{}{
		"geometry": boxPolygon(0.5),
	}
	got, err := EvalCQL2(mustParse(t,
		`S_INTERSECTS(geometry, POLYGON((-10 -10, 10 -10, 10 10, -10 10, -10 -10)))`), item)
	require.NoError(t, err)
	require.True(t, got, "want item geometry to intersect surrounding polygon")
}

func TestEvalCQL2_SIntersects_NoMatch(t *testing.T) {
	// Item geometry sits to the east of the literal polygon.
	item := map[string]interface{}{
		"geometry": map[string]interface{}{
			"type": "Polygon",
			"coordinates": []interface{}{
				[]interface{}{
					[]interface{}{20.0, 20.0},
					[]interface{}{21.0, 20.0},
					[]interface{}{21.0, 21.0},
					[]interface{}{20.0, 21.0},
					[]interface{}{20.0, 20.0},
				},
			},
		},
	}
	got, err := EvalCQL2(mustParse(t,
		`S_INTERSECTS(geometry, POLYGON((-10 -10, 10 -10, 10 10, -10 10, -10 -10)))`), item)
	require.NoError(t, err)
	require.False(t, got, "want disjoint geometries to NOT intersect")
}

func TestEvalCQL2_SIntersects_NullGeometry(t *testing.T) {
	// Item with null geometry must drop out (false), not crash.
	item := map[string]interface{}{
		"geometry": nil,
	}
	got, err := EvalCQL2(mustParse(t,
		`S_INTERSECTS(geometry, POLYGON((-10 -10, 10 -10, 10 10, -10 10, -10 -10)))`), item)
	require.NoError(t, err)
	require.False(t, got, "want false for null item geometry")
}

func TestEvalCQL2_TopLevelNotBoolean(t *testing.T) {
	_, err := EvalCQL2(mustParse(t, "42"), map[string]interface{}{})
	require.Error(t, err, "want error for non-boolean top-level")
}
