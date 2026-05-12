package stac

import (
	"testing"

	cql2 "github.com/exergy-dev/go-cql2"
	_ "github.com/exergy-dev/go-cql2/codecs"
)

func mustParse(t *testing.T, s string) cql2.Node {
	t.Helper()
	n, err := cql2.Parse([]byte(s))
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return n
}

func TestEvalCQL2_NumericComparison(t *testing.T) {
	item := map[string]interface{}{
		"properties": map[string]interface{}{
			"eo:cloud_cover": 12.5,
		},
	}
	got, err := EvalCQL2(mustParse(t, "eo:cloud_cover < 20"), item)
	if err != nil || !got {
		t.Fatalf("want true/nil, got %v/%v", got, err)
	}
	got, err = EvalCQL2(mustParse(t, "eo:cloud_cover < 10"), item)
	if err != nil || got {
		t.Fatalf("want false/nil, got %v/%v", got, err)
	}
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
		if err != nil {
			t.Errorf("%s: err=%v", c.expr, err)
			continue
		}
		if got != c.want {
			t.Errorf("%s: got=%v want=%v", c.expr, got, c.want)
		}
	}
}

func TestEvalCQL2_TopLevelField(t *testing.T) {
	item := map[string]interface{}{
		"id":         "abc",
		"collection": "sentinel-2-l2a",
		"properties": map[string]interface{}{},
	}
	got, err := EvalCQL2(mustParse(t, "collection = 'sentinel-2-l2a'"), item)
	if err != nil || !got {
		t.Fatalf("want true, got %v err=%v", got, err)
	}
}

func TestEvalCQL2_InOperator(t *testing.T) {
	item := map[string]interface{}{
		"properties": map[string]interface{}{
			"platform": "sentinel-2a",
		},
	}
	got, err := EvalCQL2(mustParse(t, "platform IN ('sentinel-2a','sentinel-2b')"), item)
	if err != nil || !got {
		t.Fatalf("want true, got %v err=%v", got, err)
	}
	got, err = EvalCQL2(mustParse(t, "platform IN ('landsat-8','landsat-9')"), item)
	if err != nil || got {
		t.Fatalf("want false, got %v err=%v", got, err)
	}
}

func TestEvalCQL2_IsNull(t *testing.T) {
	item := map[string]interface{}{
		"properties": map[string]interface{}{},
	}
	got, err := EvalCQL2(mustParse(t, "platform IS NULL"), item)
	if err != nil || !got {
		t.Fatalf("want true, got %v err=%v", got, err)
	}
}

func TestEvalCQL2_UnsupportedSpatial(t *testing.T) {
	item := map[string]interface{}{}
	_, err := EvalCQL2(mustParse(t, `S_INTERSECTS(geometry, POINT(0 0))`), item)
	if err == nil {
		t.Fatal("want unsupported error for spatial op")
	}
	if _, ok := err.(*ErrUnsupportedNode); !ok {
		// Wrapping is fine; just want the error.
		t.Logf("err type: %T %v", err, err)
	}
}

func TestEvalCQL2_TopLevelNotBoolean(t *testing.T) {
	if _, err := EvalCQL2(mustParse(t, "42"), map[string]interface{}{}); err == nil {
		t.Fatal("want error for non-boolean top-level")
	}
}
