package stac

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTypeAliasesRoundTrip is a smoke test that the library-backed
// STAC types preserve foreign members through a marshal/unmarshal
// cycle, which is the foundational guarantee we adopted the library
// for. The library has its own exhaustive tests for shape-by-shape
// behavior; here we only verify the integration boundary holds.
func TestTypeAliasesRoundTrip(t *testing.T) {
	t.Parallel()

	const raw = `{
		"type": "Feature",
		"stac_version": "1.0.0",
		"stac_extensions": ["https://stac-extensions.github.io/eo/v1.0.0/schema.json"],
		"id": "test-1",
		"geometry": {"type":"Point","coordinates":[1,2]},
		"properties": {
			"datetime": "2024-01-01T00:00:00Z",
			"eo:cloud_cover": 5.5
		},
		"links": [{"href":"https://example.com/items/test-1","rel":"self"}],
		"assets": {
			"data": {"href":"https://example.com/data.tif","type":"image/tiff"}
		},
		"collection": "test-collection",
		"custom:foreign": "preserved"
	}`

	var item Item
	require.NoError(t, json.Unmarshal([]byte(raw), &item))

	assert.Equal(t, "test-1", item.ID)
	require.Len(t, item.Extensions, 1)
	assert.Contains(t, item.Extensions[0], "/eo/", "Extensions[0] = %q, want eo extension", item.Extensions[0])
	assert.Equal(t, 5.5, item.Properties["eo:cloud_cover"])
	assert.Equal(t, "preserved", item.AdditionalFields["custom:foreign"], "custom:foreign foreign member dropped")

	out, err := json.Marshal(&item)
	require.NoError(t, err)
	assert.Contains(t, string(out), `"custom:foreign":"preserved"`, "foreign member dropped on re-marshal")
	assert.Contains(t, string(out), `"stac_extensions"`, "stac_extensions dropped on re-marshal")
}

// TestItemDatetimeHelper covers the typed helper that bridges the
// library's untyped map[string]any Properties to a Go time.Time.
func TestItemDatetimeHelper(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		props map[string]any
		want  bool
	}{
		{"datetime present", map[string]any{"datetime": "2024-01-01T00:00:00Z"}, true},
		{"start_datetime fallback", map[string]any{"datetime": nil, "start_datetime": "2024-01-01T00:00:00Z"}, true},
		{"rfc3339nano", map[string]any{"datetime": "2024-01-01T00:00:00.123456789Z"}, true},
		{"date-only fallback", map[string]any{"datetime": "2024-01-01"}, true},
		{"absent", map[string]any{}, false},
		{"unparseable", map[string]any{"datetime": "not-a-date"}, false},
		{"nil properties", nil, false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			item := &Item{Properties: tt.props}
			_, ok := ItemDatetime(item)
			assert.Equal(t, tt.want, ok, "ItemDatetime ok = %v, want %v", ok, tt.want)
		})
	}
}

// TestForeignMemberHelpers covers SetItemForeignMember /
// SetCollectionForeignMember — proxy code uses them to attach
// stac_proxy:* markers without leaking through the map directly.
func TestForeignMemberHelpers(t *testing.T) {
	t.Parallel()

	item := &Item{ID: "x"}
	SetItemForeignMember(item, "stac_proxy:origin", "origin-a")
	assert.Equal(t, "origin-a", item.AdditionalFields["stac_proxy:origin"], "item foreign member not set")

	coll := &Collection{ID: "x"}
	SetCollectionForeignMember(coll, "stac_proxy:origin", "origin-a")
	assert.Equal(t, "origin-a", coll.AdditionalFields["stac_proxy:origin"], "collection foreign member not set")
}

// TestSearchContextOfHandlesMapForm verifies that SearchContextOf
// recovers a typed *SearchContext both from the in-memory typed value
// and from a JSON-round-tripped map[string]any.
func TestSearchContextOfHandlesMapForm(t *testing.T) {
	t.Parallel()

	fc := &FeatureCollection{
		Type:    "FeatureCollection",
		Context: &SearchContext{Returned: 3, Matched: 10, Limit: 5},
	}
	sc := SearchContextOf(fc)
	require.NotNil(t, sc, "typed: got nil")
	assert.Equal(t, 3, sc.Returned)
	assert.Equal(t, 10, sc.Matched)

	out, _ := json.Marshal(fc)
	var parsed FeatureCollection
	require.NoError(t, json.Unmarshal(out, &parsed))
	sc = SearchContextOf(&parsed)
	require.NotNil(t, sc, "after round-trip: got nil")
	assert.Equal(t, 3, sc.Returned)
	assert.Equal(t, 10, sc.Matched)

	assert.Nil(t, SearchContextOf(nil), "nil fc should yield nil context")
	assert.Nil(t, SearchContextOf(&FeatureCollection{}), "absent context should yield nil")
}
