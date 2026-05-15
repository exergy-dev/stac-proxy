package stac

import (
	"encoding/json"
	"strings"
	"testing"
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
	if err := json.Unmarshal([]byte(raw), &item); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if item.ID != "test-1" {
		t.Errorf("ID = %q, want test-1", item.ID)
	}
	if len(item.Extensions) != 1 {
		t.Fatalf("Extensions len = %d, want 1", len(item.Extensions))
	}
	if !strings.Contains(item.Extensions[0], "/eo/") {
		t.Errorf("Extensions[0] = %q, want eo extension", item.Extensions[0])
	}
	if got := item.Properties["eo:cloud_cover"]; got != 5.5 {
		t.Errorf("eo:cloud_cover = %v, want 5.5", got)
	}
	if got := item.AdditionalFields["custom:foreign"]; got != "preserved" {
		t.Errorf("custom:foreign foreign member dropped, got %v", got)
	}

	out, err := json.Marshal(&item)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(out), `"custom:foreign":"preserved"`) {
		t.Error("foreign member dropped on re-marshal")
	}
	if !strings.Contains(string(out), `"stac_extensions"`) {
		t.Error("stac_extensions dropped on re-marshal")
	}
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
			if ok != tt.want {
				t.Errorf("ItemDatetime ok = %v, want %v", ok, tt.want)
			}
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
	if item.AdditionalFields["stac_proxy:origin"] != "origin-a" {
		t.Errorf("item foreign member not set")
	}

	coll := &Collection{ID: "x"}
	SetCollectionForeignMember(coll, "stac_proxy:origin", "origin-a")
	if coll.AdditionalFields["stac_proxy:origin"] != "origin-a" {
		t.Errorf("collection foreign member not set")
	}
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
	if sc := SearchContextOf(fc); sc == nil || sc.Returned != 3 || sc.Matched != 10 {
		t.Fatalf("typed: got %+v", sc)
	}

	out, _ := json.Marshal(fc)
	var parsed FeatureCollection
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if sc := SearchContextOf(&parsed); sc == nil || sc.Returned != 3 || sc.Matched != 10 {
		t.Fatalf("after round-trip: got %+v", sc)
	}

	if SearchContextOf(nil) != nil {
		t.Errorf("nil fc should yield nil context")
	}
	if SearchContextOf(&FeatureCollection{}) != nil {
		t.Errorf("absent context should yield nil")
	}
}
