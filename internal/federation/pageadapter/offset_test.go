package pageadapter

import (
	"testing"

	"github.com/exergy-dev/stac-proxy/internal/stac"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Basic offset capture and the custom OffsetParam knob are covered in
// adapter_test.go. These tests cover the URL-alongside-offset contract,
// the (deliberately lenient) Done fallbacks for malformed input, and
// Probe confidence.

// TestOffset_CapturesURLAlongsideOffset: the adapter captures the full
// next-page URL alongside the numeric offset so the paginator can fetch
// verbatim instead of reconstructing the upstream's query shape.
func TestOffset_CapturesURLAlongsideOffset(t *testing.T) {
	t.Parallel()
	a := newOffset(Config{})
	href := "https://api.example.com/search?offset=50&limit=25&collections=c1"
	st, err := a.Capture(UpstreamResponse{
		FC:      fcWithNext(href, nil),
		BaseURL: "https://api.example.com",
	})
	require.NoError(t, err)
	assert.Equal(t, 50, st.Offset, "Offset")
	assert.Equal(t, href, st.URL, "URL; want verbatim next href alongside the offset")
	assert.False(t, st.Done, "Done; want false")
}

// TestOffset_DoneFallbacks: the offset adapter is deliberately lenient —
// anything it cannot parse as its convention (including a cross-origin
// href) degrades to Done=true rather than erroring, retiring the cursor
// cleanly.
func TestOffset_DoneFallbacks(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		fc   *stac.FeatureCollection
	}{
		{"nil FeatureCollection", nil},
		{"no rel=next link", &stac.FeatureCollection{Links: []*stac.Link{
			{Rel: "self", Href: "https://api.example.com/search?offset=0"},
		}}},
		{"empty href", fcWithNext("", nil)},
		{"unparseable href", fcWithNext("://not-a-url", nil)},
		{"missing offset param", fcWithNext("https://api.example.com/search?token=ABC", nil)},
		{"non-numeric offset", fcWithNext("https://api.example.com/search?offset=fifty", nil)},
		{"cross-origin href", fcWithNext("https://evil.example.com/search?offset=50", nil)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			a := newOffset(Config{})
			st, err := a.Capture(UpstreamResponse{FC: c.fc, BaseURL: "https://api.example.com"})
			require.NoError(t, err, "offset adapter degrades to Done, never errors")
			assert.True(t, st.Done, "Done; want true")
			assert.Empty(t, st.URL, "URL; want none")
			assert.Zero(t, st.Offset, "Offset; want zero")
		})
	}
}

// TestOffset_CustomParamIgnoresDefault: with OffsetParam overridden to
// "page", a next link carrying only ?offset= is not this adapter's
// convention and degrades to Done.
func TestOffset_CustomParamIgnoresDefault(t *testing.T) {
	t.Parallel()
	a := newOffset(Config{OffsetParam: "page"})
	st, err := a.Capture(UpstreamResponse{
		FC:      fcWithNext("https://api.example.com/search?offset=50", nil),
		BaseURL: "https://api.example.com",
	})
	require.NoError(t, err)
	assert.True(t, st.Done, "Done; want true (configured param 'page' absent)")
	assert.Zero(t, st.Offset, "Offset; must not fall back to the default 'offset' param")
}

// TestOffset_Probe: 0.7 when the offset convention matches (above
// next_url's 0.6 so auto prefers the explicit signal, below token's
// 0.9), 0 otherwise.
func TestOffset_Probe(t *testing.T) {
	t.Parallel()
	a := newOffset(Config{})

	conf, st := a.Probe(UpstreamResponse{
		FC:      fcWithNext("https://api.example.com/search?offset=50", nil),
		BaseURL: "https://api.example.com",
	})
	assert.InDelta(t, 0.7, conf, 0.001, "confidence; want 0.7 on offset match")
	assert.Equal(t, 50, st.Offset, "Probe state carries the offset")

	conf, st = a.Probe(UpstreamResponse{
		FC:      fcWithNext("https://api.example.com/search?token=ABC", nil),
		BaseURL: "https://api.example.com",
	})
	assert.Zero(t, conf, "confidence; want 0 when the offset param is absent")
	assert.True(t, st.Done, "Probe state degrades to Done for non-offset links")
}
