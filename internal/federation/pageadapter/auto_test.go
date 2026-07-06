package pageadapter

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/stac-proxy/internal/stac"
)

// auto's token-over-next_url preference, the Earth Search fallback to
// next_url, and Done-on-no-match are covered in adapter_test.go. These
// tests pin down the rest of the probe ranking (post_body > token >
// offset > link_header > next_url), the AdapterName lock-in contract,
// and auto's own Probe.

// TestAuto_PicksPostBodyForPOSTNextLink: a spec-style POST rel=next link
// with a body matches both post_body (0.95) and token (0.9, via
// body.token); post_body must win and the choice must be locked into
// AdapterName for the cursor's lifetime.
func TestAuto_PicksPostBodyForPOSTNextLink(t *testing.T) {
	t.Parallel()
	a := newAuto(Config{})
	st, err := a.Capture(UpstreamResponse{
		FC:      fcWithNext("https://api.example.com/search", map[string]any{"token": "PC-CURSOR"}),
		BaseURL: "https://api.example.com",
	})
	require.NoError(t, err)
	assert.Equal(t, "post_body", st.AdapterName, "AdapterName; POST-with-body must beat token")
	assert.Equal(t, "https://api.example.com/search", st.URL, "URL; want the POST replay target")
	assert.JSONEq(t, `{"token":"PC-CURSOR"}`, string(st.Body), "Body; want the verbatim replay body")
	assert.False(t, st.Done, "Done; want false")
}

// TestAuto_PicksOffsetOverNextURL: a ?offset= next link matches both
// offset (0.7) and next_url (0.6); the explicit offset signal wins.
func TestAuto_PicksOffsetOverNextURL(t *testing.T) {
	t.Parallel()
	a := newAuto(Config{})
	st, err := a.Capture(UpstreamResponse{
		FC:      fcWithNext("https://api.example.com/search?offset=50&limit=25", nil),
		BaseURL: "https://api.example.com",
	})
	require.NoError(t, err)
	assert.Equal(t, "offset", st.AdapterName, "AdapterName; explicit offset must beat generic next_url")
	assert.Equal(t, 50, st.Offset, "Offset")
	assert.Equal(t, "https://api.example.com/search?offset=50&limit=25", st.URL, "URL captured alongside the offset")
}

// TestAuto_PicksLinkHeaderWhenOnlyHeaderSignal: with no body links at
// all, the RFC 5988 Link header (0.5) is the only positive probe.
func TestAuto_PicksLinkHeaderWhenOnlyHeaderSignal(t *testing.T) {
	t.Parallel()
	a := newAuto(Config{})
	hdr := http.Header{}
	hdr.Set("Link", `<https://api.example.com/v1/search?startindex=20>; rel="next"`)
	st, err := a.Capture(UpstreamResponse{
		FC:      &stac.FeatureCollection{},
		Header:  hdr,
		BaseURL: "https://api.example.com/v1",
	})
	require.NoError(t, err)
	assert.Equal(t, "link_header", st.AdapterName, "AdapterName; header is the only signal")
	assert.Equal(t, "https://api.example.com/v1/search?startindex=20", st.URL, "URL from the Link header")
}

// TestAuto_BodyNextURLBeatsLinkHeader: when a GET-style body rel=next
// (0.6) and a Link header (0.5) are both present, the body link wins —
// its URL is what gets followed.
func TestAuto_BodyNextURLBeatsLinkHeader(t *testing.T) {
	t.Parallel()
	a := newAuto(Config{})
	hdr := http.Header{}
	hdr.Set("Link", `<https://api.example.com/v1/search?from-header=1>; rel="next"`)
	st, err := a.Capture(UpstreamResponse{
		FC:      fcWithNext("https://api.example.com/v1/search?cursor=from-body", nil),
		Header:  hdr,
		BaseURL: "https://api.example.com/v1",
	})
	require.NoError(t, err)
	assert.Equal(t, "next_url", st.AdapterName, "AdapterName; body link outranks Link header")
	assert.Equal(t, "https://api.example.com/v1/search?cursor=from-body", st.URL, "URL; want the body link's href")
}

// TestAuto_DoneStateCarriesNoAdapterName: at end-of-pagination (or on
// an unrecognised convention) auto returns a clean Done state without
// locking any adapter name into the cursor.
func TestAuto_DoneStateCarriesNoAdapterName(t *testing.T) {
	t.Parallel()
	a := newAuto(Config{})

	// No links anywhere.
	st, err := a.Capture(UpstreamResponse{FC: &stac.FeatureCollection{}, BaseURL: "https://api.example.com"})
	require.NoError(t, err)
	assert.True(t, st.Done, "Done; want true")
	assert.Empty(t, st.AdapterName, "AdapterName; must not be set on Done")

	// A rel=next link every inner adapter refuses — a cross-origin
	// GET href with no token/offset param. The SSRF guards zero out
	// the URL-following probes, so auto retires the cursor cleanly
	// instead of erroring or following the foreign URL. (A foreign
	// href with ?token= would still be claimed by the token adapter,
	// which extracts the opaque token rather than following the URL.)
	st, err = a.Capture(UpstreamResponse{
		FC:      fcWithNext("https://evil.example.com/search?next=X", nil),
		BaseURL: "https://api.example.com",
	})
	require.NoError(t, err)
	if assert.True(t, st.Done, "Done; want true when no adapter claims the link") {
		assert.Empty(t, st.URL, "URL; the cross-origin href must not leak into the cursor")
	}
}

// TestAuto_Probe: composite confidence is 1.0 when any inner adapter
// matches and 0 at end-of-pagination.
func TestAuto_Probe(t *testing.T) {
	t.Parallel()
	a := newAuto(Config{})

	conf, st := a.Probe(UpstreamResponse{
		FC:      fcWithNext("https://api.example.com/search?token=ABC", nil),
		BaseURL: "https://api.example.com",
	})
	assert.InDelta(t, 1.0, conf, 0.001, "confidence; want 1.0 when an inner adapter matches")
	assert.Equal(t, "token", st.AdapterName, "Probe state carries the locked adapter name")

	conf, st = a.Probe(UpstreamResponse{FC: &stac.FeatureCollection{}, BaseURL: "https://api.example.com"})
	assert.Zero(t, conf, "confidence; want 0 at end of pagination")
	assert.True(t, st.Done, "Probe state reports Done")
}
