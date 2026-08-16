package pageadapter

import (
	"testing"

	"github.com/exergy-dev/stac-proxy/internal/stac"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Verbatim-href capture and the cross-origin SSRF rejection are covered
// in adapter_test.go. These tests cover the Done/exhausted cases, the
// POST-link deferral to post_body, and Probe confidence.

// TestNextURL_DoneCases: absent rel=next (or nothing to follow) signals
// end-of-pagination cleanly.
func TestNextURL_DoneCases(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		fc   *stac.FeatureCollection
	}{
		{"nil FeatureCollection", nil},
		{"no links at all", &stac.FeatureCollection{}},
		{"no rel=next link", &stac.FeatureCollection{Links: []*stac.Link{
			{Rel: "self", Href: "https://api.example.com/search"},
		}}},
		{"rel=next with empty href", fcWithNext("", nil)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			a := newNextURL(Config{})
			st, err := a.Capture(UpstreamResponse{FC: c.fc, BaseURL: "https://api.example.com"})
			require.NoError(t, err)
			assert.True(t, st.Done, "Done; want true")
			assert.Empty(t, st.URL, "URL; want none")
		})
	}
}

// TestNextURL_DefersPOSTLinks: a rel=next link declaring method=POST is
// post_body's territory. next_url must not capture its href (a bare GET
// against it would return the upstream's unfiltered default page). It
// reports Done=false so the link stays claimable by another adapter.
func TestNextURL_DefersPOSTLinks(t *testing.T) {
	t.Parallel()
	for _, method := range []string{"POST", "post", "Post"} {
		t.Run(method, func(t *testing.T) {
			t.Parallel()
			a := newNextURL(Config{})
			st, err := a.Capture(UpstreamResponse{
				FC:      fcWithPOSTLink("https://api.example.com/search", method, map[string]any{"token": "X"}),
				BaseURL: "https://api.example.com",
			})
			require.NoError(t, err, "POST link is not an error, just unclaimed")
			assert.Empty(t, st.URL, "URL; next_url must not claim a POST link")
			assert.False(t, st.Done, "Done; want false (next link present, deferred to post_body)")
		})
	}
}

// TestNextURL_FollowsExplicitGETLink: a link that declares method=GET
// explicitly is captured like a method-less one.
func TestNextURL_FollowsExplicitGETLink(t *testing.T) {
	t.Parallel()
	a := newNextURL(Config{})
	href := "https://api.example.com/v1/search?cursor=abc"
	st, err := a.Capture(UpstreamResponse{
		FC:      fcWithPOSTLink(href, "GET", nil),
		BaseURL: "https://api.example.com/v1",
	})
	require.NoError(t, err)
	assert.Equal(t, href, st.URL, "URL; explicit method=GET links are followed verbatim")
	assert.False(t, st.Done, "Done; want false")
}

// TestNextURL_Probe: 0.6 on a followable link (ranked below token's 0.9
// so auto prefers the more efficient token convention when both match),
// 0 at end-of-pagination, and 0 — with a zero state, not a poisoned one
// — when Capture errors on a cross-origin href.
func TestNextURL_Probe(t *testing.T) {
	t.Parallel()
	a := newNextURL(Config{})

	conf, st := a.Probe(UpstreamResponse{
		FC:      fcWithNext("https://api.example.com/v1/search?next=ABC", nil),
		BaseURL: "https://api.example.com/v1",
	})
	assert.InDelta(t, 0.6, conf, 0.001, "confidence; want 0.6 on followable link")
	assert.Equal(t, "https://api.example.com/v1/search?next=ABC", st.URL, "Probe state carries the URL")

	conf, st = a.Probe(UpstreamResponse{FC: &stac.FeatureCollection{}, BaseURL: "https://api.example.com"})
	assert.Zero(t, conf, "confidence; want 0 at end of pagination")
	assert.True(t, st.Done, "Probe state reports Done at end of pagination")

	conf, st = a.Probe(UpstreamResponse{
		FC:      fcWithNext("https://evil.example.com/v1/search?next=x", nil),
		BaseURL: "https://api.example.com/v1",
	})
	assert.Zero(t, conf, "confidence; want 0 when Capture errors (cross-origin)")
	assert.Empty(t, st.URL, "Probe state must not leak the cross-origin URL")
}
