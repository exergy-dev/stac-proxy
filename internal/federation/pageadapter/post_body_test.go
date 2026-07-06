package pageadapter

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/stac-proxy/internal/stac"
)

// fcWithPOSTLink builds an upstream FeatureCollection carrying a single
// rel="next" link with an explicit method casing and optional body.
// Unlike the package-level fcWithNext (which always stamps method=POST
// when a body is present), this lets tests drive method casing and the
// no-body case independently.
func fcWithPOSTLink(href, method string, body any) *stac.FeatureCollection {
	fields := map[string]any{}
	if method != "" {
		fields["method"] = method
	}
	if body != nil {
		fields["body"] = body
	}
	link := &stac.Link{Rel: "next", Href: href}
	if len(fields) > 0 {
		link.AdditionalFields = fields
	}
	return &stac.FeatureCollection{Links: []*stac.Link{link}}
}

// --- post_body adapter ----------------------------------------------

// TestPostBody_CapturesVerbatimBody covers the core contract: a POST
// rel=next link with a body is captured verbatim (URL + JSON body) and
// reports not-done so the paginator replays it for the next page.
func TestPostBody_CapturesVerbatimBody(t *testing.T) {
	a := newPostBody(Config{})
	href := "https://api.example.com/search"
	st, err := a.Capture(UpstreamResponse{
		FC:      fcWithNext(href, map[string]any{"token": "PC-CURSOR", "collections": []any{"c1"}}),
		BaseURL: "https://api.example.com",
	})
	require.NoError(t, err)
	assert.Equal(t, href, st.URL, "URL; want verbatim next href")
	assert.False(t, st.Done, "Done; want false (body present, more pages)")
	// Body round-trips to the same JSON object (order-independent).
	assert.JSONEq(t, `{"token":"PC-CURSOR","collections":["c1"]}`, string(st.Body),
		"Body; want the rel=next link body captured verbatim")
}

// TestPostBody_MethodCasing asserts method matching is case-insensitive.
func TestPostBody_MethodCasing(t *testing.T) {
	for _, method := range []string{"post", "POST", "Post"} {
		t.Run(method, func(t *testing.T) {
			a := newPostBody(Config{})
			st, err := a.Capture(UpstreamResponse{
				FC:      fcWithPOSTLink("https://api.example.com/search", method, map[string]any{"token": "X"}),
				BaseURL: "https://api.example.com",
			})
			require.NoError(t, err)
			assert.False(t, st.Done, "Done; want false for method=%q", method)
			assert.JSONEq(t, `{"token":"X"}`, string(st.Body), "Body captured for method=%q", method)
		})
	}
}

// TestPostBody_GETNextLinkFallsThrough documents the actual contract for
// a NON-POST rel=next link: post_body does NOT claim it. It returns no
// error, no captured URL/body, and Done=false (because a rel=next link
// IS present — end-of-pagination is signaled only by Done=true). The
// false Done leaves the link for another adapter (token / next_url) to
// pick up via the auto adapter.
func TestPostBody_GETNextLinkFallsThrough(t *testing.T) {
	cases := []struct {
		name   string
		method string
	}{
		{"explicit GET", "GET"},
		{"no method (defaults to GET-style)", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := newPostBody(Config{})
			st, err := a.Capture(UpstreamResponse{
				FC:      fcWithPOSTLink("https://api.example.com/search?token=ABC", c.method, nil),
				BaseURL: "https://api.example.com",
			})
			require.NoError(t, err, "non-POST link is not an error, just unclaimed")
			assert.False(t, st.Done, "Done; want false (next link present, deferred to another adapter)")
			assert.Empty(t, st.URL, "URL; post_body must not claim a non-POST link")
			assert.Empty(t, st.Body, "Body; post_body must not claim a non-POST link")
		})
	}
}

// TestPostBody_DoneOnNoNextLink: absent rel=next → end of pagination.
func TestPostBody_DoneOnNoNextLink(t *testing.T) {
	a := newPostBody(Config{})
	st, err := a.Capture(UpstreamResponse{
		FC:      &stac.FeatureCollection{},
		BaseURL: "https://api.example.com",
	})
	require.NoError(t, err)
	assert.True(t, st.Done, "Done; want true (no rel=next link)")
	assert.Empty(t, st.Body, "Body; want none")
}

// TestPostBody_SameOriginGuard exercises the SSRF defense in both
// directions: a same-origin POST href is accepted; a cross-origin one is
// rejected with an error (mirrors next_url's same-origin check).
func TestPostBody_SameOriginGuard(t *testing.T) {
	a := newPostBody(Config{})

	t.Run("accepts same-origin href", func(t *testing.T) {
		st, err := a.Capture(UpstreamResponse{
			FC:      fcWithNext("https://api.example.com/v1/search", map[string]any{"token": "OK"}),
			BaseURL: "https://api.example.com/v1",
		})
		require.NoError(t, err)
		assert.Equal(t, "https://api.example.com/v1/search", st.URL, "URL accepted for same origin")
	})

	t.Run("rejects cross-origin href", func(t *testing.T) {
		_, err := a.Capture(UpstreamResponse{
			FC:      fcWithNext("https://evil.example.com/v1/search", map[string]any{"token": "X"}),
			BaseURL: "https://api.example.com/v1",
		})
		require.Error(t, err, "expected SSRF guard to error on cross-origin POST href")
	})
}

// TestPostBody_MissingBodyGraceful: a POST rel=next link with a valid
// same-origin href but NO body field is handled gracefully — no panic,
// no error, nothing captured, and Done=false (next link present). The
// paginator defers to another adapter rather than replaying an empty body.
func TestPostBody_MissingBodyGraceful(t *testing.T) {
	a := newPostBody(Config{})
	st, err := a.Capture(UpstreamResponse{
		FC:      fcWithPOSTLink("https://api.example.com/search", "POST", nil),
		BaseURL: "https://api.example.com",
	})
	require.NoError(t, err, "missing body on POST link must not error")
	assert.False(t, st.Done, "Done; want false (next link present)")
	assert.Empty(t, st.Body, "Body; want none when link carries no body field")
	assert.Empty(t, st.URL, "URL; want none when no body to replay")
}

// TestPostBody_EmptyHrefIsDone: a POST rel=next link with an empty href
// signals end-of-pagination.
func TestPostBody_EmptyHrefIsDone(t *testing.T) {
	a := newPostBody(Config{})
	st, err := a.Capture(UpstreamResponse{
		FC:      fcWithPOSTLink("", "POST", map[string]any{"token": "X"}),
		BaseURL: "https://api.example.com",
	})
	require.NoError(t, err)
	assert.True(t, st.Done, "Done; want true (empty next href)")
}

// TestPostBody_Probe: post_body probes with high confidence when it can
// capture a replayable body, and zero otherwise (so auto skips it).
func TestPostBody_Probe(t *testing.T) {
	a := newPostBody(Config{})

	conf, st := a.Probe(UpstreamResponse{
		FC:      fcWithNext("https://api.example.com/search", map[string]any{"token": "X"}),
		BaseURL: "https://api.example.com",
	})
	assert.InDelta(t, 0.95, conf, 0.001, "confidence; want high for POST-with-body")
	assert.NotEmpty(t, st.Body, "Probe state carries the captured body")

	// GET-style next link: nothing to replay → zero confidence.
	conf, _ = a.Probe(UpstreamResponse{
		FC:      fcWithPOSTLink("https://api.example.com/search?token=X", "GET", nil),
		BaseURL: "https://api.example.com",
	})
	assert.Zero(t, conf, "confidence; want 0 for GET-style link (no body)")
}
