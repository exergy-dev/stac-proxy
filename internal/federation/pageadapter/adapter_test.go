package pageadapter

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/stac-proxy/internal/stac"
)

// fcWithNext builds a synthetic upstream FeatureCollection carrying a
// single rel="next" link with the given Href and optional POST-body.
// Used across adapter tests.
func fcWithNext(href string, body map[string]any) *stac.FeatureCollection {
	link := &stac.Link{Rel: "next", Href: href}
	if body != nil {
		link.AdditionalFields = map[string]any{
			"method": "POST",
			"body":   body,
		}
	}
	return &stac.FeatureCollection{Links: []*stac.Link{link}}
}

func TestNew_RejectsUnknownAdapter(t *testing.T) {
	_, err := New(Config{Adapter: "bogus"})
	require.Error(t, err, "expected error for unknown adapter")
}

// TestAdapterRegistry exercises the default-to-auto path, KnownAdapters
// (used by config validation), the offset adapter's custom-param knob,
// and the auto adapter's no-match branch in one consolidated test.
func TestAdapterRegistry(t *testing.T) {
	a, err := New(Config{})
	require.NoError(t, err)
	assert.Equal(t, "auto", a.Name(), "default adapter")
	assert.Equal(t, []string{"auto", "token", "next_url", "post_body", "offset", "link_header"}, KnownAdapters())

	off, _ := newOffset(Config{OffsetParam: "page"}).Capture(UpstreamResponse{
		FC: fcWithNext("https://api.example.com/search?page=3", nil), BaseURL: "https://api.example.com",
	})
	assert.Equal(t, 3, off.Offset, "custom offset param")

	auto, _ := newAuto(Config{}).Capture(UpstreamResponse{FC: &stac.FeatureCollection{}, BaseURL: "https://api.example.com"})
	assert.True(t, auto.Done, "auto Done on no match")
}

func TestSameOrigin(t *testing.T) {
	cases := []struct {
		name    string
		rawURL  string
		baseURL string
		want    bool
	}{
		{"empty url is vacuously safe", "", "https://api.example.com", true},
		{"same host + path prefix", "https://api.example.com/v1/search?next=x", "https://api.example.com/v1", true},
		{"different host", "https://evil.example.com/v1/search", "https://api.example.com/v1", false},
		{"different scheme", "http://api.example.com/v1/search", "https://api.example.com/v1", false},
		{"path outside base prefix", "https://api.example.com/other/search", "https://api.example.com/v1", false},
		{"non-absolute URL rejected", "/v1/search?next=x", "https://api.example.com/v1", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equalf(t, c.want, SameOrigin(c.rawURL, c.baseURL), "SameOrigin(%q, %q)", c.rawURL, c.baseURL)
		})
	}
}

// --- token adapter ---------------------------------------------------

func TestToken_CapturesTokenQueryParam(t *testing.T) {
	a := newToken(Config{})
	st, err := a.Capture(UpstreamResponse{
		FC:      fcWithNext("https://api.example.com/search?token=ABC", nil),
		BaseURL: "https://api.example.com",
	})
	require.NoError(t, err)
	assert.Equal(t, "ABC", st.Token, "Token")
	assert.False(t, st.Done, "Done; want false (cursor present)")
}

func TestToken_CapturesPOSTBodyToken(t *testing.T) {
	a := newToken(Config{})
	st, err := a.Capture(UpstreamResponse{
		FC:      fcWithNext("https://api.example.com/search", map[string]any{"token": "PC-CURSOR"}),
		BaseURL: "https://api.example.com",
	})
	require.NoError(t, err)
	assert.Equal(t, "PC-CURSOR", st.Token, "Token")
}

func TestToken_CustomParamName(t *testing.T) {
	a := newToken(Config{TokenParam: "next"})
	st, _ := a.Capture(UpstreamResponse{
		FC:      fcWithNext("https://api.example.com/search?next=XYZ", nil),
		BaseURL: "https://api.example.com",
	})
	assert.Equal(t, "XYZ", st.Token, "Token (custom param name)")
}

func TestToken_DoneOnNoNextLink(t *testing.T) {
	a := newToken(Config{})
	st, _ := a.Capture(UpstreamResponse{
		FC:      &stac.FeatureCollection{},
		BaseURL: "https://api.example.com",
	})
	assert.True(t, st.Done, "Done; want true (no next link)")
}

// --- next_url adapter -----------------------------------------------

func TestNextURL_CapturesVerbatimHref(t *testing.T) {
	a := newNextURL(Config{})
	href := "https://earth-search.aws.element84.com/v1/search?next=ABC,DEF"
	st, err := a.Capture(UpstreamResponse{
		FC:      fcWithNext(href, nil),
		BaseURL: "https://earth-search.aws.element84.com/v1",
	})
	require.NoError(t, err)
	assert.Equal(t, href, st.URL, "URL")
}

func TestNextURL_RejectsCrossOriginHref(t *testing.T) {
	a := newNextURL(Config{})
	_, err := a.Capture(UpstreamResponse{
		FC:      fcWithNext("https://evil.example.com/v1/search?next=x", nil),
		BaseURL: "https://api.example.com/v1",
	})
	require.Error(t, err, "expected SSRF guard to error on cross-origin href")
}

// --- offset adapter --------------------------------------------------

func TestOffset_CapturesOffset(t *testing.T) {
	a := newOffset(Config{})
	st, _ := a.Capture(UpstreamResponse{
		FC:      fcWithNext("https://api.example.com/search?offset=50&limit=25", nil),
		BaseURL: "https://api.example.com",
	})
	assert.Equal(t, 50, st.Offset, "Offset")
}

// --- link_header adapter --------------------------------------------

func TestLinkHeader_CapturesRelNext(t *testing.T) {
	a := newLinkHeader(Config{})
	hdr := http.Header{}
	hdr.Set("Link", `<https://api.example.com/v1/search?offset=50>; rel="next"; type="application/json"`)
	st, err := a.Capture(UpstreamResponse{
		Header:  hdr,
		BaseURL: "https://api.example.com/v1",
	})
	require.NoError(t, err)
	assert.Equal(t, "https://api.example.com/v1/search?offset=50", st.URL, "URL; want absolute next-page URL")
}

func TestLinkHeader_HandlesMultipleLinksPerHeader(t *testing.T) {
	a := newLinkHeader(Config{})
	hdr := http.Header{}
	hdr.Set("Link", `<https://api.example.com/v1/search?offset=0>; rel="prev", <https://api.example.com/v1/search?offset=50>; rel="next"`)
	st, _ := a.Capture(UpstreamResponse{
		Header:  hdr,
		BaseURL: "https://api.example.com/v1",
	})
	assert.Equal(t, "https://api.example.com/v1/search?offset=50", st.URL, "URL; want the rel=next entry")
}

func TestLinkHeader_RejectsCrossOriginHref(t *testing.T) {
	a := newLinkHeader(Config{})
	hdr := http.Header{}
	hdr.Set("Link", `<https://evil.example.com/v1/search>; rel="next"`)
	_, err := a.Capture(UpstreamResponse{
		Header:  hdr,
		BaseURL: "https://api.example.com/v1",
	})
	require.Error(t, err, "expected SSRF guard to error on cross-origin Link header")
}

// --- auto adapter ---------------------------------------------------

func TestAuto_PicksTokenOverNextURL(t *testing.T) {
	a := newAuto(Config{})
	st, err := a.Capture(UpstreamResponse{
		// rel=next with a ?token= param — both token and next_url
		// would match, but token is the higher-confidence choice.
		FC:      fcWithNext("https://api.example.com/search?token=ABC", nil),
		BaseURL: "https://api.example.com",
	})
	require.NoError(t, err)
	assert.Equal(t, "token", st.AdapterName, "AdapterName; auto should prefer token over next_url")
	assert.Equal(t, "ABC", st.Token, "Token")
}

func TestAuto_FallsBackToNextURL(t *testing.T) {
	a := newAuto(Config{})
	// Earth Search shape: ?next= (no ?token=) — only next_url matches.
	st, err := a.Capture(UpstreamResponse{
		FC:      fcWithNext("https://earth-search.example.com/v1/search?next=ABC", nil),
		BaseURL: "https://earth-search.example.com/v1",
	})
	require.NoError(t, err)
	assert.Equal(t, "next_url", st.AdapterName, "AdapterName; auto should fall back to next_url for Earth Search shape")
	assert.NotEmpty(t, st.URL, "URL not captured by next_url")
}
