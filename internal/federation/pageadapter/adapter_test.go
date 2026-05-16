package pageadapter

import (
	"net/http"
	"testing"

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
	if _, err := New(Config{Adapter: "bogus"}); err == nil {
		t.Fatal("expected error for unknown adapter, got nil")
	}
}

func TestNew_DefaultsToAuto(t *testing.T) {
	a, err := New(Config{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if a.Name() != "auto" {
		t.Errorf("New(Config{}).Name() = %q, want %q", a.Name(), "auto")
	}
}

func TestKnownAdapters(t *testing.T) {
	want := []string{"auto", "token", "next_url", "offset", "link_header"}
	got := KnownAdapters()
	if len(got) != len(want) {
		t.Fatalf("KnownAdapters() len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("KnownAdapters()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
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
		{"case-insensitive host", "https://API.Example.COM/v1/search", "https://api.example.com/v1", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := SameOrigin(c.rawURL, c.baseURL); got != c.want {
				t.Errorf("SameOrigin(%q, %q) = %v, want %v", c.rawURL, c.baseURL, got, c.want)
			}
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
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if st.Token != "ABC" {
		t.Errorf("Token = %q, want %q", st.Token, "ABC")
	}
	if st.Done {
		t.Error("Done = true; want false (cursor present)")
	}
}

func TestToken_CapturesPOSTBodyToken(t *testing.T) {
	a := newToken(Config{})
	st, err := a.Capture(UpstreamResponse{
		FC:      fcWithNext("https://api.example.com/search", map[string]any{"token": "PC-CURSOR"}),
		BaseURL: "https://api.example.com",
	})
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if st.Token != "PC-CURSOR" {
		t.Errorf("Token = %q, want %q", st.Token, "PC-CURSOR")
	}
}

func TestToken_CustomParamName(t *testing.T) {
	a := newToken(Config{TokenParam: "next"})
	st, _ := a.Capture(UpstreamResponse{
		FC:      fcWithNext("https://api.example.com/search?next=XYZ", nil),
		BaseURL: "https://api.example.com",
	})
	if st.Token != "XYZ" {
		t.Errorf("Token = %q, want %q (custom param name)", st.Token, "XYZ")
	}
}

func TestToken_DoneOnNoNextLink(t *testing.T) {
	a := newToken(Config{})
	st, _ := a.Capture(UpstreamResponse{
		FC:      &stac.FeatureCollection{},
		BaseURL: "https://api.example.com",
	})
	if !st.Done {
		t.Errorf("Done = false; want true (no next link)")
	}
}

// --- next_url adapter -----------------------------------------------

func TestNextURL_CapturesVerbatimHref(t *testing.T) {
	a := newNextURL(Config{})
	href := "https://earth-search.aws.element84.com/v1/search?next=ABC,DEF"
	st, err := a.Capture(UpstreamResponse{
		FC:      fcWithNext(href, nil),
		BaseURL: "https://earth-search.aws.element84.com/v1",
	})
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if st.URL != href {
		t.Errorf("URL = %q, want %q", st.URL, href)
	}
}

func TestNextURL_RejectsCrossOriginHref(t *testing.T) {
	a := newNextURL(Config{})
	_, err := a.Capture(UpstreamResponse{
		FC:      fcWithNext("https://evil.example.com/v1/search?next=x", nil),
		BaseURL: "https://api.example.com/v1",
	})
	if err == nil {
		t.Fatal("expected SSRF guard to error on cross-origin href; got nil")
	}
}

// --- offset adapter --------------------------------------------------

func TestOffset_CapturesOffset(t *testing.T) {
	a := newOffset(Config{})
	st, _ := a.Capture(UpstreamResponse{
		FC:      fcWithNext("https://api.example.com/search?offset=50&limit=25", nil),
		BaseURL: "https://api.example.com",
	})
	if st.Offset != 50 {
		t.Errorf("Offset = %d, want 50", st.Offset)
	}
}

func TestOffset_CustomParamName(t *testing.T) {
	a := newOffset(Config{OffsetParam: "page"})
	st, _ := a.Capture(UpstreamResponse{
		FC:      fcWithNext("https://api.example.com/search?page=3", nil),
		BaseURL: "https://api.example.com",
	})
	if st.Offset != 3 {
		t.Errorf("Offset = %d, want 3", st.Offset)
	}
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
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if st.URL != "https://api.example.com/v1/search?offset=50" {
		t.Errorf("URL = %q, want absolute next-page URL", st.URL)
	}
}

func TestLinkHeader_HandlesMultipleLinksPerHeader(t *testing.T) {
	a := newLinkHeader(Config{})
	hdr := http.Header{}
	hdr.Set("Link", `<https://api.example.com/v1/search?offset=0>; rel="prev", <https://api.example.com/v1/search?offset=50>; rel="next"`)
	st, _ := a.Capture(UpstreamResponse{
		Header:  hdr,
		BaseURL: "https://api.example.com/v1",
	})
	if st.URL == "" || st.URL != "https://api.example.com/v1/search?offset=50" {
		t.Errorf("URL = %q, want the rel=next entry", st.URL)
	}
}

func TestLinkHeader_RejectsCrossOriginHref(t *testing.T) {
	a := newLinkHeader(Config{})
	hdr := http.Header{}
	hdr.Set("Link", `<https://evil.example.com/v1/search>; rel="next"`)
	_, err := a.Capture(UpstreamResponse{
		Header:  hdr,
		BaseURL: "https://api.example.com/v1",
	})
	if err == nil {
		t.Fatal("expected SSRF guard to error on cross-origin Link header; got nil")
	}
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
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if st.AdapterName != "token" {
		t.Errorf("AdapterName = %q, want %q (auto should prefer token over next_url)", st.AdapterName, "token")
	}
	if st.Token != "ABC" {
		t.Errorf("Token = %q, want %q", st.Token, "ABC")
	}
}

func TestAuto_FallsBackToNextURL(t *testing.T) {
	a := newAuto(Config{})
	// Earth Search shape: ?next= (no ?token=) — only next_url matches.
	st, err := a.Capture(UpstreamResponse{
		FC:      fcWithNext("https://earth-search.example.com/v1/search?next=ABC", nil),
		BaseURL: "https://earth-search.example.com/v1",
	})
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if st.AdapterName != "next_url" {
		t.Errorf("AdapterName = %q, want %q (auto should fall back to next_url for Earth Search shape)", st.AdapterName, "next_url")
	}
	if st.URL == "" {
		t.Error("URL not captured by next_url")
	}
}

func TestAuto_DoneOnNoMatch(t *testing.T) {
	a := newAuto(Config{})
	st, _ := a.Capture(UpstreamResponse{
		FC:      &stac.FeatureCollection{}, // no next link at all
		BaseURL: "https://api.example.com",
	})
	if !st.Done {
		t.Errorf("Done = false; want true (no next link, no match)")
	}
}
