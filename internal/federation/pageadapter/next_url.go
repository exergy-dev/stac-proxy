package pageadapter

import "fmt"

// nextURL captures the upstream's `rel: next` href verbatim and asks
// the paginator to fetch it directly (GET) on the next page. This is
// the universal fallback for upstreams that use a non-spec cursor
// parameter name — Earth Search emits `?next=<cursor-id>`, some
// pygeoapi-based servers use `?cursor=<...>`, etc. The proxy doesn't
// need to know the convention; it just follows the link.
//
// The captured URL is allowlist-checked against the origin's BaseURL
// in both Capture (here) and in DecodeCursor when a signed cursor is
// later round-tripped (cursor.go's allowlist check). This is a
// belt-and-braces defense against SSRF via tampered upstream responses.
type nextURL struct{}

func newNextURL(_ Config) *nextURL { return &nextURL{} }

func (a *nextURL) Name() string { return "next_url" }

func (a *nextURL) Capture(r UpstreamResponse) (NextState, error) {
	link := nextLinkOf(r)
	if link == nil || link.Href == "" {
		return NextState{Done: true}, nil
	}
	if !SameOrigin(link.Href, r.BaseURL) {
		return NextState{}, fmt.Errorf("next_url: rel=next href %q not rooted at origin %q", link.Href, r.BaseURL)
	}
	return NextState{URL: link.Href}, nil
}

func (a *nextURL) Probe(r UpstreamResponse) (float64, NextState) {
	st, err := a.Capture(r)
	if err != nil {
		return 0, NextState{}
	}
	if st.URL == "" {
		return 0, st
	}
	// The next_url adapter is the universal fallback; rank it slightly
	// below an explicit token match so `auto` prefers `token` when both
	// would work (the token adapter is more efficient — no allowlist
	// round-trip per page).
	return 0.6, st
}
