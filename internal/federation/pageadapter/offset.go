package pageadapter

import (
	"net/url"
	"strconv"
)

// offset implements offset-based pagination: the upstream's `rel: next`
// href carries `?offset=N` (or a configurable equivalent like `?page=N`).
// The proxy advances the offset on each page; the paginator passes the
// new offset back via OriginCursor.Offset, and the offset adapter
// expresses that on the wire by building a verbatim next-URL with the
// param updated.
type offset struct{ param string }

func newOffset(cfg Config) *offset {
	param := cfg.OffsetParam
	if param == "" {
		param = "offset"
	}
	return &offset{param: param}
}

func (a *offset) Name() string { return "offset" }

func (a *offset) Capture(r UpstreamResponse) (NextState, error) {
	link := nextLinkOf(r)
	if link == nil || link.Href == "" {
		return NextState{Done: true}, nil
	}
	u, err := url.Parse(link.Href)
	if err != nil {
		return NextState{Done: true}, nil
	}
	v := u.Query().Get(a.param)
	if v == "" {
		return NextState{Done: true}, nil
	}
	off, err := strconv.Atoi(v)
	if err != nil {
		return NextState{Done: true}, nil
	}
	// Capture the full URL too so the paginator can fetch verbatim
	// rather than reconstructing the upstream's expected query shape.
	if !SameOrigin(link.Href, r.BaseURL) {
		return NextState{Done: true}, nil
	}
	return NextState{URL: link.Href, Offset: off}, nil
}

func (a *offset) Probe(r UpstreamResponse) (float64, NextState) {
	st, _ := a.Capture(r)
	if st.Offset > 0 || (st.URL != "" && !st.Done) {
		return 0.7, st
	}
	return 0, st
}
