package pageadapter

import (
	"encoding/json"
	"fmt"
	"strings"
)

// postBody captures the verbatim POST body from the upstream's
// `rel: next` link when that link is method=POST + body=<json>. This
// is the STAC API spec convention for cursor pagination over POST
// /search (§5.5.1): the link carries the full request body to issue
// on the next page, including the original search filters AND a
// cursor field (whose name varies: `token` per spec, `next` for
// Earth Search, `cursor` for some pygeoapi-based servers).
//
// Unlike the token adapter, post_body doesn't try to extract or
// rename the cursor field — it captures the whole body verbatim and
// replays it on the next page. This makes it convention-agnostic:
// any upstream that emits a POST-style rel=next link is supported
// without per-origin configuration.
//
// The captured href is allowlist-checked against the origin's
// BaseURL in both Capture (here) and DecodeCursor (cursor.go) — the
// same belt-and-braces SSRF defense the next_url adapter uses.
type postBody struct{}

func newPostBody(_ Config) *postBody { return &postBody{} }

func (a *postBody) Name() string { return "post_body" }

func (a *postBody) Capture(r UpstreamResponse) (NextState, error) {
	link := nextLinkOf(r)
	if link == nil {
		return NextState{Done: true}, nil
	}
	method, _ := link.AdditionalFields["method"].(string)
	if !strings.EqualFold(method, "POST") {
		return NextState{Done: !hasNextLink(r)}, nil
	}
	if link.Href == "" {
		return NextState{Done: true}, nil
	}
	if !SameOrigin(link.Href, r.BaseURL) {
		return NextState{}, fmt.Errorf("post_body: rel=next href %q not rooted at origin %q", link.Href, r.BaseURL)
	}
	rawBody, ok := link.AdditionalFields["body"]
	if !ok {
		return NextState{Done: !hasNextLink(r)}, nil
	}
	bodyJSON, err := json.Marshal(rawBody)
	if err != nil {
		return NextState{}, fmt.Errorf("post_body: marshal next link body: %w", err)
	}
	return NextState{URL: link.Href, Body: bodyJSON}, nil
}

func (a *postBody) Probe(r UpstreamResponse) (float64, NextState) {
	st, err := a.Capture(r)
	if err != nil || len(st.Body) == 0 {
		return 0, NextState{}
	}
	// post_body wins over token when both could match (POST link with
	// a body), since replaying the verbatim body is more faithful
	// than extracting one cursor field — it carries the original
	// filters explicitly and doesn't rely on the proxy's request
	// rebuild for the next page. Token still wins on GET-style links
	// (no body to replay), which post_body skips above.
	return 0.95, st
}
