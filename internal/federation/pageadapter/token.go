package pageadapter

import (
	"net/url"

	"github.com/exergy-dev/stac-proxy/internal/stac"
)

// token implements the STAC API spec pagination convention: the
// upstream's `rel: next` href carries a `?token=<value>` query param,
// or the link's AdditionalFields["body"]["token"] for POST-style
// upstreams (Planetary Computer). On a follow-up call the proxy puts
// the token back into SearchRequest.Token, which is JSON-marshaled as
// `body.token` on POST /search or as `?token=...` on GET /search.
type token struct{ tokenParam string }

func newToken(cfg Config) *token {
	param := cfg.TokenParam
	if param == "" {
		param = "token"
	}
	return &token{tokenParam: param}
}

func (a *token) Name() string { return "token" }

func (a *token) Capture(r UpstreamResponse) (NextState, error) {
	tok := extractTokenFromNextLink(r, a.tokenParam)
	if tok == "" {
		return NextState{Done: !hasNextLink(r)}, nil
	}
	return NextState{Token: tok}, nil
}

func (a *token) Probe(r UpstreamResponse) (float64, NextState) {
	st, _ := a.Capture(r)
	if st.Token != "" {
		return 0.9, st
	}
	return 0, st
}

// extractTokenFromNextLink looks for the configured param in both the
// `rel: next` link's Href query string and (for POST-style upstreams)
// the link's AdditionalFields["body"][param] entry.
func extractTokenFromNextLink(r UpstreamResponse, paramName string) string {
	link := nextLinkOf(r)
	if link == nil {
		return ""
	}
	if link.Href != "" {
		if u, err := url.Parse(link.Href); err == nil {
			if v := u.Query().Get(paramName); v != "" {
				return v
			}
		}
	}
	// PC-style: POST link with body.token
	if link.AdditionalFields != nil {
		if body, ok := link.AdditionalFields["body"].(map[string]any); ok {
			if v, ok := body[paramName].(string); ok && v != "" {
				return v
			}
		}
	}
	return ""
}

// nextLinkOf returns the rel="next" link from the upstream FC, or nil.
func nextLinkOf(r UpstreamResponse) *stac.Link {
	if r.FC == nil {
		return nil
	}
	for _, l := range r.FC.Links {
		if l != nil && l.Rel == "next" {
			return l
		}
	}
	return nil
}

// hasNextLink returns true when the upstream FC carries any rel="next"
// link, regardless of whether this adapter can parse it. Used to
// distinguish "end of pagination" (Done=true) from "next link present
// but in a format this adapter does not handle" (Done=false; another
// adapter may pick it up).
func hasNextLink(r UpstreamResponse) bool {
	return nextLinkOf(r) != nil
}
