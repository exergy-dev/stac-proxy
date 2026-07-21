package pageadapter

import (
	"fmt"
	"strings"
)

// linkHeader implements RFC 5988 `Link:` header pagination. Some OGC
// API Features gateways advertise the next page via:
//
//	Link: <https://host/path?offset=N>; rel="next"
//
// rather than (or in addition to) emitting a `rel: next` link inside
// the FeatureCollection body. The adapter parses the header, picks the
// link with rel="next", and follows it verbatim.
type linkHeader struct{}

func newLinkHeader(_ Config) *linkHeader { return &linkHeader{} }

func (a *linkHeader) Name() string { return "link_header" }

func (a *linkHeader) Capture(r UpstreamResponse) (NextState, error) {
	href := parseNextFromLinkHeader(r.Header.Values("Link"))
	if href == "" {
		return NextState{Done: true}, nil
	}
	if !SameOrigin(href, r.BaseURL) {
		return NextState{}, fmt.Errorf("link_header: rel=next href %q not rooted at origin %q", href, r.BaseURL)
	}
	return NextState{URL: href}, nil
}

func (a *linkHeader) Probe(r UpstreamResponse) (float64, NextState) {
	st, err := a.Capture(r)
	if err != nil || st.URL == "" {
		return 0, st
	}
	return 0.5, st
}

// parseNextFromLinkHeader extracts the href whose `rel` parameter
// includes "next" from one or more Link header values. The Link header
// grammar (RFC 5988 §5) admits multiple links per value separated by
// commas, with each link's parameters separated by semicolons. This
// parser handles the common subset; it does not implement quoted-pair
// escape sequences (very rare in practice for Link values).
func parseNextFromLinkHeader(values []string) string {
	for _, header := range values {
		for _, link := range splitLinkValues(header) {
			href, rel := parseLinkValue(link)
			if href != "" && containsRel(rel, "next") {
				return href
			}
		}
	}
	return ""
}

// splitLinkValues splits a header value at commas that are not inside
// angle brackets. <https://a>; rel="next", <https://b>; rel="prev"
// produces two entries.
func splitLinkValues(s string) []string {
	var (
		out   []string
		depth int
		buf   strings.Builder
	)
	for _, r := range s {
		switch r {
		case '<':
			depth++
		case '>':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				out = append(out, strings.TrimSpace(buf.String()))
				buf.Reset()
				continue
			}
		}
		buf.WriteRune(r)
	}
	if buf.Len() > 0 {
		out = append(out, strings.TrimSpace(buf.String()))
	}
	return out
}

// parseLinkValue extracts the href and the rel parameter from a single
// Link value like `<https://a>; rel="next"; type="application/json"`.
func parseLinkValue(link string) (href, rel string) {
	link = strings.TrimSpace(link)
	if !strings.HasPrefix(link, "<") {
		return "", ""
	}
	end := strings.Index(link, ">")
	if end < 0 {
		return "", ""
	}
	href = link[1:end]
	rest := link[end+1:]
	for _, part := range strings.Split(rest, ";") {
		part = strings.TrimSpace(part)
		if !strings.HasPrefix(part, "rel") {
			continue
		}
		eq := strings.Index(part, "=")
		if eq < 0 {
			continue
		}
		val := strings.TrimSpace(part[eq+1:])
		val = strings.Trim(val, `"`)
		rel = val
		break
	}
	return href, rel
}

// containsRel returns true when relValue is a space-separated rel set
// that contains target. Per RFC 5988 the rel parameter may carry
// multiple tokens (e.g., rel="next prev").
func containsRel(relValue, target string) bool {
	for _, tok := range strings.Fields(relValue) {
		if strings.EqualFold(tok, target) {
			return true
		}
	}
	return false
}
