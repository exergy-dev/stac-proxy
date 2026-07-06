// Package pageadapter abstracts upstream pagination conventions so the
// federation handler can drive different STAC servers (and STAC-adjacent
// catalogues) without hardcoding any one server's choice of cursor
// parameter name.
//
// Different upstreams emit `rel: next` in different shapes:
//
//   - STAC API spec & Planetary Computer: POST /search with body.token,
//     or GET /search?token=...
//   - Element 84 Earth Search: GET /search?next=...
//   - Legacy / non-STAC catalogues: GET /search?offset=N (or ?page=N)
//   - OGC API Features gateways: HTTP `Link:` header with rel="next"
//
// Each Adapter knows how to parse pagination state from an upstream
// response (`Capture`) and report its confidence that a given response
// uses its convention (`Probe`). The `auto` adapter wraps the named
// adapters and locks its choice for the cursor's lifetime via
// `NextState.AdapterName`.
//
// Adapters MUST NOT mutate the request directly — request mutation is
// done by the federation paginator based on the captured NextState
// (OriginCursor.NextToken populates SearchRequest.Token; NextURL
// populates SearchRequest.OverrideURL; Offset populates an offset
// adapter's query). Keeping mutation centralised means tests can swap
// adapters without re-wiring the searcher.
package pageadapter

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/yourorg/stac-proxy/internal/stac"
)

// Adapter abstracts an upstream pagination convention.
type Adapter interface {
	// Name returns the adapter's canonical name (matches the YAML
	// `pagination.adapter` value).
	Name() string

	// Capture parses pagination state from an upstream response.
	// Returns a zero NextState (with Done=true) when the upstream
	// signals end-of-pagination. Returns an error only on genuinely
	// malformed responses — an absent next link is not an error.
	Capture(UpstreamResponse) (NextState, error)

	// Probe returns this adapter's confidence (0.0–1.0) that the
	// response uses its convention. Used by the auto adapter to
	// select an inner adapter on the first response. The returned
	// NextState is the value Capture would return for the same input.
	Probe(UpstreamResponse) (confidence float64, state NextState)
}

// UpstreamResponse is the input to Capture/Probe — everything an
// adapter could reasonably need from an upstream response.
type UpstreamResponse struct {
	FC      *stac.FeatureCollection
	Header  http.Header
	BaseURL string // origin's BaseURL; adapters MUST reject URLs not rooted here
	Status  int
}

// NextState is the captured pagination state. The federation paginator
// stores it on `OriginCursor` and reads it back on the next page.
type NextState struct {
	// Token is the opaque cursor parameter for spec-compliant
	// servers (POST body.token / GET ?token=).
	Token string

	// URL is the verbatim next-page URL. When non-empty the
	// paginator instructs the OriginClient to fetch this URL with
	// GET instead of POST-ing the standard /search — unless Body is
	// also non-empty, in which case the paginator POSTs URL with
	// Body as the request body (the post_body adapter's convention).
	URL string

	// Body is the verbatim POST body captured from the rel=next
	// link's `body` field (STAC API spec §5.5.1 — pagination links
	// can carry method/href/body). When non-empty alongside URL,
	// signals POST-with-body replay. Empty for GET-style next links.
	Body []byte

	// Offset is the next page's offset for offset-style adapters.
	Offset int

	// Done is true when the upstream signals end-of-pagination
	// (no `rel: next` link, or an explicit terminal marker).
	Done bool

	// AdapterName, when set, locks the adapter choice into the cursor
	// so subsequent pages use the same convention. Populated by the
	// `auto` adapter after its first successful probe.
	AdapterName string
}

// SameOrigin returns true when rawURL is rooted at the origin's
// BaseURL. Adapters use this to reject NextStates that point at a
// different host, defending against SSRF via tampered upstream
// responses.
//
// rawURL == "" returns true (vacuously safe — there's no URL to follow).
func SameOrigin(rawURL, baseURL string) bool {
	if rawURL == "" {
		return true
	}
	u, err := url.Parse(rawURL)
	if err != nil || !u.IsAbs() {
		return false
	}
	b, err := url.Parse(baseURL)
	if err != nil {
		return false
	}
	if !strings.EqualFold(u.Scheme, b.Scheme) {
		return false
	}
	if !strings.EqualFold(u.Host, b.Host) {
		return false
	}
	// Path of the rawURL must start with the base's path prefix —
	// guards against rooted but cross-tenant URLs on shared hosts.
	basePath := strings.TrimSuffix(b.Path, "/")
	return strings.HasPrefix(u.Path, basePath)
}

// Config carries adapter-specific knobs from YAML.
type Config struct {
	// Adapter is the canonical name (token, next_url, offset,
	// link_header, auto). Empty means "auto".
	Adapter string

	// OffsetParam is the query-param name the offset adapter uses
	// (default "offset"; some servers use "page").
	OffsetParam string

	// TokenParam is the query-param name the token adapter looks
	// for in the next-link URL (default "token").
	TokenParam string
}

// New constructs an Adapter by name. Unknown names return an error
// — the validator enforces the allowlist at config load.
func New(cfg Config) (Adapter, error) {
	name := cfg.Adapter
	if name == "" {
		name = "auto"
	}
	switch name {
	case "auto":
		return newAuto(cfg), nil
	case "token":
		return newToken(cfg), nil
	case "next_url":
		return newNextURL(cfg), nil
	case "post_body":
		return newPostBody(cfg), nil
	case "offset":
		return newOffset(cfg), nil
	case "link_header":
		return newLinkHeader(cfg), nil
	default:
		return nil, fmt.Errorf("pageadapter: unknown adapter %q (want token, next_url, offset, link_header, or auto)", name)
	}
}

// KnownAdapters returns the canonical adapter names. Used by config
// validation.
func KnownAdapters() []string {
	return []string{"auto", "token", "next_url", "post_body", "offset", "link_header"}
}
