package pageadapter

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Single-link capture, multi-link splitting, and the cross-origin SSRF
// rejection are covered in adapter_test.go. These tests cover the
// exhausted case, repeated header values, RFC 5988 rel-set semantics,
// malformed-value tolerance, and Probe confidence.

// TestLinkHeader_DoneOnNoHeader: absent (or next-less) Link headers
// signal end-of-pagination.
func TestLinkHeader_DoneOnNoHeader(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		hdr  http.Header
	}{
		{"no Link header at all", http.Header{}},
		{"nil header map", nil},
		{"Link header without rel=next", func() http.Header {
			h := http.Header{}
			h.Set("Link", `<https://api.example.com/v1/search?offset=0>; rel="prev"`)
			return h
		}()},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			a := newLinkHeader(Config{})
			st, err := a.Capture(UpstreamResponse{Header: c.hdr, BaseURL: "https://api.example.com/v1"})
			require.NoError(t, err)
			assert.True(t, st.Done, "Done; want true")
			assert.Empty(t, st.URL, "URL; want none")
		})
	}
}

// TestLinkHeader_MultipleHeaderValues: rel=next may live in the second
// of several repeated Link header fields (Header.Values order).
func TestLinkHeader_MultipleHeaderValues(t *testing.T) {
	t.Parallel()
	a := newLinkHeader(Config{})
	hdr := http.Header{}
	hdr.Add("Link", `<https://api.example.com/v1/search?offset=0>; rel="prev"`)
	hdr.Add("Link", `<https://api.example.com/v1/search?offset=50>; rel="next"`)
	st, err := a.Capture(UpstreamResponse{Header: hdr, BaseURL: "https://api.example.com/v1"})
	require.NoError(t, err)
	assert.Equal(t, "https://api.example.com/v1/search?offset=50", st.URL, "URL; want rel=next from the second header field")
}

// TestLinkHeader_RelSetAndCasing: per RFC 5988 the rel parameter is a
// space-separated set and matching is case-insensitive; unquoted rel
// values are also accepted.
func TestLinkHeader_RelSetAndCasing(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		value string
	}{
		{"rel set containing next", `<https://api.example.com/v1/search?offset=50>; rel="alternate next"`},
		{"uppercase NEXT", `<https://api.example.com/v1/search?offset=50>; rel="NEXT"`},
		{"unquoted rel value", `<https://api.example.com/v1/search?offset=50>; rel=next`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			a := newLinkHeader(Config{})
			hdr := http.Header{}
			hdr.Set("Link", c.value)
			st, err := a.Capture(UpstreamResponse{Header: hdr, BaseURL: "https://api.example.com/v1"})
			require.NoError(t, err)
			assert.Equal(t, "https://api.example.com/v1/search?offset=50", st.URL, "URL")
		})
	}
}

// TestLinkHeader_CommaInsideAngleBrackets: commas inside the <...>
// target must not split the value (splitLinkValues tracks bracket depth).
func TestLinkHeader_CommaInsideAngleBrackets(t *testing.T) {
	t.Parallel()
	a := newLinkHeader(Config{})
	hdr := http.Header{}
	hdr.Set("Link", `<https://api.example.com/v1/search?ids=a,b,c&offset=50>; rel="next"`)
	st, err := a.Capture(UpstreamResponse{Header: hdr, BaseURL: "https://api.example.com/v1"})
	require.NoError(t, err)
	assert.Equal(t, "https://api.example.com/v1/search?ids=a,b,c&offset=50", st.URL, "URL; comma inside <> must not split the link value")
}

// TestLinkHeader_MalformedValuesAreIgnored: values the parser cannot
// understand are skipped (treated as no next link), never an error or a
// panic.
func TestLinkHeader_MalformedValuesAreIgnored(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		value string
	}{
		{"missing angle brackets", `https://api.example.com/v1/search?offset=50; rel="next"`},
		{"unterminated target", `<https://api.example.com/v1/search?offset=50; rel="next"`},
		{"rel param without value", `<https://api.example.com/v1/search?offset=50>; rel`},
		{"no rel parameter at all", `<https://api.example.com/v1/search?offset=50>; type="application/json"`},
		{"empty value", ``},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			a := newLinkHeader(Config{})
			hdr := http.Header{}
			hdr.Set("Link", c.value)
			st, err := a.Capture(UpstreamResponse{Header: hdr, BaseURL: "https://api.example.com/v1"})
			require.NoError(t, err, "malformed Link values must be skipped, not errored")
			assert.True(t, st.Done, "Done; want true (no usable rel=next)")
		})
	}
}

// TestLinkHeader_Probe: 0.5 when a followable header link is present
// (the lowest-priority positive signal in auto's ranking), 0 at
// end-of-pagination, and 0 when Capture errors on a cross-origin href.
func TestLinkHeader_Probe(t *testing.T) {
	t.Parallel()
	a := newLinkHeader(Config{})

	hdr := http.Header{}
	hdr.Set("Link", `<https://api.example.com/v1/search?offset=50>; rel="next"`)
	conf, st := a.Probe(UpstreamResponse{Header: hdr, BaseURL: "https://api.example.com/v1"})
	assert.InDelta(t, 0.5, conf, 0.001, "confidence; want 0.5 on header match")
	assert.Equal(t, "https://api.example.com/v1/search?offset=50", st.URL, "Probe state carries the URL")

	conf, st = a.Probe(UpstreamResponse{Header: http.Header{}, BaseURL: "https://api.example.com/v1"})
	assert.Zero(t, conf, "confidence; want 0 with no Link header")
	assert.True(t, st.Done, "Probe state reports Done with no Link header")

	evil := http.Header{}
	evil.Set("Link", `<https://evil.example.com/v1/search>; rel="next"`)
	conf, st = a.Probe(UpstreamResponse{Header: evil, BaseURL: "https://api.example.com/v1"})
	assert.Zero(t, conf, "confidence; want 0 when Capture errors (cross-origin)")
	assert.Empty(t, st.URL, "Probe state must not leak the cross-origin URL")
}
