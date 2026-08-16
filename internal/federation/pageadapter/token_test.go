package pageadapter

import (
	"testing"

	"github.com/exergy-dev/stac-proxy/internal/stac"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Basic happy paths (query-param capture, POST body.token, custom param
// name, Done on no next link) are covered in adapter_test.go. These
// tests cover the remaining contract: the "unclaimed but not done"
// branch, nil/malformed inputs, precedence, and Probe confidence.

// TestToken_NextLinkWithoutTokenIsNotDone: a rel=next link IS present
// but carries no token param. The adapter must not claim it (empty
// Token) and must NOT report Done — another adapter (next_url) may
// still follow the link.
func TestToken_NextLinkWithoutTokenIsNotDone(t *testing.T) {
	t.Parallel()
	a := newToken(Config{})
	st, err := a.Capture(UpstreamResponse{
		FC:      fcWithNext("https://api.example.com/search?next=ABC", nil),
		BaseURL: "https://api.example.com",
	})
	require.NoError(t, err)
	assert.Empty(t, st.Token, "Token; want none (param absent)")
	assert.False(t, st.Done, "Done; want false (next link present, just unclaimed)")
}

// TestToken_NilFeatureCollectionIsDone: a nil FC (e.g. non-JSON
// upstream response) must be handled gracefully as end-of-pagination,
// not panic.
func TestToken_NilFeatureCollectionIsDone(t *testing.T) {
	t.Parallel()
	a := newToken(Config{})
	st, err := a.Capture(UpstreamResponse{FC: nil, BaseURL: "https://api.example.com"})
	require.NoError(t, err)
	assert.True(t, st.Done, "Done; want true for nil FeatureCollection")
}

// TestToken_IgnoresNonNextLinks: only rel="next" is consulted; self and
// prev links must not be mistaken for a cursor.
func TestToken_IgnoresNonNextLinks(t *testing.T) {
	t.Parallel()
	a := newToken(Config{})
	fc := &stac.FeatureCollection{Links: []*stac.Link{
		{Rel: "self", Href: "https://api.example.com/search?token=SELF"},
		{Rel: "prev", Href: "https://api.example.com/search?token=PREV"},
		nil, // defensive: nil entries must be skipped, not dereferenced
	}}
	st, err := a.Capture(UpstreamResponse{FC: fc, BaseURL: "https://api.example.com"})
	require.NoError(t, err)
	assert.Empty(t, st.Token, "Token; want none from self/prev links")
	assert.True(t, st.Done, "Done; want true (no rel=next link)")
}

// TestToken_MalformedHrefFallsBackToBody: an unparseable href must not
// error; the adapter falls through to the POST-style body[param] path.
func TestToken_MalformedHrefFallsBackToBody(t *testing.T) {
	t.Parallel()
	a := newToken(Config{})
	fc := &stac.FeatureCollection{Links: []*stac.Link{{
		Rel:  "next",
		Href: "://not-a-url",
		AdditionalFields: map[string]any{
			"body": map[string]any{"token": "FROM-BODY"},
		},
	}}}
	st, err := a.Capture(UpstreamResponse{FC: fc, BaseURL: "https://api.example.com"})
	require.NoError(t, err)
	assert.Equal(t, "FROM-BODY", st.Token, "Token; want body fallback when href is unparseable")
}

// TestToken_HrefParamWinsOverBody: when both the href query string and
// the link body carry the param, the href value wins (it is checked
// first).
func TestToken_HrefParamWinsOverBody(t *testing.T) {
	t.Parallel()
	a := newToken(Config{})
	fc := &stac.FeatureCollection{Links: []*stac.Link{{
		Rel:  "next",
		Href: "https://api.example.com/search?token=FROM-HREF",
		AdditionalFields: map[string]any{
			"body": map[string]any{"token": "FROM-BODY"},
		},
	}}}
	st, err := a.Capture(UpstreamResponse{FC: fc, BaseURL: "https://api.example.com"})
	require.NoError(t, err)
	assert.Equal(t, "FROM-HREF", st.Token, "Token; href query param takes precedence over body")
}

// TestToken_BodyWithNonStringTokenUnclaimed: a body whose token value is
// not a string (e.g. a number) must be ignored, not panic or stringify.
func TestToken_BodyWithNonStringTokenUnclaimed(t *testing.T) {
	t.Parallel()
	a := newToken(Config{})
	fc := &stac.FeatureCollection{Links: []*stac.Link{{
		Rel:  "next",
		Href: "https://api.example.com/search",
		AdditionalFields: map[string]any{
			"body": map[string]any{"token": 42},
		},
	}}}
	st, err := a.Capture(UpstreamResponse{FC: fc, BaseURL: "https://api.example.com"})
	require.NoError(t, err)
	assert.Empty(t, st.Token, "Token; non-string body token must be ignored")
	assert.False(t, st.Done, "Done; want false (next link still present)")
}

// TestToken_Probe: confidence is 0.9 when a token is captured (so auto
// prefers it over next_url's 0.6) and 0 otherwise. The probe state must
// match what Capture returns.
func TestToken_Probe(t *testing.T) {
	t.Parallel()
	a := newToken(Config{})

	conf, st := a.Probe(UpstreamResponse{
		FC:      fcWithNext("https://api.example.com/search?token=ABC", nil),
		BaseURL: "https://api.example.com",
	})
	assert.InDelta(t, 0.9, conf, 0.001, "confidence; want 0.9 on token match")
	assert.Equal(t, "ABC", st.Token, "Probe state carries the captured token")

	conf, st = a.Probe(UpstreamResponse{
		FC:      fcWithNext("https://api.example.com/search?next=ABC", nil),
		BaseURL: "https://api.example.com",
	})
	assert.Zero(t, conf, "confidence; want 0 when no token param present")
	assert.Empty(t, st.Token, "Probe state carries no token")

	conf, st = a.Probe(UpstreamResponse{FC: &stac.FeatureCollection{}, BaseURL: "https://api.example.com"})
	assert.Zero(t, conf, "confidence; want 0 at end of pagination")
	assert.True(t, st.Done, "Probe state reports Done at end of pagination")
}
