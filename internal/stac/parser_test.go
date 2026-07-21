package stac

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Parser tests are scoped to the proxy-owned parser logic:
// ParseSearchRequest, parseSearchFromQuery, ExtractNextLink/Token, and the
// Validate* helpers (including the new bbox/intersects mutual-exclusion
// check). The library owns marshaling of Item/Collection/Catalog and is
// tested upstream; the alias smoke test in types_test.go covers our
// integration boundary.

func TestNewParser(t *testing.T) {
	t.Parallel()
	require.NotNil(t, NewParser(), "NewParser returned nil")
}

func TestParseItem_WrongTypeRejected(t *testing.T) {
	t.Parallel()
	p := NewParser()
	_, err := p.ParseItem([]byte(`{"type":"Collection","id":"x"}`))
	require.Error(t, err, "expected error for wrong type")
}

func TestParseItem_ValidPassesThrough(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	body := `{
		"type":"Feature","stac_version":"1.0.0","id":"x",
		"geometry":{"type":"Point","coordinates":[0,0]},
		"properties":{"datetime":"` + now.Format(time.RFC3339) + `"},
		"links":[],"assets":{},"collection":"c"
	}`
	item, err := NewParser().ParseItem([]byte(body))
	require.NoError(t, err)
	assert.Equal(t, "x", item.ID)
	assert.Equal(t, "c", item.Collection)
	assert.Equal(t, "1.0.0", item.Version)
}

func TestParse_WrongTypeRejected(t *testing.T) {
	t.Parallel()
	p := NewParser()
	tests := []struct {
		name string
		fn   func([]byte) error
		body string
	}{
		{"Collection", func(b []byte) error { _, err := p.ParseCollection(b); return err }, `{"type":"Feature","id":"x"}`},
		{"Catalog", func(b []byte) error { _, err := p.ParseCatalog(b); return err }, `{"type":"Feature","id":"x"}`},
		{"FeatureCollection", func(b []byte) error { _, err := p.ParseFeatureCollection(b); return err }, `{"type":"NotIt"}`},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Error(t, tt.fn([]byte(tt.body)), "expected error for wrong type")
		})
	}
}

func TestParseSearchRequest_BodyShapes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		body   string
		assert func(*testing.T, *SearchRequest)
	}{
		{
			"collections + bbox + limit",
			`{"collections":["a","b"],"bbox":[1,2,3,4],"limit":50}`,
			func(t *testing.T, r *SearchRequest) {
				assert.Len(t, r.Collections, 2)
				assert.Equal(t, 50, r.Limit)
				assert.Len(t, r.BBox, 4)
			},
		},
		{
			"intersects as JSON object",
			`{"intersects":{"type":"Point","coordinates":[0,0]}}`,
			func(t *testing.T, r *SearchRequest) {
				require.NotEmpty(t, r.Intersects, "intersects empty")
				var probe struct{ Type string }
				err := json.Unmarshal(r.Intersects, &probe)
				require.NoError(t, err)
				assert.Equal(t, "Point", probe.Type)
			},
		},
		{
			"datetime + token",
			`{"datetime":"2024-01-01/..","token":"abc"}`,
			func(t *testing.T, r *SearchRequest) {
				assert.NotEmpty(t, r.Datetime)
				assert.Equal(t, "abc", r.Token)
			},
		},
		{
			"cursor + fields object",
			`{"cursor":"signed.cursor","fields":{"include":["id","bbox"],"exclude":["geometry"]}}`,
			func(t *testing.T, r *SearchRequest) {
				assert.Equal(t, "signed.cursor", r.Cursor)
				require.NotNil(t, r.Fields, "Fields nil")
				assert.Equal(t, []string{"id", "bbox"}, r.Fields.Include)
				assert.Equal(t, []string{"geometry"}, r.Fields.Exclude)
			},
		},
		{
			// Earth Search (and several other real-world catalogs) emit
			// `next` as the pagination field name on POST link bodies.
			// The proxy must capture it on inbound parse and re-emit it
			// on outbound marshal; dropping it loops the client back to
			// page 1.
			"next field captured",
			`{"limit":2,"next":"2026-05-17T13:43:40Z,SENT-1A-FOO,sentinel-1-grd"}`,
			func(t *testing.T, r *SearchRequest) {
				assert.Equal(t, 2, r.Limit)
				assert.Equal(t, "2026-05-17T13:43:40Z,SENT-1A-FOO,sentinel-1-grd", r.Next)
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req, err := NewParser().ParseSearchRequest([]byte(tt.body))
			require.NoError(t, err)
			tt.assert(t, req)
		})
	}
}

func TestParseSearchRequestFromHTTP(t *testing.T) {
	t.Parallel()

	t.Run("POST body", func(t *testing.T) {
		t.Parallel()
		body := `{"collections":["c"],"limit":7}`
		r := httptest.NewRequest(http.MethodPost, "/search", strings.NewReader(body))
		req, err := NewParser().ParseSearchRequestFromHTTP(r)
		require.NoError(t, err)
		assert.Equal(t, 7, req.Limit)
		assert.Len(t, req.Collections, 1)
		// Body must be restored so downstream proxy can forward it.
		got, _ := io.ReadAll(r.Body)
		assert.True(t, bytes.Equal(got, []byte(body)), "body not restored: got %q want %q", got, body)
	})

	t.Run("GET delegates to parseSearchFromQuery", func(t *testing.T) {
		t.Parallel()
		r := httptest.NewRequest(http.MethodGet, "/search?collections=a,b&limit=12", nil)
		req, err := NewParser().ParseSearchRequestFromHTTP(r)
		require.NoError(t, err)
		assert.Equal(t, 12, req.Limit)
		assert.Len(t, req.Collections, 2)
	})
}

func TestParseSearchFromQuery(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		url    string
		assert func(*testing.T, *SearchRequest)
	}{
		{
			"bbox 4-tuple",
			"/search?bbox=1,2,3,4",
			func(t *testing.T, r *SearchRequest) {
				assert.Len(t, r.BBox, 4)
			},
		},
		{
			"intersects valid GeoJSON",
			`/search?intersects={"type":"Point","coordinates":[1,2]}`,
			func(t *testing.T, r *SearchRequest) {
				require.NotEmpty(t, r.Intersects, "Intersects empty")
				var probe struct{ Type string }
				_ = json.Unmarshal(r.Intersects, &probe)
				assert.Equal(t, "Point", probe.Type)
			},
		},
		{
			"sortby asc + desc",
			"/search?sortby=-datetime,id",
			func(t *testing.T, r *SearchRequest) {
				require.Len(t, r.Sortby, 2)
				assert.Equal(t, "desc", r.Sortby[0].Direction)
				assert.Equal(t, "datetime", r.Sortby[0].Field)
				assert.Equal(t, "asc", r.Sortby[1].Direction)
				assert.Equal(t, "id", r.Sortby[1].Field)
			},
		},
		{
			"filter w/ default cql2-text",
			"/search?filter=collection=foo",
			func(t *testing.T, r *SearchRequest) {
				assert.Equal(t, "cql2-text", r.FilterLang)
			},
		},
		{
			"token query param",
			"/search?token=abc.def",
			func(t *testing.T, r *SearchRequest) {
				assert.Equal(t, "abc.def", r.Token)
			},
		},
		{
			"cursor query param",
			"/search?cursor=xyz.123",
			func(t *testing.T, r *SearchRequest) {
				assert.Equal(t, "xyz.123", r.Cursor)
			},
		},
		{
			"next query param",
			"/search?next=off-12",
			func(t *testing.T, r *SearchRequest) {
				assert.Equal(t, "off-12", r.Next)
			},
		},
		{
			"fields include and exclude shorthand",
			"/search?fields=%2Bid,-geometry,properties.eo:cloud_cover",
			func(t *testing.T, r *SearchRequest) {
				require.NotNil(t, r.Fields, "Fields is nil")
				assert.Equal(t, []string{"id", "properties.eo:cloud_cover"}, r.Fields.Include)
				assert.Equal(t, []string{"geometry"}, r.Fields.Exclude)
			},
		},
		{
			"fields empty produces nil",
			"/search?fields=,,",
			func(t *testing.T, r *SearchRequest) {
				assert.Nil(t, r.Fields, "Fields should be nil, got %+v", r.Fields)
			},
		},
	}
	p := NewParser()
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := httptest.NewRequest(http.MethodGet, tt.url, nil)
			req, err := p.parseSearchFromQuery(r)
			require.NoError(t, err)
			tt.assert(t, req)
		})
	}
}

// TestParseSearchFromQuery_BadParamsReturn400 verifies malformed query
// params surface as typed *ParseError values (caller-mappable to HTTP
// 400) rather than being silently coerced or dropped.
func TestParseSearchFromQuery_BadParamsReturn400(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		url       string
		wantParam string
	}{
		{"bad bbox", "/search?bbox=foo,bar,3,4", "bbox"},
		{"bad limit", "/search?limit=abc", "limit"},
		// Polygon with a non-array `coordinates` value — parses as
		// JSON but is not a valid GeoJSON Polygon.
		{"bad intersects (valid JSON, invalid geometry)", `/search?intersects={"type":"Polygon","coordinates":"not-an-array"}`, "intersects"},
		// Raw JSON parse failure path.
		{"non-JSON intersects", "/search?intersects={broken", "intersects"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := httptest.NewRequest(http.MethodGet, tt.url, nil)
			_, err := NewParser().ParseSearchRequestFromHTTP(r)
			require.Error(t, err)
			var pe *ParseError
			require.Truef(t, errors.As(err, &pe), "error type = %T, want *ParseError; err=%v", err, err)
			assert.Equal(t, tt.wantParam, pe.Param)
			// Exercise ParseError.Error() so the substring also
			// surfaces param-name context in the rendered message.
			assert.Contains(t, err.Error(), tt.wantParam)
		})
	}
}

func TestExtractNextLink(t *testing.T) {
	t.Parallel()
	links := []*Link{
		{Rel: "self", Href: "https://example.com/self"},
		{Rel: "next", Href: "https://example.com/next"},
	}
	got := ExtractNextLink(links)
	require.NotNil(t, got)
	assert.Equal(t, "https://example.com/next", got.Href)
	assert.Nil(t, ExtractNextLink(nil), "ExtractNextLink(nil) should be nil")
	assert.Nil(t, ExtractNextLink([]*Link{{Rel: "self"}}), "no next link should yield nil")
}
