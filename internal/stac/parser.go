// Package stac provides STAC type definitions and parsing.
package stac

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/yourorg/stac-proxy/internal/geo"
)

// ParseError is returned by the parser when a query parameter is
// malformed. Callers (e.g. an HTTP middleware) can detect this with
// errors.As and translate it to an HTTP 400.
type ParseError struct {
	// Param is the query parameter name (e.g. "bbox", "limit").
	Param string
	// Value is the raw value that failed to parse.
	Value string
	// Err is the underlying error from strconv (or similar).
	Err error
}

func (e *ParseError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("invalid %s %q: %v", e.Param, e.Value, e.Err)
	}
	return fmt.Sprintf("invalid %s %q", e.Param, e.Value)
}

func (e *ParseError) Unwrap() error { return e.Err }

// Parser handles STAC response parsing.
type Parser struct{}

// NewParser creates a new STAC parser.
func NewParser() *Parser {
	return &Parser{}
}

// ParseItem parses a single STAC item from JSON. The library validates
// that the "type" field equals "Feature" during unmarshal.
func (p *Parser) ParseItem(data []byte) (*Item, error) {
	var item Item
	if err := json.Unmarshal(data, &item); err != nil {
		return nil, fmt.Errorf("failed to parse item: %w", err)
	}
	return &item, nil
}

// ParseCollection parses a single STAC collection from JSON. The
// library validates that the "type" field equals "Collection".
func (p *Parser) ParseCollection(data []byte) (*Collection, error) {
	var collection Collection
	if err := json.Unmarshal(data, &collection); err != nil {
		return nil, fmt.Errorf("failed to parse collection: %w", err)
	}
	return &collection, nil
}

// ParseFeatureCollection parses a STAC item collection (search results).
func (p *Parser) ParseFeatureCollection(data []byte) (*FeatureCollection, error) {
	var fc FeatureCollection
	if err := json.Unmarshal(data, &fc); err != nil {
		return nil, fmt.Errorf("failed to parse feature collection: %w", err)
	}

	if fc.Type != "FeatureCollection" {
		return nil, errors.New("invalid response: type must be 'FeatureCollection'")
	}

	return &fc, nil
}

// ParseCollections parses a collections response.
func (p *Parser) ParseCollections(data []byte) (*CollectionsResponse, error) {
	var resp CollectionsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse collections: %w", err)
	}

	return &resp, nil
}

// ParseCatalog parses a STAC catalog (landing page). The library
// validates that the "type" field equals "Catalog".
func (p *Parser) ParseCatalog(data []byte) (*Catalog, error) {
	var catalog Catalog
	if err := json.Unmarshal(data, &catalog); err != nil {
		return nil, fmt.Errorf("failed to parse catalog: %w", err)
	}
	return &catalog, nil
}

// ParseSearchRequest parses a search request from JSON body.
func (p *Parser) ParseSearchRequest(data []byte) (*SearchRequest, error) {
	var req SearchRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("failed to parse search request: %w", err)
	}

	return &req, nil
}

// ParseSearchRequestFromHTTP parses search request from HTTP request.
func (p *Parser) ParseSearchRequestFromHTTP(r *http.Request) (*SearchRequest, error) {
	req := &SearchRequest{}

	if r.Method == http.MethodGet {
		return p.parseSearchFromQuery(r)
	}

	// POST request - parse body, then restore it so downstream
	// handlers (the proxy/federation) can still forward the original
	// bytes to upstream.
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	r.Body = io.NopCloser(bytes.NewReader(body))

	if len(body) > 0 {
		if err := json.Unmarshal(body, req); err != nil {
			return nil, err
		}
	}

	return req, nil
}

// parseSearchFromQuery parses search parameters from query string.
func (p *Parser) parseSearchFromQuery(r *http.Request) (*SearchRequest, error) {
	q := r.URL.Query()
	req := &SearchRequest{}

	// Collections
	if collections := q.Get("collections"); collections != "" {
		req.Collections = strings.Split(collections, ",")
	}

	// IDs
	if ids := q.Get("ids"); ids != "" {
		req.IDs = strings.Split(ids, ",")
	}

	// Bbox — strict parse: every component must be a valid float, and
	// the resulting slice must have 4 or 6 entries. Anything else is a
	// client error and we surface it as a typed *ParseError so the HTTP
	// layer can translate to a 400.
	if bbox := q.Get("bbox"); bbox != "" {
		parts := strings.Split(bbox, ",")
		coords := make([]float64, 0, len(parts))
		for _, s := range parts {
			s = strings.TrimSpace(s)
			f, err := strconv.ParseFloat(s, 64)
			if err != nil {
				return nil, &ParseError{Param: "bbox", Value: s, Err: err}
			}
			coords = append(coords, f)
		}
		if len(coords) != 4 && len(coords) != 6 {
			return nil, &ParseError{
				Param: "bbox",
				Value: bbox,
				Err:   fmt.Errorf("expected 4 or 6 components, got %d", len(coords)),
			}
		}
		req.BBox = coords
	}

	// Datetime
	if datetime := q.Get("datetime"); datetime != "" {
		req.Datetime = datetime
	}

	// Limit — strict parse so that "?limit=abc" is a 400 rather than
	// being silently coerced to 0 (which then trips the upstream's
	// default page size).
	if limit := q.Get("limit"); limit != "" {
		l, err := strconv.Atoi(strings.TrimSpace(limit))
		if err != nil {
			return nil, &ParseError{Param: "limit", Value: limit, Err: err}
		}
		req.Limit = l
	}

	// Token
	if token := q.Get("token"); token != "" {
		req.Token = token
	}

	// Cursor — alternate spelling used by federation-aware clients.
	// Kept separate from Token so callers can prefer one over the other
	// without losing the original wire value.
	if cursor := q.Get("cursor"); cursor != "" {
		req.Cursor = cursor
	}

	// Fields (STAC API Fields Extension, GET shorthand).
	if fields := q.Get("fields"); fields != "" {
		req.Fields = parseFieldsShorthand(fields)
	}

	// Intersects (as GeoJSON string) — validate it parses as a real
	// GeoJSON geometry (not just any JSON object) so malformed shapes
	// surface as a 400 here rather than at the upstream. Store the raw
	// bytes so downstream forwards them verbatim.
	if intersects := q.Get("intersects"); intersects != "" {
		var probe map[string]interface{}
		if err := json.Unmarshal([]byte(intersects), &probe); err != nil {
			return nil, &ParseError{Param: "intersects", Value: intersects, Err: err}
		}
		if _, err := geo.ParseGeoJSON(json.RawMessage(intersects)); err != nil {
			return nil, &ParseError{Param: "intersects", Value: intersects, Err: err}
		}
		req.Intersects = json.RawMessage(intersects)
	}

	// Filter
	if filter := q.Get("filter"); filter != "" {
		req.Filter = filter
		req.FilterLang = q.Get("filter-lang")
		if req.FilterLang == "" {
			req.FilterLang = "cql2-text"
		}
	}

	// Sortby
	if sortby := q.Get("sortby"); sortby != "" {
		for _, s := range strings.Split(sortby, ",") {
			spec := SortSpec{Field: s, Direction: "asc"}
			if strings.HasPrefix(s, "-") {
				spec.Field = s[1:]
				spec.Direction = "desc"
			} else if strings.HasPrefix(s, "+") {
				spec.Field = s[1:]
			}
			req.Sortby = append(req.Sortby, spec)
		}
	}

	return req, nil
}

// parseFieldsShorthand parses the GET-style "+a,-b,c" fields parameter
// into a FieldsSpec. "-x" routes to Exclude; "+x" and bare "x" route to
// Include. Empty / whitespace-only entries are dropped. Returns nil
// when the result is empty so the field stays absent from JSON
// serialization.
func parseFieldsShorthand(raw string) *FieldsSpec {
	spec := &FieldsSpec{}
	for _, part := range strings.Split(raw, ",") {
		field := strings.TrimSpace(part)
		if field == "" {
			continue
		}
		switch field[0] {
		case '-':
			if name := strings.TrimSpace(field[1:]); name != "" {
				spec.Exclude = append(spec.Exclude, name)
			}
		case '+':
			if name := strings.TrimSpace(field[1:]); name != "" {
				spec.Include = append(spec.Include, name)
			}
		default:
			spec.Include = append(spec.Include, field)
		}
	}
	if len(spec.Include) == 0 && len(spec.Exclude) == 0 {
		return nil
	}
	return spec
}

// ExtractNextLink finds the "next" link from a set of links.
func ExtractNextLink(links []*Link) *Link {
	for _, link := range links {
		if link != nil && link.Rel == "next" {
			return link
		}
	}
	return nil
}

// ExtractNextToken extracts token from next link.
func ExtractNextToken(links []*Link) string {
	link := ExtractNextLink(links)
	if link == nil {
		return ""
	}

	// Try to extract token from URL
	if link.Href != "" {
		// Parse URL and get token parameter
		if strings.Contains(link.Href, "token=") {
			parts := strings.Split(link.Href, "token=")
			if len(parts) > 1 {
				token := strings.Split(parts[1], "&")[0]
				return token
			}
		}
	}

	return ""
}

// ValidateItem validates a STAC item.
func ValidateItem(item *Item) error {
	if item.ID == "" {
		return errors.New("item missing ID")
	}
	if len(item.Geometry) == 0 {
		return errors.New("item missing geometry")
	}
	return nil
}

// ValidateCollection validates a STAC collection.
func ValidateCollection(collection *Collection) error {
	if collection.ID == "" {
		return errors.New("collection missing ID")
	}
	if collection.Description == "" {
		return errors.New("collection missing description")
	}
	if collection.License == "" {
		return errors.New("collection missing license")
	}
	return nil
}

// ValidateSearchRequest validates a search request.
//
// Per STAC API §7.2.1, `bbox` and `intersects` are mutually exclusive.
// Both being set is a client error.
func ValidateSearchRequest(req *SearchRequest) error {
	// Validate bbox
	if req.BBox != nil {
		if len(req.BBox) != 4 && len(req.BBox) != 6 {
			return errors.New("bbox must have 4 or 6 coordinates")
		}
		// Check coordinate order
		if req.BBox[0] > req.BBox[2] {
			return errors.New("bbox west must be less than east")
		}
		if req.BBox[1] > req.BBox[3] {
			return errors.New("bbox south must be less than north")
		}
	}

	// Mutual exclusion (STAC API §7.2.1).
	if req.BBox != nil && len(req.Intersects) > 0 {
		return errors.New("bbox and intersects are mutually exclusive")
	}

	// Validate limit
	if req.Limit < 0 {
		return errors.New("limit must be non-negative")
	}

	return nil
}
