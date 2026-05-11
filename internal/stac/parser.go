// Package stac provides STAC type definitions and parsing.
package stac

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Parser handles STAC response parsing.
type Parser struct{}

// NewParser creates a new STAC parser.
func NewParser() *Parser {
	return &Parser{}
}

// ParseItem parses a single STAC item from JSON.
func (p *Parser) ParseItem(data []byte) (*Item, error) {
	var item Item
	if err := json.Unmarshal(data, &item); err != nil {
		return nil, fmt.Errorf("failed to parse item: %w", err)
	}

	if item.Type != "Feature" {
		return nil, errors.New("invalid item: type must be 'Feature'")
	}

	return &item, nil
}

// ParseCollection parses a single STAC collection from JSON.
func (p *Parser) ParseCollection(data []byte) (*Collection, error) {
	var collection Collection
	if err := json.Unmarshal(data, &collection); err != nil {
		return nil, fmt.Errorf("failed to parse collection: %w", err)
	}

	if collection.Type != "Collection" {
		return nil, errors.New("invalid collection: type must be 'Collection'")
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

// Note: CollectionsResponse is defined in types.go

// ParseCatalog parses a STAC catalog (landing page).
func (p *Parser) ParseCatalog(data []byte) (*Catalog, error) {
	var catalog Catalog
	if err := json.Unmarshal(data, &catalog); err != nil {
		return nil, fmt.Errorf("failed to parse catalog: %w", err)
	}

	if catalog.Type != "Catalog" {
		return nil, errors.New("invalid catalog: type must be 'Catalog'")
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

	// POST request - parse body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}

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

	// Bbox
	if bbox := q.Get("bbox"); bbox != "" {
		var coords []float64
		for _, s := range strings.Split(bbox, ",") {
			var f float64
			if _, err := fmt.Sscanf(s, "%f", &f); err == nil {
				coords = append(coords, f)
			}
		}
		if len(coords) == 4 || len(coords) == 6 {
			req.BBox = coords
		}
	}

	// Datetime
	if datetime := q.Get("datetime"); datetime != "" {
		req.Datetime = datetime
	}

	// Limit
	if limit := q.Get("limit"); limit != "" {
		var l int
		if _, err := fmt.Sscanf(limit, "%d", &l); err == nil {
			req.Limit = l
		}
	}

	// Token
	if token := q.Get("token"); token != "" {
		req.Token = token
	}

	// Intersects (as GeoJSON string)
	if intersects := q.Get("intersects"); intersects != "" {
		var geom Geometry
		if err := json.Unmarshal([]byte(intersects), &geom); err == nil {
			req.Intersects = &geom
		}
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

// ExtractNextLink finds the "next" link from a set of links.
func ExtractNextLink(links []Link) *Link {
	for _, link := range links {
		if link.Rel == "next" {
			return &link
		}
	}
	return nil
}

// ExtractNextToken extracts token from next link.
func ExtractNextToken(links []Link) string {
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
	if item.Type != "Feature" {
		return errors.New("item type must be 'Feature'")
	}
	if item.Geometry == nil {
		return errors.New("item missing geometry")
	}
	// Properties is a struct, not a pointer, so we don't check for nil
	return nil
}

// ValidateCollection validates a STAC collection.
func ValidateCollection(collection *Collection) error {
	if collection.ID == "" {
		return errors.New("collection missing ID")
	}
	if collection.Type != "Collection" {
		return errors.New("collection type must be 'Collection'")
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

	// Validate limit
	if req.Limit < 0 {
		return errors.New("limit must be non-negative")
	}

	return nil
}
