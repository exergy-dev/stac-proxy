// Package stac provides core STAC (SpatioTemporal Asset Catalog) types.
package stac

import (
	"encoding/json"
	"time"
)

// Item represents a STAC Item - the core atomic unit describing a single spatiotemporal asset.
type Item struct {
	Type       string                 `json:"type"` // Always "Feature"
	StacVersion string                `json:"stac_version"`
	ID         string                 `json:"id"`
	Geometry   *Geometry              `json:"geometry"`
	BBox       []float64              `json:"bbox,omitempty"`
	Properties Properties             `json:"properties"`
	Links      []Link                 `json:"links"`
	Assets     map[string]Asset       `json:"assets"`
	Collection string                 `json:"collection,omitempty"`
	Extra      map[string]interface{} `json:"-"` // Additional fields
}

// Properties contains item properties including required datetime.
type Properties struct {
	DateTime  *time.Time             `json:"datetime"`
	Created   *time.Time             `json:"created,omitempty"`
	Updated   *time.Time             `json:"updated,omitempty"`
	StartDateTime *time.Time         `json:"start_datetime,omitempty"`
	EndDateTime   *time.Time         `json:"end_datetime,omitempty"`
	Title     string                 `json:"title,omitempty"`
	Extra     map[string]interface{} `json:"-"` // Additional properties
}

// Collection represents a STAC Collection - a group of related items.
type Collection struct {
	Type          string                 `json:"type"` // Always "Collection"
	StacVersion   string                 `json:"stac_version"`
	ID            string                 `json:"id"`
	Title         string                 `json:"title,omitempty"`
	Description   string                 `json:"description"`
	Keywords      []string               `json:"keywords,omitempty"`
	License       string                 `json:"license"`
	Providers     []Provider             `json:"providers,omitempty"`
	Extent        Extent                 `json:"extent"`
	Summaries     map[string]interface{} `json:"summaries,omitempty"`
	Links         []Link                 `json:"links"`
	Assets        map[string]Asset       `json:"assets,omitempty"`
	Properties    map[string]interface{} `json:"properties,omitempty"` // For proxy-added metadata
}

// Provider describes a provider of STAC data.
type Provider struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Roles       []string `json:"roles,omitempty"`
	URL         string   `json:"url,omitempty"`
}

// Extent describes the spatial and temporal extent of a collection.
type Extent struct {
	Spatial  SpatialExtent  `json:"spatial"`
	Temporal TemporalExtent `json:"temporal"`
}

// SpatialExtent describes the spatial extent.
type SpatialExtent struct {
	BBox [][]float64 `json:"bbox"`
}

// TemporalExtent describes the temporal extent.
type TemporalExtent struct {
	Interval [][]interface{} `json:"interval"` // Array of [start, end] pairs, can be null
}

// Catalog represents a STAC Catalog.
type Catalog struct {
	Type          string `json:"type"` // Always "Catalog"
	StacVersion   string `json:"stac_version"`
	ID            string `json:"id"`
	Title         string `json:"title,omitempty"`
	Description   string `json:"description"`
	Links         []Link `json:"links"`
	ConformsTo    []string `json:"conformsTo,omitempty"`
}

// Link represents a STAC link.
type Link struct {
	Href   string `json:"href"`
	Rel    string `json:"rel"`
	Type   string `json:"type,omitempty"`
	Title  string `json:"title,omitempty"`
	Method string `json:"method,omitempty"` // For STAC API
	Body   interface{} `json:"body,omitempty"` // For STAC API POST links
}

// Asset represents a STAC Asset - a link to data associated with an item.
type Asset struct {
	Href        string   `json:"href"`
	Title       string   `json:"title,omitempty"`
	Description string   `json:"description,omitempty"`
	Type        string   `json:"type,omitempty"` // Media type
	Roles       []string `json:"roles,omitempty"`
	Extra       map[string]interface{} `json:"-"` // Additional fields
}

// Geometry represents a GeoJSON geometry.
type Geometry struct {
	Type        string          `json:"type"`
	Coordinates json.RawMessage `json:"coordinates,omitempty"`
	Geometries  []Geometry      `json:"geometries,omitempty"` // For GeometryCollection
}

// FeatureCollection represents a GeoJSON FeatureCollection, used for search results.
type FeatureCollection struct {
	Type           string         `json:"type"` // Always "FeatureCollection"
	Features       []Item         `json:"features"`
	Links          []Link         `json:"links,omitempty"`
	Context        *SearchContext `json:"context,omitempty"`
	NumberMatched  *int           `json:"numberMatched,omitempty"`
	NumberReturned int            `json:"numberReturned,omitempty"`
}

// SearchContext provides context about search results (STAC API extension).
type SearchContext struct {
	Returned int  `json:"returned"`
	Limit    int  `json:"limit,omitempty"`
	Matched  int  `json:"matched,omitempty"`
	Next     bool `json:"-"` // Internal flag for pagination
}

// SearchRequest represents a STAC API search request.
type SearchRequest struct {
	// Core parameters
	Collections []string    `json:"collections,omitempty"`
	IDs         []string    `json:"ids,omitempty"`
	BBox        []float64   `json:"bbox,omitempty"`
	Intersects  *Geometry   `json:"intersects,omitempty"`
	Datetime    string      `json:"datetime,omitempty"`
	Limit       int         `json:"limit,omitempty"`

	// Pagination
	Cursor      string      `json:"cursor,omitempty"` // For federated pagination
	Token       string      `json:"token,omitempty"`  // Legacy pagination token

	// Sorting
	Sortby      []SortSpec  `json:"sortby,omitempty"`

	// Filter extension
	Filter      interface{} `json:"filter,omitempty"`
	FilterLang  string      `json:"filter-lang,omitempty"`
	FilterCRS   string      `json:"filter-crs,omitempty"`

	// Query extension (deprecated but still used)
	Query map[string]interface{} `json:"query,omitempty"`
}

// SortSpec specifies a sort field and direction.
type SortSpec struct {
	Field     string `json:"field"`
	Direction string `json:"direction"` // "asc" or "desc"
}

// CollectionsResponse is the response for GET /collections.
type CollectionsResponse struct {
	Collections []Collection `json:"collections"`
	Links       []Link       `json:"links,omitempty"`
}
