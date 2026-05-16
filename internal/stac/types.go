// Package stac provides core STAC (SpatioTemporal Asset Catalog) types.
//
// The core STAC document types (Item, Collection, Catalog, Asset, Link,
// Provider, Extent, …) come from github.com/robert-malhotra/go-stac-client
// and are re-exported here as type aliases. The library implements
// foreign-member preservation (the "AdditionalFields" pattern) on every
// type, which is essential for proxying STAC extensions (eo:*, proj:*,
// view:*, sar:*, etc.) without silently dropping fields.
//
// The STAC API protocol types (SearchRequest, SearchContext, SortSpec)
// stay local because they are not part of the STAC core data model.
package stac

import (
	"encoding/json"

	lib "github.com/robert-malhotra/go-stac-client/pkg/stac"
)

// Core STAC types — re-exported as aliases so that
// `stac.Item == lib.Item` (identical underlying type, identical field
// names). Field-level access in callers uses the library's spelling
// (`item.Bbox`, `item.Properties` as `map[string]any`, etc.).
type (
	Item           = lib.Item
	Collection     = lib.Collection
	Catalog        = lib.Catalog
	Asset          = lib.Asset
	Link           = lib.Link
	Provider       = lib.Provider
	Extent         = lib.Extent
	SpatialExtent  = lib.SpatialExtent
	TemporalExtent = lib.TemporalExtent
)

// FeatureCollection is the GeoJSON FeatureCollection wrapper used for
// search results. The library's ItemsList covers the spec shape; we
// alias to keep call-site spellings stable.
type FeatureCollection = lib.ItemsList

// CollectionsResponse is the body of GET /collections.
type CollectionsResponse = lib.CollectionsList

// SearchContext provides context about search results (STAC API extension).
// Not part of the library because it's an API protocol type, not a core
// STAC type.
type SearchContext struct {
	Returned int  `json:"returned"`
	Limit    int  `json:"limit,omitempty"`
	Matched  int  `json:"matched,omitempty"`
	Next     bool `json:"-"` // Internal flag for pagination
}

// SearchRequest represents a STAC API search request.
type SearchRequest struct {
	// Core parameters
	Collections []string        `json:"collections,omitempty"`
	IDs         []string        `json:"ids,omitempty"`
	BBox        []float64       `json:"bbox,omitempty"`
	Intersects  json.RawMessage `json:"intersects,omitempty"`
	Datetime    string          `json:"datetime,omitempty"`
	Limit       int             `json:"limit,omitempty"`

	// Pagination
	Cursor string `json:"cursor,omitempty"` // For federated pagination
	Token  string `json:"token,omitempty"`  // Legacy pagination token

	// Sorting
	Sortby []SortSpec `json:"sortby,omitempty"`

	// Filter extension
	Filter     interface{} `json:"filter,omitempty"`
	FilterLang string      `json:"filter-lang,omitempty"`
	FilterCRS  string      `json:"filter-crs,omitempty"`

	// Query extension (deprecated but still used)
	Query map[string]interface{} `json:"query,omitempty"`

	// Fields extension (STAC API Fields Extension).
	// GET form: ?fields=+id,-geometry,properties.eo:cloud_cover — the
	// parser translates "+x" / "x" into Include and "-x" into Exclude.
	// POST form: {"fields": {"include": [...], "exclude": [...]}}.
	Fields *FieldsSpec `json:"fields,omitempty"`

	// OverrideURL is a federation-private transport field (NOT
	// serialized upstream). When non-empty, the OriginClient fetches
	// this URL verbatim (GET) instead of POST-ing the standard /search
	// with this body. Populated by the paginator from
	// OriginCursor.NextURL for adapters that capture full next-page
	// URLs (next_url, link_header, offset). The OriginClient
	// allowlist-checks the URL against its BaseURL.
	OverrideURL string `json:"-"`

	// AdapterName is a federation-private transport field (NOT
	// serialized upstream) carrying the locked pagination adapter
	// name from the cursor. The `auto` adapter sets this on the first
	// response; subsequent pages use it to route to the named adapter
	// directly without re-probing.
	AdapterName string `json:"-"`
}

// FieldsSpec is the Fields extension include/exclude selector.
type FieldsSpec struct {
	Include []string `json:"include,omitempty"`
	Exclude []string `json:"exclude,omitempty"`
}

// SortSpec specifies a sort field and direction.
type SortSpec struct {
	Field     string `json:"field"`
	Direction string `json:"direction"` // "asc" or "desc"
}
