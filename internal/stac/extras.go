package stac

import (
	"time"
)

// SearchContextOf returns the embedded SearchContext from a
// FeatureCollection. The library types ItemsList.Context as `any` to
// stay neutral toward the STAC context extension shape: when we build
// a response we store `*SearchContext` directly, but after a JSON
// round-trip the field decodes as `map[string]any`. This helper covers
// both cases. Returns nil when no context is present.
func SearchContextOf(fc *FeatureCollection) *SearchContext {
	if fc == nil || fc.Context == nil {
		return nil
	}
	switch v := fc.Context.(type) {
	case *SearchContext:
		return v
	case SearchContext:
		out := v
		return &out
	case map[string]any:
		out := &SearchContext{}
		if r, ok := v["returned"].(float64); ok {
			out.Returned = int(r)
		}
		if l, ok := v["limit"].(float64); ok {
			out.Limit = int(l)
		}
		if m, ok := v["matched"].(float64); ok {
			out.Matched = int(m)
		}
		return out
	}
	return nil
}

// ItemDatetime returns the canonical datetime for a STAC Item, parsed
// from properties.datetime. When that field is null (a STAC Item may
// omit datetime in favor of start_datetime/end_datetime), it falls
// back to properties.start_datetime. Returns (zero, false) if neither
// is present or parseable as RFC 3339.
//
// The library represents Properties as map[string]any, so datetime is
// surfaced as a JSON string rather than a typed *time.Time. This
// helper centralises the parse so call sites don't have to repeat it.
func ItemDatetime(item *Item) (time.Time, bool) {
	if item == nil || item.Properties == nil {
		return time.Time{}, false
	}
	for _, key := range []string{"datetime", "start_datetime"} {
		v, ok := item.Properties[key]
		if !ok || v == nil {
			continue
		}
		s, ok := v.(string)
		if !ok {
			continue
		}
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// SetItemForeignMember stores a foreign (non-spec) field on an Item so
// it survives marshal/unmarshal through the library's AdditionalFields
// machinery. Use this rather than mutating item.AdditionalFields
// directly so we can change the storage convention without touching
// callers.
func SetItemForeignMember(item *Item, key string, value any) {
	if item == nil {
		return
	}
	if item.AdditionalFields == nil {
		item.AdditionalFields = make(map[string]any)
	}
	item.AdditionalFields[key] = value
}

// SetCollectionForeignMember mirrors SetItemForeignMember for
// Collections. STAC Collections have no spec-defined Properties field
// for proxy-added metadata, so foreign members live at the top level
// (and serialize there via the library's custom marshaller).
func SetCollectionForeignMember(coll *Collection, key string, value any) {
	if coll == nil {
		return
	}
	if coll.AdditionalFields == nil {
		coll.AdditionalFields = make(map[string]any)
	}
	coll.AdditionalFields[key] = value
}

// OriginLinkRel is the link rel value the proxy attaches to every
// STAC document it merges from a federation origin. It identifies
// which upstream catalog a given Item/Collection came from. The link
// is preferred over a property/foreign-member because it lives in
// the standard `links[]` array, which clients already walk for `self`,
// `parent`, `next`, etc.
//
// The link shape is:
//
//	{
//	  "href":  "<origin BaseURL>",
//	  "rel":   "stac_proxy:origin",
//	  "type":  "application/json",
//	  "title": "<origin ID>"
//	}
const OriginLinkRel = "stac_proxy:origin"

// OriginLink builds the link that identifies a STAC document's
// upstream origin. originURL goes in href so clients can follow it
// back to the origin's catalog; originID goes in title for display.
func OriginLink(originID, originURL string) *Link {
	return &Link{
		Href:  originURL,
		Rel:   OriginLinkRel,
		Type:  "application/json",
		Title: originID,
	}
}

// AddItemOriginLink appends a stac_proxy:origin link to item.Links,
// or no-ops if a link with the same rel + title is already present
// (idempotent so callers don't have to worry about double-attachment).
// The links slice is reallocated rather than mutated in place to
// avoid aliasing the caller's slice.
func AddItemOriginLink(item *Item, originID, originURL string) {
	if item == nil {
		return
	}
	for _, l := range item.Links {
		if l != nil && l.Rel == OriginLinkRel && l.Title == originID {
			return
		}
	}
	out := make([]*Link, len(item.Links), len(item.Links)+1)
	copy(out, item.Links)
	out = append(out, OriginLink(originID, originURL))
	item.Links = out
}

// AddCollectionOriginLink mirrors AddItemOriginLink for *Collection.
func AddCollectionOriginLink(coll *Collection, originID, originURL string) {
	if coll == nil {
		return
	}
	for _, l := range coll.Links {
		if l != nil && l.Rel == OriginLinkRel && l.Title == originID {
			return
		}
	}
	out := make([]*Link, len(coll.Links), len(coll.Links)+1)
	copy(out, coll.Links)
	out = append(out, OriginLink(originID, originURL))
	coll.Links = out
}

// ItemOriginID extracts the upstream origin ID a STAC Item was
// merged from, by reading the title of the stac_proxy:origin link.
// Returns "" if no such link is present (e.g. single-origin
// pass-through responses, which don't go through the merger).
func ItemOriginID(item *Item) string {
	if item == nil {
		return ""
	}
	for _, l := range item.Links {
		if l != nil && l.Rel == OriginLinkRel {
			return l.Title
		}
	}
	return ""
}

// CollectionOriginID mirrors ItemOriginID for *Collection.
func CollectionOriginID(coll *Collection) string {
	if coll == nil {
		return ""
	}
	for _, l := range coll.Links {
		if l != nil && l.Rel == OriginLinkRel {
			return l.Title
		}
	}
	return ""
}
