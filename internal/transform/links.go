// Package transform provides response transformation utilities.
package transform

import (
	"encoding/json"
	"strings"
)

// LinkRewriter rewrites links in STAC responses to point through the proxy.
type LinkRewriter struct {
	proxyBaseURL   string
	originMappings map[string]string // origin base URL -> proxy path prefix
}

// NewLinkRewriter creates a new link rewriter.
func NewLinkRewriter(proxyBaseURL string) *LinkRewriter {
	return &LinkRewriter{
		proxyBaseURL:   proxyBaseURL,
		originMappings: make(map[string]string),
	}
}

// AddOriginMapping adds a mapping from an origin URL to a proxy path prefix.
func (r *LinkRewriter) AddOriginMapping(originBaseURL, proxyPrefix string) {
	r.originMappings[originBaseURL] = proxyPrefix
}

// RewriteLinks rewrites all links in a JSON response.
func (r *LinkRewriter) RewriteLinks(data []byte, originBaseURL string) ([]byte, error) {
	var obj map[string]interface{}
	if err := json.Unmarshal(data, &obj); err != nil {
		return data, err
	}

	r.rewriteObject(obj, originBaseURL)

	return json.Marshal(obj)
}

// rewriteObject recursively rewrites links in a JSON object.
func (r *LinkRewriter) rewriteObject(obj map[string]interface{}, originBaseURL string) {
	// Rewrite "links" array
	if links, ok := obj["links"].([]interface{}); ok {
		for _, link := range links {
			if linkMap, ok := link.(map[string]interface{}); ok {
				if href, ok := linkMap["href"].(string); ok {
					linkMap["href"] = r.rewriteURL(href, originBaseURL)
				}
			}
		}
	}

	// Rewrite asset hrefs
	if assets, ok := obj["assets"].(map[string]interface{}); ok {
		for _, asset := range assets {
			if assetMap, ok := asset.(map[string]interface{}); ok {
				if href, ok := assetMap["href"].(string); ok {
					assetMap["href"] = r.rewriteURL(href, originBaseURL)
				}
			}
		}
	}

	// Recurse into features array
	if features, ok := obj["features"].([]interface{}); ok {
		for _, feature := range features {
			if featureMap, ok := feature.(map[string]interface{}); ok {
				r.rewriteObject(featureMap, originBaseURL)
			}
		}
	}

	// Recurse into collections array
	if collections, ok := obj["collections"].([]interface{}); ok {
		for _, collection := range collections {
			if collMap, ok := collection.(map[string]interface{}); ok {
				r.rewriteObject(collMap, originBaseURL)
			}
		}
	}
}

// rewriteURL rewrites a single URL to point through the proxy.
func (r *LinkRewriter) rewriteURL(href, originBaseURL string) string {
	// Check if URL starts with origin base URL
	if strings.HasPrefix(href, originBaseURL) {
		path := strings.TrimPrefix(href, originBaseURL)
		return r.proxyBaseURL + path
	}

	// Check origin mappings
	for origin, prefix := range r.originMappings {
		if strings.HasPrefix(href, origin) {
			path := strings.TrimPrefix(href, origin)
			return r.proxyBaseURL + prefix + path
		}
	}

	// Return unchanged if no mapping found
	return href
}

// RewriteItem rewrites links in a STAC Item.
func (r *LinkRewriter) RewriteItem(data []byte, originBaseURL string) ([]byte, error) {
	return r.RewriteLinks(data, originBaseURL)
}

// RewriteCollection rewrites links in a STAC Collection.
func (r *LinkRewriter) RewriteCollection(data []byte, originBaseURL string) ([]byte, error) {
	return r.RewriteLinks(data, originBaseURL)
}

// RewriteFeatureCollection rewrites links in a STAC FeatureCollection (search results).
func (r *LinkRewriter) RewriteFeatureCollection(data []byte, originBaseURL string) ([]byte, error) {
	return r.RewriteLinks(data, originBaseURL)
}

// StripOriginPrefix removes the origin prefix from collection IDs.
func StripOriginPrefix(collectionID, prefix string) string {
	return strings.TrimPrefix(collectionID, prefix)
}

// AddOriginPrefix adds an origin prefix to collection IDs.
func AddOriginPrefix(collectionID, prefix string) string {
	if prefix == "" {
		return collectionID
	}
	return prefix + collectionID
}

// ExtractOriginFromID extracts the origin ID from a prefixed collection or item ID.
func ExtractOriginFromID(id, separator string) (originID, localID string) {
	if separator == "" {
		separator = ":"
	}
	parts := strings.SplitN(id, separator, 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return "", id
}
