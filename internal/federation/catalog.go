package federation

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/exergy-dev/stac-proxy/internal/stac"
)

// handleGetCollections handles GET /collections.
//
// Single-origin fast path: when only one origin is registered, forward
// end-to-end via reverseProxyOnce — preserves headers/X-Forwarded,
// suppresses stac_proxy:origin injection (dynamic-on-routed-count).
func (h *Handler) handleGetCollections(ctx context.Context,
	req *request) (*response, error) {

	if len(h.origins) == 1 {
		return h.reverseProxyOnce(ctx, h.primaryOrigin(), req)
	}

	ctx, cancel := context.WithTimeout(ctx, h.aggregateTimeout)
	defer cancel()

	clients := make([]*OriginClient, 0, len(h.origins))
	for _, client := range h.origins {
		clients = append(clients, client)
	}
	results := fanOut(clients, 0,
		func(client *OriginClient) *OriginCollectionsResult {
			origin := client.Origin()
			collections, err := client.GetCollections(ctx)

			result := &OriginCollectionsResult{
				OriginID:  origin.ID,
				OriginURL: client.BaseURL(),
				Error:     err,
			}
			if err == nil {
				// Apply collection prefix. The stac_proxy:origin marker
				// is attached centrally by merger.MergeCollections so
				// that mutation happens in a single goroutine after the
				// fan-out — writing it here too would double-write the
				// map under the race detector even though it's
				// logically safe.
				for _, coll := range collections {
					if coll == nil {
						continue
					}
					if origin.CollectionPrefix != "" {
						coll.ID = origin.CollectionPrefix + coll.ID
					}
				}
				result.Collections = collections
			}
			return result
		},
		func(client *OriginClient, r any) *OriginCollectionsResult {
			originID := client.Origin().ID
			slog.Error("federation origin GetCollections panicked",
				"origin", originID,
				"panic", r,
				"stack", string(debug.Stack()),
			)
			return &OriginCollectionsResult{
				OriginID:  originID,
				OriginURL: client.BaseURL(),
				Error:     fmt.Errorf("origin %s panicked: %v", originID, r),
			}
		})

	// All origins down → 502; a subset down → 200 with the partial
	// headers, so a caller can tell a shrunken catalog from the real
	// one.
	failed := originFailures(results, func(r *OriginCollectionsResult) (string, bool) {
		return r.OriginID, r.Error != nil
	})
	if resp, err := h.respondIfAllFailed("GET /collections", failed, len(results)); resp != nil || err != nil {
		return resp, err
	}

	// Merge collections
	collections := h.merger.MergeCollections(results)

	// Build response
	resp := &stac.CollectionsResponse{
		Collections: collections,
	}

	body, err := json.Marshal(resp)
	if err != nil {
		return nil, err
	}

	out := &response{
		StatusCode: http.StatusOK,
		Headers: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body: body,
	}
	h.markPartial(out, failed)
	return out, nil
}

// handleGetCollection handles GET /collections/{collectionId}. Iterates
// candidate origins in priority order via reverseProxyOnce; first
// non-404 wins. Origin metadata is only injected when there is more
// than one registered origin (true federation mode).
func (h *Handler) handleGetCollection(ctx context.Context,
	req *request) (*response, error) {
	return h.handleSingleResource(ctx, req, "Collection not found")
}

// handleGetItem handles GET /collections/{collectionId}/items/{itemId}.
// Same priority-order iteration as handleGetCollection.
func (h *Handler) handleGetItem(ctx context.Context,
	req *request) (*response, error) {
	return h.handleSingleResource(ctx, req, "Item not found")
}

// handleSingleResource is the shared body of handleGetCollection and
// handleGetItem: route by collection ID, iterate candidate origins in
// priority order via reverseProxyOnce, and return the first non-404.
// Origin metadata is injected when more than one origin is configured.
// notFoundDescription is used for both the empty-routing 404 and the
// all-origins-404 fallthrough.
func (h *Handler) handleSingleResource(ctx context.Context,
	req *request, notFoundDescription string) (*response, error) {

	collectionID := req.Collection
	origins := h.router.RouteCollection(collectionID)

	if len(origins) == 0 {
		return notFoundResponse(notFoundDescription), nil
	}

	annotate := len(h.origins) > 1

	for _, origin := range origins {
		// Optionally strip a configured collection prefix before
		// forwarding upstream.
		reqOut := req
		if origin.CollectionPrefix != "" && strings.HasPrefix(collectionID, origin.CollectionPrefix) {
			reqOut = adaptRequestStripCollectionPrefix(req, origin.CollectionPrefix)
		}

		resp, err := h.reverseProxyOnce(ctx, origin, reqOut)
		if err != nil {
			continue
		}
		if resp.StatusCode == http.StatusNotFound {
			continue
		}
		if resp.StatusCode != http.StatusOK {
			return resp, nil
		}
		if annotate {
			injectOriginMetadata(resp, origin.ID, origin.BaseURL)
		}
		return resp, nil
	}

	return notFoundResponse(notFoundDescription), nil
}

// notFoundResponse builds a uniform 404 STAC error response.
func notFoundResponse(description string) *response {
	return errorResponse(http.StatusNotFound, "NotFound", description)
}

// handleQueryables handles GET /queryables and
// GET /collections/{collectionId}/queryables.
//
// The merged schema is the conservative intersection of properties
// returned by all reachable origins: a property is advertised only
// when every origin agrees on it. Origin failures are skipped (logged
// and excluded from the intersection) so a single bad upstream cannot
// block discovery of common queryables.
func (h *Handler) handleQueryables(ctx context.Context, req *request) (*response, error) {
	path := "/queryables"
	if req.Collection != "" {
		path = "/collections/" + req.Collection + "/queryables"
	}

	// Determine the candidate origin set. For collection-scoped
	// queryables, only origins that route the collection.
	var clients []*OriginClient
	if req.Collection != "" {
		for _, o := range h.router.Route([]string{req.Collection}) {
			if c, ok := h.origins[o.ID]; ok {
				clients = append(clients, c)
			}
		}
	} else {
		for _, c := range h.origins {
			clients = append(clients, c)
		}
	}
	if len(clients) == 0 {
		return errorResponse(http.StatusServiceUnavailable, "ServiceUnavailable",
			"no origins available for queryables"), nil
	}

	// Single-origin shortcut: pass through transparently.
	if len(clients) == 1 {
		origin := clients[0].Origin()
		return h.reverseProxyOnce(ctx, origin, req)
	}

	perOrigin := 5 * time.Second
	if h.aggregateTimeout > 0 && h.aggregateTimeout < perOrigin {
		perOrigin = h.aggregateTimeout
	}

	results := fanOut(clients, 0,
		func(c *OriginClient) map[string]any {
			fctx, cancel := context.WithTimeout(ctx, perOrigin)
			defer cancel()
			resp, err := c.DoRequest(fctx, http.MethodGet, path, nil)
			if err != nil {
				slog.Warn("queryables fetch failed", "origin", c.Origin().ID, "error", err)
				return nil
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return nil
			}
			var schema map[string]any
			if err := json.NewDecoder(resp.Body).Decode(&schema); err != nil {
				slog.Warn("queryables decode failed", "origin", c.Origin().ID, "error", err)
				return nil
			}
			if schema == nil {
				// A literal `null` body decodes without error; count it
				// as a (vacuous) success — nil is the failure sentinel.
				schema = map[string]any{}
			}
			return schema
		},
		func(c *OriginClient, r any) map[string]any {
			slog.Error("queryables fetch panicked",
				"origin", c.Origin().ID, "panic", r,
			)
			return nil
		})

	var schemas []map[string]any
	for _, schema := range results {
		if schema != nil {
			schemas = append(schemas, schema)
		}
	}
	if len(schemas) == 0 {
		return errorResponse(http.StatusServiceUnavailable, "ServiceUnavailable",
			"queryables unavailable from all origins"), nil
	}

	merged := intersectQueryables(schemas, h.proxyBaseURL, path)
	body, err := json.Marshal(merged)
	if err != nil {
		return nil, err
	}
	return &response{
		StatusCode: http.StatusOK,
		Headers:    http.Header{"Content-Type": []string{"application/schema+json"}},
		Body:       body,
	}, nil
}

// intersectQueryables returns a JSON Schema whose `properties` is the
// per-property intersection across `schemas`: a property is kept only
// when every schema declares it. Per-property values are taken from
// the first schema that declared them, which is acceptable for the
// metadata-discovery use case the queryables endpoint exists for.
func intersectQueryables(schemas []map[string]any, proxyBase, path string) map[string]any {
	out := map[string]any{
		"$schema":              "https://json-schema.org/draft/2019-09/schema",
		"type":                 "object",
		"title":                "Queryables",
		"description":          "Federated queryables (intersection across origins)",
		"additionalProperties": false,
	}
	if proxyBase != "" {
		out["$id"] = strings.TrimRight(proxyBase, "/") + path
	}
	if len(schemas) == 0 {
		out["properties"] = map[string]any{}
		return out
	}

	// Count property occurrences across schemas.
	counts := map[string]int{}
	firstSeen := map[string]any{}
	for _, s := range schemas {
		props, _ := s["properties"].(map[string]any)
		for name, def := range props {
			counts[name]++
			if _, exists := firstSeen[name]; !exists {
				firstSeen[name] = def
			}
		}
	}
	keep := map[string]any{}
	for name, n := range counts {
		if n == len(schemas) {
			keep[name] = firstSeen[name]
		}
	}
	out["properties"] = keep
	return out
}

// handleGenericProxy proxies requests to the highest priority origin
// via ReverseProxy. Used for STAC endpoints that don't have dedicated
// federation handling.
func (h *Handler) handleGenericProxy(ctx context.Context,
	req *request) (*response, error) {

	origin := h.primaryOrigin()
	if origin == nil {
		return errorResponse(http.StatusServiceUnavailable, "NoOrigins", "No origins available"), nil
	}

	return h.reverseProxyOnce(ctx, origin, req)
}

// handleConformance returns the intersection of the proxy's
// advertised capabilities with each routed origin's /conformance
// response. We never advertise a class the proxy itself does not
// support (per ProxyConformanceFor), and we never advertise a class
// no origin actually implements — the spec calls for honest
// conformance and our previous "passthrough first origin" behavior
// could surprise federated clients.
func (h *Handler) handleConformance(ctx context.Context,
	req *request) (*response, error) {

	classes := h.advertisedConformance(ctx)
	body, err := json.Marshal(map[string]interface{}{
		"conformsTo": classes,
	})
	if err != nil {
		return nil, err
	}
	return &response{
		StatusCode: http.StatusOK,
		Headers:    http.Header{"Content-Type": []string{"application/json"}},
		Body:       body,
	}, nil
}

// handleLanding builds a STAC Catalog landing page whose conformsTo
// reflects the intersected proxy/origin capability set, plus the five
// STAC API §1.4 required link rels (self, root, data, conformance,
// search). When ProxyBaseURL is configured links are absolute; otherwise
// they stay relative so callers behind a path-only reverse proxy still
// produce usable links.
func (h *Handler) handleLanding(ctx context.Context,
	req *request) (*response, error) {

	classes := h.advertisedConformance(ctx)
	body, err := json.Marshal(map[string]interface{}{
		"type":         "Catalog",
		"stac_version": "1.0.0",
		"id":           "stac-proxy",
		"description":  "Federated STAC proxy",
		"conformsTo":   classes,
		"links":        h.landingLinks(),
	})
	if err != nil {
		return nil, err
	}
	return &response{
		StatusCode: http.StatusOK,
		Headers:    http.Header{"Content-Type": []string{"application/json"}},
		Body:       body,
	}, nil
}

// landingLinks returns the STAC API §1.4 required link rels for the
// landing page. Hrefs are rooted at proxyBaseURL when configured;
// otherwise they are emitted as relative paths.
func (h *Handler) landingLinks() []map[string]string {
	base := strings.TrimRight(h.proxyBaseURL, "/")
	href := func(p string) string { return base + p }
	const (
		jsonType    = "application/json"
		geoJSONType = "application/geo+json"
	)
	return []map[string]string{
		{"rel": "self", "href": href("/"), "type": jsonType, "title": "Landing page"},
		{"rel": "root", "href": href("/"), "type": jsonType, "title": "Landing page"},
		{"rel": "data", "href": href("/collections"), "type": jsonType, "title": "Collections"},
		{"rel": "conformance", "href": href("/conformance"), "type": jsonType, "title": "Conformance"},
		{"rel": "search", "href": href("/search"), "type": geoJSONType, "method": "GET", "title": "STAC search (GET)"},
		{"rel": "search", "href": href("/search"), "type": geoJSONType, "method": "POST", "title": "STAC search (POST)"},
	}
}

// advertisedConformance returns the conformance classes the proxy is
// willing to advertise: the intersection of ProxyConformanceFor(caps)
// with each routed origin's /conformance response. Origins that fail
// to respond within the per-origin timeout are excluded from the
// intersection (their classes simply aren't considered as supported).
// If no origins are configured we fall back to the proxy's own caps.
func (h *Handler) advertisedConformance(ctx context.Context) []string {
	proxy := stac.ProxyConformanceFor(h.conformanceCaps)
	if len(h.origins) == 0 {
		return stac.Intersect(proxy)
	}

	perOrigin := 5 * time.Second
	if h.aggregateTimeout > 0 && h.aggregateTimeout < perOrigin {
		perOrigin = h.aggregateTimeout
	}

	clients := make([]*OriginClient, 0, len(h.origins))
	for _, client := range h.origins {
		clients = append(clients, client)
	}
	results := fanOut(clients, 0,
		func(client *OriginClient) []string {
			fetchCtx, cancel := context.WithTimeout(ctx, perOrigin)
			defer cancel()
			classes, err := stac.FetchConformance(fetchCtx, client.httpClient, client.BaseURL())
			if err != nil {
				slog.Warn("conformance probe failed",
					"origin", client.Origin().ID,
					"error", err,
				)
				return nil
			}
			if classes == nil {
				// Success with an empty conformsTo still participates
				// in the intersection; nil is the failure sentinel.
				classes = []string{}
			}
			return classes
		},
		// A panic in conformance probing must not take the process
		// down — log and treat the origin as if it failed to advertise.
		func(client *OriginClient, r any) []string {
			slog.Error("conformance probe panicked",
				"origin", client.Origin().ID,
				"panic", r,
			)
			return nil
		})

	var originSets [][]string
	for _, classes := range results {
		if classes != nil {
			originSets = append(originSets, classes)
		}
	}
	// If no origin responded, advertise just the proxy's caps to keep
	// the surface honest about what we can serve from cache or
	// fallback handlers.
	if len(originSets) == 0 {
		return stac.Intersect(proxy)
	}
	return stac.Intersect(proxy, originSets...)
}
