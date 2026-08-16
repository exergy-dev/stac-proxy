package federation

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"github.com/yourorg/stac-proxy/internal/httpx"
	"github.com/yourorg/stac-proxy/internal/middleware"
	"github.com/yourorg/stac-proxy/internal/stac"
)

// reverseProxyOnce forwards req to a single origin via
// httputil.ReverseProxy. Auth + retry are applied transparently via
// the origin's RoundTripper chain; the captured response is returned
// as a response.
//
// When proxyBaseURL is configured and the upstream returns 2xx with a
// JSON body, links are rewritten to point at the proxy.
func (h *Handler) reverseProxyOnce(ctx context.Context, origin *Origin,
	req *request) (*response, error) {

	client := h.origins[origin.ID]
	if client == nil {
		return nil, &middleware.InternalError{Message: "unknown origin: " + origin.ID}
	}

	outReq, err := h.buildOutboundRequest(ctx, client, req)
	if err != nil {
		return nil, err
	}

	// Bound the captured upstream body so a hostile or runaway origin
	// cannot OOM the proxy via the reverse-proxy fast path. The cap
	// matches the per-origin MaxResponseBytes used by OriginClient's
	// JSON paths, falling back to defaultMaxResponseBytes (32 MiB) when
	// the origin did not configure one.
	maxBytes := client.MaxResponseBytes()
	if maxBytes <= 0 {
		maxBytes = defaultMaxResponseBytes
	}
	cap := &boundedCapture{ResponseCapture: httpx.NewResponseCaptureWithLimit(maxBytes)}
	var upstreamErr error
	rp := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(client.BaseURLParsed())
			r.SetXForwarded()
			r.Out.Header.Set("Accept", "application/geo+json, application/json")
		},
		Transport: client.Transport(),
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			upstreamErr = err
		},
	}

	rp.ServeHTTP(cap, outReq)

	if upstreamErr != nil {
		return nil, &middleware.InternalError{Message: "upstream request failed: " + upstreamErr.Error(), Cause: upstreamErr}
	}

	// If the upstream body exceeded the cap, surface 502 Bad Gateway
	// rather than forwarding the truncated bytes (which are not a
	// valid response). Logged so operators can identify the offending
	// origin.
	if cap.overflowed() {
		slog.Error("federation: upstream response exceeded capture limit",
			slog.String("origin", origin.ID),
			slog.Int64("max_bytes", maxBytes),
		)
		return errorResponse(http.StatusBadGateway, "BadGateway",
			fmt.Sprintf("upstream response exceeded %d bytes", maxBytes)), nil
	}

	headers := cap.Header()
	httpx.StripHopByHopHeaders(headers)

	resp := &response{
		StatusCode: cap.Status(),
		Headers:    headers,
		Body:       cap.BodyBytes(),
	}

	if h.proxyBaseURL != "" && cap.Status() == http.StatusOK {
		resp = h.transformResponse(ctx, client, resp)
	}
	return resp, nil
}

// boundedCapture wraps an httpx.ResponseCapture and remembers whether
// any Write was rejected with ErrResponseTooLarge. ReverseProxy
// silently swallows writer errors (they only surface in its error
// log), so this side channel is needed to detect overflow at the call
// site.
type boundedCapture struct {
	*httpx.ResponseCapture
	over bool
}

// Write proxies to the underlying capture and records overflow. Any
// other error is returned as-is.
func (b *boundedCapture) Write(p []byte) (int, error) {
	n, err := b.ResponseCapture.Write(p)
	if errors.Is(err, httpx.ErrResponseTooLarge) {
		b.over = true
	}
	return n, err
}

// overflowed reports whether the upstream body exceeded the configured
// cap during this capture's lifetime.
func (b *boundedCapture) overflowed() bool { return b.over }

// buildOutboundRequest constructs the *http.Request that ReverseProxy
// will dispatch. It:
//   - Re-serializes req.SearchReq as POST body for search-like routes,
//     so middleware mutations (CQL2 injection, etc.) reach upstream.
//   - Forwards the inbound request ID via the standard helper.
//
// The returned request's URL is left as the inbound path/query;
// ReverseProxy.Rewrite.SetURL composes the upstream URL at dispatch.
func (h *Handler) buildOutboundRequest(ctx context.Context, client *OriginClient,
	req *request) (*http.Request, error) {

	method := req.Request.Method
	var body io.Reader
	if req.Request.Body != nil {
		body = req.Request.Body
	}

	// Path+query — ReverseProxy.SetURL will rebase onto the origin.
	pathQuery := req.Request.URL.RequestURI()

	if req.SearchReq != nil && isSearchLike(req.RequestType) {
		marshaled, err := json.Marshal(req.SearchReq)
		if err != nil {
			return nil, fmt.Errorf("re-serialize SearchReq: %w", err)
		}
		body = bytes.NewReader(marshaled)
		method = http.MethodPost
		// Search-like requests always POST to /search. The collection
		// scope for /collections/{id}/items rides in SearchReq.Collections
		// (set by handleItems); STAC servers do not accept POST on the
		// items list endpoint, so forwarding the inbound path verbatim
		// turns a valid items request into a 404.
		pathQuery = "/search"
	}

	outReq, err := http.NewRequestWithContext(ctx, method, pathQuery, body)
	if err != nil {
		return nil, fmt.Errorf("build outbound request: %w", err)
	}

	if body != nil {
		if err := httpx.BufferAndSetGetBody(outReq); err != nil {
			return nil, fmt.Errorf("buffer outbound body: %w", err)
		}
		outReq.Header.Set("Content-Type", "application/json")
	}

	// Inherit safe headers from the inbound request so things like
	// Accept-Encoding, conditional GET headers (If-None-Match), and
	// downstream-meaningful trace headers propagate.
	if req.Request != nil {
		stripAuth := !client.Origin().ForwardUserIdentity
		originAuthHeader := http.CanonicalHeaderKey(client.Origin().Auth.APIKeyHeader)
		for k, vs := range req.Request.Header {
			// Skip hop-by-hop; ReverseProxy strips them again at
			// dispatch, but starting clean keeps the trace simple.
			if isHopByHop(k) {
				continue
			}
			// Strip inbound client credentials before fan-out. The
			// proxy holds its own per-origin credentials and applies
			// them via authRoundTripper; the end user's credentials
			// (intended for the proxy) MUST NOT leak to upstreams.
			// Operators who specifically want OIDC-token-pass-through
			// must set Origin.ForwardUserIdentity=true.
			if stripAuth && isInboundAuthHeader(k) {
				continue
			}
			// Always strip a header that collides with this origin's
			// own configured API key header — letting the inbound
			// version through would override what authRoundTripper
			// injects (or, if not configured, leak something
			// unrelated upstream).
			if originAuthHeader != "" && http.CanonicalHeaderKey(k) == originAuthHeader {
				continue
			}
			for _, v := range vs {
				outReq.Header.Add(k, v)
			}
		}
		// Carry the inbound identity onto the outbound request so
		// ReverseProxy.Rewrite.SetXForwarded has values to read.
		// SetXForwarded uses RemoteAddr/Host/TLS off the inbound *req*
		// that was passed to ServeHTTP; in our flow that's outReq.
		outReq.Host = req.Request.Host
		outReq.RemoteAddr = req.Request.RemoteAddr
		outReq.TLS = req.Request.TLS
	}

	middleware.ForwardRequestID(ctx, outReq)
	return outReq, nil
}

// isInboundAuthHeader reports whether name is an end-user credential
// header that the proxy strips before fan-out (unless the origin opts
// in via ForwardUserIdentity). These are credentials the client sent
// to the proxy; passing them to upstreams turns the proxy into a
// confused deputy and can leak tokens to untrusted origins.
func isInboundAuthHeader(name string) bool {
	switch http.CanonicalHeaderKey(name) {
	case "Authorization", "Cookie", "Set-Cookie",
		"Proxy-Authorization", "X-Api-Key":
		return true
	}
	return false
}

// transformResponse rewrites links pointing to the upstream origin so
// downstream clients follow links back through this proxy. ctx is the
// inbound request context — it is forwarded to the asset signer so that
// signing observes client cancellation, deadlines, and any
// request-scoped values (request-id, principal, etc.).
//
// Performance (M-federation-1): the decode/re-encode round-trip
// is skipped entirely when the response body has no top-level "links"
// AND no "assets" tokens — for those bodies there's nothing to
// rewrite, and large feature collections see a dramatic speedup by
// avoiding per-item map allocation.
func (h *Handler) transformResponse(ctx context.Context, client *OriginClient, resp *response) *response {
	if h.proxyBaseURL == "" {
		return resp
	}

	contentType := resp.Headers.Get("Content-Type")
	if !strings.Contains(contentType, "json") {
		return resp
	}

	// Cheap byte-scan: if the body contains no "links" or "assets"
	// JSON keys, there is nothing for rewriteLinks to do — pass the
	// bytes through unchanged. This avoids a full unmarshal/marshal
	// round-trip on bodies that don't reference the upstream origin.
	if !bodyMayContainRewritableKeys(resp.Body) {
		return resp
	}

	var data map[string]interface{}
	if err := json.Unmarshal(resp.Body, &data); err != nil {
		return resp // not JSON — leave as-is
	}

	h.rewriteLinks(ctx, client, data)

	newBody, err := json.Marshal(data)
	if err != nil {
		return resp
	}
	resp.Body = newBody
	return resp
}

// bodyMayContainRewritableKeys reports whether the JSON body contains a
// top-level key the rewriter cares about. False positives are
// acceptable (the unmarshal then no-ops); false negatives would skip
// rewriting and are not. The two byte-strings we look for are the
// quoted JSON keys for "links" and "assets".
func bodyMayContainRewritableKeys(body []byte) bool {
	return bytes.Contains(body, []byte(`"links"`)) ||
		bytes.Contains(body, []byte(`"assets"`))
}

// rewriteLinks recursively rewrites href values in the data structure.
//
// Two link rewrite passes happen here:
//
//   - `links[*].href` is always rebased onto the proxy when it points
//     into the upstream origin's base URL — this is the standard STAC
//     navigation rewrite so downstream clients keep following the
//     proxy.
//
//   - `assets[*].href` is rewritten according to the origin's
//     RewriteAssets mode (never/sign/proxy). Asset hrefs typically
//     point at object storage that the proxy does not front, so the
//     default ("never") is intentional. Operators who need authz
//     gating or audit on asset access opt into "sign" or "proxy".
//
// Recursion (M-federation-2): we descend ONLY into keys whose STAC
// shape is documented to nest more link-bearing objects. STAC items
// carry arbitrary user data under "properties" (megabytes of payload
// on dense feature collections), and that subtree by spec contains
// no proxy-rewritable links — recursing into it was pure cost. The
// allowlist below is the closed set of nesting keys; anything else
// (properties, geometry, bbox, individual asset payloads) is skipped.
// A max-depth guard provides defense-in-depth against pathological
// JSON.
func (h *Handler) rewriteLinks(ctx context.Context, client *OriginClient, data interface{}) {
	h.rewriteLinksDepth(ctx, client, data, 0)
}

// rewriteLinksMaxDepth caps recursion to defend against deeply-nested
// attacker JSON. STAC documents in the wild nest at most ~3 levels
// (catalog → collections[] → items[] → links[]); 16 is comfortably
// over that.
const rewriteLinksMaxDepth = 16

// rewriteLinksRecurseKeys is the closed set of map keys whose values
// the rewriter recurses into. Anything outside this set is left
// untouched — most importantly, STAC items' "properties" subtree
// (arbitrary user data) and "geometry"/"bbox" (large payloads with
// no STAC-meaningful link structure inside).
var rewriteLinksRecurseKeys = map[string]struct{}{
	"features":    {}, // FeatureCollection.features[] → each feature has its own links/assets
	"collections": {}, // /collections envelope
	"included":    {}, // STAC API includes (rarely seen, but spec-described)
	"items":       {}, // some catalogs nest items[] under collections in extras
	"children":    {}, // nested catalog hierarchies
}

func (h *Handler) rewriteLinksDepth(ctx context.Context, client *OriginClient, data interface{}, depth int) {
	if depth > rewriteLinksMaxDepth {
		return
	}
	switch v := data.(type) {
	case map[string]interface{}:
		if links, ok := v["links"].([]interface{}); ok {
			for _, link := range links {
				if linkMap, ok := link.(map[string]interface{}); ok {
					if href, ok := linkMap["href"].(string); ok {
						linkMap["href"] = h.rewriteURL(client, href)
					}
				}
			}
		}
		if assets, ok := v["assets"].(map[string]interface{}); ok {
			for _, a := range assets {
				if am, ok := a.(map[string]interface{}); ok {
					if href, ok := am["href"].(string); ok {
						am["href"] = h.rewriteAssetHref(ctx, client, href)
					}
				}
			}
		}
		// Only recurse into keys known to nest more link-bearing
		// STAC objects. Skipping the rest avoids walking megabytes
		// of opaque user data under "properties".
		for k, val := range v {
			if _, ok := rewriteLinksRecurseKeys[k]; !ok {
				continue
			}
			h.rewriteLinksDepth(ctx, client, val, depth+1)
		}
	case []interface{}:
		for _, val := range v {
			h.rewriteLinksDepth(ctx, client, val, depth+1)
		}
	}
}

// rewriteAssetHref dispatches on the origin's RewriteAssets mode.
// `never` (the default) preserves backwards compatibility. ctx is the
// inbound request context — passed to the asset signer so that signing
// is cancellable with the client request and observes any
// request-scoped values.
func (h *Handler) rewriteAssetHref(ctx context.Context, client *OriginClient, href string) string {
	origin := client.Origin()
	switch origin.RewriteAssets {
	case "sign":
		if h.assetSigner == nil {
			// Signer is not wired — fall back to passthrough rather
			// than silently leaking unsigned URLs while pretending we
			// gated them.
			return href
		}
		ttl := origin.AssetSignTTL
		if ttl <= 0 {
			ttl = 15 * time.Minute
		}
		return h.assetSigner.Sign(ctx, href, ttl)
	case "proxy":
		if h.proxyBaseURL == "" {
			return href
		}
		ref := base64.RawURLEncoding.EncodeToString([]byte(href))
		return strings.TrimRight(h.proxyBaseURL, "/") + "/assets/" + origin.ID + "/" + ref
	default:
		// "" or "never": pass through unchanged.
		return href
	}
}

// rewriteURL replaces the upstream base URL prefix with the proxy
// base URL.
func (h *Handler) rewriteURL(client *OriginClient, href string) string {
	upstreamBase := client.BaseURL()
	if strings.HasPrefix(href, upstreamBase) {
		return h.proxyBaseURL + strings.TrimPrefix(href, upstreamBase)
	}
	return href
}

// isHopByHop reports whether a header name is one of the RFC 7230
// hop-by-hop headers (a small set; ReverseProxy strips Connection-listed
// names itself at dispatch).
func isHopByHop(name string) bool {
	switch http.CanonicalHeaderKey(name) {
	case "Connection", "Proxy-Connection", "Keep-Alive",
		"Proxy-Authenticate", "Proxy-Authorization", "Te",
		"Trailer", "Transfer-Encoding", "Upgrade":
		return true
	}
	return false
}

// injectOriginMetadata appends a stac_proxy:origin link to a JSON
// STAC document's `links` array. Best-effort: a no-op on parse
// errors. Idempotent: if a link with the same rel + title is already
// present, it is left untouched.
//
// The link shape matches stac.OriginLink — kept in lockstep with the
// merger's links so federated-merge and single-origin-passthrough
// responses are indistinguishable to clients.
func injectOriginMetadata(resp *response, originID, originURL string) {
	var obj map[string]interface{}
	if err := json.Unmarshal(resp.Body, &obj); err != nil {
		return
	}

	links, _ := obj["links"].([]interface{})
	for _, l := range links {
		if lm, ok := l.(map[string]interface{}); ok {
			rel, _ := lm["rel"].(string)
			title, _ := lm["title"].(string)
			if rel == stac.OriginLinkRel && title == originID {
				return
			}
		}
	}

	links = append(links, map[string]interface{}{
		"href":  originURL,
		"rel":   stac.OriginLinkRel,
		"type":  "application/json",
		"title": originID,
	})
	obj["links"] = links

	if b, err := json.Marshal(obj); err == nil {
		resp.Body = b
	}
}

// adaptRequestStripCollectionPrefix returns a shallow copy of req with
// the URL path and Collection field rewritten to strip the origin's
// configured collection prefix.
func adaptRequestStripCollectionPrefix(req *request, prefix string) *request {
	if req.Request == nil || prefix == "" {
		return req
	}
	stripped := strings.Replace(req.Request.URL.Path, "/collections/"+req.Collection, "/collections/"+strings.TrimPrefix(req.Collection, prefix), 1)
	clonedV := *req
	cloned := &clonedV
	// Clone the URL so we don't mutate the inbound one.
	newURL := *cloned.Request.URL
	newURL.Path = stripped
	newReq := cloned.Request.Clone(cloned.Context)
	newReq.URL = &newURL
	cloned.Request = newReq
	cloned.Collection = strings.TrimPrefix(req.Collection, prefix)
	return cloned
}
