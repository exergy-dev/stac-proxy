package federation

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/exergy-dev/stac-proxy/internal/middleware"
)

// Asset-streaming headers we forward in either direction.
var (
	assetRequestPassthroughHeaders = []string{
		"Range",
		"If-Match",
		"If-None-Match",
		"If-Modified-Since",
		"If-Unmodified-Since",
		"Accept",
		"Accept-Encoding",
		"User-Agent",
	}
	assetResponsePassthroughHeaders = []string{
		"Content-Type",
		"Content-Length",
		"Content-Range",
		"Content-Encoding",
		"Content-Disposition",
		"Accept-Ranges",
		"ETag",
		"Last-Modified",
		"Cache-Control",
		"Expires",
		"Vary",
	}
)

// ServeAssetHTTP handles GET /assets/{originId}/{ref}. The handler:
//
//   - validates `originId` is a configured, enabled origin
//   - base64-url-decodes `ref` into an absolute upstream URL
//   - verifies that the decoded URL starts with the origin's configured
//     base URL (so this endpoint cannot be coerced into proxying
//     arbitrary internet URLs — defense against using us as a relay)
//   - issues an authenticated, retry-wrapped request via the origin's
//     RoundTripper chain (so upstream auth is applied)
//   - streams the response body back via io.Copy, forwarding the
//     standard byte-range/conditional-GET headers in both directions
//
// Per-request authz/ratelimit gating happens in the chi middleware
// chain wrapping this handler; STACInfo carries RequestType=Asset and
// the originID so policies can key off them.
//
// The router is expected to be the caller; tests and direct callers
// must populate `STACInfo` on the request context.
func (h *Handler) ServeAssetHTTP(w http.ResponseWriter, r *http.Request, originID, ref string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	client, ok := h.origins[originID]
	if !ok {
		http.Error(w, "unknown origin", http.StatusNotFound)
		return
	}
	if client.Origin().RewriteAssets != "proxy" {
		// We only route through this endpoint when the origin opts in.
		// Treating other modes as 404 avoids leaking which origins
		// exist via differential responses.
		http.Error(w, "asset proxying not enabled for this origin", http.StatusNotFound)
		return
	}

	hrefBytes, err := base64.RawURLEncoding.DecodeString(ref)
	if err != nil {
		http.Error(w, "invalid asset reference", http.StatusBadRequest)
		return
	}
	upstreamHref := string(hrefBytes)

	// Defense: the decoded URL MUST live under the origin's configured
	// base URL host+path. Without this check the endpoint could be
	// used to fetch arbitrary internet URLs through the proxy's
	// network position.
	if !assetHrefUnderOrigin(upstreamHref, client.BaseURL()) {
		http.Error(w, "asset reference does not belong to origin", http.StatusBadRequest)
		return
	}

	upstreamURL, err := url.Parse(upstreamHref)
	if err != nil {
		http.Error(w, "invalid asset url", http.StatusBadRequest)
		return
	}

	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL.String(), nil)
	if err != nil {
		http.Error(w, "build upstream request failed", http.StatusInternalServerError)
		return
	}
	// Forward range / conditional-GET / negotiation headers verbatim.
	for _, name := range assetRequestPassthroughHeaders {
		if v := r.Header.Get(name); v != "" {
			outReq.Header.Set(name, v)
		}
	}
	middleware.ForwardRequestID(r.Context(), outReq)

	// Use the origin's RoundTripper chain (auth + retry are layered in).
	resp, err := client.transport.RoundTrip(outReq)
	if err != nil {
		// Distinguish a client disconnect from a real upstream error
		// for cleaner logs; both are surfaced as 502 to the caller
		// because the proxy cannot meaningfully serve the bytes.
		if errors.Is(err, context.Canceled) || errors.Is(r.Context().Err(), context.Canceled) {
			// Client went away mid-flight; nothing to write.
			return
		}
		slog.Error("asset upstream request failed",
			"origin", originID,
			"href", upstreamHref,
			"error", err,
		)
		http.Error(w, "upstream asset fetch failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Forward upstream response headers (after stripping hop-by-hop).
	for _, name := range assetResponsePassthroughHeaders {
		if v := resp.Header.Get(name); v != "" {
			w.Header().Set(name, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	// Stream the bytes. io.Copy honors r.Context() cancellation via
	// the http.Transport's read path, so a client disconnect aborts
	// the upstream read rather than buffering forever.
	if _, err := io.Copy(w, resp.Body); err != nil {
		// Best-effort log; the response is already partially written.
		slog.Warn("asset stream interrupted",
			"origin", originID,
			"error", err,
		)
	}
}

// assetHrefUnderOrigin reports whether href is a valid URL whose
// scheme+host+path-prefix matches the origin's base URL. We compare
// scheme+host case-insensitively and require the path of the asset
// to start with the origin's base path so origins cannot accidentally
// open the relay endpoint up to other hosts they happen to share a
// hostname suffix with.
func assetHrefUnderOrigin(href, originBase string) bool {
	hu, err := url.Parse(href)
	if err != nil {
		return false
	}
	ou, err := url.Parse(originBase)
	if err != nil {
		return false
	}
	if !strings.EqualFold(hu.Scheme, ou.Scheme) {
		return false
	}
	if !strings.EqualFold(hu.Host, ou.Host) {
		return false
	}
	basePath := strings.TrimSuffix(ou.Path, "/")
	if basePath == "" {
		return true
	}
	return hu.Path == basePath || strings.HasPrefix(hu.Path, basePath+"/")
}
