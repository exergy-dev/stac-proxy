package federation

import (
	"errors"
	"net/http"
	"sort"
	"strings"

	"github.com/yourorg/stac-proxy/internal/httpx"
)

// Partial-result signaling headers. Set on 200 responses whenever at
// least one routed origin failed for the page being served. Header
// (not body-only) so callers, caches, and edge proxies can react
// without parsing GeoJSON — and so the response cache can decline to
// store partial pages.
const (
	// HeaderFederationPartial is "true" when the response body was
	// merged from a subset of the routed origins.
	HeaderFederationPartial = "X-Federation-Partial"
	// HeaderFederationFailedOrigins lists the failed origin IDs,
	// comma-separated, sorted.
	HeaderFederationFailedOrigins = "X-Federation-Failed-Origins"
)

// classifyOriginError maps a fan-out error to the machine-readable
// status string carried in OriginStatus.Error: "circuit_open" for the
// breaker's fast-fail (the origin is cooling down and will be probed
// again), "fetch_failed" for a live failure.
func classifyOriginError(err error) string {
	if errors.Is(err, httpx.ErrCircuitOpen) {
		return "circuit_open"
	}
	return "fetch_failed"
}

// originFailures collects the sorted IDs of failed origins from a
// fan-out result set. status reports (originID, failed) per result.
func originFailures[T any](results []T, status func(T) (string, bool)) []string {
	var failed []string
	for _, r := range results {
		if id, f := status(r); f {
			failed = append(failed, id)
		}
	}
	sort.Strings(failed)
	return failed
}

// failedFromStatuses extracts the IDs of origins whose status carries
// an error, sorted.
func failedFromStatuses(statuses []OriginStatus) []string {
	return originFailures(statuses, func(s OriginStatus) (string, bool) {
		return s.ID, s.Error != ""
	})
}

// respondIfAllFailed returns the 502 UpstreamFederationFailure
// response when every one of total routed origins failed, and
// (nil, nil) when the caller should proceed with a normal (possibly
// partial) response. Shared by the fan-out search, collections, and
// paginated paths.
func (h *Handler) respondIfAllFailed(op string, failed []string, total int) (*response, error) {
	if total == 0 || len(failed) != total {
		return nil, nil
	}
	h.logger.Warn(op+" failed on every routed origin",
		"origins", strings.Join(failed, ","))
	return federationFailureResponse(failed), nil
}

// stampPartialHeaders writes the partial-result contract onto h:
// the X-Federation-* markers plus Cache-Control: no-store.
//
// no-store protects every cache — the proxy's own response cache
// (which honors it generically) AND any CDN or edge cache the
// operator put in front. A cached partial page would keep serving the
// shrunken result set for its full TTL after the origins recovered.
func stampPartialHeaders(h http.Header, failed []string) {
	h.Set(HeaderFederationPartial, "true")
	h.Set(HeaderFederationFailedOrigins, strings.Join(failed, ","))
	h.Set("Cache-Control", "no-store")
}

// markPartial stamps the partial-result headers onto resp and logs a
// throttled warning. No-op when failed is empty.
func (h *Handler) markPartial(resp *response, failed []string) {
	if len(failed) == 0 {
		return
	}
	if resp.Headers == nil {
		resp.Headers = http.Header{}
	}
	stampPartialHeaders(resp.Headers, failed)
	h.partialWarn.Warn(h.logger, "federation returned partial results",
		"failed_origins", strings.Join(failed, ","),
	)
}

// federationFailureResponse is the 502 returned when every routed
// origin failed and there is nothing to serve. Before this existed,
// an all-origins-down search returned an empty 200 FeatureCollection
// indistinguishable from a genuine zero-match query.
func federationFailureResponse(failed []string) *response {
	resp := errorResponse(http.StatusBadGateway, "UpstreamFederationFailure",
		"all routed origins failed: "+strings.Join(failed, ","))
	stampPartialHeaders(resp.Headers, failed)
	return resp
}
