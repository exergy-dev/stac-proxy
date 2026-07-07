package federation

import (
	"encoding/json"
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

// respondIfAllFailed returns the 502 UpstreamFederationFailure
// response (and done=true) when every one of total routed origins
// failed. Shared by the fan-out search and collections paths; the
// paginated path has its own variant keyed off cursor statuses.
func (h *Handler) respondIfAllFailed(op string, failed []string, total int) (*response, error, bool) {
	if total == 0 || len(failed) != total {
		return nil, nil, false
	}
	h.logger.Warn(op+" failed on every routed origin",
		"origins", strings.Join(failed, ","))
	resp, err := federationFailureResponse(failed)
	return resp, err, true
}

// failedFromStatuses extracts the IDs of origins whose status carries
// an error, sorted.
func failedFromStatuses(statuses []OriginStatus) []string {
	var failed []string
	for _, s := range statuses {
		if s.Error != "" {
			failed = append(failed, s.ID)
		}
	}
	sort.Strings(failed)
	return failed
}

// markPartial stamps the partial-result headers onto resp and logs a
// throttled warning. No-op when failed is empty.
//
// Cache-Control: no-store protects every cache — the proxy's own
// response cache (which honors no-store generically) AND any CDN or
// edge cache the operator put in front. A cached partial page would
// keep serving the shrunken result set for its full TTL after the
// origins recovered.
func (h *Handler) markPartial(resp *response, failed []string) {
	if len(failed) == 0 {
		return
	}
	if resp.Headers == nil {
		resp.Headers = http.Header{}
	}
	resp.Headers.Set(HeaderFederationPartial, "true")
	resp.Headers.Set(HeaderFederationFailedOrigins, strings.Join(failed, ","))
	resp.Headers.Set("Cache-Control", "no-store")
	h.partialWarn.Warn(h.logger, "federation returned partial results",
		"failed_origins", strings.Join(failed, ","),
	)
}

// federationFailureResponse is the 502 returned when every routed
// origin failed and there is nothing to serve. Before this existed,
// an all-origins-down search returned an empty 200 FeatureCollection
// indistinguishable from a genuine zero-match query.
func federationFailureResponse(failed []string) (*response, error) {
	body, err := json.Marshal(map[string]string{
		"code":        "UpstreamFederationFailure",
		"description": "all routed origins failed: " + strings.Join(failed, ","),
	})
	if err != nil {
		return nil, err
	}
	return &response{
		StatusCode: http.StatusBadGateway,
		Headers: http.Header{
			"Content-Type":                []string{"application/json"},
			"Cache-Control":               []string{"no-store"},
			HeaderFederationPartial:       []string{"true"},
			HeaderFederationFailedOrigins: []string{strings.Join(failed, ",")},
		},
		Body: body,
	}, nil
}
