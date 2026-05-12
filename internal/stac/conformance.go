package stac

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// FilterExtensionConformance lists the conformance URIs that indicate
// STAC Filter Extension support. The Item Search + Filter URI is the
// canonical one used by /search; Features Filter applies to
// /collections/{id}/items. We accept any of them as a positive signal,
// since most implementations advertise multiple.
var FilterExtensionConformance = []string{
	"https://api.stacspec.org/v1.0.0/item-search#filter",
	"https://api.stacspec.org/v1.0.0-rc.1/item-search#filter",
	"https://api.stacspec.org/v1.0.0-rc.2/item-search#filter",
	"http://www.opengis.net/spec/cql2/1.0/conf/cql2-text",
	"http://www.opengis.net/spec/cql2/1.0/conf/cql2-json",
	"http://www.opengis.net/spec/ogcapi-features-3/1.0/conf/filter",
	"https://api.stacspec.org/v1.0.0/collection-search#filter",
}

// conformanceResponse is the shape of GET /conformance.
type conformanceResponse struct {
	ConformsTo []string `json:"conformsTo"`
}

// ProbeFilterExtension issues GET {baseURL}/conformance and reports
// whether the upstream advertises any of the URIs in
// FilterExtensionConformance. Network or parse errors are returned
// verbatim; callers should typically log and default to "not
// supported" rather than failing.
//
// httpClient may be nil, in which case http.DefaultClient is used.
func ProbeFilterExtension(ctx context.Context, httpClient *http.Client, baseURL string) (bool, error) {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	u := strings.TrimRight(baseURL, "/") + "/conformance"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return false, fmt.Errorf("build conformance request: %w", err)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("fetch %s: %w", u, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("conformance: status %d", resp.StatusCode)
	}
	var body conformanceResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return false, fmt.Errorf("decode conformance: %w", err)
	}
	want := make(map[string]struct{}, len(FilterExtensionConformance))
	for _, w := range FilterExtensionConformance {
		want[w] = struct{}{}
	}
	for _, c := range body.ConformsTo {
		if _, ok := want[c]; ok {
			return true, nil
		}
	}
	return false, nil
}
