package stac

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
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

// ProxyConformanceCore lists the conformance classes this proxy
// implements unconditionally — the OGC API Common / STAC API endpoints
// that exist as soon as the proxy is running.
var ProxyConformanceCore = []string{
	"https://api.stacspec.org/v1.0.0/core",
	"https://api.stacspec.org/v1.0.0/collections",
	"https://api.stacspec.org/v1.0.0/ogcapi-features",
	"https://api.stacspec.org/v1.0.0/item-search",
	"http://www.opengis.net/spec/ogcapi-common-1/1.0/conf/core",
	"http://www.opengis.net/spec/ogcapi-common-2/1.0/conf/collections",
	"http://www.opengis.net/spec/ogcapi-features-1/1.0/conf/core",
	"http://www.opengis.net/spec/ogcapi-features-1/1.0/conf/geojson",
}

// ConformanceCaps captures runtime-conditional capabilities that
// influence which conformance classes the proxy advertises.
type ConformanceCaps struct {
	// CQL2InjectionEnabled means the proxy's authz middleware can
	// inject CQL2 filters into outgoing search requests. When true,
	// and when every routed origin supports the filter extension, the
	// proxy advertises filter extension classes itself.
	CQL2InjectionEnabled bool

	// AllOriginsSupportFilter is true when every configured origin
	// claims filter extension support. Combined with CQL2InjectionEnabled,
	// it governs filter advertisement.
	AllOriginsSupportFilter bool
}

// ProxyConformanceFor returns the conformance classes the proxy is
// willing to advertise given its current runtime capabilities. The
// caller is responsible for intersecting this with what each origin
// actually advertises via Intersect.
func ProxyConformanceFor(caps ConformanceCaps) []string {
	out := append([]string(nil), ProxyConformanceCore...)
	if caps.CQL2InjectionEnabled && caps.AllOriginsSupportFilter {
		out = append(out, FilterExtensionConformance...)
	}
	return out
}

// Intersect returns the set of conformance URIs present in `proxy`
// AND in every set in `origins`. When origins is empty, returns
// `proxy` unchanged (no origin constraint to apply yet). The result
// is sorted for stable output across calls. Nil/empty origin sets
// indicate "this origin didn't respond"; we err on the side of
// trusting the proxy when no origins have spoken, but require at
// least one origin to confirm in order to keep a class once any
// origin set is provided.
func Intersect(proxy []string, origins ...[]string) []string {
	if len(origins) == 0 {
		out := append([]string(nil), proxy...)
		sort.Strings(out)
		return out
	}
	keep := make(map[string]struct{}, len(proxy))
	for _, c := range proxy {
		keep[c] = struct{}{}
	}
	for _, set := range origins {
		want := make(map[string]struct{}, len(set))
		for _, c := range set {
			want[c] = struct{}{}
		}
		for c := range keep {
			if _, ok := want[c]; !ok {
				delete(keep, c)
			}
		}
	}
	out := make([]string, 0, len(keep))
	for c := range keep {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// conformanceResponse is the shape of GET /conformance.
type conformanceResponse struct {
	ConformsTo []string `json:"conformsTo"`
}

// FetchConformance issues GET {baseURL}/conformance and returns the
// full conformsTo set. Network or parse errors are wrapped and
// returned; callers typically log and treat the origin as advertising
// no classes (i.e., it will be excluded from the proxy intersection).
func FetchConformance(ctx context.Context, httpClient *http.Client, baseURL string) ([]string, error) {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	u := strings.TrimRight(baseURL, "/") + "/conformance"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("build conformance request: %w", err)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", u, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("conformance: status %d", resp.StatusCode)
	}
	var body conformanceResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("decode conformance: %w", err)
	}
	return body.ConformsTo, nil
}

// ProbeFilterExtension issues GET {baseURL}/conformance and reports
// whether the upstream advertises any of the URIs in
// FilterExtensionConformance. Retained for callers that only need the
// yes/no signal; new code should prefer FetchConformance for the full
// set.
//
// httpClient may be nil, in which case http.DefaultClient is used.
func ProbeFilterExtension(ctx context.Context, httpClient *http.Client, baseURL string) (bool, error) {
	classes, err := FetchConformance(ctx, httpClient, baseURL)
	if err != nil {
		return false, err
	}
	want := make(map[string]struct{}, len(FilterExtensionConformance))
	for _, w := range FilterExtensionConformance {
		want[w] = struct{}{}
	}
	for _, c := range classes {
		if _, ok := want[c]; ok {
			return true, nil
		}
	}
	return false, nil
}
