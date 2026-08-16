package server

import (
	"net/http"

	"github.com/exergy-dev/stac-proxy/internal/middleware"
	"github.com/exergy-dev/stac-proxy/internal/stac"
)

// searchParserMiddleware populates STACInfo.SearchReq from the request
// body or query string before authz runs, so authz constraint
// enforcement (AllowedCollections, DeniedCollections, RequiredFilters)
// can mutate the parsed SearchRequest. Without this, info.SearchReq
// would still be nil when authz fires and applyConstraints would be a
// no-op (the federation handler parses lazily, after authz returns).
//
// stac.Parser.ParseSearchRequestFromHTTP handles both POST body and
// GET query, and restores r.Body for downstream readers (the reverse
// proxy and the federation request re-serializer).
func searchParserMiddleware() func(http.Handler) http.Handler {
	parser := stac.NewParser()
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			info := middleware.STACInfoFromContext(r.Context())
			if info == nil || info.SearchReq != nil {
				next.ServeHTTP(w, r)
				return
			}

			switch info.RequestType {
			case middleware.RequestTypeSearch:
				sr, err := parser.ParseSearchRequestFromHTTP(r)
				if err != nil {
					http.Error(w, "parse search request: "+err.Error(), http.StatusBadRequest)
					return
				}
				info.SearchReq = sr
			case middleware.RequestTypeItems:
				sr, err := parser.ParseSearchRequestFromHTTP(r)
				if err != nil {
					http.Error(w, "parse items request: "+err.Error(), http.StatusBadRequest)
					return
				}
				if info.Collection != "" {
					sr.Collections = []string{info.Collection}
				}
				info.SearchReq = sr
			}

			next.ServeHTTP(w, r)
		})
	}
}
