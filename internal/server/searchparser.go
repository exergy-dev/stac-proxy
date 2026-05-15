package server

import (
	"bytes"
	"io"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/yourorg/stac-proxy/internal/middleware"
	"github.com/yourorg/stac-proxy/internal/stac"
)

// searchParserMiddleware populates STACInfo.SearchReq from the inbound
// request body (POST /search) or query string (GET /search and items
// listing) before downstream middlewares (authz, ratelimit, cache) run.
//
// This is what makes authz constraint enforcement actually take effect:
// without it, info.SearchReq is nil when authz runs and applyConstraints
// becomes a no-op (the federation handler parses the body later, after
// authz has already returned). The federation handler still calls its
// own parser for any code path that bypasses this middleware (tests,
// alternate routings) — when SearchReq is already populated it skips
// re-parsing.
//
// For POST /search the body is read in full and restored as a fresh
// io.NopCloser around the buffered bytes so downstream readers (the
// reverse proxy, the federation request re-serializer) see the same
// content. The MaxBodyBytes cap from the bodyLimit middleware is
// still in effect because that middleware wraps r.Body before this
// one runs.
func searchParserMiddleware() func(http.Handler) http.Handler {
	parser := stac.NewParser()
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			info := middleware.STACInfoFromContext(r.Context())
			if info == nil || info.SearchReq != nil {
				// No STACInfo (e.g. /health) or already parsed by a test
				// fixture — nothing to do.
				next.ServeHTTP(w, r)
				return
			}

			switch info.RequestType {
			case middleware.RequestTypeSearch:
				if r.Method == http.MethodPost {
					body, err := io.ReadAll(r.Body)
					if err != nil {
						http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
						return
					}
					_ = r.Body.Close()
					r.Body = io.NopCloser(bytes.NewReader(body))
					if len(body) == 0 {
						info.SearchReq = &stac.SearchRequest{}
						break
					}
					sr, err := parser.ParseSearchRequest(body)
					if err != nil {
						http.Error(w, "parse search body: "+err.Error(), http.StatusBadRequest)
						return
					}
					info.SearchReq = sr
				} else {
					sr, err := parser.ParseSearchRequestFromHTTP(r)
					if err != nil {
						http.Error(w, "parse search query: "+err.Error(), http.StatusBadRequest)
						return
					}
					info.SearchReq = sr
				}
			case middleware.RequestTypeItems:
				sr, err := parser.ParseSearchRequestFromHTTP(r)
				if err != nil {
					http.Error(w, "parse items query: "+err.Error(), http.StatusBadRequest)
					return
				}
				if collection := chi.URLParam(r, "collectionId"); collection != "" {
					sr.Collections = []string{collection}
				}
				info.SearchReq = sr
			}

			next.ServeHTTP(w, r)
		})
	}
}

// isSearchLikePath reports whether p resembles a search/items route,
// for callers that need to make routing decisions without depending on
// the chi route pattern. Currently unused outside the middleware but
// kept exported-shaped for potential reuse from federation tests.
//
//nolint:unused // reserved for future cross-package use
func isSearchLikePath(p string) bool {
	return p == "/search" || strings.HasSuffix(p, "/items")
}
