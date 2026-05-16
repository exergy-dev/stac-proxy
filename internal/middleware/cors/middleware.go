// Package cors provides Cross-Origin Resource Sharing middleware.
//
// CORS is a chi-style http middleware that:
//   - short-circuits preflight (OPTIONS + Access-Control-Request-Method)
//     requests with a 204 response carrying the negotiated CORS headers;
//   - on actual requests, sets Access-Control-Allow-Origin (and related
//     headers) when the request Origin is permitted, then delegates to
//     the inner handler.
//
// Origin matching is byte-exact on the full origin string
// (scheme://host[:port]). Host-only matching would let an http:// caller
// bypass a config that only meant to allow https://, so the spec form is
// required.
package cors

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Config carries the parsed CORS settings.
//
// AllowedOrigins entries are matched byte-exact against the request's
// Origin header. The literal "*" is a wildcard but is only honored when
// AllowCredentials is false — the CORS spec forbids the combination.
type Config struct {
	AllowedOrigins   []string
	AllowedMethods   []string
	AllowedHeaders   []string
	ExposedHeaders   []string
	AllowCredentials bool
	MaxAge           time.Duration
}

var (
	defaultAllowedMethods = []string{
		http.MethodGet, http.MethodHead, http.MethodPost, http.MethodOptions,
	}
	defaultAllowedHeaders = []string{
		"Authorization", "Content-Type", "Accept", "Range",
		"If-None-Match", "If-Modified-Since",
	}
	defaultMaxAge = 600 * time.Second
)

// NewHTTPMiddleware returns chi-compatible CORS middleware. The returned
// handler is safe for concurrent use; precomputation happens once during
// construction.
func NewHTTPMiddleware(cfg Config) func(http.Handler) http.Handler {
	methods := cfg.AllowedMethods
	if len(methods) == 0 {
		methods = defaultAllowedMethods
	}
	allowedHeaders := cfg.AllowedHeaders
	useRequestHeaderEcho := len(allowedHeaders) == 0
	if useRequestHeaderEcho {
		// Sentinel value for the echo path; the canonical default set
		// is still advertised when the client did not send any
		// Access-Control-Request-Headers.
		allowedHeaders = defaultAllowedHeaders
	}
	maxAge := cfg.MaxAge
	if maxAge <= 0 {
		maxAge = defaultMaxAge
	}

	originSet := make(map[string]struct{}, len(cfg.AllowedOrigins))
	allowAll := false
	for _, o := range cfg.AllowedOrigins {
		if o == "*" {
			allowAll = true
			continue
		}
		originSet[o] = struct{}{}
	}
	// Spec: wildcard is invalid with credentials. Defensive — config
	// validation should have caught this, but never advertise "*" in
	// that combination even if a bad Config is constructed directly.
	if cfg.AllowCredentials {
		allowAll = false
	}

	methodsHeader := strings.Join(upperEach(methods), ", ")
	allowedHeadersHeader := strings.Join(allowedHeaders, ", ")
	exposedHeadersHeader := strings.Join(cfg.ExposedHeaders, ", ")
	maxAgeHeader := strconv.Itoa(int(maxAge / time.Second))

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin == "" {
				// Not a CORS request — do not emit any CORS headers
				// (avoids polluting cache keys for non-browser clients).
				next.ServeHTTP(w, r)
				return
			}

			allowOrigin := ""
			if allowAll {
				allowOrigin = "*"
			} else if _, ok := originSet[origin]; ok {
				allowOrigin = origin
			}

			isPreflight := r.Method == http.MethodOptions &&
				r.Header.Get("Access-Control-Request-Method") != ""

			// Vary entries must accumulate even when an inner handler
			// later calls Header().Set("Vary", ...). The writer wrapper
			// re-applies the CORS Vary contributions just before the
			// first WriteHeader / Write call.
			varyContrib := []string{"Origin"}
			if isPreflight {
				varyContrib = append(varyContrib,
					"Access-Control-Request-Method",
					"Access-Control-Request-Headers",
				)
			}
			w = &varyWriter{ResponseWriter: w, entries: varyContrib}

			if allowOrigin != "" {
				w.Header().Set("Access-Control-Allow-Origin", allowOrigin)
				if cfg.AllowCredentials && allowOrigin != "*" {
					w.Header().Set("Access-Control-Allow-Credentials", "true")
				}
				if exposedHeadersHeader != "" && !isPreflight {
					w.Header().Set("Access-Control-Expose-Headers", exposedHeadersHeader)
				}
			}

			if isPreflight {
				// Preflight always short-circuits, even when the origin
				// is disallowed. The browser will block the eventual
				// request anyway; skipping the inner handler avoids
				// wasted upstream RTT on a guaranteed-to-fail request.
				if allowOrigin != "" {
					w.Header().Set("Access-Control-Allow-Methods", methodsHeader)
					reqHeaders := r.Header.Get("Access-Control-Request-Headers")
					if useRequestHeaderEcho && reqHeaders != "" {
						w.Header().Set("Access-Control-Allow-Headers", reqHeaders)
					} else {
						w.Header().Set("Access-Control-Allow-Headers", allowedHeadersHeader)
					}
					w.Header().Set("Access-Control-Max-Age", maxAgeHeader)
				}
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// NewFromConfig constructs a chi-style CORS middleware from a raw YAML
// config block (the shape carried by config.MiddlewareConfig.Config).
//
// Accepts both int and float64 for max_age because YAML numerics may
// decode either way depending on representation.
func NewFromConfig(cfg map[string]interface{}) (func(http.Handler) http.Handler, error) {
	origins, err := stringList(cfg, "allowed_origins")
	if err != nil {
		return nil, err
	}
	methods, err := stringList(cfg, "allowed_methods")
	if err != nil {
		return nil, err
	}
	headers, err := stringList(cfg, "allowed_headers")
	if err != nil {
		return nil, err
	}
	exposed, err := stringList(cfg, "exposed_headers")
	if err != nil {
		return nil, err
	}

	allowCreds := false
	if v, ok := cfg["allow_credentials"].(bool); ok {
		allowCreds = v
	}

	var maxAge time.Duration
	switch v := cfg["max_age"].(type) {
	case int:
		maxAge = time.Duration(v) * time.Second
	case int64:
		maxAge = time.Duration(v) * time.Second
	case float64:
		maxAge = time.Duration(v) * time.Second
	case nil:
		// leave zero → default in NewHTTPMiddleware
	default:
		return nil, fmt.Errorf("cors: max_age must be a number of seconds, got %T", v)
	}

	if allowCreds {
		for _, o := range origins {
			if o == "*" {
				return nil, fmt.Errorf("cors: allow_credentials cannot be true with wildcard allowed_origins '*'")
			}
		}
	}

	return NewHTTPMiddleware(Config{
		AllowedOrigins:   origins,
		AllowedMethods:   methods,
		AllowedHeaders:   headers,
		ExposedHeaders:   exposed,
		AllowCredentials: allowCreds,
		MaxAge:           maxAge,
	}), nil
}

// stringList extracts a []string from a YAML-decoded map[interface{}]
// slice. Missing keys return nil with no error; non-list types error.
func stringList(cfg map[string]interface{}, key string) ([]string, error) {
	raw, ok := cfg[key]
	if !ok || raw == nil {
		return nil, nil
	}
	switch v := raw.(type) {
	case []string:
		return v, nil
	case []interface{}:
		out := make([]string, 0, len(v))
		for i, item := range v {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("cors: %s[%d] must be a string, got %T", key, i, item)
			}
			out = append(out, s)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("cors: %s must be a list of strings, got %T", key, raw)
	}
}

func upperEach(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = strings.ToUpper(s)
	}
	return out
}

// varyWriter wraps an http.ResponseWriter to guarantee a set of Vary
// entries survive even when an inner handler calls Header().Set("Vary", …).
// Entries are appended (deduped) immediately before the first
// WriteHeader / Write so they win regardless of inner-handler ordering.
type varyWriter struct {
	http.ResponseWriter
	entries []string
	flushed bool
}

func (vw *varyWriter) ensureVary() {
	if vw.flushed {
		return
	}
	vw.flushed = true
	existing := vw.ResponseWriter.Header().Values("Vary")
	have := make(map[string]struct{}, len(existing))
	for _, v := range existing {
		for _, part := range strings.Split(v, ",") {
			have[strings.TrimSpace(part)] = struct{}{}
		}
	}
	for _, e := range vw.entries {
		if _, ok := have[e]; ok {
			continue
		}
		vw.ResponseWriter.Header().Add("Vary", e)
		have[e] = struct{}{}
	}
}

func (vw *varyWriter) WriteHeader(status int) {
	vw.ensureVary()
	vw.ResponseWriter.WriteHeader(status)
}

func (vw *varyWriter) Write(b []byte) (int, error) {
	vw.ensureVary()
	return vw.ResponseWriter.Write(b)
}
