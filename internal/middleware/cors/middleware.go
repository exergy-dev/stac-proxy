// Package cors adapts github.com/go-chi/cors to the proxy's
// YAML-configured middleware shape.
//
// The chi library handles preflight short-circuiting, Vary accumulation,
// origin matching, and the credentials/wildcard interaction; this
// package's only job is to coerce the YAML config block into
// cors.Options and reject the credentials+wildcard combination at
// load time so misconfigs surface at startup rather than at request
// time.
package cors

import (
	"fmt"
	"net/http"

	chicors "github.com/go-chi/cors"
)

var (
	defaultAllowedMethods = []string{
		http.MethodGet, http.MethodHead, http.MethodPost, http.MethodOptions,
	}
	defaultAllowedHeaders = []string{
		"Authorization", "Content-Type", "Accept", "Range",
		"If-None-Match", "If-Modified-Since",
	}
	defaultMaxAgeSeconds = 600
)

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

	maxAge := defaultMaxAgeSeconds
	switch v := cfg["max_age"].(type) {
	case int:
		maxAge = v
	case int64:
		maxAge = int(v)
	case float64:
		maxAge = int(v)
	case nil:
		// keep default
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

	if len(methods) == 0 {
		methods = defaultAllowedMethods
	}
	if len(headers) == 0 {
		headers = defaultAllowedHeaders
	}

	return chicors.Handler(chicors.Options{
		AllowedOrigins:   origins,
		AllowedMethods:   methods,
		AllowedHeaders:   headers,
		ExposedHeaders:   exposed,
		AllowCredentials: allowCreds,
		MaxAge:           maxAge,
	}), nil
}

// stringList extracts a []string from a YAML-decoded map slice value.
// Missing keys return nil with no error; non-list types error.
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
