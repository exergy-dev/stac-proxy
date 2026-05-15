// Package remap provides URL remapping middleware.
//
// Remap is a chi-style http middleware that buffers the inner handler's
// response body, walks any JSON payload for "href" keys, applies the
// configured regex rules, optionally signs the result, then writes the
// (possibly mutated) bytes to the outer ResponseWriter. Non-JSON
// responses pass through unchanged.
package remap

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/yourorg/stac-proxy/internal/httpx"
)

// Rule defines a URL remapping rule.
type Rule struct {
	Match   *regexp.Regexp
	Replace string
	Sign    bool
	SignTTL time.Duration
	Signer  Signer
}

// RuleConfig is the configuration for a single rule.
type RuleConfig struct {
	Match   string        // Regex pattern
	Replace string        // Replacement string
	Sign    bool          // Whether to sign the URL
	SignTTL time.Duration // TTL for signed URLs
}

// Config contains configuration for the remap middleware.
type Config struct {
	Rules  []RuleConfig
	Signer Signer // URL signer for signed URLs
}

// compileRules compiles RuleConfigs to runtime Rules. Returned errors
// indicate an invalid regex pattern; the caller should fail loudly
// rather than ship a middleware with partial rules.
func compileRules(cfg Config) ([]Rule, error) {
	rules := make([]Rule, 0, len(cfg.Rules))
	for _, rc := range cfg.Rules {
		re, err := regexp.Compile(rc.Match)
		if err != nil {
			return nil, err
		}
		rules = append(rules, Rule{
			Match:   re,
			Replace: rc.Replace,
			Sign:    rc.Sign,
			SignTTL: rc.SignTTL,
			Signer:  cfg.Signer,
		})
	}
	return rules, nil
}

// NewHTTPMiddleware returns chi-compatible URL-remap middleware.
//
// On every request it captures the inner handler's response, attempts
// to JSON-decode the body, recursively rewrites any "href" string
// values that match a configured rule, and re-encodes. On non-JSON
// bodies or decode failures the original bytes pass through. Status
// and headers from the inner handler are preserved.
func NewHTTPMiddleware(cfg Config) (func(http.Handler) http.Handler, error) {
	rules, err := compileRules(cfg)
	if err != nil {
		return nil, err
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(rules) == 0 {
				next.ServeHTTP(w, r)
				return
			}
			cap := httpx.NewResponseCapture()
			next.ServeHTTP(cap, r)
			body := cap.BodyBytes()
			// M-remap-1: only attempt to decode JSON when the
			// upstream Content-Type advertises JSON. Asset bytes
			// (image/png, application/octet-stream) that slipped
			// through the cache/route layer would otherwise be
			// buffered AND parsed, wasting memory and adding
			// latency for no benefit (no href to rewrite).
			if isJSONContentType(cap.HeadersOut().Get("Content-Type")) {
				if mutated, ok := tryRemap(r.Context(), rules, body); ok {
					body = mutated
				}
			}
			for k, vs := range cap.HeadersOut() {
				for _, v := range vs {
					w.Header().Add(k, v)
				}
			}
			w.WriteHeader(cap.Status())
			_, _ = w.Write(body)
		})
	}, nil
}

// NewFromConfig constructs a chi-style remap middleware from a raw
// YAML config block (the shape carried by config.MiddlewareConfig.Config).
// Only the `rules` array (with match/replace string pairs) is read
// today; signed-URL support is wired separately by callers that supply
// a remap.Signer through the typed Config struct.
func NewFromConfig(cfg map[string]interface{}) (func(http.Handler) http.Handler, error) {
	var rules []RuleConfig
	if rulesCfg, ok := cfg["rules"].([]interface{}); ok {
		for _, rCfg := range rulesCfg {
			rMap, ok := rCfg.(map[string]interface{})
			if !ok {
				continue
			}
			rules = append(rules, RuleConfig{
				Match:   strFromMap(rMap, "match"),
				Replace: strFromMap(rMap, "replace"),
			})
		}
	}
	return NewHTTPMiddleware(Config{Rules: rules})
}

func strFromMap(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

// isJSONContentType reports whether ct names a JSON payload.
//
// Recognises the canonical "application/json" plus the +json suffix
// family (application/geo+json, application/vnd.* +json, …) that STAC
// uses heavily. Comparison is case-insensitive; charset and other
// parameters after a ; are tolerated.
func isJSONContentType(ct string) bool {
	if ct == "" {
		return false
	}
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	ct = strings.TrimSpace(strings.ToLower(ct))
	if ct == "application/json" {
		return true
	}
	if strings.HasPrefix(ct, "application/") && strings.HasSuffix(ct, "+json") {
		return true
	}
	return false
}

// tryRemap returns mutated bytes + true on success; returns nil + false
// when body isn't valid JSON or no href values changed.
func tryRemap(ctx context.Context, rules []Rule, body []byte) ([]byte, bool) {
	if len(body) == 0 {
		return nil, false
	}
	var data interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, false
	}
	transformURLs(ctx, rules, data, 0)
	out, err := json.Marshal(data)
	if err != nil {
		return nil, false
	}
	return out, true
}

// maxRemapDepth bounds transformURLs recursion. STAC payloads are
// typically <=4 deep (FeatureCollection → features[] → assets →
// alternate); 16 leaves headroom for deeply-nested vendor extensions
// while preventing pathological JSON (an attacker-supplied payload of
// arbitrary nesting) from blowing the stack.
const maxRemapDepth = 16

// transformURLs recursively rewrites href string values according to
// the rules. Mutates data in place. depth tracks the current recursion
// level; once it exceeds maxRemapDepth the walk stops silently and
// nested href values at deeper levels are left unrewritten.
func transformURLs(ctx context.Context, rules []Rule, data interface{}, depth int) {
	if depth > maxRemapDepth {
		return
	}
	switch v := data.(type) {
	case map[string]interface{}:
		if href, ok := v["href"].(string); ok {
			v["href"] = remapURL(ctx, rules, href)
		}
		for _, val := range v {
			transformURLs(ctx, rules, val, depth+1)
		}
	case []interface{}:
		for _, val := range v {
			transformURLs(ctx, rules, val, depth+1)
		}
	}
}

// remapURL applies the first matching rule to url. Returns url
// unchanged when no rule matches.
func remapURL(ctx context.Context, rules []Rule, url string) string {
	for _, rule := range rules {
		if rule.Match.MatchString(url) {
			newURL := rule.Match.ReplaceAllString(url, rule.Replace)
			if rule.Sign && rule.Signer != nil {
				newURL = rule.Signer.Sign(ctx, newURL, rule.SignTTL)
			}
			return newURL
		}
	}
	return url
}
