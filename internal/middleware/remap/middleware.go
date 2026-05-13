// Package remap provides URL remapping middleware.
package remap

import (
	"context"
	"encoding/json"
	"regexp"
	"time"

	"github.com/yourorg/stac-proxy/internal/middleware"
)

// Middleware remaps URLs in STAC responses.
type Middleware struct {
	middleware.BaseMiddleware
	rules []Rule
}

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

// NewMiddleware creates a new URL remap middleware.
func NewMiddleware(cfg Config) (*Middleware, error) {
	m := &Middleware{
		BaseMiddleware: middleware.NewBaseMiddleware("remap", middleware.PriorityTransform),
	}

	for _, rc := range cfg.Rules {
		re, err := regexp.Compile(rc.Match)
		if err != nil {
			return nil, err
		}

		m.rules = append(m.rules, Rule{
			Match:   re,
			Replace: rc.Replace,
			Sign:    rc.Sign,
			SignTTL: rc.SignTTL,
			Signer:  cfg.Signer,
		})
	}

	return m, nil
}

// NewFromConfig constructs a remap middleware from a raw YAML config
// block (the shape carried by config.MiddlewareConfig.Config). Only
// the `rules` array (with match/replace string pairs) is read today;
// signed-URL support is wired separately by callers that supply a
// remap.Signer through the typed Config struct.
func NewFromConfig(cfg map[string]interface{}) (middleware.Middleware, error) {
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
	return NewMiddleware(Config{Rules: rules})
}

func strFromMap(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

// ProcessResponse remaps URLs in the response.
func (m *Middleware) ProcessResponse(ctx context.Context, req *middleware.STACRequest,
	resp *middleware.STACResponse) (*middleware.STACResponse, error) {

	if len(m.rules) == 0 {
		return resp, nil
	}

	// Parse response body
	var data map[string]interface{}
	if err := json.Unmarshal(resp.Body, &data); err != nil {
		return resp, nil // Not JSON, pass through
	}

	// Recursively transform URLs
	m.transformURLs(ctx, data)

	// Re-encode
	body, err := json.Marshal(data)
	if err != nil {
		return resp, nil
	}

	resp.Body = body
	return resp, nil
}

// transformURLs recursively transforms URLs in the data structure.
func (m *Middleware) transformURLs(ctx context.Context, data interface{}) {
	switch v := data.(type) {
	case map[string]interface{}:
		// Check for "href" keys (STAC asset/link URLs)
		if href, ok := v["href"].(string); ok {
			v["href"] = m.remapURL(ctx, href)
		}
		// Recurse into nested objects
		for _, val := range v {
			m.transformURLs(ctx, val)
		}

	case []interface{}:
		for _, val := range v {
			m.transformURLs(ctx, val)
		}
	}
}

// remapURL applies remapping rules to a URL.
func (m *Middleware) remapURL(ctx context.Context, url string) string {
	for _, rule := range m.rules {
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

// AddRule adds a new remapping rule.
func (m *Middleware) AddRule(pattern, replace string, sign bool, signTTL time.Duration) error {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}

	m.rules = append(m.rules, Rule{
		Match:   re,
		Replace: replace,
		Sign:    sign,
		SignTTL: signTTL,
	})

	return nil
}

// RuleCount returns the number of configured rules.
func (m *Middleware) RuleCount() int {
	return len(m.rules)
}
