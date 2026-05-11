// Package transform provides response transformation utilities.
package transform

import (
	"net/url"
	"regexp"
	"strings"
)

// AssetTransformer transforms asset URLs in STAC responses.
type AssetTransformer struct {
	rules     []AssetRule
	signer    URLSigner
	proxyBase string
}

// AssetRule defines a transformation rule for asset URLs.
type AssetRule struct {
	Match    *regexp.Regexp
	Replace  string
	Sign     bool
	SignTTL  int // seconds
	Redirect bool
}

// AssetTransformerConfig configures the asset transformer.
type AssetTransformerConfig struct {
	Rules     []AssetRuleConfig
	Signer    URLSigner
	ProxyBase string
}

// AssetRuleConfig is the configuration format for asset rules.
type AssetRuleConfig struct {
	Match    string `yaml:"match"`
	Replace  string `yaml:"replace"`
	Sign     bool   `yaml:"sign"`
	SignTTL  int    `yaml:"sign_ttl"`
	Redirect bool   `yaml:"redirect"`
}

// URLSigner signs URLs for temporary access.
type URLSigner interface {
	Sign(url string, ttlSeconds int) (string, error)
}

// NewAssetTransformer creates a new asset transformer.
func NewAssetTransformer(cfg AssetTransformerConfig) (*AssetTransformer, error) {
	t := &AssetTransformer{
		signer:    cfg.Signer,
		proxyBase: cfg.ProxyBase,
	}

	for _, ruleCfg := range cfg.Rules {
		pattern, err := regexp.Compile(ruleCfg.Match)
		if err != nil {
			return nil, err
		}
		t.rules = append(t.rules, AssetRule{
			Match:    pattern,
			Replace:  ruleCfg.Replace,
			Sign:     ruleCfg.Sign,
			SignTTL:  ruleCfg.SignTTL,
			Redirect: ruleCfg.Redirect,
		})
	}

	return t, nil
}

// TransformAssets transforms asset URLs in a STAC item.
func (t *AssetTransformer) TransformAssets(item map[string]interface{}) error {
	assets, ok := item["assets"].(map[string]interface{})
	if !ok {
		return nil
	}

	for name, assetData := range assets {
		asset, ok := assetData.(map[string]interface{})
		if !ok {
			continue
		}

		href, ok := asset["href"].(string)
		if !ok {
			continue
		}

		newHref, err := t.TransformURL(href)
		if err != nil {
			continue // Skip failed transformations
		}

		asset["href"] = newHref
		assets[name] = asset
	}

	return nil
}

// TransformURL transforms a single asset URL.
func (t *AssetTransformer) TransformURL(originalURL string) (string, error) {
	result := originalURL

	for _, rule := range t.rules {
		if !rule.Match.MatchString(result) {
			continue
		}

		// Apply replacement
		if rule.Replace != "" {
			result = rule.Match.ReplaceAllString(result, rule.Replace)
		}

		// Sign URL if requested
		if rule.Sign && t.signer != nil {
			ttl := rule.SignTTL
			if ttl == 0 {
				ttl = 3600 // 1 hour default
			}
			signed, err := t.signer.Sign(result, ttl)
			if err != nil {
				return "", err
			}
			result = signed
		}

		// Wrap with proxy redirect if requested
		if rule.Redirect && t.proxyBase != "" {
			result = t.wrapWithProxy(result)
		}
	}

	return result, nil
}

// wrapWithProxy wraps a URL to redirect through the proxy.
func (t *AssetTransformer) wrapWithProxy(assetURL string) string {
	encoded := url.QueryEscape(assetURL)
	return t.proxyBase + "/assets/redirect?url=" + encoded
}

// TransformFeatureCollection transforms all assets in a feature collection.
func (t *AssetTransformer) TransformFeatureCollection(fc map[string]interface{}) error {
	features, ok := fc["features"].([]interface{})
	if !ok {
		return nil
	}

	for _, featureData := range features {
		feature, ok := featureData.(map[string]interface{})
		if !ok {
			continue
		}

		if err := t.TransformAssets(feature); err != nil {
			continue // Skip failed items
		}
	}

	return nil
}

// S3URLRewriter rewrites S3 URLs to use a different endpoint.
type S3URLRewriter struct {
	endpoint   string
	pathStyle  bool
	urlSigning bool
}

// S3URLRewriterConfig configures S3 URL rewriting.
type S3URLRewriterConfig struct {
	Endpoint   string
	PathStyle  bool
	URLSigning bool
}

// NewS3URLRewriter creates a new S3 URL rewriter.
func NewS3URLRewriter(cfg S3URLRewriterConfig) *S3URLRewriter {
	return &S3URLRewriter{
		endpoint:   cfg.Endpoint,
		pathStyle:  cfg.PathStyle,
		urlSigning: cfg.URLSigning,
	}
}

// Rewrite rewrites an S3 URL to use the configured endpoint.
func (r *S3URLRewriter) Rewrite(s3URL string) (string, error) {
	parsed, err := url.Parse(s3URL)
	if err != nil {
		return "", err
	}

	// Check if it's an S3 URL
	if !isS3URL(parsed) {
		return s3URL, nil // Return unchanged
	}

	// Extract bucket and key
	bucket, key := extractS3BucketKey(parsed)
	if bucket == "" {
		return s3URL, nil
	}

	// Build new URL
	endpoint := strings.TrimSuffix(r.endpoint, "/")
	if r.pathStyle {
		return endpoint + "/" + bucket + "/" + key, nil
	}

	// Virtual-hosted style
	endpointParsed, err := url.Parse(endpoint)
	if err != nil {
		return "", err
	}
	endpointParsed.Host = bucket + "." + endpointParsed.Host
	endpointParsed.Path = "/" + key
	return endpointParsed.String(), nil
}

// isS3URL checks if a URL is an S3 URL.
func isS3URL(u *url.URL) bool {
	host := u.Host
	return strings.HasSuffix(host, ".amazonaws.com") ||
		strings.HasPrefix(host, "s3.") ||
		strings.Contains(host, ".s3.") ||
		u.Scheme == "s3"
}

// extractS3BucketKey extracts bucket and key from an S3 URL.
func extractS3BucketKey(u *url.URL) (bucket, key string) {
	host := u.Host
	path := strings.TrimPrefix(u.Path, "/")

	// s3://bucket/key format
	if u.Scheme == "s3" {
		return host, path
	}

	// Virtual-hosted style: bucket.s3.region.amazonaws.com/key
	if strings.Contains(host, ".s3.") {
		parts := strings.SplitN(host, ".s3.", 2)
		if len(parts) == 2 {
			return parts[0], path
		}
	}

	// Path style: s3.region.amazonaws.com/bucket/key
	if strings.HasPrefix(host, "s3.") {
		pathParts := strings.SplitN(path, "/", 2)
		if len(pathParts) == 2 {
			return pathParts[0], pathParts[1]
		}
		if len(pathParts) == 1 {
			return pathParts[0], ""
		}
	}

	return "", ""
}

// CloudFrontRewriter rewrites URLs to use CloudFront.
type CloudFrontRewriter struct {
	distributionDomain string
	originPatterns     []*regexp.Regexp
}

// NewCloudFrontRewriter creates a new CloudFront URL rewriter.
func NewCloudFrontRewriter(distributionDomain string, originPatterns []string) (*CloudFrontRewriter, error) {
	r := &CloudFrontRewriter{
		distributionDomain: distributionDomain,
	}

	for _, pattern := range originPatterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, err
		}
		r.originPatterns = append(r.originPatterns, re)
	}

	return r, nil
}

// Rewrite rewrites matching URLs to use CloudFront.
func (r *CloudFrontRewriter) Rewrite(originalURL string) (string, error) {
	parsed, err := url.Parse(originalURL)
	if err != nil {
		return "", err
	}

	// Check if URL matches any origin pattern
	for _, pattern := range r.originPatterns {
		if pattern.MatchString(parsed.Host) {
			// Replace host with CloudFront distribution
			parsed.Host = r.distributionDomain
			return parsed.String(), nil
		}
	}

	return originalURL, nil
}
