// Package authz provides authorization middleware.
package authz

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"
)

// PolicyEnforcer enforces file-based authorization policies.
type PolicyEnforcer struct {
	mu       sync.RWMutex
	policies []Policy
	name     string
}

// Policy represents an authorization policy.
type Policy struct {
	ID          string       `json:"id"`
	Description string       `json:"description"`
	Effect      PolicyEffect `json:"effect"` // allow or deny
	Priority    int          `json:"priority"`

	// Conditions for when this policy applies
	Principals *PrincipalMatcher `json:"principals,omitempty"`
	Resources  *ResourceMatcher  `json:"resources,omitempty"`
	Actions    []string          `json:"actions,omitempty"`
	Conditions []Condition       `json:"conditions,omitempty"`

	// Constraints to apply if policy matches
	Constraints *AuthzConstraints `json:"constraints,omitempty"`
}

// PolicyEffect is either allow or deny.
type PolicyEffect string

const (
	PolicyEffectAllow PolicyEffect = "allow"
	PolicyEffectDeny  PolicyEffect = "deny"
)

// PrincipalMatcher defines which principals a policy applies to.
type PrincipalMatcher struct {
	IDs        []string `json:"ids,omitempty"`
	Roles      []string `json:"roles,omitempty"`
	Groups     []string `json:"groups,omitempty"`
	Types      []string `json:"types,omitempty"`
	Attributes map[string]interface{} `json:"attributes,omitempty"`
}

// ResourceMatcher defines which resources a policy applies to.
type ResourceMatcher struct {
	Types       []string `json:"types,omitempty"`
	Collections []string `json:"collections,omitempty"`
	Origins     []string `json:"origins,omitempty"`
	Patterns    []string `json:"patterns,omitempty"` // glob patterns
}

// Condition is an additional condition for policy evaluation.
type Condition struct {
	Type   string      `json:"type"` // time_range, ip_range, attribute
	Config interface{} `json:"config"`
}

// PolicyConfig configures the policy enforcer.
type PolicyConfig struct {
	Name       string
	PolicyFile string
	Policies   []Policy
}

// NewPolicyEnforcer creates a new policy-based enforcer.
func NewPolicyEnforcer(cfg PolicyConfig) (*PolicyEnforcer, error) {
	e := &PolicyEnforcer{
		name:     cfg.Name,
		policies: cfg.Policies,
	}

	if cfg.PolicyFile != "" {
		policies, err := loadPoliciesFromFile(cfg.PolicyFile)
		if err != nil {
			return nil, err
		}
		e.policies = append(e.policies, policies...)
	}

	// Sort policies by priority
	e.sortPolicies()

	return e, nil
}

// Name returns the enforcer name.
func (e *PolicyEnforcer) Name() string {
	return e.name
}

// Authorize evaluates policies against the authorization input.
func (e *PolicyEnforcer) Authorize(ctx context.Context, input *AuthzInput) (*AuthzDecision, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// Find all matching policies
	var matchedAllow *Policy
	var matchedDeny *Policy

	for i := range e.policies {
		policy := &e.policies[i]
		if e.matches(policy, input) {
			switch policy.Effect {
			case PolicyEffectAllow:
				if matchedAllow == nil || policy.Priority > matchedAllow.Priority {
					matchedAllow = policy
				}
			case PolicyEffectDeny:
				if matchedDeny == nil || policy.Priority > matchedDeny.Priority {
					matchedDeny = policy
				}
			}
		}
	}

	// Deny takes precedence if at same priority
	if matchedDeny != nil {
		if matchedAllow == nil || matchedDeny.Priority >= matchedAllow.Priority {
			return &AuthzDecision{
				Allowed: false,
				Reasons: []string{"denied by policy: " + matchedDeny.ID},
			}, nil
		}
	}

	if matchedAllow != nil {
		return &AuthzDecision{
			Allowed:     true,
			Reasons:     []string{"allowed by policy: " + matchedAllow.ID},
			Constraints: matchedAllow.Constraints,
		}, nil
	}

	// Default deny if no matching policies
	return &AuthzDecision{
		Allowed: false,
		Reasons: []string{"no matching policy found"},
	}, nil
}

// matches checks if a policy matches the input.
func (e *PolicyEnforcer) matches(policy *Policy, input *AuthzInput) bool {
	// Check principal matcher
	if policy.Principals != nil && !e.matchesPrincipal(policy.Principals, input.Principal) {
		return false
	}

	// Check resource matcher
	if policy.Resources != nil && !e.matchesResource(policy.Resources, input.Resource) {
		return false
	}

	// Check action matcher. An empty Actions slice is interpreted as
	// "no actions allowed" (fail-closed) rather than "no constraint";
	// callers wanting to match all actions should use ["*"].
	if policy.Actions != nil && !e.matchesAction(policy.Actions, input.Request) {
		return false
	}

	// Check conditions
	for _, cond := range policy.Conditions {
		if !e.evaluateCondition(cond, input) {
			return false
		}
	}

	return true
}

// matchesPrincipal checks if principal matches the matcher.
func (e *PolicyEnforcer) matchesPrincipal(matcher *PrincipalMatcher, principal *PrincipalInfo) bool {
	if principal == nil {
		return false
	}

	// Check IDs
	if len(matcher.IDs) > 0 {
		if !containsString(matcher.IDs, principal.ID) && !containsString(matcher.IDs, "*") {
			return false
		}
	}

	// Check roles
	if len(matcher.Roles) > 0 {
		if !hasAnyRole(principal.Roles, matcher.Roles) && !containsString(matcher.Roles, "*") {
			return false
		}
	}

	// Check groups
	if len(matcher.Groups) > 0 {
		if !hasAnyRole(principal.Groups, matcher.Groups) && !containsString(matcher.Groups, "*") {
			return false
		}
	}

	// Check types
	if len(matcher.Types) > 0 {
		if !containsString(matcher.Types, principal.Type) && !containsString(matcher.Types, "*") {
			return false
		}
	}

	return true
}

// matchesResource checks if resource matches the matcher.
func (e *PolicyEnforcer) matchesResource(matcher *ResourceMatcher, resource *ResourceInfo) bool {
	if resource == nil {
		return false
	}

	// Check types
	if len(matcher.Types) > 0 {
		if !containsString(matcher.Types, resource.Type) && !containsString(matcher.Types, "*") {
			return false
		}
	}

	// Check collections
	if len(matcher.Collections) > 0 {
		matched := containsString(matcher.Collections, "*")
		if !matched && resource.Collection != "" {
			for _, pattern := range matcher.Collections {
				if matchGlob(pattern, resource.Collection) {
					matched = true
					break
				}
			}
		}
		if !matched {
			return false
		}
	}

	return true
}

// matchesAction checks if the request matches allowed actions.
func (e *PolicyEnforcer) matchesAction(actions []string, req *RequestInfo) bool {
	if req == nil {
		return false
	}

	action := strings.ToLower(req.Method + ":" + req.RequestType)

	for _, allowed := range actions {
		if allowed == "*" || strings.ToLower(allowed) == action {
			return true
		}
		if matchGlob(strings.ToLower(allowed), action) {
			return true
		}
	}

	return false
}

// evaluateCondition evaluates a single Condition against the authz
// input. Returns true when the condition is satisfied (i.e. the
// surrounding policy may proceed). Unknown condition types
// fail-closed (return false) so a misconfigured policy doesn't
// silently grant access.
//
// Supported types:
//   - "time_range": Config is a map with "start" and/or "end"
//     RFC3339 strings; the current wall clock must fall inside.
//   - "ip_range": Config is a map with "cidrs" (a []string of CIDR
//     blocks); the request's ClientIP must match at least one.
//   - "attribute": Config is a map with "key" and "value"; the
//     principal's Attributes[key] must equal value (string compare).
func (e *PolicyEnforcer) evaluateCondition(cond Condition, input *AuthzInput) bool {
	cfg, ok := cond.Config.(map[string]interface{})
	if !ok {
		return false
	}
	switch cond.Type {
	case "time_range":
		return evalTimeRange(cfg)
	case "ip_range":
		return evalIPRange(cfg, input)
	case "attribute":
		return evalAttribute(cfg, input)
	default:
		return false
	}
}

func evalTimeRange(cfg map[string]interface{}) bool {
	now := time.Now().UTC()
	if s, ok := cfg["start"].(string); ok && s != "" {
		start, err := time.Parse(time.RFC3339, s)
		if err != nil || now.Before(start) {
			return false
		}
	}
	if s, ok := cfg["end"].(string); ok && s != "" {
		end, err := time.Parse(time.RFC3339, s)
		if err != nil || now.After(end) {
			return false
		}
	}
	return true
}

func evalIPRange(cfg map[string]interface{}, input *AuthzInput) bool {
	if input == nil || input.Request == nil || input.Request.ClientIP == "" {
		return false
	}
	// Strip port if present (RemoteAddr is "host:port").
	host := input.Request.ClientIP
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	cidrs, ok := cfg["cidrs"].([]interface{})
	if !ok {
		return false
	}
	for _, c := range cidrs {
		s, ok := c.(string)
		if !ok {
			continue
		}
		prefix, err := netip.ParsePrefix(s)
		if err != nil {
			continue
		}
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func evalAttribute(cfg map[string]interface{}, input *AuthzInput) bool {
	if input == nil || input.Principal == nil {
		return false
	}
	key, _ := cfg["key"].(string)
	want, hasWant := cfg["value"]
	if key == "" || !hasWant {
		return false
	}
	got, ok := input.Principal.Attributes[key]
	if !ok {
		return false
	}
	return fmt.Sprintf("%v", got) == fmt.Sprintf("%v", want)
}

// loadPoliciesFromFile loads policies from a JSON file.
func loadPoliciesFromFile(path string) ([]Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var policies []Policy
	if err := json.Unmarshal(data, &policies); err != nil {
		return nil, err
	}

	return policies, nil
}

// sortPolicies sorts policies by priority (descending).
func (e *PolicyEnforcer) sortPolicies() {
	// Simple bubble sort for small policy sets
	for i := 0; i < len(e.policies); i++ {
		for j := i + 1; j < len(e.policies); j++ {
			if e.policies[j].Priority > e.policies[i].Priority {
				e.policies[i], e.policies[j] = e.policies[j], e.policies[i]
			}
		}
	}
}

// ReloadPolicies reloads policies from the configured file.
func (e *PolicyEnforcer) ReloadPolicies(path string) error {
	policies, err := loadPoliciesFromFile(path)
	if err != nil {
		return err
	}

	e.mu.Lock()
	e.policies = policies
	e.sortPolicies()
	e.mu.Unlock()

	return nil
}

// containsString checks if slice contains string.
func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

// hasAnyRole checks if any role in a matches any role in b.
func hasAnyRole(a, b []string) bool {
	for _, ra := range a {
		for _, rb := range b {
			if ra == rb {
				return true
			}
		}
	}
	return false
}

// matchGlob performs simple glob matching (* wildcard).
func matchGlob(pattern, s string) bool {
	if pattern == "*" {
		return true
	}
	if !strings.Contains(pattern, "*") {
		return pattern == s
	}

	parts := strings.Split(pattern, "*")
	if len(parts) == 2 {
		return strings.HasPrefix(s, parts[0]) && strings.HasSuffix(s, parts[1])
	}

	return false
}

// ValidatePolicies validates a set of policies.
func ValidatePolicies(policies []Policy) error {
	seen := make(map[string]bool)
	for _, p := range policies {
		if p.ID == "" {
			return errors.New("policy missing ID")
		}
		if seen[p.ID] {
			return errors.New("duplicate policy ID: " + p.ID)
		}
		seen[p.ID] = true

		if p.Effect != PolicyEffectAllow && p.Effect != PolicyEffectDeny {
			return errors.New("invalid policy effect: " + string(p.Effect))
		}
	}
	return nil
}
