// Package authz provides authorization middleware.
package authz

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"sync"

	"github.com/open-policy-agent/opa/rego"
)

// EmbeddedOPAEnforcer runs OPA policies in-process.
type EmbeddedOPAEnforcer struct {
	mu          sync.RWMutex
	query       rego.PreparedEvalQuery
	name        string
	policyPath  string
	queryString string
}

// EmbeddedOPAConfig configures the embedded OPA enforcer.
type EmbeddedOPAConfig struct {
	Name        string
	PolicyPath  string            // Path to .rego file
	PolicyPaths []string          // Multiple policy files
	Query       string            // e.g., "data.stac.authz.allow"
	Modules     map[string]string // Inline policy modules
}

// NewEmbeddedOPAEnforcer creates a new embedded OPA enforcer.
func NewEmbeddedOPAEnforcer(cfg EmbeddedOPAConfig) (*EmbeddedOPAEnforcer, error) {
	e := &EmbeddedOPAEnforcer{
		name:        cfg.Name,
		policyPath:  cfg.PolicyPath,
		queryString: cfg.Query,
	}

	if e.queryString == "" {
		e.queryString = "data.stac.authz"
	}

	// Collect all policy sources
	modules := make(map[string]string)

	// Load from file(s)
	if cfg.PolicyPath != "" {
		content, err := os.ReadFile(cfg.PolicyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read policy file: %w", err)
		}
		modules[cfg.PolicyPath] = string(content)
	}

	for _, path := range cfg.PolicyPaths {
		content, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read policy file %s: %w", path, err)
		}
		modules[path] = string(content)
	}

	// Add inline modules
	for name, content := range cfg.Modules {
		modules[name] = content
	}

	if len(modules) == 0 {
		// No operator policy supplied: install a fail-closed default
		// that denies every request. Operators must explicitly opt in
		// to permissive behavior by supplying their own policy.
		modules["default.rego"] = defaultPolicy
	}

	// Prepare the query
	if err := e.prepareQuery(modules); err != nil {
		return nil, err
	}

	return e, nil
}

// defaultPolicy is the fail-closed fallback used when the operator
// supplies no policy. It denies every request; operators who want
// allow-all behavior must opt in explicitly.
const defaultPolicy = `
package stac.authz

default allow = false

result = {
    "allow": allow,
    "reasons": reasons,
    "constraints": constraints
}

reasons[msg] {
    allow
    msg := "allowed by operator policy"
}

reasons[msg] {
    not allow
    msg := "denied by default fail-closed policy (no operator policy supplied)"
}

constraints = {}
`

// prepareQuery compiles the Rego modules and prepares the query.
// When multiple modules declare the same `default <rule>` in the same
// package, OPA rejects the bundle. Loading multiple .rego files into
// a single package is a common operator pattern, so we dedupe such
// declarations textually: the first occurrence wins.
func (e *EmbeddedOPAEnforcer) prepareQuery(modules map[string]string) error {
	ctx := context.Background()

	// Build rego options
	options := []func(*rego.Rego){
		rego.Query(e.queryString),
	}

	cleaned := dedupeDefaultRules(modules)
	for name, content := range cleaned {
		options = append(options, rego.Module(name, content))
	}

	r := rego.New(options...)

	query, err := r.PrepareForEval(ctx)
	if err != nil {
		return fmt.Errorf("failed to prepare OPA query: %w", err)
	}

	e.mu.Lock()
	e.query = query
	e.mu.Unlock()

	return nil
}

// defaultRulePattern matches an entire Rego `default <name> [:=|=] <expr>`
// line, capturing the rule name. Trailing newline is consumed so
// removing the line doesn't leave a blank that re-parses oddly.
var defaultRulePattern = regexp.MustCompile(`(?m)^[ \t]*default[ \t]+([A-Za-z_][A-Za-z0-9_]*)[ \t]*(?::=|=)[^\n]*\n?`)

// dedupeDefaultRules scans every module for `default <rule>`
// declarations and strips later occurrences so OPA's "multiple
// default rules" error doesn't fire when operators legitimately split
// policies across files. Modules are processed in a deterministic
// (lexicographic by name) order so the outcome is reproducible.
func dedupeDefaultRules(modules map[string]string) map[string]string {
	names := make([]string, 0, len(modules))
	for n := range modules {
		names = append(names, n)
	}
	sort.Strings(names)

	seen := make(map[string]bool)
	out := make(map[string]string, len(modules))
	for _, name := range names {
		content := modules[name]
		// Replace each matched `default <x>` line either by keeping it
		// (first time we've seen <x>) or by removing it.
		content = defaultRulePattern.ReplaceAllStringFunc(content, func(line string) string {
			m := defaultRulePattern.FindStringSubmatch(line)
			if len(m) < 2 {
				return line
			}
			rule := m[1]
			if seen[rule] {
				return "" // drop subsequent default for the same rule
			}
			seen[rule] = true
			return line
		})
		// A wholly-stripped line leaves an orphan tail (the RHS).
		// Strip those lines too: any line that starts with whitespace
		// and an assignment/operand we can't easily classify is left
		// alone — but bare `default` removal is captured by the regex.
		// In practice the trailing `= true` is on the same line, so
		// ReplaceAllStringFunc removes the entire `default x = y` line.
		out[name] = content
	}
	return out
}

// Name returns the enforcer name.
func (e *EmbeddedOPAEnforcer) Name() string {
	return e.name
}

// Authorize evaluates the OPA policy.
func (e *EmbeddedOPAEnforcer) Authorize(ctx context.Context, input *AuthzInput) (*AuthzDecision, error) {
	e.mu.RLock()
	query := e.query
	e.mu.RUnlock()

	// Convert input to map for OPA
	inputMap, err := structToMap(input)
	if err != nil {
		return nil, fmt.Errorf("failed to convert input: %w", err)
	}

	// Evaluate query
	results, err := query.Eval(ctx, rego.EvalInput(inputMap))
	if err != nil {
		return nil, fmt.Errorf("OPA evaluation failed: %w", err)
	}

	if len(results) == 0 {
		return &AuthzDecision{
			Allowed: false,
			Reasons: []string{"no policy result"},
		}, nil
	}

	// Parse result
	return parseEmbeddedResult(results[0])
}

// parseEmbeddedResult parses the OPA evaluation result.
func parseEmbeddedResult(result rego.Result) (*AuthzDecision, error) {
	decision := &AuthzDecision{
		Allowed: false,
	}

	// Handle different result structures
	for _, expr := range result.Expressions {
		switch v := expr.Value.(type) {
		case bool:
			decision.Allowed = v
		case map[string]interface{}:
			// When the query was `data.stac.authz` (the default), the
			// value is the whole package and the structured response
			// lives under "result". Unwrap if present.
			if r, ok := v["result"].(map[string]interface{}); ok {
				if _, hasAllow := r["allow"]; hasAllow {
					v = r
				}
			}
			if allow, ok := v["allow"].(bool); ok {
				decision.Allowed = allow
			}
			if reasons, ok := v["reasons"].([]interface{}); ok {
				for _, r := range reasons {
					if s, ok := r.(string); ok {
						decision.Reasons = append(decision.Reasons, s)
					}
				}
			}
			if constraints, ok := v["constraints"].(map[string]interface{}); ok {
				decision.Constraints = parseOPAConstraints(constraints)
			}
		}
	}

	if len(decision.Reasons) == 0 {
		if decision.Allowed {
			decision.Reasons = []string{"allowed by policy"}
		} else {
			decision.Reasons = []string{"denied by policy"}
		}
	}

	return decision, nil
}

// structToMap converts a struct to a map using JSON.
func structToMap(v interface{}) (map[string]interface{}, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// ReloadPolicy reloads the policy from disk.
func (e *EmbeddedOPAEnforcer) ReloadPolicy() error {
	if e.policyPath == "" {
		return nil
	}

	content, err := os.ReadFile(e.policyPath)
	if err != nil {
		return err
	}

	modules := map[string]string{
		e.policyPath: string(content),
	}

	return e.prepareQuery(modules)
}
