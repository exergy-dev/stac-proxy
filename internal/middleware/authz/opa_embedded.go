// Package authz provides authorization middleware.
package authz

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
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
	PolicyPath  string   // Path to .rego file
	PolicyPaths []string // Multiple policy files
	Query       string   // e.g., "data.stac.authz.allow"
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
		// Use default allow-all policy
		modules["default.rego"] = defaultPolicy
	}

	// Prepare the query
	if err := e.prepareQuery(modules); err != nil {
		return nil, err
	}

	return e, nil
}

// Default policy that allows everything
const defaultPolicy = `
package stac.authz

default allow = true

result = {
    "allow": allow,
    "reasons": reasons,
    "constraints": constraints
}

reasons[msg] {
    allow
    msg := "allowed by default policy"
}

reasons[msg] {
    not allow
    msg := "denied by default policy"
}

constraints = {}
`

// prepareQuery compiles the Rego modules and prepares the query.
func (e *EmbeddedOPAEnforcer) prepareQuery(modules map[string]string) error {
	ctx := context.Background()

	// Build rego options
	options := []func(*rego.Rego){
		rego.Query(e.queryString),
	}

	for name, content := range modules {
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
