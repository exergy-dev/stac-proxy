// Package authz provides authorization middleware.
package authz

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"

	"github.com/open-policy-agent/opa/rego"
)

// EmbeddedOPAEnforcer runs OPA policies in-process.
type EmbeddedOPAEnforcer struct {
	mu          sync.RWMutex
	query       rego.PreparedEvalQuery
	name        string
	policyPath  string
	queryString string

	// missingAllowWarned latches the WARN about a missing `allow` key
	// to once per enforcer lifetime. The error path always returns a
	// useful Reason, so the log is purely operator hygiene.
	missingAllowWarned atomic.Bool
}

// EmbeddedOPAConfig configures the embedded OPA enforcer.
type EmbeddedOPAConfig struct {
	Name        string
	PolicyPath  string            // Path to .rego file
	PolicyPaths []string          // Multiple policy files
	Query       string            // e.g., "data.stac.authz.allow"
	Modules     map[string]string // Inline policy modules
}

// NewEmbeddedOPAEnforcer creates a new embedded OPA enforcer. ctx bounds
// the one-shot policy compilation (PrepareForEval); pass the process's
// construction/lifetime context so a shutdown during boot aborts the
// compile rather than running detached.
func NewEmbeddedOPAEnforcer(ctx context.Context, cfg EmbeddedOPAConfig) (*EmbeddedOPAEnforcer, error) {
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
	if err := e.prepareQuery(ctx, modules); err != nil {
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
//
// Historical note: this used to run a regex-based pass that stripped
// duplicate `default <rule>` declarations across modules so multi-file
// policies wouldn't trip OPA's "multiple default rules" error. That
// silently corrupted multi-line default rules and — worse — silently
// dropped a `default allow = false`, turning the policy fail-OPEN
// (H-authz-6). The dedup is gone; OPA's compiler is the source of
// truth and any duplicate defaults are surfaced as a clear error to
// the operator. Operators with multi-file policies must consolidate
// to a single `default` rule per name (e.g. keep the
// `default allow = false` only in one shared base module).
func (e *EmbeddedOPAEnforcer) prepareQuery(ctx context.Context, modules map[string]string) error {
	options := make([]func(*rego.Rego), 0, 1+len(modules))
	options = append(options, rego.Query(e.queryString))
	for name, content := range modules {
		options = append(options, rego.Module(name, content))
	}

	r := rego.New(options...)

	query, err := r.PrepareForEval(ctx)
	if err != nil {
		// rego.PrepareForEval already surfaces ast.Compiler errors
		// (including rego_type_error / "multiple default rules") with
		// file/line context. Wrap so operators see *which* enforcer
		// failed to compile.
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
	decision, err := parseEmbeddedResult(results[0], e.queryString)
	if err != nil {
		// Latch the WARN to the first occurrence per enforcer so a
		// continuously-misconfigured policy doesn't spam the log.
		if e.missingAllowWarned.CompareAndSwap(false, true) {
			slog.Warn("OPA policy returned a structured result with no `allow` key",
				"enforcer", e.name, "query", e.queryString, "err", err)
		}
		return nil, err
	}
	return decision, nil
}

// parseEmbeddedResult parses the OPA evaluation result.
//
// M-authz-6: a policy that returns a structured map without an
// `allow` key (e.g. `{"reasons": [...]}`) is malformed — we can't
// tell allow from deny. Previously the parser treated that as a
// silent deny with reason "denied by policy", making misconfiguration
// effectively invisible. Now we return a non-nil error; the caller
// surfaces it as 500 InternalError so operators see exactly what's
// wrong (which policy, which query). A bare boolean expression value
// or a wrapper that does carry `allow` keeps working as before.
//
// queryString is the rego query the enforcer ran (e.g.
// `data.stac.authz`); included in the error for traceability.
func parseEmbeddedResult(result rego.Result, queryString string) (*AuthzDecision, error) {
	decision := &AuthzDecision{
		Allowed: false,
	}

	sawAllowKey := false

	// Handle different result structures
	for _, expr := range result.Expressions {
		switch v := expr.Value.(type) {
		case bool:
			// Bare boolean (e.g. query was `data.x.allow` directly)
			// carries the allow signal directly.
			decision.Allowed = v
			sawAllowKey = true
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
				sawAllowKey = true
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

	if !sawAllowKey {
		// No `allow` key anywhere in the result map nor a bare bool
		// expression — policy is malformed. Return an error so the
		// chi-style middleware writes 500 InternalError; surface the
		// query in Reasons so an operator parsing the audit log can
		// see *which* module is at fault.
		msg := fmt.Sprintf("OPA policy result for query %q is missing the `allow` key; treat as 500 InternalError, not silent deny", queryString)
		decision.Reasons = append(decision.Reasons, msg)
		return decision, fmt.Errorf("opa: %s", msg)
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

// ReloadPolicy reloads the policy from disk. ctx bounds the recompile.
func (e *EmbeddedOPAEnforcer) ReloadPolicy(ctx context.Context) error {
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

	return e.prepareQuery(ctx, modules)
}
