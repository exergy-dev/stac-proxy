// Package authz provides authorization middleware.
package authz

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

// OPAErrorMode controls how the external-OPA enforcer handles
// transport, timeout, or non-200 errors when calling the OPA server.
//
// Default behaviour is fail-closed (deny). Operators who prefer
// fail-open (e.g. during planned OPA outages) can opt in via
// OPAErrorAllow — the choice is logged at WARN on every error and the
// decision carries a Reason explaining why.
type OPAErrorMode string

const (
	// OPAErrorDeny returns an explicit deny decision when the OPA
	// server is unreachable or returns an error. This is the default.
	OPAErrorDeny OPAErrorMode = "deny"
	// OPAErrorAllow returns an explicit allow decision when the OPA
	// server is unreachable or returns an error. Use with care; intended
	// for planned outages where an operator has accepted the risk.
	OPAErrorAllow OPAErrorMode = "allow"
)

// OPAEnforcer uses Open Policy Agent for authorization.
type OPAEnforcer struct {
	client     *http.Client
	serverURL  string
	policyPath string
	name       string
	onError    OPAErrorMode
}

// OPAConfig configures the OPA enforcer.
type OPAConfig struct {
	Name       string
	ServerURL  string
	PolicyPath string
	Timeout    time.Duration
	// OnError selects the fail-mode when the OPA server is unreachable
	// or returns a non-200 response. Defaults to OPAErrorDeny
	// (fail-closed). Documented values: "deny", "allow".
	OnError OPAErrorMode
}

// OPARequest is the request sent to OPA.
type OPARequest struct {
	Input *AuthzInput `json:"input"`
}

// OPAResponse is the response from OPA.
type OPAResponse struct {
	Result *OPAResult `json:"result"`
}

// OPAResult is the decision result from OPA.
type OPAResult struct {
	Allow       bool                   `json:"allow"`
	Reasons     []string               `json:"reasons,omitempty"`
	Constraints map[string]interface{} `json:"constraints,omitempty"`
}

// NewOPAEnforcer creates a new OPA-based enforcer.
func NewOPAEnforcer(cfg OPAConfig) (*OPAEnforcer, error) {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	policyPath := cfg.PolicyPath
	if policyPath == "" {
		policyPath = "/v1/data/stac/authz"
	}

	onError := cfg.OnError
	switch onError {
	case OPAErrorDeny, OPAErrorAllow:
		// valid
	case "":
		onError = OPAErrorDeny
	default:
		return nil, fmt.Errorf("invalid OPA OnError mode %q (want %q or %q)",
			onError, OPAErrorDeny, OPAErrorAllow)
	}

	return &OPAEnforcer{
		client: &http.Client{
			Timeout: timeout,
		},
		serverURL:  cfg.ServerURL,
		policyPath: policyPath,
		name:       cfg.Name,
		onError:    onError,
	}, nil
}

// Name returns the enforcer name.
func (e *OPAEnforcer) Name() string {
	return e.name
}

// Authorize queries OPA for an authorization decision.
func (e *OPAEnforcer) Authorize(ctx context.Context, input *AuthzInput) (*AuthzDecision, error) {
	// Prepare OPA request
	opaReq := &OPARequest{Input: input}
	body, err := json.Marshal(opaReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal OPA request: %w", err)
	}

	// Build request URL
	url := e.serverURL + e.policyPath

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create OPA request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Send request. Transport / non-200 / decode failures yield an
	// EXPLICIT decision (not a bare error) so CompositeEnforcer.authorizeAny
	// cannot silently fall through to a more permissive enforcer during
	// an OPA outage. The decision's allowed flag is governed by OnError.
	resp, err := e.client.Do(req)
	if err != nil {
		return e.errorDecision(fmt.Errorf("OPA request failed: %w", err)), nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return e.errorDecision(fmt.Errorf("OPA returned status %d", resp.StatusCode)), nil
	}

	// Parse response
	var opaResp OPAResponse
	if err := json.NewDecoder(resp.Body).Decode(&opaResp); err != nil {
		return e.errorDecision(fmt.Errorf("failed to decode OPA response: %w", err)), nil
	}

	// Convert to AuthzDecision
	decision := &AuthzDecision{
		Allowed: false,
		Reasons: []string{"denied by OPA policy"},
	}

	if opaResp.Result != nil {
		decision.Allowed = opaResp.Result.Allow
		if len(opaResp.Result.Reasons) > 0 {
			decision.Reasons = opaResp.Result.Reasons
		} else if decision.Allowed {
			decision.Reasons = []string{"allowed by OPA policy"}
		}

		// Parse constraints
		if opaResp.Result.Constraints != nil {
			decision.Constraints = parseOPAConstraints(opaResp.Result.Constraints)
		}
	}

	return decision, nil
}

// errorDecision converts a transport / response error into an explicit
// AuthzDecision honoring OnError. Returning a decision (rather than a
// bare error) prevents CompositeEnforcer.authorizeAny from swallowing
// the failure and silently falling through to a fallback enforcer
// during an OPA outage. The reason string names the chosen mode so
// operators can spot fail-open events in audit logs.
func (e *OPAEnforcer) errorDecision(err error) *AuthzDecision {
	switch e.onError {
	case OPAErrorAllow:
		slog.Warn("external OPA unreachable; allowing per OnError=allow",
			"enforcer", e.name, "err", err)
		return &AuthzDecision{
			Allowed: true,
			Reasons: []string{"external-opa unavailable: allow on error"},
			Final:   true,
		}
	default: // deny / unset
		slog.Warn("external OPA unreachable; denying per OnError=deny",
			"enforcer", e.name, "err", err)
		return &AuthzDecision{
			Allowed: false,
			Reasons: []string{"external-opa unavailable: deny on error"},
			Final:   true,
		}
	}
}

// parseOPAConstraints converts OPA constraint output to AuthzConstraints.
func parseOPAConstraints(raw map[string]interface{}) *AuthzConstraints {
	constraints := &AuthzConstraints{}

	if collections, ok := raw["allowed_collections"].([]interface{}); ok {
		for _, c := range collections {
			if s, ok := c.(string); ok {
				constraints.AllowedCollections = append(constraints.AllowedCollections, s)
			}
		}
	}

	if collections, ok := raw["denied_collections"].([]interface{}); ok {
		for _, c := range collections {
			if s, ok := c.(string); ok {
				constraints.DeniedCollections = append(constraints.DeniedCollections, s)
			}
		}
	}

	constraints.MaxResults = toInt(raw["max_results"])

	if geofence, ok := raw["geofence"].(map[string]interface{}); ok {
		constraints.Geofence = &GeofenceConstraint{}
		if area, ok := geofence["allowed_area"]; ok {
			constraints.Geofence.AllowedArea = area
		}
		if area, ok := geofence["denied_area"]; ok {
			constraints.Geofence.DeniedArea = area
		}
		if fm, ok := geofence["filter_mode"].(bool); ok {
			constraints.Geofence.FilterMode = fm
		}
		if gp, ok := geofence["geometry_property"].(string); ok {
			constraints.Geofence.GeometryProperty = gp
		}
	}

	if s, ok := raw["cql2_filter"].(string); ok {
		constraints.CQL2Filter = s
	}

	if v, ok := raw["cql2_filter_json"]; ok {
		constraints.CQL2FilterJSON = v
	}

	if rf, ok := raw["required_filters"].(map[string]interface{}); ok {
		constraints.RequiredFilters = rf
	}

	return constraints
}

// toInt coerces a JSON-decoded numeric value to int. OPA may return
// numbers as float64, int, int64, or json.Number depending on origin
// and version, so this normalises across them. Unknown/nil values
// yield 0.
func toInt(v interface{}) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case float32:
		return int(n)
	case int:
		return n
	case int64:
		return int(n)
	case int32:
		return int(n)
	case json.Number:
		i, err := n.Int64()
		if err == nil {
			return int(i)
		}
		f, err := n.Float64()
		if err == nil {
			return int(f)
		}
	}
	return 0
}

// OPAHealthCheck checks if the OPA server is healthy.
func (e *OPAEnforcer) OPAHealthCheck(ctx context.Context) error {
	url := e.serverURL + "/health"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("OPA health check failed with status %d", resp.StatusCode)
	}

	return nil
}
