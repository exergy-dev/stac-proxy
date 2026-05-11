// Package authz provides authorization middleware.
package authz

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// OPAEnforcer uses Open Policy Agent for authorization.
type OPAEnforcer struct {
	client     *http.Client
	serverURL  string
	policyPath string
	name       string
}

// OPAConfig configures the OPA enforcer.
type OPAConfig struct {
	Name       string
	ServerURL  string
	PolicyPath string
	Timeout    time.Duration
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

	return &OPAEnforcer{
		client: &http.Client{
			Timeout: timeout,
		},
		serverURL:  cfg.ServerURL,
		policyPath: policyPath,
		name:       cfg.Name,
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

	// Send request
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("OPA request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OPA returned status %d", resp.StatusCode)
	}

	// Parse response
	var opaResp OPAResponse
	if err := json.NewDecoder(resp.Body).Decode(&opaResp); err != nil {
		return nil, fmt.Errorf("failed to decode OPA response: %w", err)
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

	if maxResults, ok := raw["max_results"].(float64); ok {
		constraints.MaxResults = int(maxResults)
	}

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
	}

	return constraints
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
