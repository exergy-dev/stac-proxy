// Package authz provides authorization middleware.
package authz

import "encoding/json"

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
