package authz

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// requiredFiltersToCQL2 translates a policy's required_filters map into
// a cql2-text predicate that can be AND-merged with other CQL2.
//
// Supported value shapes (per the embedded-OPA test fixture and the
// policies/stac_authz.rego example):
//
//	"key": "v"             →  key = 'v'
//	"key": 42 / 3.14       →  key = 42
//	"key": true            →  key = TRUE
//	"key": {"eq":  v}      →  key = v
//	"key": {"neq": v}      →  key <> v
//	"key": {"lt":  v}      →  key < v
//	"key": {"lte": v}      →  key <= v
//	"key": {"gt":  v}      →  key > v
//	"key": {"gte": v}      →  key >= v
//	"key": {"in":  [...]}  →  key IN (a, b, c)
//
// Multiple keys are joined with AND in deterministic (sorted-key) order
// so the produced predicate is stable across map iterations and useful
// for cache-key purposes.
//
// String values are single-quoted with embedded single-quotes doubled
// per CQL2 lexical rules. Unsupported value shapes return an error;
// the middleware treats this as a 403 because it cannot honor the
// policy.
func requiredFiltersToCQL2(rf map[string]interface{}) (string, error) {
	if len(rf) == 0 {
		return "", nil
	}
	keys := make([]string, 0, len(rf))
	for k := range rf {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		expr, err := requiredFilterClause(k, rf[k])
		if err != nil {
			return "", fmt.Errorf("required_filters[%q]: %w", k, err)
		}
		if expr != "" {
			parts = append(parts, expr)
		}
	}
	if len(parts) == 0 {
		return "", nil
	}
	if len(parts) == 1 {
		return parts[0], nil
	}
	return strings.Join(parts, " AND "), nil
}

func requiredFilterClause(key string, value interface{}) (string, error) {
	identifier := cql2Identifier(key)
	switch v := value.(type) {
	case string:
		return identifier + " = " + cql2Literal(v), nil
	case bool:
		if v {
			return identifier + " = TRUE", nil
		}
		return identifier + " = FALSE", nil
	case json.Number:
		return identifier + " = " + v.String(), nil
	case float64, float32, int, int32, int64, uint, uint32, uint64:
		return identifier + " = " + cql2Literal(v), nil
	case nil:
		return identifier + " IS NULL", nil
	case map[string]interface{}:
		return mapPredicate(identifier, v)
	default:
		return "", fmt.Errorf("unsupported value type %T", value)
	}
}

func mapPredicate(identifier string, ops map[string]interface{}) (string, error) {
	if len(ops) != 1 {
		return "", fmt.Errorf("expected single operator, got %d", len(ops))
	}
	for op, raw := range ops {
		switch strings.ToLower(op) {
		case "eq":
			return identifier + " = " + cql2Literal(raw), nil
		case "neq", "ne":
			return identifier + " <> " + cql2Literal(raw), nil
		case "lt":
			return identifier + " < " + cql2Literal(raw), nil
		case "lte", "le":
			return identifier + " <= " + cql2Literal(raw), nil
		case "gt":
			return identifier + " > " + cql2Literal(raw), nil
		case "gte", "ge":
			return identifier + " >= " + cql2Literal(raw), nil
		case "in":
			items, ok := raw.([]interface{})
			if !ok {
				return "", fmt.Errorf("in: expected array, got %T", raw)
			}
			parts := make([]string, len(items))
			for i, it := range items {
				parts[i] = cql2Literal(it)
			}
			return identifier + " IN (" + strings.Join(parts, ", ") + ")", nil
		default:
			return "", fmt.Errorf("unsupported operator %q", op)
		}
	}
	return "", nil
}

// cql2Identifier returns the property reference. STAC item-property
// access in CQL2 uses bare identifiers for top-level properties (e.g.
// `datetime`), and double-quoted identifiers when the name contains a
// colon (e.g. `"eo:cloud_cover"`) so the parser doesn't trip on the
// extension prefix.
func cql2Identifier(key string) string {
	if strings.ContainsAny(key, ":-") {
		return `"` + strings.ReplaceAll(key, `"`, `""`) + `"`
	}
	return key
}

// cql2Literal renders a Go value as a CQL2 literal.
func cql2Literal(v interface{}) string {
	switch x := v.(type) {
	case string:
		return "'" + strings.ReplaceAll(x, "'", "''") + "'"
	case bool:
		if x {
			return "TRUE"
		}
		return "FALSE"
	case json.Number:
		return x.String()
	case float64:
		return strconvFloat(x)
	case float32:
		return strconvFloat(float64(x))
	case int:
		return fmt.Sprintf("%d", x)
	case int32:
		return fmt.Sprintf("%d", x)
	case int64:
		return fmt.Sprintf("%d", x)
	case uint:
		return fmt.Sprintf("%d", x)
	case uint32:
		return fmt.Sprintf("%d", x)
	case uint64:
		return fmt.Sprintf("%d", x)
	case nil:
		return "NULL"
	default:
		return "'" + strings.ReplaceAll(fmt.Sprintf("%v", x), "'", "''") + "'"
	}
}

// strconvFloat formats a float without a trailing ".0" when the value
// is integral, so cloud_cover=20 doesn't become "20.000000".
func strconvFloat(f float64) string {
	if f == float64(int64(f)) {
		return fmt.Sprintf("%d", int64(f))
	}
	return fmt.Sprintf("%g", f)
}
