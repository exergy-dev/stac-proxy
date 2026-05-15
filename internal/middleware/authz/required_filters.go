package authz

import (
	"fmt"
	"sort"
	"strings"

	cql2 "github.com/exergy-dev/go-cql2"
)

// requiredFiltersToCQL2 turns a policy's required_filters map into a
// cql2 expression. Returns (nil, nil) when the map is empty.
//
// Supported value shapes (per the embedded-OPA test fixture and the
// example Rego policy):
//
//	"key": "v"             →  key = 'v'
//	"key": 42              →  key = 42
//	"key": true            →  key = TRUE
//	"key": nil             →  key IS NULL
//	"key": {"eq":  v}      →  key = v
//	"key": {"neq": v}      →  key <> v
//	"key": {"lt":  v}      →  key < v
//	"key": {"lte": v}      →  key <= v
//	"key": {"gt":  v}      →  key > v
//	"key": {"gte": v}      →  key >= v
//	"key": {"in":  [...]}  →  key IN (a, b, c)
//
// Multiple keys are AND-joined in sorted-key order so the produced
// predicate is stable across map iterations — useful for cache keys.
//
// Identifier quoting, literal escaping, and float formatting are
// delegated to github.com/exergy-dev/go-cql2.
func requiredFiltersToCQL2(rf map[string]interface{}) (*cql2.Expr, error) {
	if len(rf) == 0 {
		return nil, nil
	}
	keys := make([]string, 0, len(rf))
	for k := range rf {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	parts := make([]cql2.Expr, 0, len(keys))
	for _, k := range keys {
		e, err := requiredFilterClause(k, rf[k])
		if err != nil {
			return nil, fmt.Errorf("required_filters[%q]: %w", k, err)
		}
		if e != nil {
			parts = append(parts, *e)
		}
	}
	switch len(parts) {
	case 0:
		return nil, nil
	case 1:
		return &parts[0], nil
	default:
		out := cql2.And(parts...)
		return &out, nil
	}
}

func requiredFilterClause(key string, value interface{}) (*cql2.Expr, error) {
	switch v := value.(type) {
	case nil:
		e := cql2.IsNull(key)
		return &e, nil
	case map[string]interface{}:
		return requiredFilterMapPredicate(key, v)
	default:
		e := cql2.Eq(key, v)
		return &e, nil
	}
}

func requiredFilterMapPredicate(key string, ops map[string]interface{}) (*cql2.Expr, error) {
	if len(ops) != 1 {
		return nil, fmt.Errorf("expected single operator, got %d", len(ops))
	}
	for op, raw := range ops {
		switch strings.ToLower(op) {
		case "eq":
			e := cql2.Eq(key, raw)
			return &e, nil
		case "neq", "ne":
			e := cql2.Neq(key, raw)
			return &e, nil
		case "lt":
			e := cql2.Lt(key, raw)
			return &e, nil
		case "lte", "le":
			e := cql2.Lte(key, raw)
			return &e, nil
		case "gt":
			e := cql2.Gt(key, raw)
			return &e, nil
		case "gte", "ge":
			e := cql2.Gte(key, raw)
			return &e, nil
		case "in":
			items, ok := raw.([]interface{})
			if !ok {
				return nil, fmt.Errorf("in: expected array, got %T", raw)
			}
			e := cql2.In(key, items...)
			return &e, nil
		default:
			return nil, fmt.Errorf("unsupported operator %q", op)
		}
	}
	return nil, nil
}
