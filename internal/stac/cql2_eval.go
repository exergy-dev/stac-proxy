package stac

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	cql2 "github.com/exergy-dev/go-cql2"
	cql2geojson "github.com/exergy-dev/go-cql2/geojson"
	"github.com/exergy-dev/stac-proxy/internal/geo"
)

// EvalCQL2 reports whether the given CQL2 expression evaluates to
// true against the supplied STAC item (a generic JSON object). The
// evaluator supports the subset of CQL2 most commonly emitted by
// authz policies:
//
//   - logical: AND, OR, NOT
//   - comparison: =, <>, <, <=, >, >=
//   - membership: IN
//   - null check: ISNULL
//   - property references: top-level fields and properties.<name> are
//     resolved automatically (a bare "eo:cloud_cover" looks under
//     properties first, then falls back to the top-level field).
//   - literals: bool, number, string
//
// Unsupported operators or node kinds (spatial, temporal, arithmetic,
// LIKE, BETWEEN, functions, case/accent modifiers) return an
// ErrUnsupportedNode error. Callers should typically treat that as
// a fail-closed signal (drop the item) rather than fail-open.
func EvalCQL2(expr cql2.Node, item map[string]interface{}) (bool, error) {
	v, err := eval(expr, item)
	if err != nil {
		return false, err
	}
	b, ok := v.(bool)
	if !ok {
		return false, fmt.Errorf("cql2 eval: top-level expression is not boolean (%T)", v)
	}
	return b, nil
}

// ErrUnsupportedNode is returned when the evaluator encounters an
// AST shape it doesn't (yet) handle.
type ErrUnsupportedNode struct{ Kind string }

func (e *ErrUnsupportedNode) Error() string { return "cql2 eval: unsupported node: " + e.Kind }

func eval(n cql2.Node, item map[string]interface{}) (interface{}, error) {
	switch x := n.(type) {
	case *cql2.BoolLit:
		return x.Value, nil
	case *cql2.NumLit:
		if f, err := x.Value.Float64(); err == nil {
			return f, nil
		}
		return nil, fmt.Errorf("cql2 eval: bad number %q", x.Value)
	case *cql2.StringLit:
		return x.Value, nil
	case *cql2.NullLit:
		return nil, nil
	case *cql2.PropertyRef:
		return lookupProperty(item, x.Name), nil
	case *cql2.ArrayLit:
		out := make([]interface{}, 0, len(x.Elements))
		for _, e := range x.Elements {
			v, err := eval(e, item)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case *cql2.Op:
		return evalOp(x, item)
	}
	return nil, &ErrUnsupportedNode{Kind: fmt.Sprintf("%T", n)}
}

func evalOp(op *cql2.Op, item map[string]interface{}) (interface{}, error) {
	switch op.Op {
	case cql2.OpAnd:
		for _, arg := range op.Args {
			v, err := eval(arg, item)
			if err != nil {
				return nil, err
			}
			b, ok := v.(bool)
			if !ok {
				return nil, fmt.Errorf("cql2 eval: AND arg not boolean (%T)", v)
			}
			if !b {
				return false, nil
			}
		}
		return true, nil
	case cql2.OpOr:
		for _, arg := range op.Args {
			v, err := eval(arg, item)
			if err != nil {
				return nil, err
			}
			b, ok := v.(bool)
			if !ok {
				return nil, fmt.Errorf("cql2 eval: OR arg not boolean (%T)", v)
			}
			if b {
				return true, nil
			}
		}
		return false, nil
	case cql2.OpNot:
		if len(op.Args) != 1 {
			return nil, fmt.Errorf("cql2 eval: NOT expects 1 arg, got %d", len(op.Args))
		}
		v, err := eval(op.Args[0], item)
		if err != nil {
			return nil, err
		}
		b, ok := v.(bool)
		if !ok {
			return nil, fmt.Errorf("cql2 eval: NOT arg not boolean (%T)", v)
		}
		return !b, nil
	case cql2.OpEq, cql2.OpNeq, cql2.OpLt, cql2.OpLte, cql2.OpGt, cql2.OpGte:
		if len(op.Args) != 2 {
			return nil, fmt.Errorf("cql2 eval: %s expects 2 args, got %d", op.Op, len(op.Args))
		}
		left, err := eval(op.Args[0], item)
		if err != nil {
			return nil, err
		}
		right, err := eval(op.Args[1], item)
		if err != nil {
			return nil, err
		}
		return compare(op.Op, left, right)
	case cql2.OpIn:
		if len(op.Args) != 2 {
			return nil, fmt.Errorf("cql2 eval: IN expects 2 args, got %d", len(op.Args))
		}
		needle, err := eval(op.Args[0], item)
		if err != nil {
			return nil, err
		}
		hay, err := eval(op.Args[1], item)
		if err != nil {
			return nil, err
		}
		arr, ok := hay.([]interface{})
		if !ok {
			return nil, fmt.Errorf("cql2 eval: IN second arg not array (%T)", hay)
		}
		for _, e := range arr {
			matches, err := compare(cql2.OpEq, needle, e)
			if err != nil {
				return nil, fmt.Errorf("cql2 eval: IN comparator: %w", err)
			}
			if matches {
				return true, nil
			}
		}
		return false, nil
	case cql2.OpIsNull:
		if len(op.Args) != 1 {
			return nil, fmt.Errorf("cql2 eval: ISNULL expects 1 arg, got %d", len(op.Args))
		}
		v, err := eval(op.Args[0], item)
		if err != nil {
			return nil, err
		}
		return v == nil, nil
	case cql2.OpSIntersects:
		return evalSIntersects(op, item)
	}
	return nil, &ErrUnsupportedNode{Kind: "Op:" + string(op.Op)}
}

// evalSIntersects implements the CQL2 S_INTERSECTS spatial predicate
// against an in-memory STAC item. The first argument is expected to be
// a property reference resolving to the item's geometry (typically
// "geometry"); the second is a literal GeoJSON / WKT geometry parsed
// into a *cql2.GeomLit or *cql2.BBoxLit by the CQL2 codec. Either
// argument order is accepted (some encoders flip them).
//
// Behaviour:
//   - Returns false (not error) when the item geometry is null or the
//     property resolves to nil — null-geometry items must drop out of
//     a geofence-filtered result rather than crash the evaluator.
//   - Returns false on any geometry-parse failure on either side; the
//     intersect predicate cannot be evaluated and the item should not
//     pass.
//   - Returns an error only on AST shape problems (wrong arity, both
//     args literals, etc.) since those indicate a malformed query.
func evalSIntersects(op *cql2.Op, item map[string]interface{}) (interface{}, error) {
	if len(op.Args) != 2 {
		return nil, fmt.Errorf("cql2 eval: S_INTERSECTS expects 2 args, got %d", len(op.Args))
	}
	propIdx, litIdx := -1, -1
	for i, a := range op.Args {
		switch a.(type) {
		case *cql2.PropertyRef:
			propIdx = i
		case *cql2.GeomLit, *cql2.BBoxLit:
			litIdx = i
		}
	}
	if propIdx < 0 || litIdx < 0 {
		return nil, &ErrUnsupportedNode{Kind: "Op:s_intersects (need property + literal geometry)"}
	}
	propRef := op.Args[propIdx].(*cql2.PropertyRef)
	itemGeomVal := lookupProperty(item, propRef.Name)
	if itemGeomVal == nil {
		return false, nil
	}
	itemGeom, err := geo.ParseGeoJSON(itemGeomVal)
	if err != nil || itemGeom == nil {
		return false, nil
	}
	litGeoJSON, err := literalToGeoJSON(op.Args[litIdx])
	if err != nil {
		return false, nil
	}
	litGeom, err := geo.ParseGeoJSON(litGeoJSON)
	if err != nil || litGeom == nil {
		return false, nil
	}
	return itemGeom.Intersects(litGeom), nil
}

// literalToGeoJSON converts a CQL2 geometry/bbox literal into a GeoJSON
// blob the geo facade can parse. GeomLit re-uses the cql2/geojson
// encoder; BBoxLit is materialized into a 5-point WGS84 polygon.
func literalToGeoJSON(n cql2.Node) ([]byte, error) {
	switch lit := n.(type) {
	case *cql2.GeomLit:
		return cql2geojson.Encode(lit.Geom)
	case *cql2.BBoxLit:
		var minX, minY, maxX, maxY float64
		switch len(lit.Coords) {
		case 4:
			minX, minY, maxX, maxY = lit.Coords[0], lit.Coords[1], lit.Coords[2], lit.Coords[3]
		case 6:
			minX, minY, maxX, maxY = lit.Coords[0], lit.Coords[1], lit.Coords[3], lit.Coords[4]
		default:
			return nil, fmt.Errorf("cql2 eval: bbox literal needs 4 or 6 coords, got %d", len(lit.Coords))
		}
		poly := map[string]interface{}{
			"type": "Polygon",
			"coordinates": [][][]float64{{
				{minX, minY},
				{maxX, minY},
				{maxX, maxY},
				{minX, maxY},
				{minX, minY},
			}},
		}
		return json.Marshal(poly)
	}
	return nil, fmt.Errorf("cql2 eval: unsupported geometry literal %T", n)
}

// lookupProperty resolves a CQL2 property reference against a STAC
// item. STAC items hold the bulk of their metadata under
// `properties.<name>`, but a few canonical fields (id, collection,
// type, bbox, geometry, datetime) live at the top level. The lookup
// rule:
//   - if the name contains a dot, treat it as a JSON path (best-effort)
//   - otherwise: try item["properties"][name], else item[name]
func lookupProperty(item map[string]interface{}, name string) interface{} {
	if strings.Contains(name, ".") {
		return walkPath(item, strings.Split(name, "."))
	}
	if props, ok := item["properties"].(map[string]interface{}); ok {
		if v, ok := props[name]; ok {
			return v
		}
	}
	return item[name]
}

func walkPath(v interface{}, path []string) interface{} {
	for _, p := range path {
		m, ok := v.(map[string]interface{})
		if !ok {
			return nil
		}
		v = m[p]
	}
	return v
}

// compare evaluates a binary comparison. Numeric types (float64,
// int*, json.Number) are normalised to float64; strings are compared
// lexicographically; mixed types yield false (not error) to avoid
// hard-failing on benign type mismatches in real STAC data.
func compare(op cql2.Operator, left, right interface{}) (bool, error) {
	if left == nil || right == nil {
		// CQL2 null comparisons are unknown → false here for
		// simplicity. Callers needing tri-valued logic can pre-filter
		// with ISNULL.
		if op == cql2.OpEq {
			return left == nil && right == nil, nil
		}
		if op == cql2.OpNeq {
			return !(left == nil && right == nil), nil
		}
		return false, nil
	}

	lf, lok := toFloat(left)
	rf, rok := toFloat(right)
	if lok && rok {
		return numericCmp(op, lf, rf), nil
	}

	ls, lsOK := left.(string)
	rs, rsOK := right.(string)
	if lsOK && rsOK {
		return stringCmp(op, ls, rs), nil
	}

	lb, lbOK := left.(bool)
	rb, rbOK := right.(bool)
	if lbOK && rbOK {
		switch op {
		case cql2.OpEq:
			return lb == rb, nil
		case cql2.OpNeq:
			return lb != rb, nil
		}
	}

	return false, nil
}

func numericCmp(op cql2.Operator, l, r float64) bool {
	switch op {
	case cql2.OpEq:
		return l == r
	case cql2.OpNeq:
		return l != r
	case cql2.OpLt:
		return l < r
	case cql2.OpLte:
		return l <= r
	case cql2.OpGt:
		return l > r
	case cql2.OpGte:
		return l >= r
	}
	return false
}

func stringCmp(op cql2.Operator, l, r string) bool {
	switch op {
	case cql2.OpEq:
		return l == r
	case cql2.OpNeq:
		return l != r
	case cql2.OpLt:
		return l < r
	case cql2.OpLte:
		return l <= r
	case cql2.OpGt:
		return l > r
	case cql2.OpGte:
		return l >= r
	}
	return false
}

func toFloat(v interface{}) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case float32:
		return float64(x), true
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	case int32:
		return float64(x), true
	case json.Number:
		f, err := x.Float64()
		return f, err == nil
	case string:
		f, err := strconv.ParseFloat(x, 64)
		return f, err == nil
	}
	return 0, false
}
