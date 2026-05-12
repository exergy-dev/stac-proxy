package stac

import "encoding/json"

// MarshalJSON serialises Properties by flattening its Extra map into
// the top-level object alongside the known fields. Without this,
// extension properties like "eo:cloud_cover" and proxy-added metadata
// like "stac_proxy:origin" would be silently dropped because Extra
// itself is tagged json:"-".
func (p Properties) MarshalJSON() ([]byte, error) {
	type plain Properties // alias to avoid recursion
	known, err := json.Marshal(plain(p))
	if err != nil {
		return nil, err
	}
	if len(p.Extra) == 0 {
		return known, nil
	}
	merged := make(map[string]json.RawMessage)
	if err := json.Unmarshal(known, &merged); err != nil {
		return nil, err
	}
	for k, v := range p.Extra {
		// Extra fields don't overwrite known fields — known wins on conflict.
		if _, ok := merged[k]; ok {
			continue
		}
		raw, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		merged[k] = raw
	}
	return json.Marshal(merged)
}

// UnmarshalJSON populates Properties from a JSON object, routing
// known field names to their struct fields and the remainder into
// Extra. This is the inverse of MarshalJSON above and lets STAC
// extensions and proxy metadata round-trip correctly.
func (p *Properties) UnmarshalJSON(data []byte) error {
	type plain Properties
	var tmp plain
	if err := json.Unmarshal(data, &tmp); err != nil {
		return err
	}
	*p = Properties(tmp)
	var all map[string]json.RawMessage
	if err := json.Unmarshal(data, &all); err != nil {
		return err
	}
	known := map[string]struct{}{
		"datetime":       {},
		"created":        {},
		"updated":        {},
		"start_datetime": {},
		"end_datetime":   {},
		"title":          {},
	}
	extra := make(map[string]interface{}, len(all))
	for k, v := range all {
		if _, ok := known[k]; ok {
			continue
		}
		var x interface{}
		if err := json.Unmarshal(v, &x); err != nil {
			return err
		}
		extra[k] = x
	}
	if len(extra) > 0 {
		p.Extra = extra
	}
	return nil
}
