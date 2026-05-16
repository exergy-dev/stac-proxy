package pageadapter

// auto is the default adapter: on first response it probes each named
// adapter and locks the highest-confidence match into NextState.AdapterName.
// On subsequent pages (when the cursor carries an AdapterName), the
// federation layer routes to that named adapter directly — `auto` is
// only consulted on page 0.
//
// auto deliberately does NOT recover from mid-stream selection errors.
// If page 0 says "token" and page 1's response no longer matches the
// token convention, the cursor errors out cleanly. The operator's
// remedy is to configure the adapter explicitly via
// `pagination.adapter: <name>`; auto is a convenience for the common
// case, not a robust mid-stream switcher.
type auto struct{ inner []Adapter }

func newAuto(cfg Config) *auto {
	return &auto{
		inner: []Adapter{
			newToken(cfg),       // most precise — STAC spec compliance
			newOffset(cfg),      // explicit numeric offset
			newLinkHeader(cfg),  // RFC 5988 — header signal beats body fallback
			newNextURL(cfg),     // universal fallback for any rel=next href
		},
	}
}

func (a *auto) Name() string { return "auto" }

func (a *auto) Capture(r UpstreamResponse) (NextState, error) {
	var best NextState
	var bestConf float64
	var bestName string
	for _, inner := range a.inner {
		conf, st := inner.Probe(r)
		if conf > bestConf {
			bestConf = conf
			best = st
			bestName = inner.Name()
		}
	}
	if bestConf == 0 {
		// No adapter matched — either end of pagination, or an
		// unknown convention. Either way, return Done so the cursor
		// retires this origin cleanly.
		return NextState{Done: true}, nil
	}
	best.AdapterName = bestName
	return best, nil
}

// Probe on auto returns its own composite confidence. Pragmatically
// auto wouldn't appear inside another auto, but the interface requires
// the method, so we return the best inner probe.
func (a *auto) Probe(r UpstreamResponse) (float64, NextState) {
	st, _ := a.Capture(r)
	if st.Done {
		return 0, st
	}
	return 1.0, st
}
