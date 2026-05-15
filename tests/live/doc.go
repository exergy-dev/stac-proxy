// Package live contains integration tests that drive the federation
// handler against two real public STAC APIs (Element 84 Earth Search
// and Microsoft Planetary Computer). Every test t.Skips unless the
// STAC_PROXY_LIVE=1 environment variable is set, so the default
// `go test ./...` run is unaffected.
//
// Run with:
//
//	STAC_PROXY_LIVE=1 go test -v -count=1 ./tests/live/...
//
// These tests are intentionally manual / nightly cadence — they hit
// the real public catalogs and will fail on transient upstream
// outages.
//
// # On `-race`
//
// Do not run these tests with `-race`. The upstream go-stac-client
// library implements custom MarshalJSON/UnmarshalJSON on its core
// types that themselves call json.Marshal / json.Unmarshal a second
// time over the same input (the "alias struct + foreign-member map"
// pattern). Go's race detector sometimes flags these nested encoder
// calls as conflicting writes on the encoding/json sync.Pool buffers
// even when all operations happen sequentially in a single
// goroutine. The failure is a false positive — the unit tests pass
// cleanly under `-race ./internal/...` — but it makes the live tests
// non-deterministic under the race detector.
package live
