package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// helper: build a JWKS document from a list of (kid, *rsa.PublicKey)
// pairs and return the JSON bytes.
func jwksJSON(pairs ...struct {
	kid string
	pub *rsa.PublicKey
}) []byte {
	resp := JWKSResponse{}
	for _, p := range pairs {
		resp.Keys = append(resp.Keys, JWK{
			Kty: "RSA",
			Kid: p.kid,
			Use: "sig",
			N:   base64.RawURLEncoding.EncodeToString(p.pub.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(p.pub.E)).Bytes()),
		})
	}
	b, _ := json.Marshal(resp)
	return b
}

// helper: spin up a JWKS server returning the given JSON; count GETs
// so tests can assert caching behaviour.
func newJWKSServer(t *testing.T, body func() []byte) (*httptest.Server, *int64) {
	t.Helper()
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		w.Write(body())
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func mintRS256(t *testing.T, priv *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	signed, err := tok.SignedString(priv)
	require.NoError(t, err, "sign")
	return signed
}

// TestJWKS_UnknownKidDoesNotFloodIdP exercises the flood-floor +
// negative-cache contract (HIGH H-auth-2): an attacker presenting
// tokens with random unknown kids must not be able to make the JWKS
// client hammer the IdP. With defaults (30s min-refresh + 60s negative
// cache), 100 concurrent unknown-kid lookups must result in at most
// a handful of upstream requests — singleflight collapses concurrent
// refreshes, the negative cache memoises the absence per-kid, and
// the floor blocks attempts to refresh again until 30s have elapsed.
func TestJWKS_UnknownKidDoesNotFloodIdP(t *testing.T) {
	srv, hits := newJWKSServer(t, func() []byte {
		// Always serve an empty key set. Every kid lookup is a miss.
		return []byte(`{"keys":[]}`)
	})

	c, err := NewJWKSClient(srv.URL, JWKSClientConfig{
		TTL:               time.Hour,
		AllowInsecureHTTP: true,
		// Defaults: 30s floor, 60s negative cache.
	})
	require.NoError(t, err, "NewJWKSClient")

	ctx := context.Background()
	const N = 100
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func(idx int) {
			defer wg.Done()
			// Mix of "always the same unknown kid" and "many distinct
			// unknown kids" — the latter is the realistic attack
			// shape (random kids per request).
			kid := fmt.Sprintf("attacker-kid-%d", idx)
			_, _ = c.Key(ctx, kid)
		}(i)
	}
	wg.Wait()

	got := atomic.LoadInt64(hits)
	// Singleflight collapses concurrent refreshes to one in-flight
	// request, so a single refresh is the expected steady state.
	// Allow a small margin for serial bursts that arrive after a
	// just-finished refresh (clock resolution): cap at 5.
	require.LessOrEqual(t, got, int64(5), "want ≤ 5 JWKS GETs under unknown-kid flood, got %d", got)
	require.GreaterOrEqual(t, got, int64(1), "want ≥ 1 JWKS GET (the initial refresh attempt), got 0")
}

// TestJWKS_NegativeCacheClearedOnSuccessfulRefresh verifies a kid that
// was negative-cached is allowed to succeed once a refresh actually
// publishes it (rotation path must not be blocked by the floor once
// the publishing event happens).
func TestJWKS_NegativeCacheClearedOnSuccessfulRefresh(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	var serveKey atomic.Bool
	srv, _ := newJWKSServer(t, func() []byte {
		if serveKey.Load() {
			return jwksJSON(struct {
				kid string
				pub *rsa.PublicKey
			}{"new-kid", &priv.PublicKey})
		}
		return []byte(`{"keys":[]}`)
	})

	// Tight clock so the test doesn't have to wait real seconds.
	c, err := NewJWKSClient(srv.URL, JWKSClientConfig{
		TTL:                time.Hour,
		AllowInsecureHTTP:  true,
		MinRefreshInterval: time.Nanosecond,
		NegativeCacheTTL:   time.Nanosecond,
	})
	require.NoError(t, err, "NewJWKSClient")
	ctx := context.Background()

	// First lookup: kid absent → negative-cached.
	_, err = c.Key(ctx, "new-kid")
	require.Error(t, err, "want error for absent kid")

	// Now publish it.
	serveKey.Store(true)

	// Wait long enough for both the floor and the negative-cache TTL
	// to elapse. With both at 1ns this is immediate.
	time.Sleep(time.Microsecond)
	_, err = c.Key(ctx, "new-kid")
	require.NoError(t, err, "rotation lookup")
}

// TestJWKS_RejectsEncKeysAndLogsParseErrors verifies the use=sig filter
// (M-auth-2) and that JWK parse errors are logged with structured fields
// rather than silently dropped.
func TestJWKS_RejectsEncKeysAndLogsParseErrors(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	good := JWK{
		Kty: "RSA",
		Kid: "good",
		Use: "sig",
		N:   base64.RawURLEncoding.EncodeToString(priv.PublicKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(priv.PublicKey.E)).Bytes()),
	}
	encKey := JWK{
		Kty: "RSA",
		Kid: "enc-only",
		Use: "enc",
		N:   base64.RawURLEncoding.EncodeToString(priv.PublicKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(priv.PublicKey.E)).Bytes()),
	}
	malformed := JWK{
		Kty: "RSA",
		Kid: "broken",
		Use: "sig",
		N:   "!!!not-base64!!!",
		E:   "AQAB",
	}
	doc, _ := json.Marshal(JWKSResponse{Keys: []JWK{good, encKey, malformed}})

	srv, _ := newJWKSServer(t, func() []byte { return doc })

	// Capture slog output through a JSON handler so we can assert on
	// the structured fields (jwk_kid / jwk_use).
	var buf logBuffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	logger := slog.New(handler)

	c, err := NewJWKSClient(srv.URL, JWKSClientConfig{
		AllowInsecureHTTP: true,
		Logger:            logger,
	})
	require.NoError(t, err, "NewJWKSClient")
	ctx := context.Background()

	// The good key should be available.
	_, err = c.Key(ctx, "good")
	require.NoError(t, err, "good key fetch")
	// The enc-use key must NOT be admitted.
	_, err = c.Key(ctx, "enc-only")
	require.Error(t, err, "want error for use=enc kid; the key should not have been cached")
	// The malformed key must NOT be admitted.
	_, err = c.Key(ctx, "broken")
	require.Error(t, err, "want error for malformed kid; parse error should have skipped it")

	// Internal sanity: the cache contains exactly the good kid.
	c.mu.RLock()
	cached := make([]string, 0, len(c.keys))
	for k := range c.keys {
		cached = append(cached, k)
	}
	c.mu.RUnlock()
	require.Len(t, cached, 1, "want only [good] cached, got %v", cached)
	require.Equal(t, "good", cached[0], "want only [good] cached, got %v", cached)

	// Verify the structured log entries reference the offending kids.
	out := buf.String()
	assert.Contains(t, out, `"jwk_kid":"enc-only"`, "expected enc-only kid in warning")
	assert.Contains(t, out, `"jwk_use":"enc"`, "expected use=enc in warning")
	assert.Contains(t, out, `"jwk_kid":"broken"`, "expected broken kid in parse-error warning")
}

// logBuffer is a minimal sync io.Writer for capturing slog JSON output
// without pulling in bytes.Buffer's lack of safety under goroutines.
type logBuffer struct {
	mu  sync.Mutex
	buf []byte
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	b.buf = append(b.buf, p...)
	b.mu.Unlock()
	return len(p), nil
}

func (b *logBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(b.buf)
}

// TestJWKS_StaleWhileRevalidate_KeepsServingDuringOutage verifies the
// stale-while-revalidate contract (M-auth-1): once the soft TTL has
// elapsed, the cached key is still returned without blocking on the
// upstream, and a background refresh is kicked off. On IdP outage the
// cached key is served until the hard TTL elapses.
func TestJWKS_StaleWhileRevalidate_KeepsServingDuringOutage(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)

	var fail atomic.Bool
	srv, hits := newJWKSServer(t, func() []byte {
		if fail.Load() {
			// Simulate IdP outage. We can't return an error from the
			// test handler easily; instead we return a 500 status by
			// signalling via panic-recovery. Wrap below.
			return nil
		}
		return jwksJSON(struct {
			kid string
			pub *rsa.PublicKey
		}{"k1", &priv.PublicKey})
	})
	// Replace the test server's handler so we can return 500 during
	// the "outage" phase.
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(hits, 1)
		if fail.Load() {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksJSON(struct {
			kid string
			pub *rsa.PublicKey
		}{"k1", &priv.PublicKey}))
	})

	// Injectable clock so we can fast-forward past the soft TTL
	// without sleeping in real time.
	now := time.Now()
	mu := sync.Mutex{}
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	advance := func(d time.Duration) {
		mu.Lock()
		now = now.Add(d)
		mu.Unlock()
	}

	c, err := NewJWKSClient(srv.URL, JWKSClientConfig{
		TTL:                time.Minute,      // soft
		HardTTL:            10 * time.Minute, // hard
		AllowInsecureHTTP:  true,
		MinRefreshInterval: time.Nanosecond, // not relevant to this test
	})
	require.NoError(t, err, "NewJWKSClient")
	c.now = clock

	ctx := context.Background()

	// Initial fetch populates the cache.
	_, err = c.Key(ctx, "k1")
	require.NoError(t, err, "initial fetch")
	initialHits := atomic.LoadInt64(hits)
	require.Equal(t, int64(1), initialHits, "want 1 initial GET")

	// Now break the upstream and advance past the soft TTL.
	fail.Store(true)
	advance(2 * time.Minute)

	// Foreground call must not block on the upstream. We measure
	// elapsed time as a sanity check — should be effectively
	// instantaneous (microseconds, not seconds).
	start := time.Now()
	got, err := c.Key(ctx, "k1")
	elapsed := time.Since(start)
	require.NoError(t, err, "stale fetch")
	require.NotNil(t, got, "want stale-cached key")
	require.LessOrEqual(t, elapsed, 500*time.Millisecond, "stale fetch should not block on upstream; took %v", elapsed)

	// The background refresh should have been kicked off; wait briefly
	// for it to attempt the upstream and bump the hits counter.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt64(hits) > initialHits {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	require.Greater(t, atomic.LoadInt64(hits), initialHits, "background refresh did not query upstream; hits stayed at %d", initialHits)

	// Even after the failed background refresh, subsequent foreground
	// calls (still under HardTTL) keep returning the cached key.
	_, err = c.Key(ctx, "k1")
	require.NoError(t, err, "post-refresh stale fetch")

	// Past the hard TTL, the entries are treated as missing. With the
	// upstream still failing, the foreground refresh now surfaces an
	// error.
	advance(15 * time.Minute)
	_, err = c.Key(ctx, "k1")
	require.Error(t, err, "want error past HardTTL with failing upstream")
}

// silence unused-import vet checks; only here for future debug taps.
var _ = httputil.DumpRequest
var _ = fmt.Sprintf
