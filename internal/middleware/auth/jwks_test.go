package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
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
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

func TestJWKSClient_CachesAndRotates(t *testing.T) {
	priv1, _ := rsa.GenerateKey(rand.Reader, 2048)
	priv2, _ := rsa.GenerateKey(rand.Reader, 2048)

	// JWKS body starts with only kid "k1"; we flip it to include "k2"
	// after the first request to simulate key rotation.
	var serveK2 atomic.Bool
	srv, hits := newJWKSServer(t, func() []byte {
		if serveK2.Load() {
			return jwksJSON(
				struct {
					kid string
					pub *rsa.PublicKey
				}{"k1", &priv1.PublicKey},
				struct {
					kid string
					pub *rsa.PublicKey
				}{"k2", &priv2.PublicKey},
			)
		}
		return jwksJSON(struct {
			kid string
			pub *rsa.PublicKey
		}{"k1", &priv1.PublicKey})
	})

	// Disable the unknown-kid refresh floor for this test — we want to
	// observe the rotation refresh immediately. The flood-floor
	// behaviour itself is exercised in TestJWKS_UnknownKidDoesNotFloodIdP.
	c, err := NewJWKSClientFromConfig(srv.URL, JWKSClientConfig{
		TTL:                time.Hour,
		AllowInsecureHTTP:  true,
		MinRefreshInterval: time.Nanosecond,
	})
	if err != nil {
		t.Fatalf("NewJWKSClient: %v", err)
	}
	ctx := context.Background()

	// First fetch populates the cache.
	if _, err := c.Key(ctx, "k1"); err != nil {
		t.Fatalf("k1 first: %v", err)
	}
	// Second fetch should hit the cache (no extra HTTP).
	if _, err := c.Key(ctx, "k1"); err != nil {
		t.Fatalf("k1 second: %v", err)
	}
	if got := atomic.LoadInt64(hits); got != 1 {
		t.Fatalf("want 1 JWKS GET, got %d", got)
	}

	// Now ask for k2 — cache miss should force a refresh.
	serveK2.Store(true)
	if _, err := c.Key(ctx, "k2"); err != nil {
		t.Fatalf("k2 after rotation: %v", err)
	}
	if got := atomic.LoadInt64(hits); got != 2 {
		t.Fatalf("want 2 GETs after rotation, got %d", got)
	}
}

func TestBearerProvider_VerifiesJWTAgainstJWKS(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv, _ := newJWKSServer(t, func() []byte {
		return jwksJSON(struct {
			kid string
			pub *rsa.PublicKey
		}{"primary", &priv.PublicKey})
	})

	p, err := NewBearerProvider(BearerConfig{
		Name:                  "bearer",
		Issuer:                "https://issuer.example.com",
		Audience:              "stac-proxy",
		JWKSURL:               srv.URL,
		AllowInsecureHTTPJWKS: true,
	})
	if err != nil {
		t.Fatalf("NewBearerProvider: %v", err)
	}

	token := mintRS256(t, priv, "primary", jwt.MapClaims{
		"iss": "https://issuer.example.com",
		"aud": "stac-proxy",
		"sub": "user-42",
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	princ, err := p.Authenticate(req.Context(), req)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if princ == nil {
		t.Fatal("nil principal")
	}
	if princ.ID != "user-42" {
		t.Fatalf("want sub=user-42, got %q", princ.ID)
	}
}

func TestBearerProvider_RejectsExpiredToken(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv, _ := newJWKSServer(t, func() []byte {
		return jwksJSON(struct {
			kid string
			pub *rsa.PublicKey
		}{"primary", &priv.PublicKey})
	})

	p, _ := NewBearerProvider(BearerConfig{
		Name:                  "bearer",
		Issuer:                "https://issuer.example.com",
		JWKSURL:               srv.URL,
		AllowInsecureHTTPJWKS: true,
	})

	token := mintRS256(t, priv, "primary", jwt.MapClaims{
		"iss": "https://issuer.example.com",
		"sub": "user-1",
		"exp": time.Now().Add(-time.Hour).Unix(), // expired
	})
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	if _, err := p.Authenticate(req.Context(), req); err == nil {
		t.Fatal("want error for expired token")
	}
}

func TestParseRSAKey_AndECKey_RoundTrip(t *testing.T) {
	// RSA round-trip
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwk := JWK{
		Kty: "RSA",
		N:   base64.RawURLEncoding.EncodeToString(priv.PublicKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(priv.PublicKey.E)).Bytes()),
	}
	got, err := parseRSAKey(jwk)
	if err != nil {
		t.Fatalf("parseRSAKey: %v", err)
	}
	rsaKey, ok := got.(*rsa.PublicKey)
	if !ok {
		t.Fatal("not *rsa.PublicKey")
	}
	if rsaKey.N.Cmp(priv.PublicKey.N) != 0 || rsaKey.E != priv.PublicKey.E {
		t.Fatal("RSA key mismatch")
	}

	// EC round-trip
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecJWK := JWK{
		Kty: "EC",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(ec.PublicKey.X.Bytes()),
		Y:   base64.RawURLEncoding.EncodeToString(ec.PublicKey.Y.Bytes()),
	}
	gotEC, err := parseECKey(ecJWK)
	if err != nil {
		t.Fatalf("parseECKey: %v", err)
	}
	ecKey, ok := gotEC.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("not *ecdsa.PublicKey")
	}
	if ecKey.X.Cmp(ec.PublicKey.X) != 0 || ecKey.Y.Cmp(ec.PublicKey.Y) != 0 {
		t.Fatal("EC key mismatch")
	}
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

	c, err := NewJWKSClientFromConfig(srv.URL, JWKSClientConfig{
		TTL:               time.Hour,
		AllowInsecureHTTP: true,
		// Defaults: 30s floor, 60s negative cache.
	})
	if err != nil {
		t.Fatalf("NewJWKSClient: %v", err)
	}

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
	if got > 5 {
		t.Fatalf("want ≤ 5 JWKS GETs under unknown-kid flood, got %d", got)
	}
	if got == 0 {
		t.Fatalf("want ≥ 1 JWKS GET (the initial refresh attempt), got 0")
	}
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
	c, err := NewJWKSClientFromConfig(srv.URL, JWKSClientConfig{
		TTL:                time.Hour,
		AllowInsecureHTTP:  true,
		MinRefreshInterval: time.Nanosecond,
		NegativeCacheTTL:   time.Nanosecond,
	})
	if err != nil {
		t.Fatalf("NewJWKSClient: %v", err)
	}
	ctx := context.Background()

	// First lookup: kid absent → negative-cached.
	if _, err := c.Key(ctx, "new-kid"); err == nil {
		t.Fatal("want error for absent kid")
	}

	// Now publish it.
	serveKey.Store(true)

	// Wait long enough for both the floor and the negative-cache TTL
	// to elapse. With both at 1ns this is immediate.
	time.Sleep(time.Microsecond)
	if _, err := c.Key(ctx, "new-kid"); err != nil {
		t.Fatalf("rotation lookup: %v", err)
	}
}

// silence unused-import vet checks; only here for future debug taps.
var _ = httputil.DumpRequest
var _ = fmt.Sprintf
