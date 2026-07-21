package integration

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/stac-proxy/internal/middleware"
	"github.com/yourorg/stac-proxy/internal/middleware/cache"
	redisstore "github.com/yourorg/stac-proxy/internal/store/redis"
)

// TestIntegration_RedisBackedResponseCache wires the response-cache
// middleware onto a Redis (miniredis) store the same way main.go's
// buildCacheHTTPMiddleware does with `store: redis`, and verifies:
//
//  1. second identical request is served from Redis (HIT, upstream
//     not re-invoked) — the cross-replica coherence primitive;
//  2. a second middleware instance sharing the same Redis (a stand-in
//     for another replica) also HITs — no sticky routing needed;
//  3. after Redis goes down, requests keep succeeding as misses
//     (fail-open), they do not error.
func TestIntegration_RedisBackedResponseCache(t *testing.T) {
	mr := miniredis.RunT(t)
	// Production builder: tight timeouts, no command retries — the
	// outage phase below relies on both to stay fast and fail open.
	client, err := redisstore.New(redisstore.Config{Addr: mr.Addr()})
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	newReplica := func() http.Handler {
		store := redisstore.NewKV(client, redisstore.DefaultKeyPrefix+redisstore.NSResponseCache, nil)
		mw, err := cache.NewFromConfigWithStore(map[string]interface{}{"store": "redis"}, store)
		require.NoError(t, err, "NewFromConfigWithStore")
		var upstreamCalls atomic.Uint32
		inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			upstreamCalls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"type":"FeatureCollection","features":[]}`))
		})
		return mw(inner)
	}

	info := &middleware.STACInfo{RequestType: middleware.RequestTypeCollections}
	doGet := func(h http.Handler) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/collections", nil)
		req = req.WithContext(middleware.WithSTACInfo(req.Context(), info))
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr
	}

	replicaA := newReplica()
	rr := doGet(replicaA)
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "MISS", rr.Header().Get("X-Cache-Status"), "first request must miss")

	rr = doGet(replicaA)
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "HIT", rr.Header().Get("X-Cache-Status"), "second request must hit Redis")

	// A different middleware instance over the same Redis — models a
	// second replica behind a non-sticky load balancer.
	replicaB := newReplica()
	rr = doGet(replicaB)
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "HIT", rr.Header().Get("X-Cache-Status"), "other replica must see the shared entry")

	// TTL behaves: collections default TTL is 5m; after expiry it's a
	// miss again.
	mr.FastForward(6 * time.Minute)
	rr = doGet(replicaA)
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "MISS", rr.Header().Get("X-Cache-Status"), "expired entry must miss")

	// Outage: requests keep flowing as misses.
	mr.Close()
	rr = doGet(replicaA)
	require.Equal(t, http.StatusOK, rr.Code, "redis outage must not fail requests")
	assert.Equal(t, "MISS", rr.Header().Get("X-Cache-Status"))
	rr = doGet(replicaB)
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "MISS", rr.Header().Get("X-Cache-Status"))
}
