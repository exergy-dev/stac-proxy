package cache

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yourorg/stac-proxy/internal/middleware"
)

// TestCacheHit_PreservesStatusAndContentType is C-4: cached responses must
// faithfully restore the upstream status code and Content-Type, not
// hardcode 200 + application/json.
func TestCacheHit_PreservesStatusAndContentType(t *testing.T) {
	store := NewMemoryStore(MemoryConfig{MaxSize: 16})
	m := NewMiddleware(Config{Store: store})

	originalHeaders := http.Header{}
	originalHeaders.Set("Content-Type", "application/geo+json")
	originalHeaders.Set("X-Custom", "stac-value")
	originalBody := []byte(`{"type":"FeatureCollection","features":[]}`)

	stacReq := &middleware.STACRequest{
		Request:     httptest.NewRequest("GET", "/collections/x/items", nil),
		Context:     context.Background(),
		RequestType: middleware.RequestTypeItems,
		Collection:  "x",
	}

	// Miss path: ProcessRequest stores the cache key, ProcessResponse caches.
	stacReq, err := m.ProcessRequest(stacReq.Context, stacReq)
	if err != nil {
		t.Fatalf("ProcessRequest (miss): %v", err)
	}
	missResp := &middleware.STACResponse{
		StatusCode: http.StatusOK,
		Headers:    originalHeaders.Clone(),
		Body:       originalBody,
	}
	if _, err := m.ProcessResponse(stacReq.Context, stacReq, missResp); err != nil {
		t.Fatalf("ProcessResponse (miss): %v", err)
	}

	// Hit path: a second request should pick up the cached entry.
	stacReq2 := &middleware.STACRequest{
		Request:     httptest.NewRequest("GET", "/collections/x/items", nil),
		Context:     context.Background(),
		RequestType: middleware.RequestTypeItems,
		Collection:  "x",
	}
	stacReq2, err = m.ProcessRequest(stacReq2.Context, stacReq2)
	if err != nil {
		t.Fatalf("ProcessRequest (hit): %v", err)
	}
	hitResp, err := m.ProcessResponse(stacReq2.Context, stacReq2, nil)
	if err != nil {
		t.Fatalf("ProcessResponse (hit): %v", err)
	}
	if hitResp == nil {
		t.Fatal("ProcessResponse (hit) returned nil response")
	}

	if hitResp.StatusCode != http.StatusOK {
		t.Errorf("status: want 200, got %d", hitResp.StatusCode)
	}
	if got := hitResp.Headers.Get("Content-Type"); got != "application/geo+json" {
		t.Errorf("Content-Type on hit: want application/geo+json, got %q", got)
	}
	if got := hitResp.Headers.Get("X-Custom"); got != "stac-value" {
		t.Errorf("X-Custom on hit: want stac-value, got %q", got)
	}
	if got := hitResp.Headers.Get("X-Cache-Status"); got != "HIT" {
		t.Errorf("X-Cache-Status on hit: want HIT, got %q", got)
	}
	if string(hitResp.Body) != string(originalBody) {
		t.Errorf("body on hit: want %q, got %q", originalBody, hitResp.Body)
	}
}

// TestDoSingleflight_CoalescesConcurrentCallers verifies the cache
// stampede helper invokes the upstream function once when N callers
// arrive concurrently for the same key.
func TestDoSingleflight_CoalescesConcurrentCallers(t *testing.T) {
	store := NewMemoryStore(MemoryConfig{MaxSize: 16})
	m := NewMiddleware(Config{Store: store})

	var callCount int32
	var wg sync.WaitGroup
	const N = 50

	// Block all callers in fn until we release them, so they all queue
	// on the same singleflight entry.
	release := make(chan struct{})
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, _ = m.DoSingleflight("k", func() (any, error) {
				atomic.AddInt32(&callCount, 1)
				<-release
				return "v", nil
			})
		}()
	}

	// Give goroutines a moment to all enqueue.
	time.Sleep(20 * time.Millisecond)
	close(release)
	wg.Wait()

	if got := atomic.LoadInt32(&callCount); got != 1 {
		t.Errorf("upstream fn invoked %d times, expected 1 (stampede protection)", got)
	}
}

// TestCacheStore_DeepCopiesBody is H-13: in-place mutation of the response
// body must not poison the cache.
func TestCacheStore_DeepCopiesBody(t *testing.T) {
	store := NewMemoryStore(MemoryConfig{MaxSize: 16})
	m := NewMiddleware(Config{Store: store})

	stacReq := &middleware.STACRequest{
		Request:     httptest.NewRequest("GET", "/x", nil),
		Context:     context.Background(),
		RequestType: middleware.RequestTypeCollection,
	}
	stacReq, _ = m.ProcessRequest(stacReq.Context, stacReq)

	body := []byte(`{"v":1}`)
	resp := &middleware.STACResponse{
		StatusCode: http.StatusOK,
		Headers:    http.Header{"Content-Type": []string{"application/json"}},
		Body:       body,
	}
	if _, err := m.ProcessResponse(stacReq.Context, stacReq, resp); err != nil {
		t.Fatalf("ProcessResponse: %v", err)
	}
	// Simulate a downstream rewriter mutating the original slice in place.
	for i := range body {
		body[i] = 'X'
	}
	// Wait a heartbeat to make sure the store goroutine isn't racing.
	time.Sleep(10 * time.Millisecond)

	stacReq2 := &middleware.STACRequest{
		Request:     httptest.NewRequest("GET", "/x", nil),
		Context:     context.Background(),
		RequestType: middleware.RequestTypeCollection,
	}
	stacReq2, _ = m.ProcessRequest(stacReq2.Context, stacReq2)
	hit, err := m.ProcessResponse(stacReq2.Context, stacReq2, nil)
	if err != nil {
		t.Fatalf("ProcessResponse (hit): %v", err)
	}
	if string(hit.Body) != `{"v":1}` {
		t.Fatalf("cache was poisoned by in-place mutation: got %q", hit.Body)
	}
}
