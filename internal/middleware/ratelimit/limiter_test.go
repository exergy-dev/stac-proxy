package ratelimit

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// TokenBucketLimiter is a thin wrapper around golang.org/x/time/rate
// with an LRU bucket map. These tests cover the surface this package
// adds on top of the library: the LRU cap (defense against attacker IP
// rotation), basic Allow accounting, and the deny-path RetryAfter.

// HIGH H-observability-1: inserting many distinct keys must not grow
// past the configured cap.
func TestLimiter_BoundsMapSizeUnderIPFlood(t *testing.T) {
	const max = 1024
	lim := NewTokenBucketLimiter(max)
	defer lim.Stop()

	ctx := context.Background()
	q := Quota{Requests: 100, Window: time.Minute}
	for i := 0; i < max*4; i++ {
		key := fmt.Sprintf("ip:198.51.100.%d", i)
		if _, _, err := lim.Allow(ctx, key, q); err != nil {
			t.Fatalf("Allow(%q): %v", key, err)
		}
	}
	if got := lim.buckets.Len(); got > max {
		t.Fatalf("bucket count %d exceeds cap %d", got, max)
	}
}

func TestLimiter_DenyAfterBurst(t *testing.T) {
	lim := NewTokenBucketLimiter(0)
	defer lim.Stop()
	ctx := context.Background()
	q := Quota{Requests: 10, Window: time.Second, Burst: 2}

	if ok, _, _ := lim.Allow(ctx, "k", q); !ok {
		t.Fatal("first request should be allowed")
	}
	if ok, _, _ := lim.Allow(ctx, "k", q); !ok {
		t.Fatal("second request (within burst) should be allowed")
	}
	ok, info, _ := lim.Allow(ctx, "k", q)
	if ok {
		t.Fatal("third request (over burst) should be denied")
	}
	if info.RetryAfter < 1 {
		t.Fatalf("RetryAfter should be >=1, got %d", info.RetryAfter)
	}
}

func TestLimiter_QuotaChangeRebuildsBucket(t *testing.T) {
	lim := NewTokenBucketLimiter(0)
	defer lim.Stop()
	ctx := context.Background()

	// Consume the entire burst under the first quota.
	q1 := Quota{Requests: 1, Window: time.Second, Burst: 1}
	if ok, _, _ := lim.Allow(ctx, "k", q1); !ok {
		t.Fatal("first request should be allowed under q1")
	}
	if ok, _, _ := lim.Allow(ctx, "k", q1); ok {
		t.Fatal("expected deny under q1 after burst exhausted")
	}

	// New quota shape rebuilds the bucket (no carryover by design).
	q2 := Quota{Requests: 10, Window: time.Second, Burst: 5}
	if ok, _, _ := lim.Allow(ctx, "k", q2); !ok {
		t.Fatal("expected allow under q2 (fresh bucket)")
	}
}

func TestLimiter_InfoLimit(t *testing.T) {
	lim := NewTokenBucketLimiter(0)
	defer lim.Stop()
	q := Quota{Requests: 42, Window: time.Minute, Burst: 5}
	_, info, _ := lim.Allow(context.Background(), "k", q)
	if info.Limit != 42 {
		t.Fatalf("Info.Limit=%d, want 42", info.Limit)
	}
}

func TestDefaultKeyFunc(t *testing.T) {
	if got := DefaultKeyFunc(context.Background(), "alice", "1.2.3.4"); got != "user:alice" {
		t.Fatalf("principal path got=%q", got)
	}
	if got := DefaultKeyFunc(context.Background(), "anonymous", "1.2.3.4"); got != "ip:1.2.3.4" {
		t.Fatalf("anonymous path got=%q", got)
	}
	if got := DefaultKeyFunc(context.Background(), "", "1.2.3.4"); got != "ip:1.2.3.4" {
		t.Fatalf("empty principal path got=%q", got)
	}
}
