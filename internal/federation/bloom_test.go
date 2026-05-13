package federation

import (
	"strconv"
	"sync"
	"testing"
)

func TestItemDeduplicator_FirstSeenReturnsFalse(t *testing.T) {
	d := NewItemDeduplicator(0)
	if d.IsDuplicate("a") {
		t.Fatalf("first sight of a should be unique")
	}
	if !d.IsDuplicate("a") {
		t.Fatalf("second sight of a should be duplicate")
	}
	if d.IsDuplicate("b") {
		t.Fatalf("first sight of b should be unique")
	}
}

func TestItemDeduplicator_Reset(t *testing.T) {
	d := NewItemDeduplicator(0)
	d.IsDuplicate("a")
	d.Reset()
	if d.IsDuplicate("a") {
		t.Fatalf("after Reset, a should be unique again")
	}
}

func TestItemDeduplicator_ManyUnique(t *testing.T) {
	const n = 20000
	d := NewItemDeduplicator(n)
	for i := 0; i < n; i++ {
		if d.IsDuplicate(strconv.Itoa(i)) {
			t.Fatalf("unique key %d reported as duplicate", i)
		}
	}
}

// TestItemDeduplicator_ConcurrentAccessUnderExternalLock documents the
// contract: ItemDeduplicator is NOT internally synchronized; callers
// must serialize access. (The federated merger holds a mutex around
// IsDuplicate calls — see merger.go.)
func TestItemDeduplicator_ConcurrentAccessUnderExternalLock(t *testing.T) {
	d := NewItemDeduplicator(0)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			mu.Lock()
			defer mu.Unlock()
			_ = d.IsDuplicate(strconv.Itoa(i))
		}()
	}
	wg.Wait()
}
