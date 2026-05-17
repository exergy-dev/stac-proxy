package federation

import (
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestItemDeduplicator_FirstSeenReturnsFalse(t *testing.T) {
	d := NewItemDeduplicator(0)
	require.False(t, d.IsDuplicate("a"), "first sight of a should be unique")
	require.True(t, d.IsDuplicate("a"), "second sight of a should be duplicate")
	require.False(t, d.IsDuplicate("b"), "first sight of b should be unique")
}

func TestItemDeduplicator_Reset(t *testing.T) {
	d := NewItemDeduplicator(0)
	d.IsDuplicate("a")
	d.Reset()
	require.False(t, d.IsDuplicate("a"), "after Reset, a should be unique again")
}

func TestItemDeduplicator_ManyUnique(t *testing.T) {
	const n = 20000
	d := NewItemDeduplicator(n)
	for i := 0; i < n; i++ {
		require.Falsef(t, d.IsDuplicate(strconv.Itoa(i)), "unique key %d reported as duplicate", i)
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
