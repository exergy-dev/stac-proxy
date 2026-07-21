package federation

import "sync"

// fanOut runs fn once per input, each on its own goroutine, with at
// most maxConcurrent running at a time (0 = unbounded). Results come
// back in input order — callers that need arrival-independent ordering
// (the merger, partial-result accounting) already sort or filter.
//
// A panic inside fn is recovered and converted through onPanic into
// that input's result slot, so one misbehaving origin cannot take the
// process down mid-fan-out. Pass an onPanic that re-panics to opt out
// of recovery.
//
// Context plumbing is deliberately absent: fn closes over whatever
// ctx (and per-origin timeout) it needs, exactly as the hand-rolled
// fan-outs did.
func fanOut[I, T any](inputs []I, maxConcurrent int, fn func(I) T, onPanic func(I, any) T) []T {
	results := make([]T, len(inputs))
	var sem chan struct{}
	if maxConcurrent > 0 {
		sem = make(chan struct{}, maxConcurrent)
	}
	var wg sync.WaitGroup
	for i, in := range inputs {
		wg.Add(1)
		go func(idx int, in I) {
			defer wg.Done()
			// Recover is registered before the semaphore acquire so a
			// panicking fn still releases its slot (the release defer,
			// registered later, runs first).
			defer func() {
				if r := recover(); r != nil {
					results[idx] = onPanic(in, r)
				}
			}()
			if sem != nil {
				sem <- struct{}{}
				defer func() { <-sem }()
			}
			results[idx] = fn(in)
		}(i, in)
	}
	wg.Wait()
	return results
}
