package redisstore

import (
	"log/slog"
	"sync/atomic"
	"time"
)

// LogThrottle rate-limits repetitive warnings to one per interval.
//
// With logs-only observability, a dead Redis would otherwise emit one
// warning per request — at proxy request rates that's a log storm that
// buries the signal it is meant to carry. Suppressed occurrences are
// counted and reported on the next emitted line.
type LogThrottle struct {
	interval   time.Duration
	next       atomic.Int64 // unix nanos of the next allowed emission
	suppressed atomic.Int64
}

// NewLogThrottle returns a throttle emitting at most one line per
// interval. Non-positive intervals default to 30s.
func NewLogThrottle(interval time.Duration) *LogThrottle {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	return &LogThrottle{interval: interval}
}

// Warn logs msg at Warn level if the interval has elapsed since the
// last emission; otherwise it increments the suppressed counter. The
// emitted line carries a "suppressed" attribute with the number of
// occurrences swallowed since the previous line.
func (t *LogThrottle) Warn(logger *slog.Logger, msg string, args ...any) {
	if logger == nil {
		return
	}
	now := time.Now().UnixNano()
	deadline := t.next.Load()
	if now < deadline || !t.next.CompareAndSwap(deadline, now+t.interval.Nanoseconds()) {
		t.suppressed.Add(1)
		return
	}
	n := t.suppressed.Swap(0)
	logger.Warn(msg, append(args, "suppressed", n)...)
}
