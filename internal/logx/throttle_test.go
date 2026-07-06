package logx

import (
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestLogThrottle_SuppressesWithinInterval(t *testing.T) {
	t.Parallel()
	tt := NewLogThrottle(time.Hour)
	// First call emits, the rest are suppressed; we only assert no
	// panic and that the suppressed counter accumulates.
	logger := slog.Default()
	for i := 0; i < 100; i++ {
		tt.Warn(logger, "boom")
	}
	assert.Equal(t, int64(99), tt.suppressed.Load())
	tt.Warn(nil, "nil logger is a no-op")
}
