package idle

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"
)

func testLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

func TestNextIdle(t *testing.T) {
	iv := time.Minute
	if got := nextIdle(0, 0, iv); got != iv {
		t.Errorf("idle accumulate from zero: got %v want %v", got, iv)
	}
	if got := nextIdle(5*time.Minute, 0, iv); got != 6*time.Minute {
		t.Errorf("idle keeps accumulating: got %v", got)
	}
	if got := nextIdle(5*time.Minute, 2, iv); got != 0 {
		t.Errorf("any connection resets idle: got %v", got)
	}
}

func TestShouldStop(t *testing.T) {
	if shouldStop(29*time.Minute, 30*time.Minute) {
		t.Error("must not stop before the timeout")
	}
	if !shouldStop(30*time.Minute, 30*time.Minute) {
		t.Error("must stop at the timeout")
	}
}

func TestRun_StopsWhenIdle(t *testing.T) {
	var stopped atomic.Bool
	a := &Accountant{
		Count:       func(context.Context) (int, error) { return 0, nil },
		Stop:        func(context.Context) error { stopped.Store(true); return nil },
		IdleTimeout: 3 * time.Millisecond,
		Interval:    time.Millisecond,
		Log:         testLogger(),
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = a.Run(ctx)
	if !stopped.Load() {
		t.Error("expected Stop after the idle window with zero connections")
	}
}

func TestRun_DoesNotStopWhileActive(t *testing.T) {
	var stops atomic.Int32
	a := &Accountant{
		Count:       func(context.Context) (int, error) { return 1, nil }, // always connected
		Stop:        func(context.Context) error { stops.Add(1); return nil },
		IdleTimeout: 2 * time.Millisecond,
		Interval:    time.Millisecond,
		Log:         testLogger(),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	_ = a.Run(ctx)
	if stops.Load() != 0 {
		t.Errorf("must never stop while a session has a connection; stops=%d", stops.Load())
	}
}

func TestRun_CountErrorIsFailSafe(t *testing.T) {
	var stops atomic.Int32
	a := &Accountant{
		Count:       func(context.Context) (int, error) { return 0, errors.New("dcv unavailable") },
		Stop:        func(context.Context) error { stops.Add(1); return nil },
		IdleTimeout: 2 * time.Millisecond,
		Interval:    time.Millisecond,
		Log:         testLogger(),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	_ = a.Run(ctx)
	if stops.Load() != 0 {
		t.Error("a count error must be treated as active and never stop the box")
	}
}
