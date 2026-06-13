// Package idle implements host-wide idle accounting for the multi-user
// workstation: it stops the EC2 instance only after the idle window elapses with
// ZERO active DCV connections across all sessions (spec MU-07). This replaces v1's
// single-console idle check, which would otherwise stop the box under one user
// while another is connected.
package idle

import (
	"context"
	"log/slog"
	"time"
)

// Accountant polls the host-wide connection count and stops the instance after a
// continuous idle window. Count and Stop are injected so the logic is testable
// without DCV or AWS.
type Accountant struct {
	// Count returns the total active DCV connections across all sessions.
	Count func(ctx context.Context) (int, error)
	// Stop stops this instance.
	Stop func(ctx context.Context) error

	IdleTimeout time.Duration
	Interval    time.Duration
	Log         *slog.Logger
}

// nextIdle returns the updated idle accumulator: reset to zero on any connection,
// otherwise grown by one interval.
func nextIdle(current time.Duration, connections int, interval time.Duration) time.Duration {
	if connections > 0 {
		return 0
	}
	return current + interval
}

// shouldStop reports whether the accumulated idle time has reached the timeout.
func shouldStop(idle, timeout time.Duration) bool {
	return idle >= timeout
}

// Run blocks, polling every Interval, and stops the instance once the host has
// been idle (zero connections) for IdleTimeout. Returns when it stops the
// instance or the context is cancelled. A Count error is treated as "not idle"
// (fail-safe: never stop the box on a transient query failure).
func (a *Accountant) Run(ctx context.Context) error {
	if a.IdleTimeout <= 0 {
		a.Log.Info("idle accounting disabled (timeout <= 0)")
		<-ctx.Done()
		return ctx.Err()
	}
	a.Log.Info("idle accounting started", "timeout", a.IdleTimeout, "interval", a.Interval)
	ticker := time.NewTicker(a.Interval)
	defer ticker.Stop()

	var idle time.Duration
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			n, err := a.Count(ctx)
			if err != nil {
				a.Log.Warn("connection count failed; treating host as active", "err", err)
				idle = 0
				continue
			}
			idle = nextIdle(idle, n, a.Interval)
			if n > 0 {
				continue
			}
			a.Log.Info("host idle", "connections", 0, "idleFor", idle, "timeout", a.IdleTimeout)
			if shouldStop(idle, a.IdleTimeout) {
				a.Log.Info("idle window reached; stopping instance")
				if err := a.Stop(ctx); err != nil {
					a.Log.Error("stop instance failed", "err", err)
					idle = 0 // back off and re-accumulate rather than spin
					continue
				}
				return nil
			}
		}
	}
}
