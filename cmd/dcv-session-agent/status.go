package main

import (
	"context"
	"fmt"
	"log/slog"
	"runtime"
	"time"

	"github.com/vhco-pro/dcv-session-agent/internal/session"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "dev"

// status is the resolved runtime configuration, printed by `dcv-session-agent --status`
// so an operator can see what was auto-detected vs configured (spec §11 / AC-16).
type status struct {
	Version      string
	Platform     string
	Addr         string
	Provisioning string
	IdleTimeout  time.Duration
	IdleInterval time.Duration
}

func resolveStatus(ctx context.Context) status {
	prov := session.DetectProvisioner(ctx, session.DefaultRunner, slog.New(slog.DiscardHandler))
	return status{
		Version:      version,
		Platform:     runtime.GOOS + "/" + runtime.GOARCH,
		Addr:         getenv("WSA_ADDR", "127.0.0.1:8444"),
		Provisioning: prov.Name(),
		IdleTimeout:  getDuration("WSA_IDLE_TIMEOUT", 30*time.Minute),
		IdleInterval: getDuration("WSA_IDLE_INTERVAL", time.Minute),
	}
}

func (s status) String() string {
	idle := "disabled"
	if s.IdleTimeout > 0 {
		idle = fmt.Sprintf("%s (poll every %s)", s.IdleTimeout, s.IdleInterval)
	}
	return fmt.Sprintf(`dcv-session-agent %s (%s)
  listen:        %s
  provisioning:  %s   (auto-detected; override WSA_PROVISIONING)
  idle-stop:     %s
`, s.Version, s.Platform, s.Addr, s.Provisioning, idle)
}
