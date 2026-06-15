package main

import (
	"strings"
	"testing"
	"time"
)

func TestStatusString_IdleEnabled(t *testing.T) {
	s := status{
		Version:      "1.2.3",
		Platform:     "linux/amd64",
		Addr:         "127.0.0.1:8444",
		Provisioning: "local",
		IdleTimeout:  30 * time.Minute,
		IdleInterval: time.Minute,
	}
	out := s.String()
	for _, want := range []string{"dcv-session-agent 1.2.3", "linux/amd64", "127.0.0.1:8444", "provisioning:  local", "idle-stop:     30m0s"} {
		if !strings.Contains(out, want) {
			t.Errorf("status output missing %q\n%s", want, out)
		}
	}
}

func TestStatusString_IdleDisabled(t *testing.T) {
	s := status{Version: "dev", Provisioning: "sssd", IdleTimeout: 0}
	if out := s.String(); !strings.Contains(out, "idle-stop:     disabled") {
		t.Errorf("expected idle-stop disabled, got:\n%s", out)
	}
}
