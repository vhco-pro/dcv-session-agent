// Package session ensures a per-user Linux account, home, and virtual DCV
// session exist on demand — the trigger DCV lacks natively (spec R1 / §12.4),
// since external token auth bypasses PAM and there is no login hook to lazily
// create the session.
package session

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strconv"
	"strings"
)

// minUserUID is the floor for a regular (non-system) account. The agent refuses
// to provision or adopt any account below it, so a username that slipped past the
// identity-mapping guard can never land a colleague in a system/service account.
const minUserUID = 1000

// Runner executes a command and returns its combined output. It is the single
// boundary to the OS, injected so the package is fully unit-testable.
type Runner func(ctx context.Context, name string, args ...string) ([]byte, error)

// DefaultRunner runs commands for real via os/exec.
func DefaultRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

// Provisioner ensures a Linux user (and home) exists for a verified identity.
// Two implementations ship and are interchangeable (spec ADR-4 / D1):
//   - LocalProvisioner — creates users on demand; no directory dependency.
//   - SSSDProvisioner  — resolves users from a joined directory; never creates.
type Provisioner interface {
	// EnsureUser makes username a usable local account with a home directory.
	EnsureUser(ctx context.Context, username string) error
	// Name is the backend identifier ("local" | "sssd").
	Name() string
}

// LocalProvisioner creates local users on demand. The org-agnostic default.
type LocalProvisioner struct {
	Run Runner
	Log *slog.Logger
}

func (p *LocalProvisioner) Name() string { return "local" }

// EnsureUser creates the user with a home directory and shell if absent. No
// password is ever set — identity is proven by the AWS token, not a secret
// (spec NF-01).
func (p *LocalProvisioner) EnsureUser(ctx context.Context, username string) error {
	if out, err := p.Run(ctx, "id", "-u", username); err == nil {
		// Already exists — refuse to adopt a system/service account (UID < 1000).
		uid, perr := strconv.Atoi(strings.TrimSpace(string(out)))
		if perr != nil || uid < minUserUID {
			return fmt.Errorf("local: refusing to use existing non-regular account %q (uid %q)", username, strings.TrimSpace(string(out)))
		}
		return nil
	}
	// `--` terminates options so a username can never be parsed as a flag (defense
	// in depth; the identity layer already requires it to start with a letter).
	if out, err := p.Run(ctx, "useradd", "--create-home", "--shell", "/bin/bash", "--", username); err != nil {
		return fmt.Errorf("local: useradd %q: %w (%s)", username, err, out)
	}
	p.Log.Info("created local user", "user", username)
	return nil
}

// SSSDProvisioner resolves users from a joined directory (AWS IAM Identity
// Center / Managed AD via SSSD). It validates that the user resolves; it never
// creates accounts. Homes are provisioned by pam_mkhomedir/oddjobd in directory
// setups.
type SSSDProvisioner struct {
	Run Runner
	Log *slog.Logger
}

func (p *SSSDProvisioner) Name() string { return "sssd" }

func (p *SSSDProvisioner) EnsureUser(ctx context.Context, username string) error {
	if _, err := p.Run(ctx, "getent", "passwd", username); err != nil {
		return fmt.Errorf("sssd: user %q does not resolve via the directory: %w", username, err)
	}
	return nil
}

// DetectProvisioner picks the backend per spec D1: a directory-joined host
// (SSSD active) → sssd; otherwise → local. Overridable by config.
func DetectProvisioner(ctx context.Context, run Runner, log *slog.Logger) Provisioner {
	if _, err := run(ctx, "systemctl", "is-active", "--quiet", "sssd"); err == nil {
		log.Info("provisioning backend auto-detected", "backend", "sssd")
		return &SSSDProvisioner{Run: run, Log: log}
	}
	log.Info("provisioning backend auto-detected", "backend", "local")
	return &LocalProvisioner{Run: run, Log: log}
}
