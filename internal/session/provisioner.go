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

// homeRoot is where user homes live. On the multi-user workstation this is a
// SEPARATE, PERSISTENT volume that outlives the instance, while the OS root
// (including /etc/passwd) is wiped and rebuilt on every instance replace. That
// asymmetry is what makes UID adoption necessary — see adoptHomeOwner.
const homeRoot = "/home"

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
	args := []string{"--create-home", "--shell", "/bin/bash"}
	if uid, gid, ok := p.adoptHomeOwner(ctx, username); ok {
		args = append(args, "--uid", uid, "--gid", gid)
	}
	// `--` terminates options so a username can never be parsed as a flag (defense
	// in depth; the identity layer already requires it to start with a letter).
	args = append(args, "--", username)
	if out, err := p.Run(ctx, "useradd", args...); err != nil {
		return fmt.Errorf("local: useradd %q: %w (%s)", username, err, out)
	}
	p.Log.Info("created local user", "user", username)
	return nil
}

// adoptHomeOwner returns the uid/gid that a leftover home directory is already
// owned by, so a recreated account reclaims its own files.
//
// Why this exists: /home is a persistent volume but /etc/passwd is not, so after
// an instance replace `useradd` hands out UIDs in *connect order*. Change who
// logs in first and everyone shifts by one. useradd will not chown an existing
// home (it only warns "the home directory already exists"), so the user lands on
// a home they cannot write and someone else silently inherits their files.
// Adopting the directory's ownership makes the persisted home the source of
// truth and is self-healing for accounts nobody enumerated in advance.
//
// Returns ok=false whenever adoption would be unsafe or pointless; the caller
// then lets useradd pick a UID as before. Adoption is best-effort by design: a
// user who cannot log in at all is worse than one with a shifted UID, so every
// failure path here degrades rather than blocks.
func (p *LocalProvisioner) adoptHomeOwner(ctx context.Context, username string) (uid, gid string, ok bool) {
	home := homeRoot + "/" + username
	out, err := p.Run(ctx, "stat", "-c", "%u:%g", home)
	if err != nil {
		return "", "", false // no leftover home — nothing to adopt
	}
	owner, group, found := strings.Cut(strings.TrimSpace(string(out)), ":")
	if !found {
		return "", "", false
	}
	n, err := strconv.Atoi(owner)
	if err != nil || n < minUserUID {
		// Never adopt a system/service UID: a root-owned home would otherwise
		// escalate the new account straight past the minUserUID guard above.
		p.Log.Warn("not adopting home ownership", "user", username, "uid", owner, "reason", "not a regular uid")
		return "", "", false
	}
	// Only adopt a UID nobody else holds. If it is taken, the persisted state is
	// already inconsistent; log it loudly and fall back rather than refusing to
	// create the account (which would lock the user out entirely).
	if _, err := p.Run(ctx, "getent", "passwd", owner); err == nil {
		p.Log.Warn("home uid already in use by another account; not adopting",
			"user", username, "home", home, "uid", owner)
		return "", "", false
	}
	// useradd --gid requires the group to exist already.
	if _, err := p.Run(ctx, "getent", "group", group); err != nil {
		if out, err := p.Run(ctx, "groupadd", "--gid", group, "--", username); err != nil {
			p.Log.Warn("could not recreate group for adopted home; not adopting",
				"user", username, "gid", group, "err", err, "out", string(out))
			return "", "", false
		}
	}
	p.Log.Info("adopting uid/gid from persisted home", "user", username, "home", home, "uid", owner, "gid", group)
	return owner, group, true
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
