// Package authz decides whether a verified user may obtain and connect to a
// session (spec MU-09 / D3).
//
// Default is "anyone with a valid AWS identity is allowed" — reaching the box
// already required IAM permission for the SSM tunnel, so that IS the gate, with
// no second list to maintain. Deployments can tighten to an OS group (works with
// SSSD directory groups) or a static allowlist file.
package authz

import (
	"bufio"
	"context"
	"os"
	"strings"
)

// Authorizer reports whether username may use the workstation.
type Authorizer interface {
	Allowed(ctx context.Context, username string) (bool, error)
}

// Runner runs a command (same shape as session.Runner) for group lookups.
type Runner func(ctx context.Context, name string, args ...string) ([]byte, error)

// AllowAll authorizes any validated identity (default; "ssmIdentity").
type AllowAll struct{}

func (AllowAll) Allowed(context.Context, string) (bool, error) { return true, nil }

// Allowlist authorizes only usernames listed in a file (one per line; blank
// lines and `#` comments ignored).
type Allowlist struct{ Path string }

func (a Allowlist) Allowed(_ context.Context, username string) (bool, error) {
	f, err := os.Open(a.Path)
	if err != nil {
		return false, err
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line == username {
			return true, nil
		}
	}
	return false, sc.Err()
}

// Group authorizes only users who are members of an OS group (membership via
// `id -nG`, which resolves local and directory/SSSD groups alike).
type Group struct {
	Name string
	Run  Runner
}

func (g Group) Allowed(ctx context.Context, username string) (bool, error) {
	out, err := g.Run(ctx, "id", "-nG", username)
	if err != nil {
		return false, err
	}
	for _, grp := range strings.Fields(string(out)) {
		if grp == g.Name {
			return true, nil
		}
	}
	return false, nil
}

// Parse builds an Authorizer from a config spec:
//
//	""  | "ssmIdentity"      -> AllowAll (default)
//	"allowlist:/etc/wsa/allow" -> Allowlist
//	"group:dcv-users"        -> Group
func Parse(spec string, run Runner) Authorizer {
	switch {
	case strings.HasPrefix(spec, "allowlist:"):
		return Allowlist{Path: strings.TrimPrefix(spec, "allowlist:")}
	case strings.HasPrefix(spec, "group:"):
		return Group{Name: strings.TrimPrefix(spec, "group:"), Run: run}
	default:
		return AllowAll{}
	}
}
