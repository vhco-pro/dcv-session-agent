// Package identity maps a verified AWS caller identity (an STS ARN) to a Linux
// username.
//
// This rule MUST stay byte-for-byte identical to the client's rule
// (SSMConnect/Auth/IdentityMapper.swift): the client targets the DCV session
// named after the user, and the agent's verifier authorizes the connection by
// the same name. A mismatch would deny a validated user their own session
// (spec CL-01 / MU-04).
//
// Security: the mapping is **reject-based, not transform-based**. It refuses any
// role-session-name that does not *already* reduce (lowercase + drop the email
// domain) to a safe, unambiguous Linux username, rather than silently deleting
// characters or truncating — both of which could merge two distinct identities
// into the same account (cross-user access). Reserved/system names are refused
// outright.
package identity

import (
	"fmt"
	"regexp"
	"strings"
)

// safeName is the only shape we accept for a Linux username: must start with a
// lowercase letter, then lowercase alphanumerics / `-` / `_`, max 32 chars.
var safeName = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)

// reserved usernames we must never map to (system/service accounts). The
// must-start-with-a-letter rule already blocks many; this is belt-and-braces for
// names that are valid-looking but privileged.
var reserved = map[string]bool{
	"root": true, "daemon": true, "bin": true, "sys": true, "sync": true,
	"games": true, "man": true, "lp": true, "mail": true, "news": true,
	"proxy": true, "www-data": true, "backup": true, "list": true, "nobody": true,
	"systemd-network": true, "dbus": true, "sshd": true, "rpc": true,
	"dcv": true, "dcvsmagent": true, "ec2-user": true, "ssm-user": true,
	"admin": true, "ubuntu": true, "centos": true,
}

// MappingError describes why an identity could not be mapped to a safe username.
type MappingError struct{ reason string }

func (e MappingError) Error() string { return "identity: " + e.reason }

// FromARN extracts the role-session-name (the segment after the last `/`) from an
// assumed-role ARN and maps it to a Linux username, rejecting anything ambiguous
// or privileged.
func FromARN(arn string) (string, error) {
	i := strings.LastIndexByte(arn, '/')
	if i < 0 || i == len(arn)-1 {
		return "", MappingError{fmt.Sprintf("ARN has no role-session-name: %q", arn)}
	}
	return Sanitize(arn[i+1:])
}

// Sanitize reduces a raw SSO username to a Linux username and validates it.
//
// Reduction is minimal and lossless-or-reject: take the local-part before any
// `@`, lowercase it. The result must then match ^[a-z][a-z0-9_-]{0,31}$ and not
// be reserved — otherwise it is REJECTED. We never strip "illegal" characters or
// truncate, because either could collapse two distinct identities into one user.
func Sanitize(raw string) (string, error) {
	s := raw
	if at := strings.IndexByte(s, '@'); at >= 0 {
		s = s[:at]
	}
	s = strings.ToLower(s)
	if !safeName.MatchString(s) {
		return "", MappingError{fmt.Sprintf("%q does not reduce to a safe username (must be ^[a-z][a-z0-9_-]{0,31}$)", raw)}
	}
	if reserved[s] {
		return "", MappingError{fmt.Sprintf("%q maps to a reserved/system username", raw)}
	}
	return s, nil
}
