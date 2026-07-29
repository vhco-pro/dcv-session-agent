package session

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
)

func testLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

type call struct {
	name string
	args []string
}

// fakeRunner records every command and returns canned results decided by respond.
type fakeRunner struct {
	calls   []call
	respond func(name string, args []string) ([]byte, error)
}

func (f *fakeRunner) run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, call{name, args})
	if f.respond != nil {
		out, err := f.respond(name, args)
		// Default `id -u` success to a regular uid when a test didn't specify one,
		// so the provisioner's UID-floor check passes for "user exists" cases.
		if name == "id" && err == nil && len(out) == 0 {
			return []byte("1001\n"), nil
		}
		return out, err
	}
	if name == "id" {
		return []byte("1001\n"), nil
	}
	return nil, nil
}

func (f *fakeRunner) called(name string, firstArg string) bool {
	for _, c := range f.calls {
		if c.name == name && len(c.args) > 0 && c.args[0] == firstArg {
			return true
		}
	}
	return false
}

func TestLocalProvisioner_CreatesWhenAbsentSkipsWhenPresent(t *testing.T) {
	t.Run("absent -> useradd", func(t *testing.T) {
		f := &fakeRunner{respond: func(name string, args []string) ([]byte, error) {
			if name == "id" {
				return nil, errors.New("no such user")
			}
			return nil, nil
		}}
		p := &LocalProvisioner{Run: f.run, Log: testLogger()}
		if err := p.EnsureUser(context.Background(), "alice"); err != nil {
			t.Fatal(err)
		}
		if !f.called("useradd", "--create-home") {
			t.Errorf("expected useradd --create-home, calls: %+v", f.calls)
		}
	})

	t.Run("present -> no useradd", func(t *testing.T) {
		f := &fakeRunner{} // id returns success (nil) by default
		p := &LocalProvisioner{Run: f.run, Log: testLogger()}
		if err := p.EnsureUser(context.Background(), "alice"); err != nil {
			t.Fatal(err)
		}
		for _, c := range f.calls {
			if c.name == "useradd" {
				t.Errorf("useradd must not be called when the user exists")
			}
		}
	})
}

// argsOf returns the args of the first call to name, or nil.
func (f *fakeRunner) argsOf(name string) []string {
	for _, c := range f.calls {
		if c.name == name {
			return c.args
		}
	}
	return nil
}

// hasFlag reports whether args contains flag immediately followed by value.
func hasFlag(args []string, flag, value string) bool {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == flag && args[i+1] == value {
			return true
		}
	}
	return false
}

// A home left on the persistent /home volume by a previous instance must be
// reclaimed by uid, otherwise the recreated account cannot write its own files
// and a later user silently inherits them. Regression guard for the connect-order
// UID shift observed on the multi-user workstation.
func TestLocalProvisioner_AdoptsUIDFromPersistedHome(t *testing.T) {
	// respondFor builds a runner where the user is absent, `stat` reports the
	// given owner for the leftover home, and getent behaves per the flags.
	respondFor := func(statOut string, uidTaken, groupExists bool) *fakeRunner {
		return &fakeRunner{respond: func(name string, args []string) ([]byte, error) {
			switch name {
			case "id":
				return nil, errors.New("no such user")
			case "stat":
				if statOut == "" {
					return nil, errors.New("no such file")
				}
				return []byte(statOut + "\n"), nil
			case "getent":
				if len(args) > 0 && args[0] == "passwd" {
					if uidTaken {
						return []byte("bob:x:1002:..."), nil
					}
					return nil, errors.New("not found")
				}
				if len(args) > 0 && args[0] == "group" {
					if groupExists {
						return []byte("qj6559-a:x:1002:"), nil
					}
					return nil, errors.New("not found")
				}
			}
			return nil, nil
		}}
	}

	t.Run("free uid -> adopted, group recreated", func(t *testing.T) {
		f := respondFor("1002:1002", false, false)
		p := &LocalProvisioner{Run: f.run, Log: testLogger()}
		if err := p.EnsureUser(context.Background(), "qj6559-a"); err != nil {
			t.Fatal(err)
		}
		args := f.argsOf("useradd")
		if !hasFlag(args, "--uid", "1002") || !hasFlag(args, "--gid", "1002") {
			t.Errorf("expected adopted --uid/--gid 1002, got useradd %v", args)
		}
		// The group must be recreated first, or `useradd --gid` fails.
		if g := f.argsOf("groupadd"); !hasFlag(g, "--gid", "1002") {
			t.Errorf("expected groupadd --gid 1002, got %v", g)
		}
		// `--` must still terminate options so a username is never read as a flag.
		if len(args) < 2 || args[len(args)-2] != "--" {
			t.Errorf("expected `-- username` to terminate args, got %v", args)
		}
	})

	t.Run("existing group -> adopted without groupadd", func(t *testing.T) {
		f := respondFor("1002:1002", false, true)
		p := &LocalProvisioner{Run: f.run, Log: testLogger()}
		if err := p.EnsureUser(context.Background(), "qj6559-a"); err != nil {
			t.Fatal(err)
		}
		if !hasFlag(f.argsOf("useradd"), "--uid", "1002") {
			t.Errorf("expected adopted uid, got %v", f.argsOf("useradd"))
		}
		if f.argsOf("groupadd") != nil {
			t.Error("must not recreate a group that already exists")
		}
	})

	t.Run("uid already taken -> falls back, never blocks login", func(t *testing.T) {
		f := respondFor("1002:1002", true, true)
		p := &LocalProvisioner{Run: f.run, Log: testLogger()}
		if err := p.EnsureUser(context.Background(), "qj6559-a"); err != nil {
			t.Fatalf("must still create the account: %v", err)
		}
		if hasFlag(f.argsOf("useradd"), "--uid", "1002") {
			t.Error("must not adopt a uid another account already holds")
		}
	})

	t.Run("system uid -> never adopted", func(t *testing.T) {
		f := respondFor("0:0", false, true)
		p := &LocalProvisioner{Run: f.run, Log: testLogger()}
		if err := p.EnsureUser(context.Background(), "qj6559-a"); err != nil {
			t.Fatal(err)
		}
		if hasFlag(f.argsOf("useradd"), "--uid", "0") {
			t.Error("adopting a root-owned home would escalate past the minUserUID guard")
		}
	})

	t.Run("no persisted home -> plain useradd", func(t *testing.T) {
		f := respondFor("", false, false)
		p := &LocalProvisioner{Run: f.run, Log: testLogger()}
		if err := p.EnsureUser(context.Background(), "newbie"); err != nil {
			t.Fatal(err)
		}
		for _, a := range f.argsOf("useradd") {
			if a == "--uid" {
				t.Error("nothing to adopt; useradd should pick the uid")
			}
		}
	})
}

func TestSSSDProvisioner_RequiresResolvableUser(t *testing.T) {
	f := &fakeRunner{respond: func(name string, _ []string) ([]byte, error) {
		if name == "getent" {
			return nil, errors.New("not found")
		}
		return nil, nil
	}}
	p := &SSSDProvisioner{Run: f.run, Log: testLogger()}
	if err := p.EnsureUser(context.Background(), "ghost"); err == nil {
		t.Fatal("expected error when the directory does not resolve the user")
	}
	// must never try to create a user
	if f.called("useradd", "--create-home") {
		t.Error("sssd backend must never create users")
	}
}

func TestManager_EnsureSession(t *testing.T) {
	newMgr := func(f *fakeRunner) *Manager {
		return NewManager(&LocalProvisioner{Run: f.run, Log: testLogger()}, f.run, testLogger())
	}

	t.Run("creates a virtual session when none exists", func(t *testing.T) {
		f := &fakeRunner{respond: func(name string, args []string) ([]byte, error) {
			if name == "dcv" && args[0] == "describe-session" {
				return nil, errors.New("no session") // not running yet
			}
			return nil, nil
		}}
		sid, err := newMgr(f).EnsureSession(context.Background(), "alice")
		if err != nil {
			t.Fatal(err)
		}
		if sid != "alice" {
			t.Errorf("sid = %q, want alice", sid)
		}
		// verify the create-session args are exactly the validated form
		var create []string
		for _, c := range f.calls {
			if c.name == "dcv" && c.args[0] == "create-session" {
				create = c.args
			}
		}
		want := []string{"create-session", "--type", "virtual", "--owner", "alice", "--user", "alice", "alice"}
		if !slices.Equal(create, want) {
			t.Errorf("create-session args = %v, want %v", create, want)
		}
	})

	t.Run("idempotent when the session already exists", func(t *testing.T) {
		f := &fakeRunner{} // describe-session returns success -> exists
		if _, err := newMgr(f).EnsureSession(context.Background(), "bob"); err != nil {
			t.Fatal(err)
		}
		if f.called("dcv", "create-session") {
			t.Error("must not create a session that already exists")
		}
	})
}

func TestApplyUserLimits(t *testing.T) {
	t.Run("no limits -> no systemctl call", func(t *testing.T) {
		f := &fakeRunner{}
		if err := ApplyUserLimits(context.Background(), f.run, "alice", Limits{}); err != nil {
			t.Fatal(err)
		}
		if f.called("systemctl", "set-property") {
			t.Error("empty limits must not call systemctl")
		}
	})

	t.Run("applies configured caps to the user's slice", func(t *testing.T) {
		f := &fakeRunner{respond: func(name string, args []string) ([]byte, error) {
			if name == "id" {
				return []byte("1002\n"), nil
			}
			return nil, nil
		}}
		err := ApplyUserLimits(context.Background(), f.run, "alice",
			Limits{CPUQuota: "200%", MemoryMax: "4G", TasksMax: "4096"})
		if err != nil {
			t.Fatal(err)
		}
		var sc *call
		for i := range f.calls {
			if f.calls[i].name == "systemctl" {
				sc = &f.calls[i]
			}
		}
		if sc == nil {
			t.Fatal("expected a systemctl set-property call")
		}
		joined := strings.Join(sc.args, " ")
		for _, want := range []string{"set-property", "user-1002.slice", "CPUQuota=200%", "MemoryMax=4G", "TasksMax=4096"} {
			if !strings.Contains(joined, want) {
				t.Errorf("set-property args missing %q: %v", want, sc.args)
			}
		}
	})
}

func TestDetectProvisioner(t *testing.T) {
	sssd := &fakeRunner{} // systemctl is-active succeeds -> sssd
	if got := DetectProvisioner(context.Background(), sssd.run, testLogger()).Name(); got != "sssd" {
		t.Errorf("with sssd active, got %q, want sssd", got)
	}
	local := &fakeRunner{respond: func(name string, _ []string) ([]byte, error) {
		return nil, errors.New("inactive")
	}}
	if got := DetectProvisioner(context.Background(), local.run, testLogger()).Name(); got != "local" {
		t.Errorf("without sssd, got %q, want local", got)
	}
}

func TestEnsureHandler(t *testing.T) {
	f := &fakeRunner{} // user exists, session exists -> trivial happy path
	mgr := NewManager(&LocalProvisioner{Run: f.run, Log: testLogger()}, f.run, testLogger())

	authn := func(_ context.Context, token string) (string, error) {
		if token == "good" {
			return "alice", nil
		}
		return "", errors.New("bad token")
	}
	h := NewHandler(authn, mgr, testLogger())

	post := func(v url.Values) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/ensure-session", strings.NewReader(v.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr
	}

	t.Run("valid token -> 200 with sessionId", func(t *testing.T) {
		rr := post(url.Values{"authenticationToken": {"good"}})
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rr.Code)
		}
		if !strings.Contains(rr.Body.String(), `"sessionId":"alice"`) {
			t.Errorf("body = %q", rr.Body.String())
		}
	})

	t.Run("bad token -> 401", func(t *testing.T) {
		if rr := post(url.Values{"authenticationToken": {"nope"}}); rr.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", rr.Code)
		}
	})

	t.Run("GET -> 405", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/ensure-session", nil)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("status = %d, want 405", rr.Code)
		}
	})

	t.Run("authenticated but authz denies -> 403 (no provisioning)", func(t *testing.T) {
		hd := NewHandler(authn, mgr, testLogger())
		hd.Authz = denyAuthz{}
		req := httptest.NewRequest(http.MethodPost, "/ensure-session", strings.NewReader(url.Values{"authenticationToken": {"good"}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		hd.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("status = %d, want 403 when authz denies", rec.Code)
		}
	})
}

// denyAuthz implements authz.Authorizer and refuses everyone.
type denyAuthz struct{}

func (denyAuthz) Allowed(context.Context, string) (bool, error) { return false, nil }
