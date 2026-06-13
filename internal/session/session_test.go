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
