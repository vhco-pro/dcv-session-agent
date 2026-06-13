// Command workstation-agent is the on-box service for multi-user Amazon DCV.
//
// It serves two loopback HTTP surfaces, reached only over the client's SSM
// port-forward (nothing here is internet-exposed):
//
//   - /validate-authentication-token — the DCV auth-token-verifier endpoint
//     (DIY, no-broker path): re-executes the presigned token, maps it to a user.
//   - /ensure-session — provisions the Linux user + home and creates the
//     per-user virtual session, authenticated by the SAME presigned token so it
//     can only ever act for the verified caller.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/vhco-pro/workstation-agent/internal/authz"
	"github.com/vhco-pro/workstation-agent/internal/identity"
	"github.com/vhco-pro/workstation-agent/internal/idle"
	"github.com/vhco-pro/workstation-agent/internal/session"
	"github.com/vhco-pro/workstation-agent/internal/verifier"
)

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "--status" || os.Args[1] == "status") {
		fmt.Print(resolveStatus(context.Background()).String())
		return
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	addr := getenv("WSA_ADDR", "127.0.0.1:8444")
	// No-redirect client: the verifier re-executes a client-supplied URL, so it
	// must never follow a 30x to an unvalidated host (SSRF). See verifier.NoRedirectClient.
	client := verifier.NoRedirectClient(10 * time.Second)

	// Verifier: validates a presigned sts:GetCallerIdentity token → username.
	v := verifier.NewHandler(client, identity.FromARN, log)

	// Provisioning backend auto-detected (D1): directory-joined → sssd, else local.
	prov := session.DetectProvisioner(context.Background(), session.DefaultRunner, log)
	mgr := session.NewManager(prov, session.DefaultRunner, log)
	// Per-user resource caps (MU-10); unset = unlimited.
	mgr.Limits = session.Limits{
		CPUQuota:  os.Getenv("WSA_USER_CPU_QUOTA"),
		MemoryMax: os.Getenv("WSA_USER_MEMORY_MAX"),
		TasksMax:  os.Getenv("WSA_USER_TASKS_MAX"),
	}

	// ensure-session is authenticated by the same token the verifier validates,
	// so a caller can only provision their own session.
	authn := func(ctx context.Context, token string) (string, error) {
		arn, err := verifier.VerifyToken(ctx, client, token)
		if err != nil {
			return "", err
		}
		return identity.FromARN(arn)
	}
	ensure := session.NewHandler(authn, mgr, log)

	// Authorization gate (MU-09 / D3): default allows any validated identity;
	// tighten with WSA_AUTHZ=group:<name> or allowlist:<path>. Both entry points
	// (token verify + ensure-session) enforce it.
	authorizer := authz.Parse(os.Getenv("WSA_AUTHZ"), session.DefaultRunner)
	v.Authz = authorizer
	ensure.Authz = authorizer

	mux := http.NewServeMux()
	mux.Handle("/validate-authentication-token", v) // DCV posts the token here
	mux.Handle("/ensure-session", ensure)           // client calls this before connecting
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	// Some deployments point auth-token-verifier at the bare URL; accept root too.
	mux.Handle("/", v)

	// Host-wide idle accounting (MU-07): stop the instance once every session has
	// zero connections for the idle window. Replaces v1's single-console idle check.
	accountant := &idle.Accountant{
		Count:       func(ctx context.Context) (int, error) { return session.CountConnections(ctx, session.DefaultRunner) },
		Stop:        idle.StopSelf(session.DefaultRunner),
		IdleTimeout: getDuration("WSA_IDLE_TIMEOUT", 30*time.Minute),
		Interval:    getDuration("WSA_IDLE_INTERVAL", time.Minute),
		Log:         log,
	}
	go func() { _ = accountant.Run(context.Background()) }()

	srv := &http.Server{
		Addr:              addr,
		Handler:           loopbackOnly(mux),
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Info("workstation-agent listening", "addr", addr, "provisioning", prov.Name(),
		"idleTimeout", accountant.IdleTimeout, "idleInterval", accountant.Interval)
	if err := srv.ListenAndServe(); err != nil {
		log.Error("server exited", "err", err)
		os.Exit(1)
	}
}

// loopbackOnly rejects any request whose source is not a loopback address. The
// agent's whole auth model assumes it is reachable only over the loopback (the
// client's SSM port-forward); this asserts it regardless of the configured bind
// address, so a `WSA_ADDR=0.0.0.0` misconfiguration cannot expose the verifier
// or ensure-session to the network.
func loopbackOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
			http.Error(w, "forbidden: loopback only", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// getDuration parses a duration env var (e.g. "30m"); falls back on absence or
// parse error. Set to "0" to disable idle accounting.
func getDuration(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return fallback
}
