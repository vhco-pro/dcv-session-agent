package session

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/vhco-pro/dcv-session-agent/internal/authz"
)

// AuthN verifies a presigned-identity token and returns the verified Linux
// username it maps to. Wired in main from the verifier + identity packages.
type AuthN func(ctx context.Context, token string) (string, error)

// Handler serves POST /ensure-session. It authenticates the request with the
// SAME presigned token used for the DCV connection, then provisions a session
// for THAT verified user only — so a caller can never provision an account other
// than their own. Reached over the client's SSM port-forward; loopback-bound.
type Handler struct {
	AuthN AuthN
	Mgr   *Manager
	Authz authz.Authorizer // nil => allow any validated identity
	Log   *slog.Logger
}

// NewHandler wires an ensure-session Handler. A nil logger discards logs.
func NewHandler(authn AuthN, mgr *Manager, log *slog.Logger) *Handler {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Handler{AuthN: authn, Mgr: mgr, Log: log}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	user, err := h.AuthN(r.Context(), r.PostForm.Get("authenticationToken"))
	if err != nil {
		h.Log.Warn("ensure-session: authentication failed", "err", err)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if h.Authz != nil {
		if ok, err := h.Authz.Allowed(r.Context(), user); err != nil || !ok {
			h.Log.Warn("ensure-session: authorization denied", "user", user, "err", err)
			http.Error(w, "not authorized for this workstation", http.StatusForbidden)
			return
		}
	}
	sid, err := h.Mgr.EnsureSession(r.Context(), user)
	if err != nil {
		h.Log.Error("ensure-session: provisioning failed", "user", user, "err", err)
		http.Error(w, "session provisioning failed", http.StatusInternalServerError)
		return
	}
	h.Log.Info("ensure-session: ready", "user", user, "sessionId", sid)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"sessionId": sid, "user": user})
}
