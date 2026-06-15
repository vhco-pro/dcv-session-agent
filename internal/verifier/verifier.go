// Package verifier implements the Amazon DCV external auth-token-verifier
// contract for the DIY (no-broker) path.
//
// The connection token handed over by the client is a presigned
// sts:GetCallerIdentity request (the Vault / aws-iam-authenticator pattern).
// The verifier proves the caller's identity by re-executing that request against
// AWS STS and reading back the verified ARN — there is no shared secret, and the
// proof is the same AWS credential the SSM tunnel already required.
//
// DCV contract (https://docs.aws.amazon.com/dcv/latest/adminguide/external-authentication.html):
//
//	request  : HTTP POST, form-encoded: sessionId, authenticationToken, clientAddress
//	response : 200, XML  <auth result="yes"><username>NAME</username></auth>
//	                  or <auth result="no"><message>WHY</message></auth>
package verifier

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/vhco-pro/dcv-session-agent/internal/authz"
)

// stsHostRE matches only the legitimate STS regional or global endpoints. The
// verifier must never re-execute an arbitrary URL supplied as a "token" — that
// would be an SSRF primitive against anything the host can reach. This is the
// gate that makes "execute the token" safe.
var stsHostRE = regexp.MustCompile(`^sts(\.[a-z0-9-]+)?\.amazonaws\.com$`)

// maxBody caps how much of the STS response we read.
const maxBody = 64 << 10

type getCallerIdentityResponse struct {
	Arn string `xml:"GetCallerIdentityResult>Arn"`
}

// MapIdentity turns a verified caller ARN into the Linux username that owns the
// session. It mirrors the client's rule (see package identity).
type MapIdentity func(arn string) (string, error)

// VerifyToken validates a presigned-GetCallerIdentity token and returns the
// verified caller ARN. It enforces, before making any request, that the token is
// an HTTPS GET to a real STS endpoint for Action=GetCallerIdentity.
func VerifyToken(ctx context.Context, client *http.Client, token string) (string, error) {
	u, err := url.Parse(token)
	if err != nil {
		return "", fmt.Errorf("token is not a URL: %w", err)
	}
	if u.Scheme != "https" {
		return "", fmt.Errorf("token must be https, got %q", u.Scheme)
	}
	// Host is case-insensitive (DNS); lowercase before matching the STS allowlist.
	if !stsHostRE.MatchString(strings.ToLower(u.Hostname())) {
		return "", fmt.Errorf("token endpoint %q is not an STS host", u.Hostname())
	}
	if u.Query().Get("Action") != "GetCallerIdentity" {
		return "", fmt.Errorf("token action is not GetCallerIdentity")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, token, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("re-executing token failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("STS rejected the token (status %d)", resp.StatusCode)
	}
	var out getCallerIdentityResponse
	if err := xml.Unmarshal(body, &out); err != nil || out.Arn == "" {
		return "", fmt.Errorf("could not parse a caller ARN from the STS response")
	}
	return out.Arn, nil
}

// Handler implements the DCV auth-token-verifier HTTP endpoint.
type Handler struct {
	Client *http.Client
	Map    MapIdentity
	Authz  authz.Authorizer // nil => allow any validated identity
	Log    *slog.Logger
}

// NoRedirectClient returns an http.Client that NEVER follows redirects — the
// token verifier re-executes a client-supplied URL, so following a 30x to an
// unvalidated host would be an SSRF primitive. The STS host allowlist is only
// checked on the first hop, so redirects must be refused outright.
func NoRedirectClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// NewHandler builds a verifier Handler. A nil client uses a no-redirect client
// and a nil logger discards logs.
func NewHandler(client *http.Client, m MapIdentity, log *slog.Logger) *Handler {
	if client == nil {
		client = NoRedirectClient(10 * time.Second)
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Handler{Client: client, Map: m, Log: log}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		writeDeny(w, "malformed request")
		return
	}
	sessionID := r.PostForm.Get("sessionId")
	token := r.PostForm.Get("authenticationToken")

	arn, err := VerifyToken(r.Context(), h.Client, token)
	if err != nil {
		h.Log.Warn("token rejected", "sessionId", sessionID, "err", err)
		writeDeny(w, "invalid token")
		return
	}
	user, err := h.Map(arn)
	if err != nil {
		h.Log.Warn("identity mapping failed", "arn", arn, "err", err)
		writeDeny(w, "identity not mappable")
		return
	}
	if h.Authz != nil {
		if ok, err := h.Authz.Allowed(r.Context(), user); err != nil || !ok {
			h.Log.Warn("authorization denied", "user", user, "err", err)
			writeDeny(w, "not authorized for this workstation")
			return
		}
	}
	// The session is named after its owner, so a verified identity may only reach
	// its own session. Require an exact match — an empty sessionId (which the DCV
	// contract always supplies) is therefore denied, closing the catch-all path to
	// a no-session-binding bypass.
	if sessionID != user {
		h.Log.Warn("identity/session mismatch", "user", user, "sessionId", sessionID)
		writeDeny(w, "not authorized for this session")
		return
	}
	h.Log.Info("token accepted", "user", user, "sessionId", sessionID)
	writeAllow(w, user)
}

func writeAllow(w http.ResponseWriter, username string) {
	writeXML(w, getCallerIdentityAuth{Result: "yes", Username: username})
}

func writeDeny(w http.ResponseWriter, message string) {
	writeXML(w, getCallerIdentityAuth{Result: "no", Message: message})
}

type getCallerIdentityAuth struct {
	XMLName  xml.Name `xml:"auth"`
	Result   string   `xml:"result,attr"`
	Username string   `xml:"username,omitempty"`
	Message  string   `xml:"message,omitempty"`
}

func writeXML(w http.ResponseWriter, a getCallerIdentityAuth) {
	w.Header().Set("Content-Type", "text/xml")
	_ = xml.NewEncoder(w).Encode(a)
}
