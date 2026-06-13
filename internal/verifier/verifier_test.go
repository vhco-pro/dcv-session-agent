package verifier

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/vhco-pro/workstation-agent/internal/identity"
)

const stsXML = `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult>
    <Arn>arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_x/alice@example.com</Arn>
    <Account>123456789012</Account>
  </GetCallerIdentityResult>
</GetCallerIdentityResponse>`

// withAllowedHost temporarily points the SSRF allowlist at the test server's
// host so the happy path can exercise re-execution + parsing, while the default
// guard (which only allows real STS endpoints) is restored afterwards.
func withAllowedHost(t *testing.T, host string) {
	t.Helper()
	prev := stsHostRE
	stsHostRE = regexp.MustCompile("^" + regexp.QuoteMeta(host) + "$")
	t.Cleanup(func() { stsHostRE = prev })
}

func TestVerifyToken_RejectsNonSTSAndMalformed(t *testing.T) {
	cases := map[string]string{
		"non-sts host (SSRF guard)": "https://evil.example.com/?Action=GetCallerIdentity",
		"plain http":                "http://sts.eu-central-1.amazonaws.com/?Action=GetCallerIdentity",
		"wrong action":              "https://sts.eu-central-1.amazonaws.com/?Action=AssumeRole",
		"not a url":                 "::::",
	}
	for name, token := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifyToken(context.Background(), http.DefaultClient, token); err == nil {
				t.Fatalf("expected rejection for %q, got nil", token)
			}
		})
	}
}

func TestVerifyToken_HappyPath(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(stsXML))
	}))
	defer srv.Close()
	withAllowedHost(t, mustHost(t, srv.URL))

	token := srv.URL + "/?Action=GetCallerIdentity&Version=2011-06-15&X-Amz-Signature=deadbeef"
	arn, err := VerifyToken(context.Background(), srv.Client(), token)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(arn, "alice@example.com") {
		t.Errorf("arn = %q, want it to carry the role-session-name", arn)
	}
}

func TestVerifyToken_STSRejection(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "InvalidClientTokenId", http.StatusForbidden)
	}))
	defer srv.Close()
	withAllowedHost(t, mustHost(t, srv.URL))

	token := srv.URL + "/?Action=GetCallerIdentity"
	if _, err := VerifyToken(context.Background(), srv.Client(), token); err == nil {
		t.Fatal("expected error when STS returns 403")
	}
}

func TestHandler_DCVContract(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(stsXML))
	}))
	defer srv.Close()
	withAllowedHost(t, mustHost(t, srv.URL))
	token := srv.URL + "/?Action=GetCallerIdentity"

	h := NewHandler(srv.Client(), identity.FromARN, nil)

	t.Run("valid token for own session -> yes", func(t *testing.T) {
		rr := postForm(h, url.Values{
			"sessionId":           {"alice"},
			"authenticationToken": {token},
			"clientAddress":       {"127.0.0.1"},
		})
		if body := rr.Body.String(); !strings.Contains(body, `result="yes"`) || !strings.Contains(body, "<username>alice</username>") {
			t.Errorf("got %q, want allow for alice", body)
		}
	})

	t.Run("valid token but wrong session -> no", func(t *testing.T) {
		rr := postForm(h, url.Values{
			"sessionId":           {"bob"}, // token proves alice
			"authenticationToken": {token},
		})
		if body := rr.Body.String(); !strings.Contains(body, `result="no"`) {
			t.Errorf("got %q, want deny on session mismatch", body)
		}
	})

	t.Run("garbage token -> no", func(t *testing.T) {
		rr := postForm(h, url.Values{
			"sessionId":           {"alice"},
			"authenticationToken": {"https://evil.example.com/?Action=GetCallerIdentity"},
		})
		if body := rr.Body.String(); !strings.Contains(body, `result="no"`) {
			t.Errorf("got %q, want deny", body)
		}
	})

	t.Run("empty sessionId -> no (no-binding bypass closed)", func(t *testing.T) {
		rr := postForm(h, url.Values{"sessionId": {""}, "authenticationToken": {token}})
		if body := rr.Body.String(); !strings.Contains(body, `result="no"`) {
			t.Errorf("got %q, want deny for empty sessionId", body)
		}
	})

	t.Run("valid token but authz denies -> no", func(t *testing.T) {
		denying := NewHandler(srv.Client(), identity.FromARN, nil)
		denying.Authz = denyAll{}
		rr := postForm(denying, url.Values{"sessionId": {"alice"}, "authenticationToken": {token}})
		if body := rr.Body.String(); !strings.Contains(body, `result="no"`) {
			t.Errorf("got %q, want deny when authz refuses", body)
		}
	})
}

// denyAll implements authz.Authorizer and refuses everyone.
type denyAll struct{}

func (denyAll) Allowed(context.Context, string) (bool, error) { return false, nil }

func postForm(h http.Handler, v url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/validate-authentication-token", strings.NewReader(v.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func mustHost(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Hostname()
}
