package authall_test

import (
	"net/http"
	"testing"

	authall "github.com/alternayte/auth-all"
	"github.com/alternayte/auth-all/apierr"
	"github.com/alternayte/auth-all/internal/testsupport"
)

// errorCode returns the code of the public error envelope.
func errorCode(t *testing.T, resp *testsupport.Response) string {
	t.Helper()
	var body struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	resp.Decode(t, &body)
	return body.Error.Code
}

// csrfHarness returns a harness with one protected host route.
func csrfHarness(t *testing.T, opts ...authall.Option) *testsupport.Harness {
	t.Helper()
	h := emailPasswordHarness(t, opts...)
	h.Handle("/host/write", h.Auth.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})))
	return h
}

// crossSite marks a request as a cross-site browser request.
func crossSite(r *http.Request) {
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	r.Header.Set("Origin", "https://evil.example.com")
}

// TestSCNCSRF001ACookiePostFromAnUntrustedOriginIsRefused proves REQ-CSRF-001,
// REQ-CSRF-002 and REQ-CSRF-003.
func TestSCNCSRF001ACookiePostFromAnUntrustedOriginIsRefused(t *testing.T) {
	h := csrfHarness(t)
	h.SignUp("csrf@example.com", testPassword)
	cookie := h.SessionCookie()
	if cookie == nil {
		t.Fatal("the sign-up returned no session cookie")
	}

	// The cookie request from a cross-site page never reaches the handler.
	resp := h.DoURL(http.MethodPost, h.BaseURL+"/host/write", nil, crossSite)
	if resp.Status != http.StatusForbidden {
		t.Fatalf("status %d: %s", resp.Status, string(resp.Body))
	}
	if code := errorCode(t, resp); code != string(apierr.CodeOriginNotAllowed) {
		t.Fatalf("the code is %q", code)
	}

	// A safe method stays allowed.
	resp = h.DoURL(http.MethodGet, h.BaseURL+"/host/write", nil, crossSite)
	if resp.Status != http.StatusNoContent {
		t.Fatalf("the safe method returned %d", resp.Status)
	}

	// The same credential in the Authorization header passes, because a
	// cross-site page cannot send a bearer credential.
	token := cookie.Value
	h.ClearCookies()
	resp = h.DoURL(http.MethodPost, h.BaseURL+"/host/write", nil, func(r *http.Request) {
		crossSite(r)
		r.Header.Set("Authorization", "Bearer "+token)
	})
	if resp.Status != http.StatusNoContent {
		t.Fatalf("the bearer request returned %d: %s", resp.Status, string(resp.Body))
	}
}

// TestSCNCSRF002TheHostCanTurnTheCheckOff proves REQ-CSRF-004.
func TestSCNCSRF002TheHostCanTurnTheCheckOff(t *testing.T) {
	h := csrfHarness(t, authall.WithHostOriginCheck(false))
	h.SignUp("csrf-off@example.com", testPassword)
	resp := h.DoURL(http.MethodPost, h.BaseURL+"/host/write", nil, crossSite)
	if resp.Status != http.StatusNoContent {
		t.Fatalf("status %d: %s", resp.Status, string(resp.Body))
	}
}
