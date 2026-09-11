package authall_test

import (
	"net/http"
	"testing"

	authall "github.com/alternayte/auth-all"
	"github.com/alternayte/auth-all/apierr"
	"github.com/alternayte/auth-all/internal/testsupport"
)

// strictHarness returns a harness with the strict origin check and one host
// route that a cookie can reach.
func strictHarness(t *testing.T, opts ...authall.Option) *testsupport.Harness {
	t.Helper()
	h := emailPasswordHarness(t, opts...)
	h.Handle("/host/write", h.Auth.RequireAuth(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })))
	return h
}

// TestStrictOriginCheckRefusesACookieRequestWithNoOrigin proves that the
// option closes the gap on the Auth-All routes and on a host route.
func TestStrictOriginCheckRefusesACookieRequestWithNoOrigin(t *testing.T) {
	h := strictHarness(t, authall.WithStrictOriginCheck())
	h.SignUp("alice@example.com", testPassword)

	// A host route. The session cookie travels with every case below.
	cases := []struct {
		name    string
		opts    []testsupport.RequestOption
		allowed bool
	}{
		{"no Origin and no Sec-Fetch-Site", []testsupport.RequestOption{
			testsupport.WithoutOrigin()}, false},
		{"an opaque origin", []testsupport.RequestOption{
			testsupport.WithHeader("Origin", "null")}, false},
		{"a cross-site fetch", []testsupport.RequestOption{
			testsupport.WithoutOrigin(),
			testsupport.WithHeader("Sec-Fetch-Site", "cross-site")}, false},
		{"a same-origin fetch", []testsupport.RequestOption{
			testsupport.WithoutOrigin(),
			testsupport.WithHeader("Sec-Fetch-Site", "same-origin")}, true},
		// A same-site request comes from another origin of the registrable
		// domain, so it needs an Origin header that the trusted list holds.
		{"a same-site fetch with no origin", []testsupport.RequestOption{
			testsupport.WithoutOrigin(),
			testsupport.WithHeader("Sec-Fetch-Site", "same-site")}, false},
		{"the trusted origin", nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := h.DoURL(http.MethodPost, h.BaseURL+"/host/write", nil, tc.opts...)
			if tc.allowed && resp.Status != http.StatusOK {
				t.Fatalf("the host route got status %d, want 200: %s", resp.Status, string(resp.Body))
			}
			if !tc.allowed {
				if resp.Status != http.StatusForbidden {
					t.Fatalf("the host route got status %d, want 403", resp.Status)
				}
				if code := resp.ErrorCode(t); code != string(apierr.CodeOriginNotAllowed) {
					t.Fatalf("the code = %s, want %s", code, apierr.CodeOriginNotAllowed)
				}
			}

			// The same rule holds on an Auth-All route.
			out := h.Do(http.MethodPost, "/password/change",
				map[string]any{"currentPassword": testPassword, "newPassword": testPassword}, tc.opts...)
			if !tc.allowed && out.Status != http.StatusForbidden {
				t.Fatalf("the Auth-All route got status %d, want 403: %s", out.Status, string(out.Body))
			}
			if !tc.allowed {
				if code := out.ErrorCode(t); code != string(apierr.CodeOriginNotAllowed) {
					t.Fatalf("the Auth-All route code = %s, want %s", code, apierr.CodeOriginNotAllowed)
				}
			}
			if tc.allowed && out.Status == http.StatusForbidden {
				if code := out.ErrorCode(t); code == string(apierr.CodeOriginNotAllowed) {
					t.Fatalf("the Auth-All route refused the origin of %s", tc.name)
				}
			}
		})
	}
}

// TestStrictOriginCheckKeepsEveryOtherClient proves that the option refuses no
// safe request, no bearer request, and no request without a cookie.
func TestStrictOriginCheckKeepsEveryOtherClient(t *testing.T) {
	h := strictHarness(t, authall.WithStrictOriginCheck())
	h.Handle("/host/read", h.Auth.RequireAuth(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })))
	_, out := h.SignUp("alice@example.com", testPassword)

	// A safe method passes with no header at all.
	read := h.DoURL(http.MethodGet, h.BaseURL+"/host/read", nil, testsupport.WithoutOrigin())
	if read.Status != http.StatusOK {
		t.Fatalf("a GET got status %d, want 200", read.Status)
	}

	// A bearer client passes, because a cross-site page cannot send a bearer
	// credential.
	result, err := h.Auth.SignIn(t.Context(), authall.SignInInput{
		Email: "alice@example.com", Password: testPassword,
	})
	if err != nil {
		t.Fatalf("SignIn = %v", err)
	}
	h.ClearCookies()
	bearer := h.DoURL(http.MethodPost, h.BaseURL+"/host/write", nil,
		testsupport.WithoutOrigin(), testsupport.WithBearer(result.Token))
	if bearer.Status != http.StatusOK {
		t.Fatalf("a bearer request got status %d, want 200: %s", bearer.Status, string(bearer.Body))
	}

	// A sign-in carries no cookie, so a client that is no browser still signs
	// in with no Origin header.
	signIn := h.Do(http.MethodPost, "/sign-in/email",
		map[string]string{"email": "alice@example.com", "password": testPassword},
		testsupport.WithoutOrigin())
	if signIn.Status != http.StatusOK {
		t.Fatalf("a sign-in with no Origin got status %d, want 200: %s", signIn.Status, string(signIn.Body))
	}
	_ = out
}

// TestTheOriginCheckIsUnchangedByDefault proves that the option changes
// nothing until the application turns it on.
func TestTheOriginCheckIsUnchangedByDefault(t *testing.T) {
	h := strictHarness(t)
	h.SignUp("alice@example.com", testPassword)

	// A cookie request with neither header keeps the released behavior.
	host := h.DoURL(http.MethodPost, h.BaseURL+"/host/write", nil, testsupport.WithoutOrigin())
	if host.Status != http.StatusOK {
		t.Fatalf("the host route got status %d, want the released 200: %s", host.Status, string(host.Body))
	}
	out := h.Do(http.MethodPost, "/sign-out", nil, testsupport.WithoutOrigin())
	if out.Status != http.StatusOK {
		t.Fatalf("the sign-out got status %d, want the released 200: %s", out.Status, string(out.Body))
	}

	// A cross-site origin is still refused without the option.
	h2 := strictHarness(t)
	h2.SignUp("bob@example.com", testPassword)
	evil := h2.DoURL(http.MethodPost, h2.BaseURL+"/host/write", nil,
		testsupport.WithHeader("Origin", "https://evil.example.com"))
	if evil.Status != http.StatusForbidden {
		t.Fatalf("a cross-site origin got status %d, want 403", evil.Status)
	}
}
