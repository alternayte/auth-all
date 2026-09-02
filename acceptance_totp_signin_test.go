package authall_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	authall "github.com/alternayte/auth-all"
	"github.com/alternayte/auth-all/email"
	"github.com/alternayte/auth-all/internal/testsupport"
)

// mfaResult is the decoded body of a sign-in that needs a second factor.
type mfaResult struct {
	MFARequired bool   `json:"mfaRequired"`
	MFAToken    string `json:"mfaToken"`
}

// enrolledHarness returns a harness whose user holds a live second factor. It
// returns the harness, the base32 secret, and the clock.
func enrolledHarness(t *testing.T, address string) (*testsupport.Harness, string, *time.Time) {
	t.Helper()
	h, clock := clockHarness(t)
	h.SignUp(address, testPassword)
	out := enrol(t, h)
	if resp := h.Do(http.MethodPost, "/totp/confirm",
		map[string]any{"code": codeAt(t, out.Secret, *clock)}); resp.Status != http.StatusOK {
		t.Fatalf("the confirmation returned %d: %s", resp.Status, string(resp.Body))
	}
	// The confirmation used the current step, so a later sign-in needs a later
	// code.
	*clock = clock.Add(2 * time.Minute)
	// The sign-up left a session behind. Remove it, so a later count measures
	// only what the gated sign-in created.
	user, err := h.Auth.GetUserByEmail(context.Background(), address)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.Store.Sessions().DeleteByUser(context.Background(), user.ID); err != nil {
		t.Fatalf("clear the sessions: %v", err)
	}
	h.ClearCookies()
	return h, out.Secret, clock
}

// TestSignInWithTOTPReturnsAChallengeAndNoSession covers the core property of
// the gate. A correct password alone opens nothing.
func TestSignInWithTOTPReturnsAChallengeAndNoSession(t *testing.T) {
	const address = "gate@example.com"
	h, _, _ := enrolledHarness(t, address)

	resp := h.Do(http.MethodPost, "/sign-in/email",
		map[string]any{"email": address, "password": testPassword})
	if resp.Status != http.StatusOK {
		t.Fatalf("status %d: %s", resp.Status, string(resp.Body))
	}
	var out mfaResult
	resp.Decode(t, &out)
	if !out.MFARequired {
		t.Fatal("the sign-in did not report that a second factor is needed")
	}
	if out.MFAToken == "" {
		t.Fatal("the sign-in returned no challenge token")
	}

	// No session cookie is set, so no half-authenticated cookie exists.
	for _, c := range resp.Cookies {
		if c.Name == authall.DefaultCookieName && c.Value != "" {
			t.Fatalf("the sign-in set a session cookie before the second factor")
		}
	}
	// No session row exists either.
	user, err := h.Auth.GetUserByEmail(context.Background(), address)
	if err != nil {
		t.Fatal(err)
	}
	list, err := h.Store.Sessions().ListByUser(context.Background(), user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 0 {
		t.Fatalf("the sign-in created %d sessions before the second factor", len(list))
	}
	// The session endpoint reports nobody.
	if got := h.GetSession(); got.User != nil {
		t.Fatal("the challenge authenticated a request")
	}
}

// TestTOTPVerifyExchangesTheChallengeForASession covers the second step.
func TestTOTPVerifyExchangesTheChallengeForASession(t *testing.T) {
	const address = "exchange@example.com"
	h, secret, clock := enrolledHarness(t, address)

	resp := h.Do(http.MethodPost, "/sign-in/email",
		map[string]any{"email": address, "password": testPassword})
	var out mfaResult
	resp.Decode(t, &out)

	verify := h.Do(http.MethodPost, "/totp/verify", map[string]any{
		"mfaToken": out.MFAToken,
		"code":     codeAt(t, secret, *clock),
	})
	if verify.Status != http.StatusOK {
		t.Fatalf("status %d: %s", verify.Status, string(verify.Body))
	}
	var auth testsupport.AuthResult
	verify.Decode(t, &auth)
	if auth.User == nil || auth.User.Email != address {
		t.Fatalf("the response carries no user: %s", string(verify.Body))
	}
	// The session cookie exists only now.
	if h.SessionCookie() == nil {
		t.Fatal("the exchange set no session cookie")
	}
	if got := h.GetSession(); got.User == nil {
		t.Fatal("the session does not authenticate")
	}
}

// TestTOTPVerifyRefusesAWrongCode checks that the challenge alone is useless.
func TestTOTPVerifyRefusesAWrongCode(t *testing.T) {
	const address = "wrongcode@example.com"
	h, _, _ := enrolledHarness(t, address)

	resp := h.Do(http.MethodPost, "/sign-in/email",
		map[string]any{"email": address, "password": testPassword})
	var out mfaResult
	resp.Decode(t, &out)

	verify := h.Do(http.MethodPost, "/totp/verify", map[string]any{
		"mfaToken": out.MFAToken, "code": "000000",
	})
	if verify.Status != http.StatusBadRequest {
		t.Fatalf("status %d: %s", verify.Status, string(verify.Body))
	}
	if code := verify.ErrorCode(t); code != "INVALID_TOTP_CODE" {
		t.Fatalf("the error code is %q", code)
	}
	if h.SessionCookie() != nil {
		t.Fatal("a wrong code set a session cookie")
	}
}

// TestTOTPVerifyRefusesAReplayedChallenge checks that the challenge token is
// consumed one time.
func TestTOTPVerifyRefusesAReplayedChallenge(t *testing.T) {
	const address = "challengereplay@example.com"
	h, secret, clock := enrolledHarness(t, address)

	resp := h.Do(http.MethodPost, "/sign-in/email",
		map[string]any{"email": address, "password": testPassword})
	var out mfaResult
	resp.Decode(t, &out)

	if v := h.Do(http.MethodPost, "/totp/verify", map[string]any{
		"mfaToken": out.MFAToken, "code": codeAt(t, secret, *clock),
	}); v.Status != http.StatusOK {
		t.Fatalf("the first exchange returned %d: %s", v.Status, string(v.Body))
	}

	// The same challenge, with a later valid code, opens nothing.
	*clock = clock.Add(2 * time.Minute)
	h.ClearCookies()
	again := h.Do(http.MethodPost, "/totp/verify", map[string]any{
		"mfaToken": out.MFAToken, "code": codeAt(t, secret, *clock),
	})
	if again.Status == http.StatusOK {
		t.Fatal("the challenge token authenticated a second time")
	}
	if h.SessionCookie() != nil {
		t.Fatal("the replayed challenge set a session cookie")
	}
}

// TestTOTPVerifyRefusesAnExpiredChallenge covers the five-minute lifetime.
func TestTOTPVerifyRefusesAnExpiredChallenge(t *testing.T) {
	const address = "expired@example.com"
	h, secret, clock := enrolledHarness(t, address)

	resp := h.Do(http.MethodPost, "/sign-in/email",
		map[string]any{"email": address, "password": testPassword})
	var out mfaResult
	resp.Decode(t, &out)

	*clock = clock.Add(10 * time.Minute)
	verify := h.Do(http.MethodPost, "/totp/verify", map[string]any{
		"mfaToken": out.MFAToken, "code": codeAt(t, secret, *clock),
	})
	if verify.Status == http.StatusOK {
		t.Fatalf("an expired challenge opened a session: %s", string(verify.Body))
	}
	if h.SessionCookie() != nil {
		t.Fatal("an expired challenge set a session cookie")
	}
}

// TestTOTPVerifyRefusesAnUnknownChallenge checks the guard on a forged token.
func TestTOTPVerifyRefusesAnUnknownChallenge(t *testing.T) {
	const address = "forged@example.com"
	h, secret, clock := enrolledHarness(t, address)

	verify := h.Do(http.MethodPost, "/totp/verify", map[string]any{
		"mfaToken": "a-token-that-was-never-issued",
		"code":     codeAt(t, secret, *clock),
	})
	if verify.Status == http.StatusOK {
		t.Fatal("a forged challenge opened a session")
	}
	if h.SessionCookie() != nil {
		t.Fatal("a forged challenge set a session cookie")
	}
}

// TestSignInWithoutTOTPIsUnchanged checks that the gate touches nobody else.
func TestSignInWithoutTOTPIsUnchanged(t *testing.T) {
	h := totpHarness(t)
	const address = "nofactor@example.com"
	h.SignUp(address, testPassword)
	h.ClearCookies()

	resp, out := h.SignIn(address, testPassword)
	if resp.Status != http.StatusOK {
		t.Fatalf("status %d: %s", resp.Status, string(resp.Body))
	}
	if out.User == nil {
		t.Fatalf("the sign-in returned no user: %s", string(resp.Body))
	}
	if h.SessionCookie() == nil {
		t.Fatal("the sign-in set no session cookie")
	}
}

// TestSignInWithAnUnconfirmedEnrolmentIsUnchanged checks that an abandoned
// enrolment never blocks a sign-in.
func TestSignInWithAnUnconfirmedEnrolmentIsUnchanged(t *testing.T) {
	h := totpHarness(t)
	const address = "abandoned@example.com"
	h.SignUp(address, testPassword)
	enrol(t, h)
	h.ClearCookies()

	resp, out := h.SignIn(address, testPassword)
	if resp.Status != http.StatusOK || out.User == nil {
		t.Fatalf("the sign-in failed: %d %s", resp.Status, string(resp.Body))
	}
	if h.SessionCookie() == nil {
		t.Fatal("the sign-in set no session cookie")
	}
}

// TestSignInWithAWrongPasswordIssuesNoChallenge checks that the challenge
// never leaks that a password was correct.
func TestSignInWithAWrongPasswordIssuesNoChallenge(t *testing.T) {
	const address = "wrongpass@example.com"
	h, _, _ := enrolledHarness(t, address)

	resp := h.Do(http.MethodPost, "/sign-in/email",
		map[string]any{"email": address, "password": "a completely wrong password"})
	if resp.Status != http.StatusUnauthorized {
		t.Fatalf("status %d: %s", resp.Status, string(resp.Body))
	}
	// The error body carries no challenge field at all.
	if strings.Contains(string(resp.Body), "mfaToken") {
		t.Fatalf("a wrong password produced a challenge token: %s", string(resp.Body))
	}
}

// TestOAuthWithTOTPRedirectsWithAChallengeCookie covers the redirect flow. The
// challenge crosses the redirect in a cookie, because a query parameter would
// reach the browser history, the server log, and any leaked Referer header.
func TestOAuthWithTOTPRedirectsWithAChallengeCookie(t *testing.T) {
	at := time.Now().UTC()
	f := newOAuthFixture(t, authall.WithTOTP(),
		authall.WithClock(func() time.Time { return at }))
	h := f.h

	// The user signs in with GitHub one time and enrols a second factor.
	state := f.startGitHub(t)
	if resp := f.callback(t, "github", "valid-code", state); resp.Status != http.StatusFound {
		t.Fatalf("the first callback returned %d: %s", resp.Status, string(resp.Body))
	}
	out := enrol(t, h)
	if resp := h.Do(http.MethodPost, "/totp/confirm",
		map[string]any{"code": codeAt(t, out.Secret, at)}); resp.Status != http.StatusOK {
		t.Fatalf("the confirmation returned %d: %s", resp.Status, string(resp.Body))
	}
	at = at.Add(2 * time.Minute)
	h.ClearCookies()

	// The second provider sign-in must not open a session.
	state = f.startGitHub(t)
	resp := f.callback(t, "github", "valid-code", state)
	if resp.Status != http.StatusFound {
		t.Fatalf("the second callback returned %d: %s", resp.Status, string(resp.Body))
	}
	if got := h.GetSession(); got.User != nil {
		t.Fatal("the provider callback authenticated the user with no second factor")
	}

	// The redirect names the requirement and carries no token.
	location := resp.Location()
	if testsupport.QueryParam(t, location, "mfa") != "required" {
		t.Fatalf("the redirect carries no marker: %s", location)
	}
	if strings.Contains(location, out.Secret) || strings.Contains(location, "mfaToken") {
		t.Fatalf("the redirect carries a token: %s", location)
	}

	// The challenge cookie completes the sign-in with no token in the body.
	verify := h.Do(http.MethodPost, "/totp/verify",
		map[string]any{"code": codeAt(t, out.Secret, at)})
	if verify.Status != http.StatusOK {
		t.Fatalf("the exchange returned %d: %s", verify.Status, string(verify.Body))
	}
	if got := h.GetSession(); got.User == nil {
		t.Fatal("the exchange opened no session")
	}
}

// TestMFACookieIsHTTPOnlyAndShortLived checks the properties of the challenge
// cookie.
func TestMFACookieIsHTTPOnlyAndShortLived(t *testing.T) {
	at := time.Now().UTC()
	f := newOAuthFixture(t, authall.WithTOTP(),
		authall.WithClock(func() time.Time { return at }))
	h := f.h

	state := f.startGitHub(t)
	f.callback(t, "github", "valid-code", state)
	out := enrol(t, h)
	h.Do(http.MethodPost, "/totp/confirm", map[string]any{"code": codeAt(t, out.Secret, at)})
	at = at.Add(2 * time.Minute)
	h.ClearCookies()

	state = f.startGitHub(t)
	resp := f.callback(t, "github", "valid-code", state)

	var challenge *http.Cookie
	for _, c := range resp.Cookies {
		if c.Name == authall.DefaultCookieName+".mfa" {
			challenge = c
		}
		if c.Name == authall.DefaultCookieName && c.Value != "" {
			t.Fatal("the callback set a session cookie before the second factor")
		}
	}
	if challenge == nil {
		t.Fatalf("the callback set no challenge cookie: %+v", resp.Cookies)
	}
	if !challenge.HttpOnly {
		t.Fatal("the challenge cookie is readable by a script")
	}
	if challenge.MaxAge <= 0 || challenge.MaxAge > 600 {
		t.Fatalf("the challenge cookie lives for %d seconds", challenge.MaxAge)
	}
}

// magicLinkTOTPHarness returns a harness with the magic-link plugin and TOTP,
// over a clock that the test moves.
func magicLinkTOTPHarness(t *testing.T) (*testsupport.Harness, *time.Time) {
	t.Helper()
	at := time.Now().UTC()
	h := magicLinkHarness(t, authall.WithTOTP(),
		authall.WithClock(func() time.Time { return at }))
	return h, &at
}

// TestMagicLinkWithTOTPIssuesAChallenge covers the third entry point. A second
// factor that guards only the password path is not a second factor.
func TestMagicLinkWithTOTPIssuesAChallenge(t *testing.T) {
	h, clock := magicLinkTOTPHarness(t)
	const address = "magic@example.com"
	h.SignUp(address, testPassword)

	out := enrol(t, h)
	if resp := h.Do(http.MethodPost, "/totp/confirm",
		map[string]any{"code": codeAt(t, out.Secret, *clock)}); resp.Status != http.StatusOK {
		t.Fatalf("the confirmation returned %d: %s", resp.Status, string(resp.Body))
	}
	*clock = clock.Add(2 * time.Minute)
	h.ClearCookies()
	h.Mail.Reset()

	if resp := sendMagicLink(t, h, address); resp.Status != http.StatusOK {
		t.Fatalf("the send returned %d: %s", resp.Status, string(resp.Body))
	}
	msg, ok := h.Mail.Find(email.IntentMagicLink)
	if !ok {
		t.Fatal("no magic-link message was produced")
	}

	// The link completes over JSON, so the challenge arrives in the body.
	resp := h.Do(http.MethodPost, "/magic-link/verify", map[string]any{"token": msg.Token})
	if resp.Status != http.StatusOK {
		t.Fatalf("the verify returned %d: %s", resp.Status, string(resp.Body))
	}
	var challenge mfaResult
	resp.Decode(t, &challenge)
	if !challenge.MFARequired || challenge.MFAToken == "" {
		t.Fatalf("the magic link opened a session with no second factor: %s", string(resp.Body))
	}
	if got := h.GetSession(); got.User != nil {
		t.Fatal("the magic link authenticated the user with no second factor")
	}

	// The challenge completes the sign-in.
	verify := h.Do(http.MethodPost, "/totp/verify", map[string]any{
		"mfaToken": challenge.MFAToken,
		"code":     codeAt(t, out.Secret, *clock),
	})
	if verify.Status != http.StatusOK {
		t.Fatalf("the exchange returned %d: %s", verify.Status, string(verify.Body))
	}
	if got := h.GetSession(); got.User == nil {
		t.Fatal("the exchange opened no session")
	}
}

// TestMagicLinkWithoutTOTPIsUnchanged checks that the plugin gate touches
// nobody else.
func TestMagicLinkWithoutTOTPIsUnchanged(t *testing.T) {
	h, _ := magicLinkTOTPHarness(t)
	const address = "magicplain@example.com"
	h.SignUp(address, testPassword)
	h.ClearCookies()
	h.Mail.Reset()

	sendMagicLink(t, h, address)
	msg, ok := h.Mail.Find(email.IntentMagicLink)
	if !ok {
		t.Fatal("no magic-link message was produced")
	}
	resp := h.Do(http.MethodPost, "/magic-link/verify", map[string]any{"token": msg.Token})
	if resp.Status != http.StatusOK {
		t.Fatalf("the verify returned %d: %s", resp.Status, string(resp.Body))
	}
	if got := h.GetSession(); got.User == nil {
		t.Fatal("the magic link opened no session")
	}
}
