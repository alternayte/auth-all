package authall_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	authall "github.com/alternayte/auth-all"
	"github.com/alternayte/auth-all/apierr"
	"github.com/alternayte/auth-all/events"
	"github.com/alternayte/auth-all/hook"
	"github.com/alternayte/auth-all/internal/testsupport"
	"github.com/alternayte/auth-all/ratelimit"
	"github.com/alternayte/auth-all/store"
)

// TestSignInAsAGoMethod proves that a library caller signs a person in with no
// HTTP route of Auth-All.
func TestSignInAsAGoMethod(t *testing.T) {
	h := emailPasswordHarness(t)
	ctx := context.Background()
	_, out := h.SignUp("alice@example.com", testPassword)
	h.ClearCookies()

	result, err := h.Auth.SignIn(ctx, authall.SignInInput{
		Email: "Alice@Example.com", Password: testPassword, ClientIP: "203.0.113.7",
	})
	if err != nil {
		t.Fatalf("SignIn = %v", err)
	}
	if result.User == nil || result.User.ID != out.User.ID {
		t.Fatalf("the user = %+v", result.User)
	}
	if result.Session == nil || result.Session.UserID != out.User.ID {
		t.Fatalf("the session = %+v", result.Session)
	}
	if result.Token == "" {
		t.Fatal("SignIn returned no session token")
	}
	if result.MFARequired {
		t.Fatal("no second factor is enrolled")
	}

	// The token authenticates a request, so a host serves its own client with
	// it.
	h.Handle("/host/probe", h.Auth.RequireAuth(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })))
	probe := h.DoURL(http.MethodGet, h.BaseURL+"/host/probe", nil, testsupport.WithBearer(result.Token))
	if probe.Status != http.StatusOK {
		t.Fatalf("the token got status %d: %s", probe.Status, string(probe.Body))
	}

	// The store keeps the digest, never the plaintext.
	stored, err := h.Store.Sessions().GetByTokenHash(ctx, sha256Hex(result.Token))
	if err != nil || stored.ID != result.Session.ID {
		t.Fatalf("the store holds no digest of the token: %v", err)
	}
}

// TestSignInRefusesEveryWrongAttempt proves that the Go method keeps the
// public error contract of the route.
func TestSignInRefusesEveryWrongAttempt(t *testing.T) {
	h := emailPasswordHarness(t)
	ctx := context.Background()
	h.SignUp("alice@example.com", testPassword)

	tests := []struct {
		name  string
		in    authall.SignInInput
		want  *apierr.Error
		setup func()
	}{
		{"an unknown address", authall.SignInInput{Email: "ghost@example.com", Password: testPassword},
			apierr.ErrInvalidCredentials, nil},
		{"a wrong password", authall.SignInInput{Email: "alice@example.com", Password: "wrong-password-value"},
			apierr.ErrInvalidCredentials, nil},
		{"an empty password", authall.SignInInput{Email: "alice@example.com"},
			apierr.ErrInvalidCredentials, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := h.Auth.SignIn(ctx, tc.in); !errors.Is(err, tc.want) {
				t.Fatalf("SignIn = %v, want %v", err, tc.want)
			}
		})
	}

	// A disabled account names the state only after a correct password.
	user, err := h.Store.Users().GetByNormalizedEmail(ctx, "alice@example.com")
	if err != nil {
		t.Fatalf("read the user: %v", err)
	}
	disabled := time.Now().UTC()
	user.DisabledAt = &disabled
	if err := h.Store.Users().Update(ctx, user); err != nil {
		t.Fatalf("disable the user: %v", err)
	}
	if _, err := h.Auth.SignIn(ctx, authall.SignInInput{
		Email: "alice@example.com", Password: "wrong-password-value",
	}); !errors.Is(err, apierr.ErrInvalidCredentials) {
		t.Fatalf("a wrong password of a disabled account = %v", err)
	}
	if _, err := h.Auth.SignIn(ctx, authall.SignInInput{
		Email: "alice@example.com", Password: testPassword,
	}); !errors.Is(err, apierr.ErrUserDisabled) {
		t.Fatalf("a disabled account = %v, want USER_DISABLED", err)
	}
}

// TestSignInReportsTheRateLimit proves that a library caller reads the retry
// time, and that the error keeps the public code.
func TestSignInReportsTheRateLimit(t *testing.T) {
	h := emailPasswordHarness(t, authall.WithRateLimiter(refusingLimiter{}))
	_, err := h.Auth.SignIn(context.Background(), authall.SignInInput{
		Email: "alice@example.com", Password: testPassword,
	})
	if !errors.Is(err, apierr.ErrRateLimited) {
		t.Fatalf("SignIn = %v, want RATE_LIMITED", err)
	}
	var limited *authall.RateLimitError
	if !errors.As(err, &limited) {
		t.Fatalf("SignIn = %v, want a RateLimitError", err)
	}
	if limited.RetryAfter != 42*time.Second {
		t.Fatalf("the retry time = %v, want 42s", limited.RetryAfter)
	}
	// The public contract keeps the code and the status of the route.
	public := apierr.From(err)
	if public.Code != apierr.CodeRateLimited || public.Status != http.StatusTooManyRequests {
		t.Fatalf("the public error = %+v", public)
	}
}

// refusingLimiter refuses every attempt and names a retry time.
type refusingLimiter struct{}

func (refusingLimiter) Allow(context.Context, ratelimit.Key) (bool, error) { return false, nil }

func (refusingLimiter) Decide(context.Context, ratelimit.Key) (ratelimit.Decision, error) {
	return ratelimit.Decision{Allowed: false, RetryAfter: 42 * time.Second}, nil
}

// TestSignInIssuesAChallengeForASecondFactor proves that the Go method follows
// the second-factor rule of the route. No session exists before the second
// proof.
func TestSignInIssuesAChallengeForASecondFactor(t *testing.T) {
	h, _, _ := enrolledHarness(t, "alice@example.com")
	ctx := context.Background()

	result, err := h.Auth.SignIn(ctx, authall.SignInInput{
		Email: "alice@example.com", Password: testPassword,
	})
	if err != nil {
		t.Fatalf("SignIn = %v", err)
	}
	if !result.MFARequired {
		t.Fatal("a confirmed second factor must give a challenge")
	}
	if result.Session != nil || result.Token != "" {
		t.Fatalf("a challenge must carry no session: %+v", result)
	}
	if result.MFAToken == "" {
		t.Fatal("the challenge holds no token")
	}
}

// TestSignOutAsAGoMethod proves that a library caller ends a session, runs the
// hook, and emits the event.
func TestSignOutAsAGoMethod(t *testing.T) {
	var seen []events.Event
	var hooked int
	h := emailPasswordHarness(t, authall.WithEventHandler(events.HandlerFunc(
		func(_ context.Context, e events.Event) { seen = append(seen, e) })))
	h.Auth.Hooks().OnAfterSignOut(func(context.Context, *hook.SignOut) error {
		hooked++
		return nil
	})
	ctx := context.Background()
	h.SignUp("alice@example.com", testPassword)
	h.ClearCookies()

	result, err := h.Auth.SignIn(ctx, authall.SignInInput{
		Email: "alice@example.com", Password: testPassword,
	})
	if err != nil {
		t.Fatalf("SignIn = %v", err)
	}
	seen = nil
	if err := h.Auth.SignOut(ctx, result.Session); err != nil {
		t.Fatalf("SignOut = %v", err)
	}
	if hooked != 1 {
		t.Fatalf("the sign-out hook ran %d times, want 1", hooked)
	}
	var event *events.Event
	for i := range seen {
		if seen[i].Name == events.SignOut {
			event = &seen[i]
		}
	}
	if event == nil {
		t.Fatal("the sign-out emitted no event")
	}
	if event.Fields["session_id"] != result.Session.ID {
		t.Fatalf("the event names %v", event.Fields["session_id"])
	}

	// The session is gone, so the token authenticates nothing.
	if _, err := h.Store.Sessions().GetByTokenHash(ctx, sha256Hex(result.Token)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the session survived: %v", err)
	}
	// A repeated sign-out and a nil session are no error.
	if err := h.Auth.SignOut(ctx, result.Session); err != nil {
		t.Fatalf("a repeated SignOut = %v", err)
	}
	if err := h.Auth.SignOut(ctx, nil); err != nil {
		t.Fatalf("SignOut of nil = %v", err)
	}
}

// TestSignOutTokenEndsTheSessionOfOneToken proves the token form of the
// sign-out.
func TestSignOutTokenEndsTheSessionOfOneToken(t *testing.T) {
	h := emailPasswordHarness(t)
	ctx := context.Background()
	h.SignUp("alice@example.com", testPassword)
	h.ClearCookies()
	result, err := h.Auth.SignIn(ctx, authall.SignInInput{
		Email: "alice@example.com", Password: testPassword,
	})
	if err != nil {
		t.Fatalf("SignIn = %v", err)
	}
	if err := h.Auth.SignOutToken(ctx, result.Token); err != nil {
		t.Fatalf("SignOutToken = %v", err)
	}
	if _, err := h.Store.Sessions().GetByTokenHash(ctx, sha256Hex(result.Token)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the session survived: %v", err)
	}
	// An unknown token and an empty token are no error.
	for _, token := range []string{result.Token, "never-existed", ""} {
		if err := h.Auth.SignOutToken(ctx, token); err != nil {
			t.Fatalf("SignOutToken(%q) = %v", token, err)
		}
	}
}

// TestChangePasswordAsAGoMethod proves that a library caller replaces the
// password of the owner of the account.
func TestChangePasswordAsAGoMethod(t *testing.T) {
	const newPassword = "an-even-longer-password-2"
	h := emailPasswordHarness(t)
	ctx := context.Background()
	_, out := h.SignUp("alice@example.com", testPassword)
	h.ClearCookies()

	first, err := h.Auth.SignIn(ctx, authall.SignInInput{Email: "alice@example.com", Password: testPassword})
	if err != nil {
		t.Fatalf("SignIn = %v", err)
	}
	second, err := h.Auth.SignIn(ctx, authall.SignInInput{Email: "alice@example.com", Password: testPassword})
	if err != nil {
		t.Fatalf("the second SignIn = %v", err)
	}

	// A wrong current password changes nothing.
	err = h.Auth.ChangePassword(ctx, authall.ChangePasswordInput{
		UserID: out.User.ID, CurrentPassword: "wrong-password-value", NewPassword: newPassword,
	})
	if !errors.Is(err, apierr.ErrInvalidCredentials) {
		t.Fatalf("a wrong current password = %v", err)
	}
	// A weak password fails the policy.
	err = h.Auth.ChangePassword(ctx, authall.ChangePasswordInput{
		UserID: out.User.ID, CurrentPassword: testPassword, NewPassword: "short",
	})
	if !errors.Is(err, apierr.ErrWeakPassword) {
		t.Fatalf("a weak password = %v", err)
	}
	// An unknown user reports the absent account.
	err = h.Auth.ChangePassword(ctx, authall.ChangePasswordInput{
		UserID: "ghost", CurrentPassword: testPassword, NewPassword: newPassword,
	})
	if err == nil {
		t.Fatal("an unknown user must fail")
	}

	// The change keeps the named session and ends the other one.
	err = h.Auth.ChangePassword(ctx, authall.ChangePasswordInput{
		UserID: out.User.ID, CurrentPassword: testPassword, NewPassword: newPassword,
		KeepSessionID: second.Session.ID,
	})
	if err != nil {
		t.Fatalf("ChangePassword = %v", err)
	}
	if _, err := h.Store.Sessions().GetByTokenHash(ctx, sha256Hex(first.Token)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the other session survived: %v", err)
	}
	if _, err := h.Store.Sessions().GetByTokenHash(ctx, sha256Hex(second.Token)); err != nil {
		t.Fatalf("the kept session is gone: %v", err)
	}

	// The old password no longer authenticates, and the new one does.
	if _, err := h.Auth.SignIn(ctx, authall.SignInInput{
		Email: "alice@example.com", Password: testPassword,
	}); !errors.Is(err, apierr.ErrInvalidCredentials) {
		t.Fatalf("the old password still works: %v", err)
	}
	if _, err := h.Auth.SignIn(ctx, authall.SignInInput{
		Email: "alice@example.com", Password: newPassword,
	}); err != nil {
		t.Fatalf("the new password = %v", err)
	}
}

// TestChangePasswordKeepsTheOtherSessions proves the option that keeps them.
func TestChangePasswordKeepsTheOtherSessions(t *testing.T) {
	const newPassword = "an-even-longer-password-3"
	h := emailPasswordHarness(t)
	ctx := context.Background()
	_, out := h.SignUp("alice@example.com", testPassword)
	h.ClearCookies()
	other, err := h.Auth.SignIn(ctx, authall.SignInInput{Email: "alice@example.com", Password: testPassword})
	if err != nil {
		t.Fatalf("SignIn = %v", err)
	}
	err = h.Auth.ChangePassword(ctx, authall.ChangePasswordInput{
		UserID: out.User.ID, CurrentPassword: testPassword, NewPassword: newPassword,
		KeepOtherSessions: true,
	})
	if err != nil {
		t.Fatalf("ChangePassword = %v", err)
	}
	if _, err := h.Store.Sessions().GetByTokenHash(ctx, sha256Hex(other.Token)); err != nil {
		t.Fatalf("the other session is gone: %v", err)
	}
}

// TestChangePasswordClearsTheTemporaryState proves that the change ends the
// temporary password state of an administrative reset.
func TestChangePasswordClearsTheTemporaryState(t *testing.T) {
	const newPassword = "an-even-longer-password-4"
	h := emailPasswordHarness(t)
	ctx := context.Background()
	_, out := h.SignUp("alice@example.com", testPassword)
	user, err := h.Store.Users().GetByID(ctx, out.User.ID)
	if err != nil {
		t.Fatalf("read the user: %v", err)
	}
	user.MustChangePassword = true
	if err := h.Store.Users().Update(ctx, user); err != nil {
		t.Fatalf("set the flag: %v", err)
	}
	err = h.Auth.ChangePassword(ctx, authall.ChangePasswordInput{
		UserID: out.User.ID, CurrentPassword: testPassword, NewPassword: newPassword,
	})
	if err != nil {
		t.Fatalf("ChangePassword = %v", err)
	}
	after, err := h.Store.Users().GetByID(ctx, out.User.ID)
	if err != nil {
		t.Fatalf("read the user: %v", err)
	}
	if after.MustChangePassword {
		t.Fatal("the change kept the temporary password state")
	}
}

// TestTheSessionCookieHelpersWriteTheCookie proves that a host serves a
// browser with the same cookie as the route of Auth-All.
func TestTheSessionCookieHelpersWriteTheCookie(t *testing.T) {
	h := emailPasswordHarness(t)
	ctx := context.Background()
	h.SignUp("alice@example.com", testPassword)
	h.ClearCookies()
	result, err := h.Auth.SignIn(ctx, authall.SignInInput{
		Email: "alice@example.com", Password: testPassword,
	})
	if err != nil {
		t.Fatalf("SignIn = %v", err)
	}

	recorder := httptest.NewRecorder()
	h.Auth.SetSessionCookie(recorder, result.Token, result.Session.ExpiresAt)
	cookies := recorder.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("the helper wrote %d cookies", len(cookies))
	}
	cookie := cookies[0]
	if cookie.Value != result.Token {
		t.Fatal("the cookie carries another value")
	}
	if !cookie.HttpOnly {
		t.Fatal("the session cookie must be HttpOnly")
	}
	if cookie.SameSite == http.SameSiteNoneMode {
		t.Fatal("the session cookie must not be SameSite=None")
	}

	cleared := httptest.NewRecorder()
	h.Auth.ClearSessionCookie(cleared)
	out := cleared.Result().Cookies()
	if len(out) != 1 || out[0].Value != "" || out[0].MaxAge >= 0 {
		t.Fatalf("the clear helper wrote %+v", out)
	}
}

// TestTheGoMethodsAndTheRoutesAgree proves that the route and the Go method
// run one implementation. A sign-in through the route and a sign-in through
// the method give the same shape of result.
func TestTheGoMethodsAndTheRoutesAgree(t *testing.T) {
	h := emailPasswordHarness(t)
	ctx := context.Background()
	h.SignUp("alice@example.com", testPassword)
	h.ClearCookies()

	// The route path.
	resp, out := h.SignIn("alice@example.com", testPassword)
	if resp.Status != http.StatusOK {
		t.Fatalf("the route sign-in got status %d", resp.Status)
	}
	routeCookie := h.SessionCookie()
	if routeCookie == nil {
		t.Fatal("the route set no cookie")
	}

	// The method path.
	result, err := h.Auth.SignIn(ctx, authall.SignInInput{
		Email: "alice@example.com", Password: testPassword,
	})
	if err != nil {
		t.Fatalf("the method sign-in = %v", err)
	}
	if result.User.ID != out.User.ID {
		t.Fatal("the two paths name another user")
	}
	// Both sessions are live rows of one user.
	for _, token := range []string{routeCookie.Value, result.Token} {
		if _, err := h.Store.Sessions().GetByTokenHash(ctx, sha256Hex(token)); err != nil {
			t.Fatalf("a session of one path is absent: %v", err)
		}
	}
}
