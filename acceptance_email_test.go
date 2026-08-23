package authall_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	authall "github.com/alternayte/auth-all"
	"github.com/alternayte/auth-all/email"
	"github.com/alternayte/auth-all/internal/testsupport"
)

const testPassword = "correct horse battery staple"

func emailPasswordHarness(t *testing.T, opts ...authall.Option) *testsupport.Harness {
	t.Helper()
	all := append([]authall.Option{authall.WithEmailPassword()}, opts...)
	return testsupport.NewHarness(t, all...)
}

// TestAUTH001SignUp covers AUTH-001.
func TestAUTH001SignUp(t *testing.T) {
	h := emailPasswordHarness(t)
	resp, out := h.SignUp("alice@example.com", testPassword)
	if resp.Status != http.StatusCreated {
		t.Fatalf("status %d: %s", resp.Status, string(resp.Body))
	}
	if out.User == nil || out.User.Email != "alice@example.com" {
		t.Fatalf("unexpected user: %+v", out.User)
	}
	if out.Session == nil || out.Session.UserID != out.User.ID {
		t.Fatalf("sign-up did not create a session: %+v", out.Session)
	}
	if h.SessionCookie() == nil {
		t.Fatalf("sign-up did not set the session cookie")
	}
	ctx := context.Background()
	user, err := h.Auth.GetUserByEmail(ctx, "ALICE@example.com")
	if err != nil {
		t.Fatalf("the normalized lookup failed: %v", err)
	}
	if user.ID != out.User.ID {
		t.Fatalf("the normalized lookup returned another user")
	}
	cred, err := h.Store.Users().GetCredential(ctx, user.ID)
	if err != nil {
		t.Fatalf("no credential record was created: %v", err)
	}
	if cred.PasswordHash == testPassword {
		t.Fatalf("the password is stored in plaintext")
	}
}

// TestAUTH002DuplicateSignUp covers AUTH-002.
func TestAUTH002DuplicateSignUp(t *testing.T) {
	h := emailPasswordHarness(t)
	if resp, _ := h.SignUp("dup@example.com", testPassword); resp.Status != http.StatusCreated {
		t.Fatalf("first sign-up failed: %s", string(resp.Body))
	}
	h.ClearCookies()
	resp, _ := h.SignUp("DUP@example.com", testPassword)
	if resp.Status != http.StatusConflict {
		t.Fatalf("expected status 409, got %d: %s", resp.Status, string(resp.Body))
	}
	if code := resp.ErrorCode(t); code != "EMAIL_ALREADY_EXISTS" {
		t.Fatalf("unexpected code %q", code)
	}
}

// TestAUTH003SignIn covers AUTH-003.
func TestAUTH003SignIn(t *testing.T) {
	h := emailPasswordHarness(t)
	h.SignUp("bob@example.com", testPassword)
	h.ClearCookies()

	resp, out := h.SignIn("bob@example.com", testPassword)
	if resp.Status != http.StatusOK {
		t.Fatalf("status %d: %s", resp.Status, string(resp.Body))
	}
	if out.Session == nil {
		t.Fatalf("sign-in created no session")
	}
	cookie := h.SessionCookie()
	if cookie == nil {
		t.Fatalf("sign-in set no cookie")
	}
	// The session is database backed and stores only the hash.
	sess, err := h.Store.Sessions().GetByTokenHash(context.Background(), sha256Hex(cookie.Value))
	if err != nil {
		t.Fatalf("the session is not in the database: %v", err)
	}
	if sess.ID != out.Session.ID {
		t.Fatalf("the stored session does not match the response")
	}
}

// TestAUTH004InvalidCredentials covers AUTH-004.
func TestAUTH004InvalidCredentials(t *testing.T) {
	h := emailPasswordHarness(t)
	h.SignUp("carol@example.com", testPassword)
	h.ClearCookies()

	wrongPassword, _ := h.SignIn("carol@example.com", "wrong password value")
	unknownUser, _ := h.SignIn("nobody@example.com", testPassword)
	for name, resp := range map[string]*testsupport.Response{"wrong password": wrongPassword, "unknown user": unknownUser} {
		if resp.Status != http.StatusUnauthorized {
			t.Fatalf("%s: expected status 401, got %d", name, resp.Status)
		}
		if code := resp.ErrorCode(t); code != "INVALID_CREDENTIALS" {
			t.Fatalf("%s: unexpected code %q", name, code)
		}
	}
	if string(wrongPassword.Body) != string(unknownUser.Body) {
		t.Fatalf("the responses disclose which field was wrong:\n%s\n%s",
			string(wrongPassword.Body), string(unknownUser.Body))
	}
	if h.SessionCookie() != nil {
		t.Fatalf("a failed sign-in created a session cookie")
	}
}

// TestAUTH005SignOut covers AUTH-005.
func TestAUTH005SignOut(t *testing.T) {
	h := emailPasswordHarness(t)
	_, out := h.SignUp("dave@example.com", testPassword)
	cookie := h.SessionCookie()

	resp := h.Do(http.MethodPost, "/sign-out", nil)
	if resp.Status != http.StatusOK {
		t.Fatalf("status %d: %s", resp.Status, string(resp.Body))
	}
	if _, err := h.Store.Sessions().GetByTokenHash(context.Background(), sha256Hex(cookie.Value)); err == nil {
		t.Fatalf("the session still exists after sign-out")
	}
	// The revoked token no longer authenticates, even when it is replayed.
	after := h.GetSession(testsupport.WithBearer(cookie.Value))
	if after.Session != nil || after.User != nil {
		t.Fatalf("the revoked session still resolves: %+v", after)
	}
	_ = out
}

// TestAUTH006SessionLookup covers AUTH-006.
func TestAUTH006SessionLookup(t *testing.T) {
	clock := testsupport.NewClock()
	h := emailPasswordHarness(t,
		authall.WithClock(clock.Now),
		authall.WithSession(authall.SessionOptions{TTL: time.Hour}))

	_, out := h.SignUp("erin@example.com", testPassword)
	current := h.GetSession()
	if current.User == nil || current.User.ID != out.User.ID {
		t.Fatalf("a valid session did not resolve to its user: %+v", current)
	}

	clock.Advance(2 * time.Hour)
	expired := h.GetSession()
	if expired.Session != nil || expired.User != nil {
		t.Fatalf("an expired session resolved: %+v", expired)
	}

	// A revoked session does not resolve either.
	clock.Advance(-2 * time.Hour)
	h.ClearCookies()
	_, signedIn := h.SignIn("erin@example.com", testPassword)
	if err := h.Auth.RevokeSession(context.Background(), signedIn.Session.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	revoked := h.GetSession()
	if revoked.Session != nil {
		t.Fatalf("a revoked session resolved: %+v", revoked)
	}
}

// TestAUTH007And008EmailVerification covers AUTH-007 and AUTH-008.
func TestAUTH007And008EmailVerification(t *testing.T) {
	h := emailPasswordHarness(t, authall.WithEmailPassword(authall.EmailPasswordOptions{
		RequireEmailVerification: true,
	}))
	resp, out := h.SignUp("frank@example.com", testPassword)
	if resp.Status != http.StatusCreated {
		t.Fatalf("status %d: %s", resp.Status, string(resp.Body))
	}
	if out.Session != nil || !out.EmailVerificationRequired {
		t.Fatalf("verification is required, so sign-up must not create a session: %+v", out)
	}
	// Sign-in is blocked until the address is verified.
	blocked, _ := h.SignIn("frank@example.com", testPassword)
	if code := blocked.ErrorCode(t); code != "EMAIL_NOT_VERIFIED" {
		t.Fatalf("unexpected code %q", code)
	}

	msg := h.Mail.Last(t, email.IntentVerifyEmail)
	verify := h.Do(http.MethodPost, "/email-verification/verify", map[string]string{"token": msg.Token})
	if verify.Status != http.StatusOK {
		t.Fatalf("verify failed: %s", string(verify.Body))
	}
	user, err := h.Auth.GetUserByEmail(context.Background(), "frank@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if user.EmailVerifiedAt == nil {
		t.Fatalf("the address is not marked as verified")
	}

	// AUTH-008: the same token cannot verify a second time.
	replay := h.Do(http.MethodPost, "/email-verification/verify", map[string]string{"token": msg.Token})
	if replay.Status != http.StatusBadRequest {
		t.Fatalf("expected the replay to fail, got status %d", replay.Status)
	}
	if code := replay.ErrorCode(t); code != "INVALID_TOKEN" {
		t.Fatalf("unexpected code %q", code)
	}
	ok, _ := h.SignIn("frank@example.com", testPassword)
	if ok.Status != http.StatusOK {
		t.Fatalf("a verified account cannot sign in: %s", string(ok.Body))
	}
}

// TestAUTH009And010PasswordReset covers AUTH-009 and AUTH-010.
func TestAUTH009And010PasswordReset(t *testing.T) {
	h := emailPasswordHarness(t)
	h.SignUp("grace@example.com", testPassword)
	h.ClearCookies()

	forgot := h.Do(http.MethodPost, "/password/forgot", map[string]string{"email": "grace@example.com"})
	if forgot.Status != http.StatusOK {
		t.Fatalf("forgot failed: %s", string(forgot.Body))
	}
	msg := h.Mail.Last(t, email.IntentResetPassword)
	const newPassword = "another sufficiently long password"

	reset := h.Do(http.MethodPost, "/password/reset", map[string]string{
		"token": msg.Token, "password": newPassword,
	})
	if reset.Status != http.StatusOK {
		t.Fatalf("reset failed: %s", string(reset.Body))
	}
	if old, _ := h.SignIn("grace@example.com", testPassword); old.Status != http.StatusUnauthorized {
		t.Fatalf("the old password still works")
	}
	if fresh, _ := h.SignIn("grace@example.com", newPassword); fresh.Status != http.StatusOK {
		t.Fatalf("the new password does not work: %s", string(fresh.Body))
	}

	// AUTH-010: the consumed token cannot change the password again.
	replay := h.Do(http.MethodPost, "/password/reset", map[string]string{
		"token": msg.Token, "password": "yet another long password",
	})
	if replay.Status != http.StatusBadRequest {
		t.Fatalf("expected the replay to fail, got %d", replay.Status)
	}
	if code := replay.ErrorCode(t); code != "INVALID_TOKEN" {
		t.Fatalf("unexpected code %q", code)
	}
	if again, _ := h.SignIn("grace@example.com", newPassword); again.Status != http.StatusOK {
		t.Fatalf("the password changed after the replay")
	}
}

// TestPasswordResetRevokesSessions checks that a reset ends every session.
func TestPasswordResetRevokesSessions(t *testing.T) {
	h := emailPasswordHarness(t)
	_, out := h.SignUp("heidi@example.com", testPassword)
	cookie := h.SessionCookie()

	h.Do(http.MethodPost, "/password/forgot", map[string]string{"email": "heidi@example.com"})
	msg := h.Mail.Last(t, email.IntentResetPassword)
	h.Do(http.MethodPost, "/password/reset", map[string]string{
		"token": msg.Token, "password": "a brand new long password",
	})
	after := h.GetSession(testsupport.WithBearer(cookie.Value))
	if after.Session != nil {
		t.Fatalf("the session of user %s survived the password reset", out.User.ID)
	}
}
