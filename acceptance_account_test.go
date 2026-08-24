package authall_test

import (
	"context"
	"net/http"
	"testing"

	authall "github.com/alternayte/auth-all"
	"github.com/alternayte/auth-all/email"
	"github.com/alternayte/auth-all/internal/testsupport"
)

const newTestPassword = "another sufficiently long password"

// TestPasswordChangeReplacesTheCredential covers the success path.
func TestPasswordChangeReplacesTheCredential(t *testing.T) {
	h := emailPasswordHarness(t)
	const address = "change-password@example.com"
	h.SignUp(address, testPassword)
	other := h.SessionCookie()

	// The person signs in on a second device, which becomes the current one.
	h.ClearCookies()
	h.SignIn(address, testPassword)
	current := h.SessionCookie()

	resp := h.Do(http.MethodPost, "/password/change", map[string]any{
		"currentPassword": testPassword,
		"newPassword":     newTestPassword,
	})
	if resp.Status != http.StatusOK {
		t.Fatalf("the change failed: %d %s", resp.Status, string(resp.Body))
	}

	// The current session lives.
	if session := h.GetSession(); session.User == nil {
		t.Fatalf("the change revoked the current session")
	}
	// The other session is gone.
	h.ClearCookies()
	if session := h.GetSession(testsupport.WithBearer(other.Value)); session.Session != nil {
		t.Fatalf("the change kept another session")
	}

	// The old password fails and the new one works.
	if old, _ := h.SignIn(address, testPassword); old.Status != http.StatusUnauthorized {
		t.Fatalf("the old password still signs in: %d", old.Status)
	}
	h.ClearCookies()
	if fresh, _ := h.SignIn(address, newTestPassword); fresh.Status != http.StatusOK {
		t.Fatalf("the new password does not sign in")
	}
	_ = current
}

// TestPasswordChangeCanKeepTheOtherSessions checks the body field.
func TestPasswordChangeCanKeepTheOtherSessions(t *testing.T) {
	h := emailPasswordHarness(t)
	const address = "change-keep@example.com"
	h.SignUp(address, testPassword)
	other := h.SessionCookie()
	h.ClearCookies()
	h.SignIn(address, testPassword)

	resp := h.Do(http.MethodPost, "/password/change", map[string]any{
		"currentPassword":     testPassword,
		"newPassword":         newTestPassword,
		"revokeOtherSessions": false,
	})
	if resp.Status != http.StatusOK {
		t.Fatalf("the change failed: %s", string(resp.Body))
	}
	h.ClearCookies()
	if session := h.GetSession(testsupport.WithBearer(other.Value)); session.Session == nil {
		t.Fatalf("the other session was revoked although the caller kept it")
	}
}

// TestPasswordChangeRejectsAWrongCurrentPassword covers the failure path.
func TestPasswordChangeRejectsAWrongCurrentPassword(t *testing.T) {
	h := emailPasswordHarness(t)
	const address = "change-wrong@example.com"
	h.SignUp(address, testPassword)

	resp := h.Do(http.MethodPost, "/password/change", map[string]any{
		"currentPassword": "a completely different password",
		"newPassword":     newTestPassword,
	})
	if resp.Status != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", resp.Status, string(resp.Body))
	}
	if code := resp.ErrorCode(t); code != "INVALID_CREDENTIALS" {
		t.Fatalf("unexpected code %q", code)
	}
	// The credential did not change.
	h.ClearCookies()
	if ok, _ := h.SignIn(address, testPassword); ok.Status != http.StatusOK {
		t.Fatalf("a failed change replaced the password")
	}
}

// TestPasswordChangeNeedsASessionAndAnOrigin covers the two guards.
func TestPasswordChangeNeedsASessionAndAnOrigin(t *testing.T) {
	h := emailPasswordHarness(t, authall.WithTrustedOrigins("https://app.example.com"))
	const address = "change-guards@example.com"
	h.SignUp(address, testPassword)

	forged := h.Do(http.MethodPost, "/password/change", map[string]any{
		"currentPassword": testPassword, "newPassword": newTestPassword,
	}, testsupport.WithHeader("Origin", "https://evil.example.com"))
	if code := forged.ErrorCode(t); code != "ORIGIN_NOT_ALLOWED" {
		t.Fatalf("unexpected code %q", code)
	}

	h.ClearCookies()
	anonymous := h.Do(http.MethodPost, "/password/change", map[string]any{
		"currentPassword": testPassword, "newPassword": newTestPassword,
	})
	if anonymous.Status != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", anonymous.Status)
	}

	// The password survives both rejected attempts.
	if ok, _ := h.SignIn(address, testPassword); ok.Status != http.StatusOK {
		t.Fatalf("a rejected change replaced the password")
	}
}

// TestPasswordChangeWithoutACredential covers the OAuth-only user.
func TestPasswordChangeWithoutACredential(t *testing.T) {
	h := emailPasswordHarness(t)
	// The user signs in once, and then loses the password credential. An
	// OAuth-only user reaches the same state.
	const address = "no-credential@example.com"
	h.SignUp(address, testPassword)
	user, err := h.Auth.GetUserByEmail(context.Background(), address)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Store.Users().DeleteCredential(context.Background(), user.ID); err != nil {
		t.Fatalf("delete the credential: %v", err)
	}

	resp := h.Do(http.MethodPost, "/password/change", map[string]any{
		"currentPassword": testPassword,
		"newPassword":     newTestPassword,
	})
	if resp.Status != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", resp.Status, string(resp.Body))
	}
	if code := resp.ErrorCode(t); code != "NO_PASSWORD_CREDENTIAL" {
		t.Fatalf("unexpected code %q", code)
	}
}

// TestPasswordChangeAppliesThePolicy checks the password policy.
func TestPasswordChangeAppliesThePolicy(t *testing.T) {
	h := emailPasswordHarness(t)
	h.SignUp("change-policy@example.com", testPassword)
	resp := h.Do(http.MethodPost, "/password/change", map[string]any{
		"currentPassword": testPassword,
		"newPassword":     "short",
	})
	if code := resp.ErrorCode(t); code != "WEAK_PASSWORD" {
		t.Fatalf("unexpected code %q", code)
	}
}

// TestAccountEmailChangeMovesTheAddress covers the success path.
func TestAccountEmailChangeMovesTheAddress(t *testing.T) {
	h := emailPasswordHarness(t)
	const oldAddress = "move-from@example.com"
	const newAddress = "move-to@example.com"
	h.SignUp(oldAddress, testPassword)
	other := h.SessionCookie()
	h.ClearCookies()
	h.SignIn(oldAddress, testPassword)
	h.Mail.Reset()

	resp := h.Do(http.MethodPost, "/email/change", map[string]any{
		"newEmail": newAddress, "currentPassword": testPassword,
	})
	if resp.Status != http.StatusOK {
		t.Fatalf("the request failed: %d %s", resp.Status, string(resp.Body))
	}

	// The confirmation goes to the new address and carries a token.
	confirm := h.Mail.Last(t, email.IntentEmailChange)
	if confirm.To != newAddress {
		t.Fatalf("the confirmation went to %q", confirm.To)
	}
	if confirm.Token == "" {
		t.Fatalf("the confirmation carries no token")
	}
	// The notice goes to the old address and carries no token.
	notice, ok := h.Mail.Find(email.IntentEmailChangeNotice)
	if !ok {
		t.Fatalf("the old address received no notice")
	}
	if notice.To != oldAddress {
		t.Fatalf("the notice went to %q", notice.To)
	}
	if notice.Token != "" || notice.URL != "" {
		t.Fatalf("the notice carries a token or a link: %+v", notice)
	}

	// The address does not move before the confirmation.
	if _, err := h.Auth.GetUserByEmail(context.Background(), newAddress); err == nil {
		t.Fatalf("the address moved before the confirmation")
	}

	verify := h.Do(http.MethodPost, "/email/change/verify", map[string]any{"token": confirm.Token})
	if verify.Status != http.StatusOK {
		t.Fatalf("the confirmation failed: %d %s", verify.Status, string(verify.Body))
	}

	user, err := h.Auth.GetUserByEmail(context.Background(), newAddress)
	if err != nil {
		t.Fatalf("the address did not move: %v", err)
	}
	if user.EmailVerifiedAt == nil {
		t.Fatalf("the new address is not verified")
	}
	if _, err := h.Auth.GetUserByEmail(context.Background(), oldAddress); err == nil {
		t.Fatalf("the old address still resolves to a user")
	}

	// The current session lives and the other one is gone.
	if session := h.GetSession(); session.User == nil {
		t.Fatalf("the change revoked the current session")
	}
	h.ClearCookies()
	if session := h.GetSession(testsupport.WithBearer(other.Value)); session.Session != nil {
		t.Fatalf("the change kept another session")
	}

	// The new address signs in and stays unique.
	if fresh, _ := h.SignIn(newAddress, testPassword); fresh.Status != http.StatusOK {
		t.Fatalf("the new address cannot sign in")
	}
	h.ClearCookies()
	taken := h.Do(http.MethodPost, "/sign-up/email", map[string]string{
		"email": newAddress, "password": testPassword,
	})
	if taken.Status != http.StatusConflict {
		t.Fatalf("the moved address is not unique: %d", taken.Status)
	}
}

// TestAccountEmailChangeIsEnumerationSafe proves that a taken address and a
// free address answer the same way.
func TestAccountEmailChangeIsEnumerationSafe(t *testing.T) {
	h := emailPasswordHarness(t)
	const taken = "already-here@example.com"
	h.SignUp(taken, testPassword)
	h.ClearCookies()
	h.SignUp("enum-change@example.com", testPassword)
	h.Mail.Reset()

	free := h.Do(http.MethodPost, "/email/change", map[string]any{
		"newEmail": "still-free@example.com", "currentPassword": testPassword,
	})
	if free.Status != http.StatusOK {
		t.Fatalf("the free address failed: %s", string(free.Body))
	}
	h.Mail.Reset()

	used := h.Do(http.MethodPost, "/email/change", map[string]any{
		"newEmail": taken, "currentPassword": testPassword,
	})
	if used.Status != free.Status || string(used.Body) != string(free.Body) {
		t.Fatalf("a taken address answers differently:\n%s\n%s", string(free.Body), string(used.Body))
	}
	// The flow stopped before the send, so the owner of the taken address
	// receives nothing.
	if len(h.Mail.All()) != 0 {
		t.Fatalf("a taken address produced a message: %+v", h.Mail.All())
	}
}

// TestAccountEmailChangeChecksThePassword covers the password guard.
func TestAccountEmailChangeChecksThePassword(t *testing.T) {
	h := emailPasswordHarness(t)
	h.SignUp("change-email-password@example.com", testPassword)
	h.Mail.Reset()

	resp := h.Do(http.MethodPost, "/email/change", map[string]any{
		"newEmail": "elsewhere@example.com", "currentPassword": "a wrong password value",
	})
	if resp.Status != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", resp.Status, string(resp.Body))
	}
	if code := resp.ErrorCode(t); code != "INVALID_CREDENTIALS" {
		t.Fatalf("unexpected code %q", code)
	}
	if len(h.Mail.All()) != 0 {
		t.Fatalf("a wrong password produced a message")
	}
}

// TestAccountEmailChangeWithoutACredential proves that a user without a
// password skips the password check.
func TestAccountEmailChangeWithoutACredential(t *testing.T) {
	h := emailPasswordHarness(t)
	const address = "provider-only@example.com"
	h.SignUp(address, testPassword)
	user, err := h.Auth.GetUserByEmail(context.Background(), address)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Store.Users().DeleteCredential(context.Background(), user.ID); err != nil {
		t.Fatal(err)
	}
	h.Mail.Reset()

	resp := h.Do(http.MethodPost, "/email/change", map[string]any{
		"newEmail": "provider-new@example.com",
	})
	if resp.Status != http.StatusOK {
		t.Fatalf("the request failed: %d %s", resp.Status, string(resp.Body))
	}
	if _, ok := h.Mail.Find(email.IntentEmailChange); !ok {
		t.Fatalf("no confirmation was sent")
	}
}

// TestAccountEmailChangeNeedsASessionAndAnOrigin covers the two guards.
func TestAccountEmailChangeNeedsASessionAndAnOrigin(t *testing.T) {
	h := emailPasswordHarness(t, authall.WithTrustedOrigins("https://app.example.com"))
	h.SignUp("change-email-guards@example.com", testPassword)

	forged := h.Do(http.MethodPost, "/email/change", map[string]any{
		"newEmail": "guard@example.com", "currentPassword": testPassword,
	}, testsupport.WithHeader("Origin", "https://evil.example.com"))
	if code := forged.ErrorCode(t); code != "ORIGIN_NOT_ALLOWED" {
		t.Fatalf("unexpected code %q", code)
	}

	h.ClearCookies()
	anonymous := h.Do(http.MethodPost, "/email/change", map[string]any{
		"newEmail": "guard@example.com", "currentPassword": testPassword,
	})
	if anonymous.Status != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", anonymous.Status)
	}
}

// TestAccountEmailChangeVerifyRejectsAReplay covers the one-time token.
func TestAccountEmailChangeVerifyRejectsAReplay(t *testing.T) {
	h := emailPasswordHarness(t)
	h.SignUp("replay-change@example.com", testPassword)
	h.Do(http.MethodPost, "/email/change", map[string]any{
		"newEmail": "replay-target@example.com", "currentPassword": testPassword,
	})
	token := h.Mail.Last(t, email.IntentEmailChange).Token

	if first := h.Do(http.MethodPost, "/email/change/verify", map[string]any{"token": token}); first.Status != http.StatusOK {
		t.Fatalf("the first confirmation failed: %s", string(first.Body))
	}
	replay := h.Do(http.MethodPost, "/email/change/verify", map[string]any{"token": token})
	if code := replay.ErrorCode(t); code != "INVALID_TOKEN" {
		t.Fatalf("unexpected code %q", code)
	}
}

// TestAccountEmailChangeVerifyRejectsATakenAddress covers the race between two
// requests for one address.
func TestAccountEmailChangeVerifyRejectsATakenAddress(t *testing.T) {
	h := emailPasswordHarness(t)
	const target = "contested@example.com"
	h.SignUp("first-mover@example.com", testPassword)
	h.Do(http.MethodPost, "/email/change", map[string]any{
		"newEmail": target, "currentPassword": testPassword,
	})
	token := h.Mail.Last(t, email.IntentEmailChange).Token

	// Another person takes the address before the confirmation arrives.
	h.ClearCookies()
	h.SignUp(target, testPassword)

	resp := h.Do(http.MethodPost, "/email/change/verify", map[string]any{"token": token})
	if resp.Status != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", resp.Status, string(resp.Body))
	}
	if code := resp.ErrorCode(t); code != "EMAIL_ALREADY_EXISTS" {
		t.Fatalf("unexpected code %q", code)
	}
}
