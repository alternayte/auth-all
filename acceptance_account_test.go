package authall_test

import (
	"context"
	"net/http"
	"testing"

	authall "github.com/alternayte/auth-all"
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
