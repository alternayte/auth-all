package authall_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	authall "github.com/alternayte/auth-all"
	"github.com/alternayte/auth-all/internal/testsupport"
	"github.com/alternayte/auth-all/internal/totp"
)

// totpHarness builds an instance with email, password, and TOTP.
func totpHarness(t *testing.T, opts ...authall.Option) *testsupport.Harness {
	t.Helper()
	all := append([]authall.Option{authall.WithEmailPassword(), authall.WithTOTP()}, opts...)
	return testsupport.NewHarness(t, all...)
}

// enrolResult is the decoded body of the enrolment response.
type enrolResult struct {
	Secret string `json:"secret"`
	URI    string `json:"uri"`
}

// enrol starts an enrolment and returns the secret of the response.
func enrol(t *testing.T, h *testsupport.Harness) enrolResult {
	t.Helper()
	resp := h.Do(http.MethodPost, "/totp/enrol", map[string]any{})
	if resp.Status != http.StatusOK {
		t.Fatalf("the enrolment returned %d: %s", resp.Status, string(resp.Body))
	}
	var out enrolResult
	resp.Decode(t, &out)
	return out
}

// codeFor returns the current code of a base32 secret.
func codeFor(t *testing.T, secret string) string {
	t.Helper()
	raw, err := totp.DecodeSecret(secret)
	if err != nil {
		t.Fatalf("decode the secret: %v", err)
	}
	return totp.Generate(raw, time.Now(), totp.Default())
}

// TestTOTPEnrolReturnsASecretAndAURI covers the first enrolment step.
func TestTOTPEnrolReturnsASecretAndAURI(t *testing.T) {
	h := totpHarness(t)
	h.SignUp("enrol@example.com", testPassword)

	out := enrol(t, h)
	if out.Secret == "" {
		t.Fatal("the response carries no secret")
	}
	if _, err := totp.DecodeSecret(out.Secret); err != nil {
		t.Fatalf("the secret is not valid base32: %v", err)
	}
	if !strings.HasPrefix(out.URI, "otpauth://totp/") {
		t.Fatalf("the URI is %q", out.URI)
	}
	if !strings.Contains(out.URI, "enrol@example.com") {
		t.Fatalf("the URI names no account: %q", out.URI)
	}

	// The enrolment is not live until the user proves one code.
	user, err := h.Auth.GetUserByEmail(context.Background(), "enrol@example.com")
	if err != nil {
		t.Fatal(err)
	}
	rec, err := h.Store.TOTP().Get(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("the enrolment wrote no row: %v", err)
	}
	if rec.ConfirmedAt != nil {
		t.Fatal("the enrolment is confirmed before the user proved a code")
	}
}

// TestTOTPEnrolNeedsASession covers the guard of the enrolment endpoint.
func TestTOTPEnrolNeedsASession(t *testing.T) {
	h := totpHarness(t)
	resp := h.Do(http.MethodPost, "/totp/enrol", map[string]any{})
	if resp.Status != http.StatusUnauthorized {
		t.Fatalf("status %d: %s", resp.Status, string(resp.Body))
	}
}

// TestTOTPConfirmActivatesTheSecondFactor covers the second enrolment step.
func TestTOTPConfirmActivatesTheSecondFactor(t *testing.T) {
	h := totpHarness(t)
	h.SignUp("confirm@example.com", testPassword)
	out := enrol(t, h)

	resp := h.Do(http.MethodPost, "/totp/confirm", map[string]any{"code": codeFor(t, out.Secret)})
	if resp.Status != http.StatusOK {
		t.Fatalf("the confirmation returned %d: %s", resp.Status, string(resp.Body))
	}

	user, err := h.Auth.GetUserByEmail(context.Background(), "confirm@example.com")
	if err != nil {
		t.Fatal(err)
	}
	rec, err := h.Store.TOTP().Get(context.Background(), user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if rec.ConfirmedAt == nil {
		t.Fatal("the enrolment is not confirmed")
	}
}

// TestTOTPConfirmRefusesAWrongCode checks that a wrong code proves nothing.
func TestTOTPConfirmRefusesAWrongCode(t *testing.T) {
	h := totpHarness(t)
	h.SignUp("wrong@example.com", testPassword)
	enrol(t, h)

	resp := h.Do(http.MethodPost, "/totp/confirm", map[string]any{"code": "000000"})
	if resp.Status != http.StatusBadRequest {
		t.Fatalf("status %d: %s", resp.Status, string(resp.Body))
	}
	if code := resp.ErrorCode(t); code != "INVALID_TOTP_CODE" {
		t.Fatalf("the error code is %q", code)
	}

	user, err := h.Auth.GetUserByEmail(context.Background(), "wrong@example.com")
	if err != nil {
		t.Fatal(err)
	}
	rec, err := h.Store.TOTP().Get(context.Background(), user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if rec.ConfirmedAt != nil {
		t.Fatal("a wrong code confirmed the enrolment")
	}
}

// TestTOTPConfirmNeedsAnEnrolment checks the order of the two steps.
func TestTOTPConfirmNeedsAnEnrolment(t *testing.T) {
	h := totpHarness(t)
	h.SignUp("noenrol@example.com", testPassword)

	resp := h.Do(http.MethodPost, "/totp/confirm", map[string]any{"code": "000000"})
	if resp.Status != http.StatusBadRequest {
		t.Fatalf("status %d: %s", resp.Status, string(resp.Body))
	}
	if code := resp.ErrorCode(t); code != "TOTP_NOT_ENROLLED" {
		t.Fatalf("the error code is %q", code)
	}
}

// TestTOTPConfirmRevokesTheOtherSessions covers the decision of the plan. A
// user who turns on a second factor usually suspects a compromise, so a
// pre-existing session must not survive the upgrade.
func TestTOTPConfirmRevokesTheOtherSessions(t *testing.T) {
	h := totpHarness(t)
	const address = "revoke@example.com"
	h.SignUp(address, testPassword)

	// A second browser opens a second session.
	h.ClearCookies()
	h.SignIn(address, testPassword)
	second := h.SessionCookie()

	out := enrol(t, h)
	resp := h.Do(http.MethodPost, "/totp/confirm", map[string]any{"code": codeFor(t, out.Secret)})
	if resp.Status != http.StatusOK {
		t.Fatalf("the confirmation returned %d: %s", resp.Status, string(resp.Body))
	}

	// The session that confirmed the enrolment still works.
	if got := h.GetSession(); got.User == nil {
		t.Fatal("the confirming session was revoked")
	}

	// Every other session is gone.
	user, err := h.Auth.GetUserByEmail(context.Background(), address)
	if err != nil {
		t.Fatal(err)
	}
	list, err := h.Store.Sessions().ListByUser(context.Background(), user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("the user holds %d sessions after the confirmation", len(list))
	}
	if list[0].TokenHash != sha256Hex(second.Value) {
		t.Fatal("the surviving session is not the confirming session")
	}
}

// TestTOTPEnrolRefusesAConfirmedEnrolment checks that a live second factor is
// never replaced without a proof.
func TestTOTPEnrolRefusesAConfirmedEnrolment(t *testing.T) {
	h := totpHarness(t)
	h.SignUp("already@example.com", testPassword)
	out := enrol(t, h)
	if resp := h.Do(http.MethodPost, "/totp/confirm",
		map[string]any{"code": codeFor(t, out.Secret)}); resp.Status != http.StatusOK {
		t.Fatalf("the confirmation returned %d: %s", resp.Status, string(resp.Body))
	}

	resp := h.Do(http.MethodPost, "/totp/enrol", map[string]any{})
	if resp.Status != http.StatusConflict {
		t.Fatalf("status %d: %s", resp.Status, string(resp.Body))
	}
	if code := resp.ErrorCode(t); code != "TOTP_ALREADY_ENROLLED" {
		t.Fatalf("the error code is %q", code)
	}
}

// TestTOTPEnrolReplacesAnAbandonedEnrolment checks that a user who never
// finished the flow can restart it.
func TestTOTPEnrolReplacesAnAbandonedEnrolment(t *testing.T) {
	h := totpHarness(t)
	h.SignUp("restart@example.com", testPassword)
	first := enrol(t, h)
	second := enrol(t, h)
	if first.Secret == second.Secret {
		t.Fatal("the restart returned the abandoned secret")
	}
	// The abandoned secret proves nothing after the restart.
	resp := h.Do(http.MethodPost, "/totp/confirm", map[string]any{"code": codeFor(t, first.Secret)})
	if resp.Status != http.StatusBadRequest {
		t.Fatalf("the abandoned secret confirmed the enrolment: %d", resp.Status)
	}
	if resp := h.Do(http.MethodPost, "/totp/confirm",
		map[string]any{"code": codeFor(t, second.Secret)}); resp.Status != http.StatusOK {
		t.Fatalf("the new secret failed: %d %s", resp.Status, string(resp.Body))
	}
}

// clockHarness builds a TOTP instance over a clock that the test moves. The
// step guard refuses a code of a step that already authenticated, so a test
// that runs two flows must move past the step between them.
func clockHarness(t *testing.T) (*testsupport.Harness, *time.Time) {
	t.Helper()
	at := time.Now().UTC()
	h := totpHarness(t, authall.WithClock(func() time.Time { return at }))
	return h, &at
}

// codeAt returns the code of a base32 secret at one instant.
func codeAt(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	raw, err := totp.DecodeSecret(secret)
	if err != nil {
		t.Fatalf("decode the secret: %v", err)
	}
	return totp.Generate(raw, at, totp.Default())
}

// TestTOTPDisableNeedsACurrentCode checks that a session alone cannot remove
// the factor that protects the session.
func TestTOTPDisableNeedsACurrentCode(t *testing.T) {
	h, clock := clockHarness(t)
	const address = "disable@example.com"
	h.SignUp(address, testPassword)
	out := enrol(t, h)
	if resp := h.Do(http.MethodPost, "/totp/confirm",
		map[string]any{"code": codeAt(t, out.Secret, *clock)}); resp.Status != http.StatusOK {
		t.Fatalf("the confirmation returned %d", resp.Status)
	}

	// The confirmation used the current step, so the disable runs later.
	*clock = clock.Add(2 * time.Minute)

	// A wrong code keeps the second factor.
	resp := h.Do(http.MethodPost, "/totp/disable", map[string]any{"code": "000000"})
	if resp.Status != http.StatusBadRequest {
		t.Fatalf("status %d: %s", resp.Status, string(resp.Body))
	}
	user, err := h.Auth.GetUserByEmail(context.Background(), address)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.Store.TOTP().Get(context.Background(), user.ID); err != nil {
		t.Fatalf("a wrong code removed the second factor: %v", err)
	}

	// A correct code removes it.
	if resp := h.Do(http.MethodPost, "/totp/disable",
		map[string]any{"code": codeAt(t, out.Secret, *clock)}); resp.Status != http.StatusOK {
		t.Fatalf("the disable returned %d: %s", resp.Status, string(resp.Body))
	}
	if _, err := h.Store.TOTP().Get(context.Background(), user.ID); err == nil {
		t.Fatal("the second factor survived the disable")
	}
}

// TestTOTPCodeIsRefusedASecondTime covers the replay defence. A code that an
// attacker reads from a shoulder or a phishing page must not authenticate a
// second time inside its own window.
func TestTOTPCodeIsRefusedASecondTime(t *testing.T) {
	h, clock := clockHarness(t)
	h.SignUp("replay@example.com", testPassword)
	out := enrol(t, h)
	code := codeAt(t, out.Secret, *clock)

	if resp := h.Do(http.MethodPost, "/totp/confirm",
		map[string]any{"code": code}); resp.Status != http.StatusOK {
		t.Fatalf("the confirmation returned %d: %s", resp.Status, string(resp.Body))
	}

	// The same code, inside the same window, proves nothing a second time.
	resp := h.Do(http.MethodPost, "/totp/disable", map[string]any{"code": code})
	if resp.Status != http.StatusBadRequest {
		t.Fatalf("the replayed code returned %d: %s", resp.Status, string(resp.Body))
	}
	if got := resp.ErrorCode(t); got != "INVALID_TOTP_CODE" {
		t.Fatalf("the error code is %q", got)
	}

	user, err := h.Auth.GetUserByEmail(context.Background(), "replay@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.Store.TOTP().Get(context.Background(), user.ID); err != nil {
		t.Fatalf("the replayed code removed the second factor: %v", err)
	}

	// A code of a later step authenticates.
	*clock = clock.Add(2 * time.Minute)
	if resp := h.Do(http.MethodPost, "/totp/disable",
		map[string]any{"code": codeAt(t, out.Secret, *clock)}); resp.Status != http.StatusOK {
		t.Fatalf("a later code returned %d: %s", resp.Status, string(resp.Body))
	}
}

// TestTOTPRoutesStayOffWithoutTheOption checks that the endpoints appear only
// when the application enables TOTP.
func TestTOTPRoutesStayOffWithoutTheOption(t *testing.T) {
	h := emailPasswordHarness(t)
	h.SignUp("off@example.com", testPassword)
	if resp := h.Do(http.MethodPost, "/totp/enrol", map[string]any{}); resp.Status != http.StatusNotFound {
		t.Fatalf("status %d: %s", resp.Status, string(resp.Body))
	}
	for _, route := range h.Auth.Routes() {
		if strings.HasPrefix(route.Path, "/totp") {
			t.Fatalf("the route %s %s exists without the option", route.Method, route.Path)
		}
	}
}

// TestTOTPSecretNeverReachesTheDatabaseInPlaintextOfTheURI checks that the
// stored row carries the base32 secret and no otpauth URI.
func TestTOTPSecretIsStoredAsBase32(t *testing.T) {
	h := totpHarness(t)
	h.SignUp("stored@example.com", testPassword)
	out := enrol(t, h)

	user, err := h.Auth.GetUserByEmail(context.Background(), "stored@example.com")
	if err != nil {
		t.Fatal(err)
	}
	rec, err := h.Store.TOTP().Get(context.Background(), user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Secret != out.Secret {
		t.Fatalf("the stored secret is %q and the response carried %q", rec.Secret, out.Secret)
	}
}

// TestTOTPEnrolChecksTheOrigin covers the state-changing guard.
func TestTOTPEnrolChecksTheOrigin(t *testing.T) {
	h := totpHarness(t)
	h.SignUp("origin@example.com", testPassword)
	resp := h.Do(http.MethodPost, "/totp/enrol", map[string]any{},
		testsupport.WithHeader("Origin", "https://evil.example.com"))
	if resp.Status != http.StatusForbidden {
		t.Fatalf("status %d: %s", resp.Status, string(resp.Body))
	}
}
