package authall_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/alternayte/auth-all/internal/crypto"
	"github.com/alternayte/auth-all/internal/testsupport"
)

// recoveryHash mirrors the storage form of a recovery code. Auth-All hashes the
// normalized value, so a code that a person retypes with a different case or no
// separator still matches.
func recoveryHash(code string) string {
	return crypto.HashToken(crypto.NormalizeRecoveryCode(code))
}

// confirmResult is the decoded body of a confirmation. It carries the recovery
// codes one time.
type confirmResult struct {
	Success       bool     `json:"success"`
	RecoveryCodes []string `json:"recoveryCodes"`
}

// enrolWithRecovery confirms an enrolment and returns the secret and the codes.
func enrolWithRecovery(t *testing.T, h *testsupport.Harness, clock *time.Time) (string, []string) {
	t.Helper()
	out := enrol(t, h)
	resp := h.Do(http.MethodPost, "/totp/confirm", map[string]any{"code": codeAt(t, out.Secret, *clock)})
	if resp.Status != http.StatusOK {
		t.Fatalf("the confirmation returned %d: %s", resp.Status, string(resp.Body))
	}
	var body confirmResult
	resp.Decode(t, &body)
	return out.Secret, body.RecoveryCodes
}

// TestConfirmReturnsTenRecoveryCodes covers the issuance. Every enrolled user
// holds codes by construction, so no user can reach a locked account.
func TestConfirmReturnsTenRecoveryCodes(t *testing.T) {
	h, clock := clockHarness(t)
	h.SignUp("codes@example.com", testPassword)
	_, codes := enrolWithRecovery(t, h, clock)

	if len(codes) != 10 {
		t.Fatalf("the confirmation returned %d codes", len(codes))
	}
	seen := map[string]bool{}
	for _, c := range codes {
		if c == "" {
			t.Fatal("the set holds an empty code")
		}
		if seen[c] {
			t.Fatalf("the code %q appears two times", c)
		}
		seen[c] = true
	}

	user, err := h.Auth.GetUserByEmail(context.Background(), "codes@example.com")
	if err != nil {
		t.Fatal(err)
	}
	n, err := h.Store.RecoveryCodes().CountByUser(context.Background(), user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if n != 10 {
		t.Fatalf("the store holds %d codes", n)
	}
}

// TestRecoveryCodeIsNotStoredInPlaintext checks that the database keeps only a
// hash. A recovery code is a complete sign-in.
func TestRecoveryCodeIsNotStoredInPlaintext(t *testing.T) {
	h, clock := clockHarness(t)
	h.SignUp("plaintext@example.com", testPassword)
	_, codes := enrolWithRecovery(t, h, clock)

	user, err := h.Auth.GetUserByEmail(context.Background(), "plaintext@example.com")
	if err != nil {
		t.Fatal(err)
	}
	// The store exposes no reader for the hashes, so the check consumes the
	// hash of the first code. A stored plaintext would not match that hash.
	ok, err := h.Store.RecoveryCodes().Consume(context.Background(), user.ID, codes[0])
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("the database stores the recovery code in plaintext")
	}
	ok, err = h.Store.RecoveryCodes().Consume(context.Background(), user.ID, recoveryHash(codes[0]))
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("the database does not store the SHA-256 hash of the code")
	}
}

// TestRecoveryCodeCompletesAGatedSignIn covers the path that this work exists
// for. A user who lost their authenticator signs in.
func TestRecoveryCodeCompletesAGatedSignIn(t *testing.T) {
	h, clock := clockHarness(t)
	const address = "lost@example.com"
	h.SignUp(address, testPassword)
	_, codes := enrolWithRecovery(t, h, clock)
	*clock = clock.Add(2 * time.Minute)

	user, err := h.Auth.GetUserByEmail(context.Background(), address)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.Store.Sessions().DeleteByUser(context.Background(), user.ID); err != nil {
		t.Fatal(err)
	}
	h.ClearCookies()

	resp := h.Do(http.MethodPost, "/sign-in/email",
		map[string]any{"email": address, "password": testPassword})
	var challenge mfaResult
	resp.Decode(t, &challenge)
	if !challenge.MFARequired {
		t.Fatal("the sign-in did not ask for a second factor")
	}

	recover := h.Do(http.MethodPost, "/totp/recovery", map[string]any{
		"mfaToken": challenge.MFAToken,
		"code":     codes[0],
	})
	if recover.Status != http.StatusOK {
		t.Fatalf("the recovery returned %d: %s", recover.Status, string(recover.Body))
	}
	if got := h.GetSession(); got.User == nil {
		t.Fatal("the recovery opened no session")
	}
}

// TestRecoveryCodeDisablesTheSecondFactor covers the decision of the plan. A
// user who signs in with a code holds no factor they cannot satisfy.
func TestRecoveryCodeDisablesTheSecondFactor(t *testing.T) {
	h, clock := clockHarness(t)
	const address = "disables@example.com"
	h.SignUp(address, testPassword)
	_, codes := enrolWithRecovery(t, h, clock)
	*clock = clock.Add(2 * time.Minute)

	user, err := h.Auth.GetUserByEmail(context.Background(), address)
	if err != nil {
		t.Fatal(err)
	}
	h.Store.Sessions().DeleteByUser(context.Background(), user.ID)
	h.ClearCookies()

	resp := h.Do(http.MethodPost, "/sign-in/email",
		map[string]any{"email": address, "password": testPassword})
	var challenge mfaResult
	resp.Decode(t, &challenge)
	h.Do(http.MethodPost, "/totp/recovery",
		map[string]any{"mfaToken": challenge.MFAToken, "code": codes[0]})

	// The enrolment is gone.
	if _, err := h.Store.TOTP().Get(context.Background(), user.ID); err == nil {
		t.Fatal("the second factor survived the recovery")
	}
	// Every remaining code is gone, so a leaked list is worthless afterwards.
	n, err := h.Store.RecoveryCodes().CountByUser(context.Background(), user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("%d recovery codes survived the recovery", n)
	}

	// The next sign-in needs no second factor.
	h.ClearCookies()
	next, out := h.SignIn(address, testPassword)
	if next.Status != http.StatusOK || out.User == nil {
		t.Fatalf("the next sign-in failed: %d %s", next.Status, string(next.Body))
	}
}

// TestRecoveryCodeWorksOneTime covers the consume.
func TestRecoveryCodeWorksOneTime(t *testing.T) {
	h, clock := clockHarness(t)
	const address = "onetime@example.com"
	h.SignUp(address, testPassword)
	_, codes := enrolWithRecovery(t, h, clock)
	*clock = clock.Add(2 * time.Minute)

	user, _ := h.Auth.GetUserByEmail(context.Background(), address)
	h.Store.Sessions().DeleteByUser(context.Background(), user.ID)
	h.ClearCookies()

	resp := h.Do(http.MethodPost, "/sign-in/email",
		map[string]any{"email": address, "password": testPassword})
	var challenge mfaResult
	resp.Decode(t, &challenge)
	if r := h.Do(http.MethodPost, "/totp/recovery",
		map[string]any{"mfaToken": challenge.MFAToken, "code": codes[0]}); r.Status != http.StatusOK {
		t.Fatalf("the first use returned %d: %s", r.Status, string(r.Body))
	}

	// The second factor is off, so a second sign-in needs no challenge. The
	// code itself must also be gone from the store.
	ok, err := h.Store.RecoveryCodes().Consume(context.Background(), user.ID, recoveryHash(codes[0]))
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("the used recovery code survived")
	}
}

// TestWrongRecoveryCodeKeepsTheSecondFactor checks that a failed attempt
// removes nothing.
func TestWrongRecoveryCodeKeepsTheSecondFactor(t *testing.T) {
	h, clock := clockHarness(t)
	const address = "wrongrecovery@example.com"
	h.SignUp(address, testPassword)
	_, codes := enrolWithRecovery(t, h, clock)
	*clock = clock.Add(2 * time.Minute)

	user, _ := h.Auth.GetUserByEmail(context.Background(), address)
	h.Store.Sessions().DeleteByUser(context.Background(), user.ID)
	h.ClearCookies()

	resp := h.Do(http.MethodPost, "/sign-in/email",
		map[string]any{"email": address, "password": testPassword})
	var challenge mfaResult
	resp.Decode(t, &challenge)

	bad := h.Do(http.MethodPost, "/totp/recovery", map[string]any{
		"mfaToken": challenge.MFAToken, "code": "zzzzz-zzzzz",
	})
	if bad.Status != http.StatusBadRequest {
		t.Fatalf("status %d: %s", bad.Status, string(bad.Body))
	}
	if h.SessionCookie() != nil {
		t.Fatal("a wrong recovery code opened a session")
	}
	if _, err := h.Store.TOTP().Get(context.Background(), user.ID); err != nil {
		t.Fatal("a wrong recovery code removed the second factor")
	}
	n, _ := h.Store.RecoveryCodes().CountByUser(context.Background(), user.ID)
	if n != 10 {
		t.Fatalf("a wrong recovery code removed codes: %d remain", n)
	}
	_ = codes
}

// TestRecoveryCodeOfAnotherUserFails covers the owner check over HTTP.
func TestRecoveryCodeOfAnotherUserFails(t *testing.T) {
	h, clock := clockHarness(t)
	h.SignUp("victim@example.com", testPassword)
	_, victimCodes := enrolWithRecovery(t, h, clock)
	*clock = clock.Add(2 * time.Minute)

	h.ClearCookies()
	h.SignUp("attacker@example.com", testPassword)
	_, _ = enrolWithRecovery(t, h, clock)
	*clock = clock.Add(2 * time.Minute)

	attacker, _ := h.Auth.GetUserByEmail(context.Background(), "attacker@example.com")
	h.Store.Sessions().DeleteByUser(context.Background(), attacker.ID)
	h.ClearCookies()

	resp := h.Do(http.MethodPost, "/sign-in/email",
		map[string]any{"email": "attacker@example.com", "password": testPassword})
	var challenge mfaResult
	resp.Decode(t, &challenge)

	// The attacker holds a code of the victim and their own challenge.
	bad := h.Do(http.MethodPost, "/totp/recovery", map[string]any{
		"mfaToken": challenge.MFAToken, "code": victimCodes[0],
	})
	if bad.Status == http.StatusOK {
		t.Fatal("a code of another user completed the sign-in")
	}
	victim, _ := h.Auth.GetUserByEmail(context.Background(), "victim@example.com")
	if n, _ := h.Store.RecoveryCodes().CountByUser(context.Background(), victim.ID); n != 10 {
		t.Fatalf("the attempt consumed a code of the victim: %d remain", n)
	}
}

// TestRegenerateReplacesTheWholeSet covers the regeneration.
func TestRegenerateReplacesTheWholeSet(t *testing.T) {
	h, clock := clockHarness(t)
	const address = "regen@example.com"
	h.SignUp(address, testPassword)
	secret, first := enrolWithRecovery(t, h, clock)
	*clock = clock.Add(2 * time.Minute)

	resp := h.Do(http.MethodPost, "/totp/recovery-codes/regenerate",
		map[string]any{"code": codeAt(t, secret, *clock)})
	if resp.Status != http.StatusOK {
		t.Fatalf("the regeneration returned %d: %s", resp.Status, string(resp.Body))
	}
	var body confirmResult
	resp.Decode(t, &body)
	if len(body.RecoveryCodes) != 10 {
		t.Fatalf("the regeneration returned %d codes", len(body.RecoveryCodes))
	}

	user, _ := h.Auth.GetUserByEmail(context.Background(), address)
	// Every old code is worthless.
	for _, c := range first {
		if ok, _ := h.Store.RecoveryCodes().Consume(context.Background(), user.ID, recoveryHash(c)); ok {
			t.Fatalf("the old code %q still works", c)
		}
	}
	if n, _ := h.Store.RecoveryCodes().CountByUser(context.Background(), user.ID); n != 10 {
		t.Fatalf("the store holds %d codes after the regeneration", n)
	}
}

// TestRegenerateNeedsACurrentCode checks the proof.
func TestRegenerateNeedsACurrentCode(t *testing.T) {
	h, clock := clockHarness(t)
	const address = "regenguard@example.com"
	h.SignUp(address, testPassword)
	_, first := enrolWithRecovery(t, h, clock)
	*clock = clock.Add(2 * time.Minute)

	resp := h.Do(http.MethodPost, "/totp/recovery-codes/regenerate",
		map[string]any{"code": "000000"})
	if resp.Status != http.StatusBadRequest {
		t.Fatalf("status %d: %s", resp.Status, string(resp.Body))
	}

	// The old set survives a failed attempt.
	user, _ := h.Auth.GetUserByEmail(context.Background(), address)
	if ok, _ := h.Store.RecoveryCodes().Consume(context.Background(), user.ID, recoveryHash(first[0])); !ok {
		t.Fatal("a failed regeneration destroyed the old set")
	}
}

// TestRegenerateNeedsASession checks the guard.
func TestRegenerateNeedsASession(t *testing.T) {
	h, _ := clockHarness(t)
	resp := h.Do(http.MethodPost, "/totp/recovery-codes/regenerate", map[string]any{"code": "000000"})
	if resp.Status != http.StatusUnauthorized {
		t.Fatalf("status %d: %s", resp.Status, string(resp.Body))
	}
}
