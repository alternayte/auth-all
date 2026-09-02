package authall_test

import (
	"context"
	"database/sql"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	authall "github.com/alternayte/auth-all"
	"github.com/alternayte/auth-all/email"
	"github.com/alternayte/auth-all/internal/crypto"
	"github.com/alternayte/auth-all/internal/testsupport"
	"github.com/alternayte/auth-all/plugins/magiclink"
	"github.com/alternayte/auth-all/ratelimit"
)

// forbiddenFragments are values that a public error body must never contain.
var forbiddenFragments = []string{
	testPassword,
	"argon2id",
	"$argon2",
	"SELECT ",
	"INSERT INTO",
	"UPDATE ",
	"auth_users",
	"goroutine",
	"sqlite",
	"pgx",
}

// TestSEC001SecretsAbsentFromErrors covers SEC-001.
func TestSEC001SecretsAbsentFromErrors(t *testing.T) {
	h := magicLinkHarness(t)
	_, out := h.SignUp("secrets@example.com", testPassword)
	cookie := h.SessionCookie()
	h.Do(http.MethodPost, "/password/forgot", map[string]string{"email": "secrets@example.com"})
	resetToken := h.Mail.Last(t, email.IntentResetPassword).Token
	sessionID := sessionIDOf(t, h, cookie.Value)

	// The signed-in routes run first, because they need the session.
	responses := []*testsupport.Response{
		h.Do(http.MethodPost, "/password/change", map[string]any{
			"currentPassword": "wrong password here", "newPassword": newTestPassword}),
		h.Do(http.MethodPost, "/password/change", map[string]any{
			"currentPassword": testPassword, "newPassword": "short"}),
		h.Do(http.MethodPost, "/email/change", map[string]any{
			"newEmail": "elsewhere@example.com", "currentPassword": "wrong password here"}),
		h.Do(http.MethodPost, "/email/change", map[string]any{
			"newEmail": "not-an-email", "currentPassword": testPassword}),
		h.Do(http.MethodPost, "/user/delete", map[string]any{"currentPassword": "wrong password here"}),
		h.Do(http.MethodDelete, "/sessions/00000000-0000-0000-0000-000000000000", nil),
		h.Do(http.MethodPost, "/sessions/revoke-all", "not json at all"),
	}
	h.ClearCookies()

	responses = append(responses,
		h.Do(http.MethodPost, "/sign-in/email", map[string]string{"email": "secrets@example.com", "password": "wrong password here"}),
		h.Do(http.MethodPost, "/sign-in/email", map[string]string{"email": "missing@example.com", "password": testPassword}),
		h.Do(http.MethodPost, "/sign-up/email", map[string]string{"email": "secrets@example.com", "password": testPassword}),
		h.Do(http.MethodPost, "/sign-up/email", map[string]string{"email": "not-an-email", "password": testPassword}),
		h.Do(http.MethodPost, "/password/reset", map[string]string{"token": "wrong-token", "password": testPassword}),
		h.Do(http.MethodPost, "/email-verification/verify", map[string]string{"token": "wrong-token"}),
		h.Do(http.MethodGet, "/magic-link/verify?token=wrong-token", nil),
		h.Do(http.MethodPost, "/magic-link/verify", map[string]string{"token": "wrong-token"}),
		h.Do(http.MethodPost, "/email/change/verify", map[string]string{"token": "wrong-token"}),
		h.Do(http.MethodPost, "/user/delete/verify", map[string]string{"token": "wrong-token"}),
		h.Do(http.MethodGet, "/sessions", nil),
		h.Do(http.MethodPost, "/user/delete", map[string]any{"currentPassword": testPassword}),
		h.Do(http.MethodPost, "/account/unlink/github", nil),
		h.Do(http.MethodPost, "/sign-up/email", "not json at all"),
	)
	secrets := []string{cookie.Value, resetToken, sessionID, sha256Hex(cookie.Value), out.User.ID + "-never"}
	for i, resp := range responses {
		body := string(resp.Body)
		for _, fragment := range forbiddenFragments {
			if strings.Contains(body, fragment) {
				t.Fatalf("response %d leaks %q: %s", i, fragment, body)
			}
		}
		for _, secret := range secrets {
			if secret != "" && strings.Contains(body, secret) {
				t.Fatalf("response %d leaks a secret value: %s", i, body)
			}
		}
	}
}

// TestSEC002SessionTokenStorage covers SEC-002.
func TestSEC002SessionTokenStorage(t *testing.T) {
	h := emailPasswordHarness(t)
	h.SignUp("stored@example.com", testPassword)
	cookie := h.SessionCookie()
	if cookie == nil || cookie.Value == "" {
		t.Fatalf("no session cookie was issued")
	}
	raw := rawDB(t, h)
	assertColumnFree(t, raw, "auth_sessions", []string{"id", "user_id", "token_hash"}, cookie.Value)

	sess, err := h.Store.Sessions().GetByTokenHash(context.Background(), sha256Hex(cookie.Value))
	if err != nil {
		t.Fatalf("the session is not stored under its hash: %v", err)
	}
	if sess.TokenHash == cookie.Value {
		t.Fatalf("the plaintext token is stored")
	}
}

// TestSEC003OneTimeTokenStorage covers SEC-003.
func TestSEC003OneTimeTokenStorage(t *testing.T) {
	h := testsupport.NewHarness(t,
		authall.WithEmailPassword(authall.EmailPasswordOptions{SendVerificationOnSignUp: true}),
		authall.WithPlugins(magiclink.New()))
	h.SignUp("tokens@example.com", testPassword)
	h.Do(http.MethodPost, "/password/forgot", map[string]string{"email": "tokens@example.com"})
	h.Do(http.MethodPost, "/magic-link/send", map[string]string{"email": "tokens@example.com"})

	raw := rawDB(t, h)
	messages := h.Mail.All()
	if len(messages) < 3 {
		t.Fatalf("expected a verification, a reset, and a magic-link message, got %d", len(messages))
	}
	for _, msg := range messages {
		if msg.Token == "" {
			t.Fatalf("the %s message carries no token", msg.Intent)
		}
		assertColumnFree(t, raw, "auth_tokens", []string{"id", "kind", "identifier", "token_hash"}, msg.Token)
		if _, err := h.Store.Tokens().Get(context.Background(), string(intentKind(t, msg.Intent)), sha256Hex(msg.Token)); err != nil {
			t.Fatalf("the %s token is not stored under its hash: %v", msg.Intent, err)
		}
	}
}

// TestSEC004TrustedOriginEnforcement covers SEC-004.
func TestSEC004TrustedOriginEnforcement(t *testing.T) {
	h := emailPasswordHarness(t, authall.WithTrustedOrigins("https://app.example.com"))
	h.SignUp("origin@example.com", testPassword)
	h.ClearCookies()

	untrusted := h.Do(http.MethodPost, "/sign-in/email",
		map[string]string{"email": "origin@example.com", "password": testPassword},
		testsupport.WithHeader("Origin", "https://evil.example.com"))
	if untrusted.Status != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d: %s", untrusted.Status, string(untrusted.Body))
	}
	if code := untrusted.ErrorCode(t); code != "ORIGIN_NOT_ALLOWED" {
		t.Fatalf("unexpected code %q", code)
	}
	if h.SessionCookie() != nil {
		t.Fatalf("an untrusted origin created a session")
	}

	// A configured origin passes.
	trusted := h.Do(http.MethodPost, "/sign-in/email",
		map[string]string{"email": "origin@example.com", "password": testPassword},
		testsupport.WithHeader("Origin", "https://app.example.com"))
	if trusted.Status != http.StatusOK {
		t.Fatalf("a trusted origin was rejected: %d %s", trusted.Status, string(trusted.Body))
	}

	// A forged referer is rejected as well.
	forged := h.Do(http.MethodPost, "/sign-out", nil,
		testsupport.WithoutOrigin(),
		testsupport.WithHeader("Referer", "https://evil.example.com/page"))
	if forged.Status != http.StatusForbidden {
		t.Fatalf("a forged referer passed: %d", forged.Status)
	}
}

// TestWildcardTrustedOriginIsRejected checks the configuration guard.
func TestWildcardTrustedOriginIsRejected(t *testing.T) {
	s := testsupport.NewSQLite(t)
	if _, err := authall.New(authall.WithStore(s), authall.WithTrustedOrigins("*")); err == nil {
		t.Fatalf("a wildcard origin was accepted")
	}
	if _, err := authall.New(authall.WithStore(s), authall.WithTrustedOrigins("https://*.example.com")); err == nil {
		t.Fatalf("a wildcard origin was accepted")
	}
}

// TestSessionFixationPrevention checks that authentication rotates the token.
func TestSessionFixationPrevention(t *testing.T) {
	h := emailPasswordHarness(t)
	h.SignUp("fixation@example.com", testPassword)
	first := h.SessionCookie()
	if first == nil {
		t.Fatalf("no session cookie was issued")
	}
	// The same browser signs in again while it still carries the old token.
	resp, _ := h.SignIn("fixation@example.com", testPassword)
	if resp.Status != http.StatusOK {
		t.Fatalf("sign-in failed: %s", string(resp.Body))
	}
	second := h.SessionCookie()
	if second == nil || second.Value == first.Value {
		t.Fatalf("the session token was not rotated")
	}
	// The jar prefers the cookie, so the check uses a clean client with the old
	// token in the authorization header.
	h.ClearCookies()
	stale := h.GetSession(testsupport.WithBearer(first.Value))
	if stale.Session != nil {
		t.Fatalf("the previous session token still authenticates")
	}
}

// TestCookieDefaultsAreSecure checks the default cookie attributes.
func TestCookieDefaultsAreSecure(t *testing.T) {
	s := testsupport.NewSQLite(t)
	auth, err := authall.New(
		authall.WithStore(s),
		authall.WithEmailPassword(),
		authall.WithBaseURL("https://app.example.com"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auth.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.CreateUser(context.Background(), authall.CreateUserInput{
		Email: "cookie@example.com", Password: testPassword,
	}); err != nil {
		t.Fatal(err)
	}
	rec := doRequest(t, auth, http.MethodPost, "https://app.example.com/api/auth/sign-in/email",
		`{"email":"cookie@example.com","password":"`+testPassword+`"}`)
	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatalf("no cookie was set: %s", rec.Body.String())
	}
	c := cookies[0]
	if c.Name != authall.DefaultCookieName {
		t.Fatalf("unexpected cookie name %q", c.Name)
	}
	if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode || c.Path != "/" {
		t.Fatalf("unsafe cookie defaults: %+v", c)
	}
}

// TestUnsafeRedirectIsIgnored checks the redirect allow list.
func TestUnsafeRedirectIsIgnored(t *testing.T) {
	h := magicLinkHarness(t)
	h.Do(http.MethodPost, "/magic-link/send", map[string]any{
		"email": "redirect@example.com", "callbackURL": "https://evil.example.com/steal",
	})
	msg := h.Mail.Last(t, email.IntentMagicLink)
	if strings.Contains(msg.URL, "evil.example.com") {
		t.Fatalf("an untrusted callback survived: %s", msg.URL)
	}
	resp := followMagicLink(t, h, msg.URL+"&callbackURL=https%3A%2F%2Fevil.example.com")
	if strings.Contains(resp.Location(), "evil.example.com") {
		t.Fatalf("the redirect target is untrusted: %s", resp.Location())
	}
}

func rawDB(t *testing.T, h *testsupport.Harness) *sql.DB {
	t.Helper()
	raw, ok := h.Store.(interface{ DB() *sql.DB })
	if !ok {
		t.Fatalf("the store does not expose a database handle")
	}
	return raw.DB()
}

// assertColumnFree fails when any listed column of a table holds the value.
func assertColumnFree(t *testing.T, db *sql.DB, table string, columns []string, value string) {
	t.Helper()
	for _, column := range columns {
		var count int
		query := "SELECT COUNT(*) FROM " + table + " WHERE " + column + " = ?"
		if err := db.QueryRow(query, value).Scan(&count); err != nil {
			t.Fatalf("query %s.%s: %v", table, column, err)
		}
		if count != 0 {
			t.Fatalf("%s.%s holds a plaintext secret", table, column)
		}
	}
}

func intentKind(t *testing.T, intent email.Intent) string {
	t.Helper()
	switch intent {
	case email.IntentVerifyEmail:
		return "verify-email"
	case email.IntentResetPassword:
		return "reset-password"
	case email.IntentMagicLink:
		return magiclink.TokenKind
	}
	t.Fatalf("unknown intent %q", intent)
	return ""
}

// TestEnumerationSafeResetResponse covers the required regression case of
// Section 29.4: a password reset request must answer the same way for a known
// and an unknown address.
func TestEnumerationSafeResetResponse(t *testing.T) {
	h := emailPasswordHarness(t)
	h.SignUp("known-reset@example.com", testPassword)
	h.ClearCookies()

	known := h.Do(http.MethodPost, "/password/forgot", map[string]string{"email": "known-reset@example.com"})
	unknown := h.Do(http.MethodPost, "/password/forgot", map[string]string{"email": "nobody-reset@example.com"})
	invalid := h.Do(http.MethodPost, "/password/forgot", map[string]string{"email": "not-an-address"})

	if known.Status != http.StatusOK {
		t.Fatalf("the known address returned status %d: %s", known.Status, string(known.Body))
	}
	for name, resp := range map[string]*testsupport.Response{"unknown": unknown, "invalid": invalid} {
		if resp.Status != known.Status {
			t.Fatalf("the %s address returns status %d, the known address returns %d",
				name, resp.Status, known.Status)
		}
		if string(resp.Body) != string(known.Body) {
			t.Fatalf("the %s address gets another body:\n%s\n%s", name, string(known.Body), string(resp.Body))
		}
	}
	if _, ok := h.Mail.Find(email.IntentResetPassword); !ok {
		t.Fatalf("the known address received no reset message")
	}
	if count := len(h.Mail.All()); count != 1 {
		t.Fatalf("expected exactly one message, got %d", count)
	}
}

// TestEnumerationSafeVerificationResponse covers the verification request.
func TestEnumerationSafeVerificationResponse(t *testing.T) {
	h := emailPasswordHarness(t, authall.WithEmailPassword(authall.EmailPasswordOptions{
		RequireEmailVerification: true,
	}))
	h.SignUp("known-verify@example.com", testPassword)
	h.Mail.Reset()

	known := h.Do(http.MethodPost, "/email-verification/send", map[string]string{"email": "known-verify@example.com"})
	unknown := h.Do(http.MethodPost, "/email-verification/send", map[string]string{"email": "nobody-verify@example.com"})
	if known.Status != unknown.Status || string(known.Body) != string(unknown.Body) {
		t.Fatalf("the response discloses the account:\n%s\n%s", string(known.Body), string(unknown.Body))
	}
}

// TestRedirectTargetsAreRestricted covers the redirect allow list of every
// entry point that accepts a target.
func TestRedirectTargetsAreRestricted(t *testing.T) {
	f := newOAuthFixture(t, authall.WithPlugins(magiclink.New()))
	// trustedHost is the one origin that Auth-All accepts, so a candidate can
	// try to borrow it.
	trustedHost := strings.TrimPrefix(strings.TrimPrefix(f.h.BaseURL, "http://"), "https://")
	unsafe := []string{
		"https://evil.example.com/steal",
		"//evil.example.com",
		"/\\evil.example.com",
		"\\\\evil.example.com",
		"/\t/evil.example.com",
		"/\r\n/evil.example.com",
		"https:/\\evil.example.com",
		// A scheme that runs code in the browser.
		"javascript:alert(1)",
		"JaVaScRiPt:alert(1)",
		"data:text/html,<script>alert(1)</script>",
		"vbscript:msgbox(1)",
		// The host is evil.example.com. The trusted name is only user
		// information, and a person reads it as the destination.
		"https://trusted.example.com@evil.example.com/",
		"http://" + trustedHost + "@evil.example.com/",
		// The trusted name sits in the fragment, so the host stays evil.
		"https://evil.example.com#@trusted.example.com",
		// A trailing dot names the same host for DNS, but not for the origin
		// comparison of a browser.
		"https://trusted.example.com./",
		"http://" + trustedHost + "./",
		// A percent escape can hide a control character. A parser that decodes
		// the value first reads //evil.example.com, which is another origin.
		"/%09/evil.example.com",
		"/%0d%0a/evil.example.com",
		"/%5cevil.example.com",
		"/%00/evil.example.com",
	}
	for _, target := range unsafe {
		// The OAuth start endpoint stores the target with the state.
		start := f.h.Do(http.MethodGet, "/oauth/github?redirect_to="+url.QueryEscape(target), nil)
		if start.Status != http.StatusFound {
			t.Fatalf("the start endpoint failed for %q: %d", target, start.Status)
		}
		state := testsupport.QueryParam(t, start.Location(), "state")
		callback := f.callback(t, "github", "valid-code", state)
		if callback.Status != http.StatusFound {
			t.Fatalf("the callback failed for %q: %s", target, string(callback.Body))
		}
		if location := callback.Location(); strings.Contains(location, "evil.example.com") || strings.Contains(location, "javascript:") {
			t.Fatalf("the OAuth callback redirects to the untrusted target %q: %s", target, location)
		}
		f.h.ClearCookies()
		f.github.SetAccount(12345, "octo@example.com", true)

		// The magic link carries the target through the email.
		f.h.Mail.Reset()
		f.h.Do(http.MethodPost, "/magic-link/send", map[string]any{
			"email": "redirects@example.com", "callbackURL": target,
		})
		msg := f.h.Mail.Last(t, email.IntentMagicLink)
		if strings.Contains(msg.URL, "evil.example.com") {
			t.Fatalf("the emailed link carries the untrusted target %q: %s", target, msg.URL)
		}
		verify := followMagicLink(t, f.h, msg.URL+"&callbackURL="+url.QueryEscape(target))
		// The fallback of the magic link is the base URL, so the check is exact.
		if location := verify.Location(); location != f.h.BaseURL {
			t.Fatalf("the magic link did not fall back for the target %q: %s", target, location)
		}
		f.h.ClearCookies()
	}

	// A relative path of the application stays intact.
	f.h.Mail.Reset()
	f.h.Do(http.MethodPost, "/magic-link/send", map[string]any{
		"email": "relative@example.com", "callbackURL": "/dashboard?tab=1",
	})
	msg := f.h.Mail.Last(t, email.IntentMagicLink)
	verify := followMagicLink(t, f.h, msg.URL)
	if verify.Location() != "/dashboard?tab=1" {
		t.Fatalf("a relative target was discarded: %q", verify.Location())
	}
}

// TestLinkStateIsBoundToTheStartingBrowser proves that a provider link cannot
// be completed in the browser of another person.
func TestLinkStateIsBoundToTheStartingBrowser(t *testing.T) {
	f := newOAuthFixture(t)
	_, attacker := f.h.SignUp("attacker@example.com", testPassword)
	resp := f.h.Do(http.MethodPost, "/account/link/github", nil)
	if resp.Status != http.StatusOK {
		t.Fatalf("the link start failed: %s", string(resp.Body))
	}
	var link struct {
		URL string `json:"url"`
	}
	resp.Decode(t, &link)
	state := testsupport.QueryParam(t, link.URL, "state")

	// The victim uses another browser and authorizes with their own account.
	f.h.ClearCookies()
	f.github.SetAccount(999, "victim@example.com", true)
	callback := f.callback(t, "github", "valid-code", state)

	if callback.Status == http.StatusFound {
		t.Fatalf("the callback completed in the browser of another person")
	}
	if code := callback.ErrorCode(t); code != "OAUTH_STATE_INVALID" {
		t.Fatalf("unexpected code %q", code)
	}
	if _, err := f.h.Store.Accounts().GetByProviderAccount(context.Background(), "github", "999"); err == nil {
		t.Fatalf("the provider identity of the victim was linked to another account")
	}
	if session := f.h.GetSession(); session.Session != nil {
		t.Fatalf("the callback signed the victim in as user %s", attacker.User.ID)
	}
}

// TestSignInStateIsBoundToTheStartingBrowser proves the same binding for the
// plain provider sign-in.
func TestSignInStateIsBoundToTheStartingBrowser(t *testing.T) {
	f := newOAuthFixture(t)
	state := f.startGitHub(t)

	// Another browser presents the same state.
	f.h.ClearCookies()
	callback := f.callback(t, "github", "valid-code", state)
	if callback.Status == http.StatusFound {
		t.Fatalf("a foreign browser completed the sign-in")
	}
	if code := callback.ErrorCode(t); code != "OAUTH_STATE_INVALID" {
		t.Fatalf("unexpected code %q", code)
	}
	if session := f.h.GetSession(); session.Session != nil {
		t.Fatalf("a foreign browser received a session")
	}
	if _, err := f.h.Store.Accounts().GetByProviderAccount(context.Background(), "github", "12345"); err == nil {
		t.Fatalf("a foreign browser created an external account")
	}
}

// TestLinkCompletionNeedsTheSameSession proves that the link callback checks
// the authenticated user, and not only the binding cookie.
func TestLinkCompletionNeedsTheSameSession(t *testing.T) {
	f := newOAuthFixture(t)
	f.h.SignUp("owner@example.com", testPassword)
	resp := f.h.Do(http.MethodPost, "/account/link/github", nil)
	var link struct {
		URL string `json:"url"`
	}
	resp.Decode(t, &link)
	state := testsupport.QueryParam(t, link.URL, "state")

	// The same browser keeps the binding cookie but signs out first.
	if out := f.h.Do(http.MethodPost, "/sign-out", nil); out.Status != http.StatusOK {
		t.Fatalf("sign-out failed: %s", string(out.Body))
	}
	callback := f.callback(t, "github", "valid-code", state)
	if callback.Status == http.StatusFound {
		t.Fatalf("the link completed without the session that started it")
	}
	if code := callback.ErrorCode(t); code != "UNAUTHORIZED" {
		t.Fatalf("unexpected code %q", code)
	}
	if _, err := f.h.Store.Accounts().GetByProviderAccount(context.Background(), "github", "12345"); err == nil {
		t.Fatalf("the account was linked without a session")
	}
}

// TestOAuthStateCookieIsRestricted checks the attributes of the binding cookie.
func TestOAuthStateCookieIsRestricted(t *testing.T) {
	f := newOAuthFixture(t)
	resp := f.h.Do(http.MethodGet, "/oauth/github", nil)
	var binding *http.Cookie
	for _, c := range resp.Cookies {
		if strings.HasSuffix(c.Name, ".oauth_state") {
			binding = c
		}
	}
	if binding == nil {
		t.Fatalf("the start endpoint set no binding cookie: %+v", resp.Cookies)
	}
	if !binding.HttpOnly || binding.SameSite != http.SameSiteLaxMode {
		t.Fatalf("the binding cookie is not restricted: %+v", binding)
	}
	if binding.Value == "" {
		t.Fatalf("the binding cookie carries no value")
	}
}

// TestSEC010MagicLinkClearsPlantedPassword proves that a magic-link sign-in
// removes a password credential that somebody planted on an unverified
// address, and that it removes every session of that address.
//
// The attack: an attacker signs up with the address of the victim and a
// password of their choice. The address stays unverified. The victim later
// signs in with a magic link. The password of the attacker must not survive.
func TestSEC010MagicLinkClearsPlantedPassword(t *testing.T) {
	h := magicLinkHarness(t)
	const address = "prehijack@example.com"

	// The attacker plants a password on the address of the victim.
	resp, planted := h.SignUp(address, testPassword)
	if resp.Status != http.StatusCreated {
		t.Fatalf("the sign-up failed: %d %s", resp.Status, string(resp.Body))
	}
	if planted.User != nil && planted.User.EmailVerified {
		t.Fatalf("the planted account must stay unverified")
	}
	attacker := h.SessionCookie()
	if attacker == nil || attacker.Value == "" {
		t.Fatalf("the sign-up issued no session")
	}

	// The victim uses another browser and signs in with a link.
	h.ClearCookies()
	h.Mail.Reset()
	sendMagicLink(t, h, address)
	msg := h.Mail.Last(t, email.IntentMagicLink)
	if done := followMagicLink(t, h, msg.URL); done.Status >= 400 {
		t.Fatalf("the link failed: %d %s", done.Status, string(done.Body))
	}
	if victim := h.GetSession(); victim.User == nil {
		t.Fatalf("the link created no session for the victim")
	}

	// The planted password no longer opens the account.
	h.ClearCookies()
	old, _ := h.SignIn(address, testPassword)
	if old.Status != http.StatusUnauthorized {
		t.Fatalf("the planted password still signs in: %d %s", old.Status, string(old.Body))
	}
	if code := old.ErrorCode(t); code != "INVALID_CREDENTIALS" {
		t.Fatalf("unexpected code %q", code)
	}

	// The session of the attacker no longer authenticates.
	if stale := h.GetSession(testsupport.WithBearer(attacker.Value)); stale.Session != nil {
		t.Fatalf("the session of the attacker survived the proof")
	}
}

// TestSEC011VerifiedUserKeepsPasswordOnMagicLink proves the no-op case. A
// verified address is already proven, so a later magic link must not remove
// the password credential and must not revoke another session.
func TestSEC011VerifiedUserKeepsPasswordOnMagicLink(t *testing.T) {
	h := magicLinkHarness(t)
	const address = "verified-keeps@example.com"
	if _, err := h.Auth.CreateUser(context.Background(), authall.CreateUserInput{
		Email: address, Password: testPassword, EmailVerified: true,
	}); err != nil {
		t.Fatalf("create the verified user: %v", err)
	}

	// The user signs in with the password in one browser.
	first, _ := h.SignIn(address, testPassword)
	if first.Status != http.StatusOK {
		t.Fatalf("the sign-in failed: %d %s", first.Status, string(first.Body))
	}
	kept := h.SessionCookie()
	if kept == nil || kept.Value == "" {
		t.Fatalf("the sign-in issued no session")
	}

	// The same user signs in with a link from another browser.
	h.ClearCookies()
	h.Mail.Reset()
	sendMagicLink(t, h, address)
	msg := h.Mail.Last(t, email.IntentMagicLink)
	if done := followMagicLink(t, h, msg.URL); done.Status >= 400 {
		t.Fatalf("the link failed: %d %s", done.Status, string(done.Body))
	}

	// The password still works.
	h.ClearCookies()
	again, _ := h.SignIn(address, testPassword)
	if again.Status != http.StatusOK {
		t.Fatalf("a verified user lost the password: %d %s", again.Status, string(again.Body))
	}

	// The first session still authenticates.
	h.ClearCookies()
	if still := h.GetSession(testsupport.WithBearer(kept.Value)); still.Session == nil {
		t.Fatalf("a repeat sign-in revoked the session of the user")
	}
}

// recordingLimiter captures the rate-limit keys that Auth-All builds.
type recordingLimiter struct {
	mu   sync.Mutex
	keys []ratelimit.Key
}

func (l *recordingLimiter) Allow(_ context.Context, k ratelimit.Key) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.keys = append(l.keys, k)
	return true, nil
}

// lastIP returns the client address of the most recent rate-limit key.
func (l *recordingLimiter) lastIP(t *testing.T) string {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.keys) == 0 {
		t.Fatalf("the handler built no rate-limit key")
	}
	return l.keys[len(l.keys)-1].IP
}

// signInFrom sends one sign-in attempt with a forged forwarded header.
func signInFrom(t *testing.T, h *testsupport.Harness, forwarded string) {
	t.Helper()
	opts := []testsupport.RequestOption{}
	if forwarded != "" {
		opts = append(opts, testsupport.WithHeader("X-Forwarded-For", forwarded))
	}
	h.Do(http.MethodPost, "/sign-in/email",
		map[string]string{"email": "proxy@example.com", "password": testPassword}, opts...)
}

// TestSEC012ForwardedHeaderIsIgnoredByDefault proves that a client cannot
// choose its own rate-limit key. Without a declared trusted proxy, Auth-All
// uses the address of the direct peer.
func TestSEC012ForwardedHeaderIsIgnoredByDefault(t *testing.T) {
	limiter := &recordingLimiter{}
	h := emailPasswordHarness(t, authall.WithRateLimiter(limiter))

	signInFrom(t, h, "")
	direct := limiter.lastIP(t)
	if direct == "" {
		t.Fatalf("the rate-limit key carries no client address")
	}

	for _, forged := range []string{"203.0.113.9", "203.0.113.9, 198.51.100.7", "not-an-address"} {
		signInFrom(t, h, forged)
		if got := limiter.lastIP(t); got != direct {
			t.Fatalf("the header %q changed the rate-limit key to %q, want %q", forged, got, direct)
		}
	}
}

// TestSEC013ForwardedHeaderIsUsedBehindATrustedProxy proves the right-to-left
// walk of the forwarded header.
func TestSEC013ForwardedHeaderIsUsedBehindATrustedProxy(t *testing.T) {
	limiter := &recordingLimiter{}
	h := emailPasswordHarness(t,
		authall.WithRateLimiter(limiter),
		authall.WithTrustedProxies("127.0.0.1", "::1", "10.0.0.0/8"))

	signInFrom(t, h, "")
	direct := limiter.lastIP(t)

	cases := []struct {
		name      string
		forwarded string
		want      string
	}{
		{"one hop", "203.0.113.9", "203.0.113.9"},
		{"a trusted hop on the right", "203.0.113.9, 10.1.2.3", "203.0.113.9"},
		{"two trusted hops on the right", "203.0.113.9, 10.1.2.3, 10.4.5.6", "203.0.113.9"},
		// The client prepends a hop of its own. The proxy appends the true
		// address on the right, so the injected value never wins.
		{"an injected extra hop", "198.51.100.7, 203.0.113.9", "203.0.113.9"},
		{"every hop is trusted", "10.1.2.3", direct},
		{"a malformed hop", "203.0.113.9, not-an-address", direct},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			signInFrom(t, h, tc.forwarded)
			if got := limiter.lastIP(t); got != tc.want {
				t.Fatalf("the header %q produced %q, want %q", tc.forwarded, got, tc.want)
			}
		})
	}
}

// TestSEC014MagicLinkGetCreatesNoSession proves that the confirmation page
// creates no session and consumes no token.
//
// A GET that signs a person in accepts a login cross-site request forgery. An
// attacker asks for a link for their own address, and then makes the browser
// of the victim open that link. A mail scanner that pre-fetches the link also
// consumes the one-time token, so the person can no longer sign in.
func TestSEC014MagicLinkGetCreatesNoSession(t *testing.T) {
	h := magicLinkHarness(t)
	sendMagicLink(t, h, "confirm@example.com")
	msg := h.Mail.Last(t, email.IntentMagicLink)

	page := h.DoURL(http.MethodGet, msg.URL, nil)
	if page.Status != http.StatusOK {
		t.Fatalf("the confirmation page returned %d: %s", page.Status, string(page.Body))
	}
	if got := page.Header.Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
		t.Fatalf("the confirmation page is not HTML: %q", got)
	}
	for _, c := range page.Cookies {
		if c.Name == authall.DefaultCookieName && c.Value != "" {
			t.Fatalf("the confirmation page set a session cookie")
		}
	}
	if session := h.GetSession(); session.Session != nil {
		t.Fatalf("the confirmation page created a session")
	}

	// The page carries the required headers.
	if got := page.Header.Get("Referrer-Policy"); got != "no-referrer" {
		t.Fatalf("unexpected referrer policy %q", got)
	}
	if got := page.Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("unexpected cache control %q", got)
	}
	if got := page.Header.Get("Pragma"); got != "no-cache" {
		t.Fatalf("unexpected pragma %q", got)
	}

	// The page needs no third-party asset and no script.
	body := string(page.Body)
	if strings.Contains(body, "<script") || strings.Contains(body, "http://") || strings.Contains(body, "https://") {
		t.Fatalf("the confirmation page carries a script or an absolute URL: %s", body)
	}
	if !strings.Contains(body, `method="post"`) || !strings.Contains(body, "</form>") {
		t.Fatalf("the confirmation page carries no form: %s", body)
	}

	// A repeated GET does not consume the token, so the link still works.
	if again := h.DoURL(http.MethodGet, msg.URL, nil); again.Status != http.StatusOK {
		t.Fatalf("a repeated page load consumed the token: %d %s", again.Status, string(again.Body))
	}
	if done := followMagicLink(t, h, msg.URL); done.Status != http.StatusSeeOther {
		t.Fatalf("the link no longer works: %d %s", done.Status, string(done.Body))
	}
	if session := h.GetSession(); session.User == nil {
		t.Fatalf("the confirmed link created no session")
	}
}

// TestSEC015MagicLinkPostRejectsAnUntrustedOrigin proves that the confirmation
// step runs the origin check.
func TestSEC015MagicLinkPostRejectsAnUntrustedOrigin(t *testing.T) {
	h := magicLinkHarness(t)
	sendMagicLink(t, h, "forgery@example.com")
	msg := h.Mail.Last(t, email.IntentMagicLink)
	token := testsupport.TokenFromURL(t, msg.URL)

	forged := h.Do(http.MethodPost, "/magic-link/verify", map[string]string{"token": token},
		testsupport.WithHeader("Origin", "https://evil.example.com"))
	if forged.Status != http.StatusForbidden {
		t.Fatalf("an untrusted origin completed the sign-in: %d %s", forged.Status, string(forged.Body))
	}
	if code := forged.ErrorCode(t); code != "ORIGIN_NOT_ALLOWED" {
		t.Fatalf("unexpected code %q", code)
	}
	if session := h.GetSession(); session.Session != nil {
		t.Fatalf("an untrusted origin created a session")
	}

	// The rejected attempt consumed no token, so the true owner can still sign
	// in.
	if done := followMagicLink(t, h, msg.URL); done.Status != http.StatusSeeOther {
		t.Fatalf("the rejected attempt consumed the token: %d %s", done.Status, string(done.Body))
	}
}

// TestSECRecoveryCodesAreHashedAtRest checks that the database never holds a
// recovery code in plaintext.
//
// A recovery code is a first factor and a second factor at the same time, so a
// leaked database row would be a complete sign-in.
func TestSECRecoveryCodesAreHashedAtRest(t *testing.T) {
	h, clock := clockHarness(t)
	h.SignUp("sec-recovery@example.com", testPassword)
	_, codes := enrolWithRecovery(t, h, clock)
	if len(codes) == 0 {
		t.Fatal("the confirmation returned no recovery codes")
	}

	raw := rawDB(t, h)
	for _, code := range codes {
		assertColumnFree(t, raw, "auth_totp_recovery", []string{"id", "user_id", "code_hash"}, code)
		// The normalized form must be absent as well, because that is the
		// value that Auth-All hashes.
		assertColumnFree(t, raw, "auth_totp_recovery",
			[]string{"id", "user_id", "code_hash"}, crypto.NormalizeRecoveryCode(code))
	}

	// The stored hash covers the normalized code, so a retyped variant matches.
	var count int
	if err := raw.QueryRow("SELECT COUNT(*) FROM auth_totp_recovery WHERE code_hash = ?",
		recoveryHash(codes[0])).Scan(&count); err != nil {
		t.Fatalf("query the hash: %v", err)
	}
	if count != 1 {
		t.Fatalf("the store holds %d rows for the hash of the first code", count)
	}
}

// TestSECTOTPSecretIsAbsentFromTheTokenTable checks that the challenge token of
// a pending second factor never carries the secret.
func TestSECTOTPSecretIsAbsentFromTheTokenTable(t *testing.T) {
	const address = "sec-challenge@example.com"
	h, secret, _ := enrolledHarness(t, address)

	resp := h.Do(http.MethodPost, "/sign-in/email",
		map[string]any{"email": address, "password": testPassword})
	var challenge mfaResult
	resp.Decode(t, &challenge)
	if challenge.MFAToken == "" {
		t.Fatal("the sign-in returned no challenge")
	}

	raw := rawDB(t, h)
	// The challenge token itself is stored as a hash, like every other
	// one-time token.
	assertColumnFree(t, raw, "auth_tokens",
		[]string{"id", "kind", "identifier", "token_hash"}, challenge.MFAToken)
	// The secret never reaches the token table.
	assertColumnFree(t, raw, "auth_tokens",
		[]string{"id", "kind", "identifier", "token_hash"}, secret)
}
