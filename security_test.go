package authall_test

import (
	"context"
	"database/sql"
	"net/http"
	"net/url"
	"strings"
	"testing"

	authall "github.com/alternayte/auth-all"
	"github.com/alternayte/auth-all/email"
	"github.com/alternayte/auth-all/internal/testsupport"
	"github.com/alternayte/auth-all/plugins/magiclink"
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
	h.ClearCookies()

	responses := []*testsupport.Response{
		h.Do(http.MethodPost, "/sign-in/email", map[string]string{"email": "secrets@example.com", "password": "wrong password here"}),
		h.Do(http.MethodPost, "/sign-in/email", map[string]string{"email": "missing@example.com", "password": testPassword}),
		h.Do(http.MethodPost, "/sign-up/email", map[string]string{"email": "secrets@example.com", "password": testPassword}),
		h.Do(http.MethodPost, "/sign-up/email", map[string]string{"email": "not-an-email", "password": testPassword}),
		h.Do(http.MethodPost, "/password/reset", map[string]string{"token": "wrong-token", "password": testPassword}),
		h.Do(http.MethodPost, "/email-verification/verify", map[string]string{"token": "wrong-token"}),
		h.Do(http.MethodGet, "/magic-link/verify?token=wrong-token", nil),
		h.Do(http.MethodPost, "/account/unlink/github", nil),
		h.Do(http.MethodPost, "/sign-up/email", "not json at all"),
	}
	secrets := []string{cookie.Value, resetToken, out.User.ID + "-never"}
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
	resp := h.DoURL(http.MethodGet, msg.URL+"&callbackURL=https%3A%2F%2Fevil.example.com", nil)
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
	unsafe := []string{
		"https://evil.example.com/steal",
		"//evil.example.com",
		"/\\evil.example.com",
		"\\\\evil.example.com",
		"/\t/evil.example.com",
		"/\r\n/evil.example.com",
		"https:/\\evil.example.com",
		"javascript:alert(1)",
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
		verify := f.h.DoURL(http.MethodGet, msg.URL+"&callbackURL="+url.QueryEscape(target), nil)
		if location := verify.Location(); strings.Contains(location, "evil.example.com") || strings.Contains(location, "javascript:") {
			t.Fatalf("the magic link redirects to the untrusted target %q: %s", target, location)
		}
		f.h.ClearCookies()
	}

	// A relative path of the application stays intact.
	f.h.Mail.Reset()
	f.h.Do(http.MethodPost, "/magic-link/send", map[string]any{
		"email": "relative@example.com", "callbackURL": "/dashboard?tab=1",
	})
	msg := f.h.Mail.Last(t, email.IntentMagicLink)
	verify := f.h.DoURL(http.MethodGet, msg.URL, nil)
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
