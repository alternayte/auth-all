package authall_test

import (
	"context"
	"database/sql"
	"net/http"
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
