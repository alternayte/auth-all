package authall_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	authall "github.com/alternayte/auth-all"
	"github.com/alternayte/auth-all/internal/testsupport"
)

// sessionEntry is one row of the session list.
type sessionEntry struct {
	ID         string `json:"id"`
	CreatedAt  string `json:"createdAt"`
	ExpiresAt  string `json:"expiresAt"`
	LastSeenAt string `json:"lastSeenAt"`
}

// listSessions reads the session list of the current user.
func listSessions(t *testing.T, h *testsupport.Harness, opts ...testsupport.RequestOption) []sessionEntry {
	t.Helper()
	resp := h.Do(http.MethodGet, "/sessions", nil, opts...)
	if resp.Status != http.StatusOK {
		t.Fatalf("the list returned %d: %s", resp.Status, string(resp.Body))
	}
	var body struct {
		Sessions []sessionEntry `json:"sessions"`
	}
	resp.Decode(t, &body)
	return body.Sessions
}

// TestSessionListReturnsTheSessionsOfTheUser checks GET /sessions.
func TestSessionListReturnsTheSessionsOfTheUser(t *testing.T) {
	h := emailPasswordHarness(t)
	const address = "list@example.com"
	h.SignUp(address, testPassword)
	first := h.SessionCookie()

	// A second browser opens a second session.
	h.ClearCookies()
	h.SignIn(address, testPassword)
	second := h.SessionCookie()
	if first == nil || second == nil || first.Value == second.Value {
		t.Fatalf("the test needs two distinct sessions")
	}

	list := listSessions(t, h)
	if len(list) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(list))
	}
	for _, entry := range list {
		if entry.ID == "" || entry.CreatedAt == "" || entry.ExpiresAt == "" || entry.LastSeenAt == "" {
			t.Fatalf("an entry misses a field: %+v", entry)
		}
	}

	// No response carries a token or a token hash.
	resp := h.Do(http.MethodGet, "/sessions", nil)
	body := string(resp.Body)
	for _, secret := range []string{first.Value, second.Value, sha256Hex(first.Value), sha256Hex(second.Value)} {
		if strings.Contains(body, secret) {
			t.Fatalf("the list leaks a token or a hash: %s", body)
		}
	}
	for _, field := range []string{"token", "Token", "hash", "Hash"} {
		if strings.Contains(body, field) {
			t.Fatalf("the list carries a %q field: %s", field, body)
		}
	}
}

// TestSessionListNeedsASession checks that the routes need authentication.
func TestSessionListNeedsASession(t *testing.T) {
	h := emailPasswordHarness(t)
	h.SignUp("anon@example.com", testPassword)
	h.ClearCookies()

	cases := []struct{ method, path string }{
		{http.MethodGet, "/sessions"},
		{http.MethodDelete, "/sessions/some-id"},
		{http.MethodPost, "/sessions/revoke-all"},
	}
	for _, tc := range cases {
		resp := h.Do(tc.method, tc.path, nil)
		if resp.Status != http.StatusUnauthorized {
			t.Fatalf("%s %s returned %d, want 401: %s", tc.method, tc.path, resp.Status, string(resp.Body))
		}
		if code := resp.ErrorCode(t); code != "UNAUTHORIZED" {
			t.Fatalf("%s %s returned the code %q", tc.method, tc.path, code)
		}
	}
}

// TestSessionRevokeOne checks DELETE /sessions/{id}.
func TestSessionRevokeOne(t *testing.T) {
	h := emailPasswordHarness(t)
	const address = "revoke-one@example.com"
	h.SignUp(address, testPassword)
	other := h.SessionCookie()

	h.ClearCookies()
	h.SignIn(address, testPassword)
	current := h.SessionCookie()

	// Find the identifier of the other session.
	var target string
	for _, entry := range listSessions(t, h) {
		if entry.ID != sessionIDOf(t, h, current.Value) {
			target = entry.ID
		}
	}
	if target == "" {
		t.Fatalf("the test found no second session")
	}

	resp := h.Do(http.MethodDelete, "/sessions/"+target, nil)
	if resp.Status != http.StatusOK {
		t.Fatalf("the revoke failed: %d %s", resp.Status, string(resp.Body))
	}
	if list := listSessions(t, h); len(list) != 1 {
		t.Fatalf("expected 1 session after the revoke, got %d", len(list))
	}

	// The revoked token no longer authenticates.
	h.ClearCookies()
	if session := h.GetSession(testsupport.WithBearer(other.Value)); session.Session != nil {
		t.Fatalf("the revoked session still authenticates")
	}
}

// TestSessionRevokeOfAForeignSessionReturns404 proves that the endpoint
// discloses nothing about a session of another user.
func TestSessionRevokeOfAForeignSessionReturns404(t *testing.T) {
	h := emailPasswordHarness(t)
	h.SignUp("owner-of-session@example.com", testPassword)
	victim := h.SessionCookie()
	victimID := sessionIDOf(t, h, victim.Value)

	h.ClearCookies()
	h.SignUp("stranger@example.com", testPassword)

	resp := h.Do(http.MethodDelete, "/sessions/"+victimID, nil)
	if resp.Status != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", resp.Status, string(resp.Body))
	}
	// An unknown identifier answers the same way, so the response discloses
	// nothing about the existence of the session.
	unknown := h.Do(http.MethodDelete, "/sessions/00000000-0000-0000-0000-000000000000", nil)
	if unknown.Status != resp.Status || string(unknown.Body) != string(resp.Body) {
		t.Fatalf("a foreign session and an unknown session answer differently:\n%s\n%s",
			string(resp.Body), string(unknown.Body))
	}

	// The session of the victim survives.
	h.ClearCookies()
	if session := h.GetSession(testsupport.WithBearer(victim.Value)); session.Session == nil {
		t.Fatalf("a stranger revoked the session of another user")
	}
}

// TestSessionRevokeAll checks POST /sessions/revoke-all.
func TestSessionRevokeAll(t *testing.T) {
	h := emailPasswordHarness(t)
	const address = "revoke-all@example.com"
	h.SignUp(address, testPassword)
	first := h.SessionCookie()
	h.ClearCookies()
	h.SignIn(address, testPassword)
	second := h.SessionCookie()
	h.ClearCookies()
	h.SignIn(address, testPassword)
	current := h.SessionCookie()

	resp := h.Do(http.MethodPost, "/sessions/revoke-all", map[string]any{})
	if resp.Status != http.StatusOK {
		t.Fatalf("the revoke failed: %d %s", resp.Status, string(resp.Body))
	}
	var body struct {
		Revoked int `json:"revoked"`
	}
	resp.Decode(t, &body)
	if body.Revoked != 2 {
		t.Fatalf("expected 2 revoked sessions, got %d", body.Revoked)
	}

	// The current session survives, and the others are gone.
	if list := listSessions(t, h); len(list) != 1 {
		t.Fatalf("expected 1 session, got %d", len(list))
	}
	for _, gone := range []string{first.Value, second.Value} {
		h.ClearCookies()
		if session := h.GetSession(testsupport.WithBearer(gone)); session.Session != nil {
			t.Fatalf("a revoked session still authenticates")
		}
	}
	_ = current
}

// TestSessionRevokeAllCanIncludeTheCurrentSession checks the body field.
func TestSessionRevokeAllCanIncludeTheCurrentSession(t *testing.T) {
	h := emailPasswordHarness(t)
	const address = "revoke-all-self@example.com"
	h.SignUp(address, testPassword)
	h.ClearCookies()
	h.SignIn(address, testPassword)
	current := h.SessionCookie()

	resp := h.Do(http.MethodPost, "/sessions/revoke-all", map[string]any{"includeCurrent": true})
	if resp.Status != http.StatusOK {
		t.Fatalf("the revoke failed: %d %s", resp.Status, string(resp.Body))
	}
	var body struct {
		Revoked int `json:"revoked"`
	}
	resp.Decode(t, &body)
	if body.Revoked != 2 {
		t.Fatalf("expected 2 revoked sessions, got %d", body.Revoked)
	}
	// The endpoint clears the cookie, so the browser holds no stale session.
	h.ClearCookies()
	if session := h.GetSession(testsupport.WithBearer(current.Value)); session.Session != nil {
		t.Fatalf("the current session survived includeCurrent")
	}
}

// TestSessionRoutesRunTheOriginCheck proves the cross-site defense.
func TestSessionRoutesRunTheOriginCheck(t *testing.T) {
	h := emailPasswordHarness(t, authall.WithTrustedOrigins("https://app.example.com"))
	h.SignUp("origin-sessions@example.com", testPassword)
	current := h.SessionCookie()
	id := sessionIDOf(t, h, current.Value)

	cases := []struct {
		method string
		path   string
		body   any
	}{
		{http.MethodDelete, "/sessions/" + id, nil},
		{http.MethodPost, "/sessions/revoke-all", map[string]any{}},
	}
	for _, tc := range cases {
		resp := h.Do(tc.method, tc.path, tc.body,
			testsupport.WithHeader("Origin", "https://evil.example.com"))
		if resp.Status != http.StatusForbidden {
			t.Fatalf("%s %s accepted an untrusted origin: %d", tc.method, tc.path, resp.Status)
		}
		if code := resp.ErrorCode(t); code != "ORIGIN_NOT_ALLOWED" {
			t.Fatalf("%s %s returned the code %q", tc.method, tc.path, code)
		}
	}
	// The session survives the rejected attempts.
	if session := h.GetSession(); session.Session == nil {
		t.Fatalf("a rejected request revoked the session")
	}
}

// sessionIDOf returns the identifier of the session behind one token.
func sessionIDOf(t *testing.T, h *testsupport.Harness, token string) string {
	t.Helper()
	sess, err := h.Store.Sessions().GetByTokenHash(context.Background(), sha256Hex(token))
	if err != nil {
		t.Fatalf("read the session: %v", err)
	}
	return sess.ID
}

// TestSessionAbsoluteLifetime proves that a session ends at the absolute
// lifetime, even when the person stays active.
//
// A stolen token that stays active never expired before, because one value
// served both the idle timeout and the total lifetime.
func TestSessionAbsoluteLifetime(t *testing.T) {
	clock := testsupport.NewClock()
	const day = 24 * time.Hour
	h := testsupport.NewHarness(t,
		authall.WithEmailPassword(),
		authall.WithClock(clock.Now),
		authall.WithSessionLifetime(7*day, 30*day))
	h.SignUp("absolute@example.com", testPassword)
	token := h.SessionCookie()
	if token == nil {
		t.Fatalf("the sign-up issued no session")
	}

	// The person stays active, so the idle timeout never fires.
	for elapsed := 6 * day; elapsed <= 24*day; elapsed += 6 * day {
		clock.Advance(6 * day)
		if session := h.GetSession(); session.User == nil {
			t.Fatalf("the idle timeout ended an active session after %v", elapsed)
		}
	}

	// Day 30 reaches the absolute lifetime.
	clock.Advance(6 * day)
	if session := h.GetSession(); session.Session != nil {
		t.Fatalf("a session past the absolute lifetime still authenticates")
	}
	// The row is gone.
	if count := countSessionsByHash(t, h, sha256Hex(token.Value)); count != 0 {
		t.Fatalf("the expired session row survived: %d", count)
	}
}

// TestSessionIdleTimeout proves that an inactive session ends before the
// absolute lifetime.
func TestSessionIdleTimeout(t *testing.T) {
	clock := testsupport.NewClock()
	const day = 24 * time.Hour
	h := testsupport.NewHarness(t,
		authall.WithEmailPassword(),
		authall.WithClock(clock.Now),
		authall.WithSessionLifetime(7*day, 30*day))
	h.SignUp("idle@example.com", testPassword)
	token := h.SessionCookie()

	// Six days of silence keep the session.
	clock.Advance(6 * day)
	if session := h.GetSession(); session.User == nil {
		t.Fatalf("the idle timeout fired too early")
	}

	// Eight days of silence end it, although the absolute lifetime is 30 days.
	clock.Advance(8 * day)
	if session := h.GetSession(); session.Session != nil {
		t.Fatalf("an idle session still authenticates")
	}
	if count := countSessionsByHash(t, h, sha256Hex(token.Value)); count != 0 {
		t.Fatalf("the idle session row survived: %d", count)
	}

}

// countSessionsByHash counts the session rows that carry one token hash.
func countSessionsByHash(t *testing.T, h *testsupport.Harness, hash string) int {
	t.Helper()
	var count int
	err := rawDB(t, h).QueryRow("SELECT COUNT(*) FROM auth_sessions WHERE token_hash = ?", hash).Scan(&count)
	if err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	return count
}

// TestSessionLifetimeDefaults checks the documented defaults.
func TestSessionLifetimeDefaults(t *testing.T) {
	if authall.DefaultSessionIdleTimeout != 7*24*time.Hour {
		t.Fatalf("unexpected default idle timeout %v", authall.DefaultSessionIdleTimeout)
	}
	if authall.DefaultSessionTTL != 30*24*time.Hour {
		t.Fatalf("unexpected default absolute lifetime %v", authall.DefaultSessionTTL)
	}
}
