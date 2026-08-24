package authall_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	authall "github.com/alternayte/auth-all"
	"github.com/alternayte/auth-all/internal/testsupport"
	"github.com/alternayte/auth-all/plugins/magiclink"
	"github.com/alternayte/auth-all/schema"
	"github.com/alternayte/auth-all/store"
)

// TestSubjectNeverComesFromTheRequestBody proves that no state-changing route
// derives the subject of the operation from the request body.
//
// CVE-2025-61928 in Better Auth was one missing ownership check. An
// unauthenticated caller created an API key for any user, because the handler
// read a user id out of the body. This test makes that class of defect fail
// the suite before the plugin ecosystem grows.
//
// The test enumerates the routes from the router, so a new route joins the
// test on its own. It covers core routes and plugin routes.
func TestSubjectNeverComesFromTheRequestBody(t *testing.T) {
	f := newOAuthFixture(t,
		authall.WithPlugins(magiclink.New(), &testPlugin{}))
	h := f.h
	ctx := context.Background()

	// The victim owns one account, one password, and one session.
	const victimAddress = "victim-subject@example.com"
	if _, err := h.Auth.CreateUser(ctx, authall.CreateUserInput{
		Email: victimAddress, Password: testPassword, EmailVerified: true,
	}); err != nil {
		t.Fatalf("create the victim: %v", err)
	}
	victimResp, _ := h.SignIn(victimAddress, testPassword)
	if victimResp.Status != http.StatusOK {
		t.Fatalf("the victim cannot sign in: %s", string(victimResp.Body))
	}
	victim, err := h.Auth.GetUserByEmail(ctx, victimAddress)
	if err != nil {
		t.Fatal(err)
	}
	victimSession := h.SessionCookie()
	if victimSession == nil {
		t.Fatalf("the victim has no session")
	}
	before := snapshotSubject(t, h, victim.ID)

	// The caller signs in as another user, so a handler that needs a session
	// finds one. The body then names the victim.
	h.ClearCookies()
	const callerAddress = "caller-subject@example.com"
	if _, err := h.Auth.CreateUser(ctx, authall.CreateUserInput{
		Email: callerAddress, Password: testPassword, EmailVerified: true,
	}); err != nil {
		t.Fatalf("create the caller: %v", err)
	}
	if resp, _ := h.SignIn(callerAddress, testPassword); resp.Status != http.StatusOK {
		t.Fatalf("the caller cannot sign in: %s", string(resp.Body))
	}

	body := map[string]any{
		"userId":    victim.ID,
		"user_id":   victim.ID,
		"sessionId": victimSession.Value,
		"email":     victimAddress,
	}

	tried := 0
	for _, route := range h.Auth.Routes() {
		if !changesState(route.Method) {
			continue
		}
		path := concreteSubjectPath(route.Path, h.Auth.BasePath())
		if path == "" {
			continue
		}
		tried++
		t.Run(route.Method+" "+route.Path, func(t *testing.T) {
			// The response itself is not the subject of this test. A handler
			// can reject the extra fields, and a rejection is a pass. The
			// database decides the result.
			h.Do(route.Method, path, body)
			after := snapshotSubject(t, h, victim.ID)
			if after != before {
				t.Fatalf("the route changed a row of another user:\nbefore %+v\nafter  %+v", before, after)
			}
		})
	}
	if tried == 0 {
		t.Fatalf("the test enumerated no state-changing route")
	}

	// The victim keeps a working password and a working session.
	h.ClearCookies()
	if resp, _ := h.SignIn(victimAddress, testPassword); resp.Status != http.StatusOK {
		t.Fatalf("the victim lost the password: %s", string(resp.Body))
	}
	h.ClearCookies()
	if session := h.GetSession(testsupport.WithBearer(victimSession.Value)); session.Session == nil {
		t.Fatalf("the victim lost the session")
	}
}

// subjectState is the observable state of one user.
type subjectState struct {
	Email           string
	EmailNormalized string
	DisplayName     string
	ImageURL        string
	Verified        bool
	PasswordHash    string
	Sessions        int
	Accounts        int
	Tokens          int
}

// snapshotSubject reads every row that belongs to one user.
func snapshotSubject(t *testing.T, h *testsupport.Harness, userID string) subjectState {
	t.Helper()
	ctx := context.Background()
	user, err := h.Auth.GetUser(ctx, userID)
	if err != nil {
		t.Fatalf("read the user %s: %v", userID, err)
	}
	state := subjectState{
		Email:           user.Email,
		EmailNormalized: user.EmailNormalized,
		DisplayName:     user.DisplayName,
		ImageURL:        user.ImageURL,
		Verified:        user.EmailVerifiedAt != nil,
	}
	cred, err := h.Store.Users().GetCredential(ctx, userID)
	switch {
	case err == nil:
		state.PasswordHash = cred.PasswordHash
	case isStoreNotFound(err):
	default:
		t.Fatalf("read the credential of %s: %v", userID, err)
	}
	accounts, err := h.Store.Accounts().ListByUser(ctx, userID)
	if err != nil {
		t.Fatalf("read the accounts of %s: %v", userID, err)
	}
	state.Accounts = len(accounts)

	state.Sessions = countUserRows(t, h, "auth_sessions", userID)
	state.Tokens = countUserRows(t, h, "auth_tokens", userID)
	return state
}

// countUserRows counts the rows of one table that reference one user.
//
// PostgreSQL and SQLite disagree about the placeholder style, so the helper
// reads the dialect of the adapter under test.
func countUserRows(t *testing.T, h *testsupport.Harness, table, userID string) int {
	t.Helper()
	column := "user_id"
	if table == "auth_users" {
		column = "id"
	}
	placeholder := "?"
	if h.Store.Migrator().Dialect() == schema.Postgres {
		placeholder = "$1"
	}
	var count int
	query := "SELECT COUNT(*) FROM " + table + " WHERE " + column + " = " + placeholder
	if err := rawDB(t, h).QueryRow(query, userID).Scan(&count); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return count
}

func isStoreNotFound(err error) bool {
	return err != nil && strings.Contains(err.Error(), store.ErrNotFound.Error())
}

// changesState reports whether a method can write.
func changesState(method string) bool {
	switch strings.ToUpper(method) {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}

// concreteSubjectPath turns a mounted route path into a callable path. It
// returns an empty string for a path that the test cannot fill.
func concreteSubjectPath(full, basePath string) string {
	path := strings.TrimPrefix(full, basePath)
	if !strings.Contains(path, "{") {
		return path
	}
	// The fixture configures GitHub, so a provider parameter has a real value.
	path = strings.ReplaceAll(path, "{provider}", "github")
	if strings.Contains(path, "{") {
		return ""
	}
	return path
}
