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
	"github.com/alternayte/auth-all/store/sqlite"
)

// newEmptyAuth builds Auth-All over an empty database that was never migrated.
func newEmptyAuth(t *testing.T, opts ...authall.Option) *authall.Auth {
	t.Helper()
	db, err := sqlite.Open("file:" + t.TempDir() + "/empty.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	base := []authall.Option{authall.WithStore(sqlite.New(db)), authall.WithEmailPassword()}
	auth, err := authall.New(append(base, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	return auth
}

// TestMIG001FreshMigration covers MIG-001 for SQLite.
func TestMIG001FreshMigration(t *testing.T) {
	ctx := context.Background()
	auth := newEmptyAuth(t, authall.WithPlugins(magiclink.New()))
	if err := auth.CheckSchema(ctx); err == nil {
		t.Fatalf("an empty database must report an outdated schema")
	}
	applied, err := auth.Migrate(ctx)
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if len(applied) == 0 {
		t.Fatalf("the migration applied no statement")
	}
	if err := auth.CheckSchema(ctx); err != nil {
		t.Fatalf("the schema is still outdated after the migration: %v", err)
	}
	// A second migration is a no-op.
	second, err := auth.Migrate(ctx)
	if err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	if len(second) != 0 {
		t.Fatalf("the second migration applied %d statements", len(second))
	}
}

// TestMIG002DeterministicSQL covers MIG-002.
func TestMIG002DeterministicSQL(t *testing.T) {
	auth := newEmptyAuth(t)
	for _, dialect := range []schema.Dialect{schema.Postgres, schema.SQLite} {
		first, err := auth.MigrationSQL(dialect)
		if err != nil {
			t.Fatalf("%s: %v", dialect, err)
		}
		second, err := auth.MigrationSQL(dialect)
		if err != nil {
			t.Fatal(err)
		}
		if len(first) != len(second) {
			t.Fatalf("%s: the statement count changed between runs", dialect)
		}
		var joined strings.Builder
		for i := range first {
			if first[i] != second[i] {
				t.Fatalf("%s: statement %d is not deterministic", dialect, i)
			}
			joined.WriteString(first[i].SQL)
			joined.WriteString(";\n")
		}
		sql := joined.String()
		for _, table := range []string{"auth_users", "auth_credentials", "auth_accounts", "auth_sessions", "auth_tokens", "auth_oauth_states"} {
			if !strings.Contains(sql, "CREATE TABLE IF NOT EXISTS "+table) {
				t.Fatalf("%s: the output misses the table %s", dialect, table)
			}
		}
		// The referenced table is created before the table that references it.
		if strings.Index(sql, "CREATE TABLE IF NOT EXISTS auth_users") > strings.Index(sql, "CREATE TABLE IF NOT EXISTS auth_accounts") {
			t.Fatalf("%s: the statement order breaks the foreign keys", dialect)
		}
	}
}

// TestMIG003NoStartupAutoMigrate covers MIG-003.
func TestMIG003NoStartupAutoMigrate(t *testing.T) {
	ctx := context.Background()
	auth := newEmptyAuth(t)
	// Construction alone must not create any table.
	if err := auth.CheckSchema(ctx); err == nil {
		t.Fatalf("construction created the schema silently")
	}
	if !strings.Contains(schemaError(auth, ctx), "auth-all migrate") {
		t.Fatalf("the startup error is not actionable: %s", schemaError(auth, ctx))
	}
	// Serving a request must not create any table either.
	rec := doRequest(t, auth, http.MethodPost, "http://app.test/api/auth/sign-up/email",
		`{"email":"nomigrate@example.com","password":"`+testPassword+`"}`)
	if rec.Code < 400 {
		t.Fatalf("the request succeeded without a schema: %d %s", rec.Code, rec.Body.String())
	}
	if err := auth.CheckSchema(ctx); err == nil {
		t.Fatalf("serving a request created the schema silently")
	}
}

func schemaError(auth *authall.Auth, ctx context.Context) string {
	e := auth.CheckSchema(ctx)
	if e == nil {
		return ""
	}
	return e.Error()
}

// TestPostgresHTTPFlows checks the required flows on the PostgreSQL adapter.
func TestPostgresHTTPFlows(t *testing.T) {
	s := testsupport.NewPostgres(t)
	h := testsupport.NewHarnessWithStore(t, s,
		authall.WithEmailPassword(),
		authall.WithPlugins(magiclink.New()))

	resp, out := h.SignUp("pg@example.com", testPassword)
	if resp.Status != http.StatusCreated || out.Session == nil {
		t.Fatalf("sign-up failed: %d %s", resp.Status, string(resp.Body))
	}
	if session := h.GetSession(); session.User == nil {
		t.Fatalf("the session does not resolve on PostgreSQL")
	}
	if signOut := h.Do(http.MethodPost, "/sign-out", nil); signOut.Status != http.StatusOK {
		t.Fatalf("sign-out failed: %s", string(signOut.Body))
	}
	if in, _ := h.SignIn("pg@example.com", testPassword); in.Status != http.StatusOK {
		t.Fatalf("sign-in failed")
	}
	h.Do(http.MethodPost, "/password/forgot", map[string]string{"email": "pg@example.com"})
	reset := h.Mail.Last(t, "reset-password")
	if r := h.Do(http.MethodPost, "/password/reset", map[string]string{
		"token": reset.Token, "password": "a replacement long password",
	}); r.Status != http.StatusOK {
		t.Fatalf("reset failed: %s", string(r.Body))
	}
	h.ClearCookies()
	h.Do(http.MethodPost, "/magic-link/send", map[string]string{"email": "pg@example.com"})
	link := h.Mail.Last(t, "magic-link")
	if v := followMagicLink(t, h, link.URL); v.Status != http.StatusSeeOther {
		t.Fatalf("the magic link failed: %s", string(v.Body))
	}
	if session := h.GetSession(); session.User == nil {
		t.Fatalf("the magic link created no session on PostgreSQL")
	}
}
