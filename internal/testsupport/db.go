// Package testsupport builds migrated databases for the Auth-All test suites.
package testsupport

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/alternayte/auth-all/schema"
	"github.com/alternayte/auth-all/store"
	"github.com/alternayte/auth-all/store/postgres"
	"github.com/alternayte/auth-all/store/sqlite"
)

// PostgresDSNEnv names the environment variable that points at the test
// PostgreSQL instance. The verification command sets it.
const PostgresDSNEnv = "AUTHALL_POSTGRES_DSN"

// NewSQLite returns a migrated SQLite store backed by a temporary file.
func NewSQLite(t *testing.T) store.Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "authall.db")
	db, err := sqlite.Open("file:" + path)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s := sqlite.New(db)
	migrate(t, s)
	return s
}

// PostgresDSN returns the configured PostgreSQL DSN. It fails the test when the
// variable is missing, because the PostgreSQL contract run is required.
func PostgresDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv(PostgresDSNEnv)
	if dsn == "" {
		t.Fatalf("%s is not set. Run the suite through: just verify", PostgresDSNEnv)
	}
	return dsn
}

// NewPostgres returns a migrated PostgreSQL store inside a private schema. The
// schema is dropped when the test ends.
func NewPostgres(t *testing.T) store.Store {
	t.Helper()
	dsn := PostgresDSN(t)
	admin, err := postgres.Open(dsn)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	name := "authall_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	ctx := context.Background()
	if _, err := admin.ExecContext(ctx, "CREATE SCHEMA "+name); err != nil {
		_ = admin.Close()
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() {
		_, _ = admin.ExecContext(context.Background(), "DROP SCHEMA "+name+" CASCADE")
		_ = admin.Close()
	})
	db, err := postgres.Open(withSearchPath(dsn, name))
	if err != nil {
		t.Fatalf("open postgres schema: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s := postgres.New(db)
	migrate(t, s)
	return s
}

func withSearchPath(dsn, name string) string {
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	return dsn + sep + "options=" + url.QueryEscape("-c search_path="+name)
}

func migrate(t *testing.T, s store.Store) {
	t.Helper()
	sc, err := schema.NewCore()
	if err != nil {
		t.Fatalf("schema: %v", err)
	}
	if _, err := s.Migrator().Apply(context.Background(), sc); err != nil {
		t.Fatalf("migrate: %v", err)
	}
}

// MigrateSchema applies an effective schema to a store.
func MigrateSchema(t *testing.T, s store.Store, sc *schema.Schema) {
	t.Helper()
	if _, err := s.Migrator().Apply(context.Background(), sc); err != nil {
		t.Fatalf("migrate: %v", err)
	}
}

// RawDB opens a second handle on the same SQLite file for direct inspection.
func RawDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sqlite.Open("file:" + path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}
