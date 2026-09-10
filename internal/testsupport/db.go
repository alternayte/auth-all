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
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alternayte/auth-all/schema"
	"github.com/alternayte/auth-all/store"
	"github.com/alternayte/auth-all/store/postgres"
	"github.com/alternayte/auth-all/store/sqlite"
)

// PostgresDSNEnv names the environment variable that points at the test
// PostgreSQL instance. The verification command sets it.
const PostgresDSNEnv = "AUTHALL_POSTGRES_DSN"

// PostgresRequiredEnv names the environment variable that makes the PostgreSQL
// run mandatory. The verification command sets it to "1", so a missing DSN
// fails the suite there. A plain "go test ./..." leaves it empty, so the
// PostgreSQL tests skip instead of fail.
const PostgresRequiredEnv = "AUTHALL_REQUIRE_POSTGRES"

// NewSQLite returns a migrated SQLite store backed by a temporary file.
func NewSQLite(t *testing.T) store.Store {
	t.Helper()
	return NewSQLiteWithOptions(t, schema.DefaultOptions())
}

// NewSQLiteWithOptions returns a migrated SQLite store that uses the given
// physical schema options.
func NewSQLiteWithOptions(t *testing.T, o schema.Options) store.Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "authall.db")
	db, err := sqlite.Open("file:" + path)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s := sqlite.New(db)
	migrateOptions(t, s, o)
	return s
}

// PostgresDSN returns the configured PostgreSQL DSN.
//
// A missing DSN skips the test, so a first "go test ./..." on a new checkout
// reports no failure. A missing DSN fails the test when PostgresRequiredEnv is
// set, because the PostgreSQL contract run is required in verification.
func PostgresDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv(PostgresDSNEnv)
	if dsn != "" {
		return dsn
	}
	if os.Getenv(PostgresRequiredEnv) != "" {
		t.Fatalf("%s is set, but %s is not. Run the suite through: just verify",
			PostgresRequiredEnv, PostgresDSNEnv)
	}
	t.Skipf("%s is not set. The PostgreSQL tests need a database. Run: just verify",
		PostgresDSNEnv)
	return ""
}

// NewPostgres returns a migrated PostgreSQL store inside a private schema. The
// schema is dropped when the test ends.
func NewPostgres(t *testing.T) store.Store {
	t.Helper()
	return NewPostgresWithOptions(t, schema.DefaultOptions())
}

// NewPostgresWithOptions returns a migrated PostgreSQL store that uses the
// given physical schema options.
func NewPostgresWithOptions(t *testing.T, o schema.Options) store.Store {
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
	migrateOptions(t, s, o)
	return s
}

func withSearchPath(dsn, name string) string {
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	return dsn + sep + "options=" + url.QueryEscape("-c search_path="+name)
}

// migrateOptions applies the schema of the options and tells the store the
// physical names.
func migrateOptions(t *testing.T, s store.Store, o schema.Options) {
	t.Helper()
	if c, ok := s.(store.SchemaConfigurable); ok {
		if err := c.UseSchema(o); err != nil {
			t.Fatalf("use schema: %v", err)
		}
	}
	sc, err := schema.NewCoreWithOptions(o)
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

// PgBouncerDSNEnv names the environment variable that points at the test
// PgBouncer instance. The verification command sets it.
const PgBouncerDSNEnv = "AUTHALL_PGBOUNCER_DSN"

// PgBouncerRequiredEnv makes the PgBouncer run mandatory.
const PgBouncerRequiredEnv = "AUTHALL_REQUIRE_PGBOUNCER"

// PgBouncerDSN returns the configured PgBouncer DSN. It skips the test when no
// DSN exists, and it fails when the run is mandatory.
func PgBouncerDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv(PgBouncerDSNEnv)
	if dsn != "" {
		return dsn
	}
	if os.Getenv(PgBouncerRequiredEnv) != "" {
		t.Fatalf("%s is set, but %s is not. Run the suite through: just verify",
			PgBouncerRequiredEnv, PgBouncerDSNEnv)
	}
	t.Skipf("%s is not set. The PgBouncer tests need a pooler. Run: just verify", PgBouncerDSNEnv)
	return ""
}

// NewPostgresPool returns a migrated store over a pgx pool that points at dsn.
//
// A transaction pooler gives one server connection for one transaction only, so
// the test cannot own a private schema through the search path. Every store
// gets a unique table prefix instead, and the cleanup drops those tables.
func NewPostgresPool(t *testing.T, dsn string, o schema.Options, opts ...postgres.Option) store.Store {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse pool config: %v", err)
	}
	// The exec mode must make no named prepared statement, because a
	// transaction pooler gives another server connection for the next
	// statement.
	cfg.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeExec
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("open pool: %v", err)
	}
	t.Cleanup(pool.Close)
	s, err := postgres.NewPool(pool, opts...)
	if err != nil {
		t.Fatalf("new pool store: %v", err)
	}
	migrateOptions(t, s, o)
	t.Cleanup(func() {
		sc, err := schema.NewCoreWithOptions(o)
		if err != nil {
			return
		}
		names := append(tableNames(sc), sc.Names().Migrations)
		for _, name := range names {
			_, _ = pool.Exec(context.Background(), "DROP TABLE IF EXISTS "+name+" CASCADE")
		}
	})
	return s
}

// UniquePrefix returns a table prefix that no other test uses.
func UniquePrefix() string {
	return "t" + strings.ReplaceAll(uuid.NewString(), "-", "")[:20] + "_"
}

func tableNames(sc *schema.Schema) []string {
	tables := sc.Tables()
	out := make([]string, 0, len(tables))
	for _, t := range tables {
		out = append(out, t.Name)
	}
	return out
}
