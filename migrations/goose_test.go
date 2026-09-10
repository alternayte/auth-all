package migrations_test

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"

	authall "github.com/alternayte/auth-all"
	"github.com/alternayte/auth-all/internal/testsupport"
	"github.com/alternayte/auth-all/migrations"
	"github.com/alternayte/auth-all/schema"
	"github.com/alternayte/auth-all/store"
	"github.com/alternayte/auth-all/store/postgres"
	"github.com/alternayte/auth-all/store/sqlite"
)

// target is one database that the goose tests drive.
type target struct {
	// dialect selects the SQL flavor of the export.
	dialect schema.Dialect
	// driver is the goose driver name.
	driver string
	// dsn is the goose connection string.
	dsn string
	// db is an open handle on the same database.
	db *sql.DB
	// store is the Auth-All store over db.
	store store.Store
}

// writeExport writes the export of the units into a new directory.
func writeExport(t *testing.T, d schema.Dialect, o schema.Options) string {
	t.Helper()
	units, err := schema.CoreUnits(o)
	if err != nil {
		t.Fatalf("units: %v", err)
	}
	files, err := migrations.Render(units, d, migrations.Goose)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	dir := t.TempDir()
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(dir, f.Name), []byte(f.Content), 0o644); err != nil {
			t.Fatalf("write %s: %v", f.Name, err)
		}
	}
	return dir
}

// goose runs the goose command line tool. The tool lives in tools.go.mod, so
// the library module requires no migration dependency.
func goose(t *testing.T, tg target, dir string, args ...string) {
	t.Helper()
	full := append([]string{"tool", "-modfile=tools.go.mod", "goose",
		"-dir", dir, tg.driver, tg.dsn}, args...)
	cmd := exec.Command("go", full...)
	cmd.Dir = repoRoot(t)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("goose %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

// repoRoot returns the module directory.
func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("working directory: %v", err)
	}
	return filepath.Dir(wd)
}

// sqliteTarget returns an empty SQLite database.
func sqliteTarget(t *testing.T) target {
	t.Helper()
	path := filepath.Join(t.TempDir(), "authall.db")
	db, err := sqlite.Open("file:" + path)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return target{dialect: schema.SQLite, driver: "sqlite3", dsn: path, db: db, store: sqlite.New(db)}
}

// postgresTarget returns an empty PostgreSQL schema.
func postgresTarget(t *testing.T) target {
	t.Helper()
	dsn := testsupport.PostgresDSN(t)
	admin, err := postgres.Open(dsn)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	name := "authall_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.ExecContext(context.Background(), "CREATE SCHEMA "+name); err != nil {
		_ = admin.Close()
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() {
		_, _ = admin.ExecContext(context.Background(), "DROP SCHEMA "+name+" CASCADE")
		_ = admin.Close()
	})
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	scoped := dsn + sep + "options=" + url.QueryEscape("-c search_path="+name)
	db, err := postgres.Open(scoped)
	if err != nil {
		t.Fatalf("open schema: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return target{dialect: schema.Postgres, driver: "postgres", dsn: scoped, db: db, store: postgres.New(db)}
}

// targets names the databases that every goose scenario drives.
var targets = []struct {
	name  string
	build func(*testing.T) target
}{
	{"sqlite", sqliteTarget},
	{"postgres", postgresTarget},
}

// TestSCNSCH002TheGooseExportAppliesAndRollsBack proves REQ-SCH-002.
func TestSCNSCH002TheGooseExportAppliesAndRollsBack(t *testing.T) {
	for _, c := range targets {
		t.Run(c.name, func(t *testing.T) {
			tg := c.build(t)
			dir := writeExport(t, tg.dialect, schema.DefaultOptions())
			goose(t, tg, dir, "up")
			assertTableExists(t, tg, true)
			// goose down rolls back one unit at a time.
			goose(t, tg, dir, "down")
			goose(t, tg, dir, "down")
			assertTableExists(t, tg, false)
			goose(t, tg, dir, "up")
			assertTableExists(t, tg, true)
		})
	}
}

// assertTableExists reports whether the users table is present.
func assertTableExists(t *testing.T, tg target, want bool) {
	t.Helper()
	inspector, ok := tg.store.(store.CatalogInspector)
	if !ok {
		t.Fatal("the store cannot read the catalog")
	}
	_, exists, err := inspector.TableColumns(context.Background(), schema.TableUsers)
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	if exists != want {
		t.Fatalf("the users table exists = %v, want %v", exists, want)
	}
}

// TestSCNSCH008TheCatalogCheckReadsTheAppliedExport proves REQ-SCH-010 and
// REQ-SCH-011.
func TestSCNSCH008TheCatalogCheckReadsTheAppliedExport(t *testing.T) {
	for _, c := range targets {
		t.Run(c.name, func(t *testing.T) {
			tg := c.build(t)
			dir := writeExport(t, tg.dialect, schema.DefaultOptions())
			goose(t, tg, dir, "up")

			auth, err := authall.New(
				authall.WithStore(tg.store),
				authall.WithBaseURL("https://app.example.com"),
				authall.WithSchemaCheck(authall.SchemaCheckCatalog),
			)
			if err != nil {
				t.Fatalf("new: %v", err)
			}
			if err := auth.CheckSchema(context.Background()); err != nil {
				t.Fatalf("the catalog check failed after the export: %v", err)
			}

			// A dropped column must appear in the error by name.
			if _, err := tg.db.ExecContext(context.Background(),
				"ALTER TABLE "+schema.TableUsers+" DROP COLUMN must_change_password"); err != nil {
				t.Fatalf("drop column: %v", err)
			}
			err = auth.CheckSchema(context.Background())
			if err == nil {
				t.Fatal("the catalog check passed with an absent column")
			}
			if !strings.Contains(err.Error(), "auth_users.must_change_password") {
				t.Fatalf("the error does not name the column: %v", err)
			}
		})
	}
}
