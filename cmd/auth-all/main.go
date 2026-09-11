// Command auth-all manages the Auth-All schema and generates the published
// contract artifacts.
//
// The tool never runs during normal application startup, so a production
// schema changes only when an operator asks for it.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	authall "github.com/alternayte/auth-all"
	"github.com/alternayte/auth-all/internal/clientgen"
	"github.com/alternayte/auth-all/internal/reference"
	"github.com/alternayte/auth-all/migrations"
	"github.com/alternayte/auth-all/openapi"
	"github.com/alternayte/auth-all/plugins/admin"
	"github.com/alternayte/auth-all/plugins/roles"
	"github.com/alternayte/auth-all/ratelimit"
	"github.com/alternayte/auth-all/schema"
	"github.com/alternayte/auth-all/store"
	"github.com/alternayte/auth-all/store/postgres"
	"github.com/alternayte/auth-all/store/sqlite"
)

const usage = `auth-all manages the Auth-All schema and contract artifacts.

Usage:
  auth-all schema [--json]
  auth-all migrate --driver <postgres|sqlite> --dsn <dsn>
  auth-all migrate --driver <postgres|sqlite> --dsn <dsn> --dry-run
  auth-all migrate --driver <postgres|sqlite> --sql
  auth-all migrate export --driver <postgres|sqlite> --format <goose|plain> --dir <path>
  auth-all user create --driver <postgres|sqlite> --dsn <dsn> --email <address> [--role <role>]
  auth-all user reset-password --driver <postgres|sqlite> --dsn <dsn> --email <address>
  auth-all openapi [--out <file>]
  auth-all client [--openapi <file>] [--out <file>]
  auth-all version

Commands:
  schema    Print the effective Auth-All schema.
  migrate   Apply the schema, plan it, emit the SQL, or export the units.
  user      Create a user or set a new password for a user.
  openapi   Emit the OpenAPI contract of the complete v1 API.
  client    Emit the generated TypeScript client.
  version   Print the version of the tool.

An application with its own plugins calls the equivalent Go API instead:
auth.Migrate, auth.MigrationPlan, auth.MigrationSQL, and auth.OpenAPI.
`

// version holds the released version. The release build sets it with the
// linker. A build from the source keeps the development value.
var version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "auth-all: "+err.Error())
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		fmt.Print(usage)
		return errors.New("a command is required")
	}
	switch args[0] {
	case "schema":
		return runSchema(args[1:])
	case "migrate":
		return runMigrate(args[1:])
	case "user":
		return runUser(args[1:])
	case "openapi":
		return runOpenAPI(args[1:])
	case "client":
		return runClient(args[1:])
	case "version", "-v", "--version":
		fmt.Println(version)
		return nil
	case "help", "-h", "--help":
		fmt.Print(usage)
		return nil
	default:
		fmt.Print(usage)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func referenceAuth() (*authall.Auth, error) { return reference.New() }

func runSchema(args []string) error {
	fs := flag.NewFlagSet("schema", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print the schema as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	auth, err := referenceAuth()
	if err != nil {
		return err
	}
	tables := auth.Schema().Tables()
	if *asJSON {
		raw, err := json.MarshalIndent(tables, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(raw))
		return nil
	}
	for _, t := range tables {
		fmt.Println(t.Name)
		for _, c := range t.Columns {
			null := "NOT NULL"
			if c.Nullable {
				null = "NULL"
			}
			key := ""
			if c.PrimaryKey {
				key = " PRIMARY KEY"
			}
			fmt.Printf("  %-20s %-10s %s%s\n", c.Name, c.Type, null, key)
		}
		for _, i := range t.Indexes {
			kind := "INDEX"
			if i.Unique {
				kind = "UNIQUE INDEX"
			}
			fmt.Printf("  %s %s (%s)\n", kind, i.Name, strings.Join(i.Columns, ", "))
		}
		fmt.Println()
	}
	return nil
}

func runMigrate(args []string) error {
	if len(args) > 0 && args[0] == "export" {
		return runMigrateExport(args[1:])
	}
	fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
	driver := fs.String("driver", "", "postgres or sqlite")
	dsn := fs.String("dsn", "", "the database connection string")
	dryRun := fs.Bool("dry-run", false, "print the pending statements without applying them")
	sqlOnly := fs.Bool("sql", false, "print the complete SQL without a database connection")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *sqlOnly {
		dialect, err := dialectOf(*driver)
		if err != nil {
			return err
		}
		auth, err := referenceAuth()
		if err != nil {
			return err
		}
		statements, err := auth.MigrationSQL(dialect)
		if err != nil {
			return err
		}
		printStatements(statements)
		return nil
	}
	if *dsn == "" {
		return errors.New("--dsn is required")
	}
	s, closeFn, err := openStore(*driver, *dsn)
	if err != nil {
		return err
	}
	defer closeFn()

	auth, err := reference.NewWithStore(s)
	if err != nil {
		return err
	}
	ctx := context.Background()
	if *dryRun {
		pending, err := auth.MigrationPlan(ctx)
		if err != nil {
			return err
		}
		if len(pending) == 0 {
			fmt.Println("-- The schema is up to date.")
			return nil
		}
		printStatements(pending)
		return nil
	}
	applied, err := auth.Migrate(ctx)
	if err != nil {
		return err
	}
	if len(applied) == 0 {
		fmt.Println("The schema is up to date.")
		return nil
	}
	for _, st := range applied {
		fmt.Println("applied " + st.ID)
	}
	return nil
}

// runMigrateExport writes one file for each migration unit. The host applies
// the files with its own migration tool.
func runMigrateExport(args []string) error {
	fs := flag.NewFlagSet("migrate export", flag.ContinueOnError)
	driver := fs.String("driver", "postgres", "postgres or sqlite")
	format := fs.String("format", "goose", "goose or plain")
	dir := fs.String("dir", "", "the target directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" {
		return errors.New("--dir is required")
	}
	dialect, err := dialectOf(*driver)
	if err != nil {
		return err
	}
	auth, err := referenceAuth()
	if err != nil {
		return err
	}
	files, err := auth.ExportMigrations(dialect, migrations.Format(*format))
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*dir, 0o755); err != nil {
		return err
	}
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(*dir, f.Name), []byte(f.Content), 0o644); err != nil {
			return err
		}
		fmt.Println("wrote " + filepath.Join(*dir, f.Name))
	}
	return nil
}

// runUser serves the operator commands of the admin plugin.
func runUser(args []string) error {
	if len(args) == 0 {
		return errors.New("user needs a command: create or reset-password")
	}
	command := args[0]
	fs := flag.NewFlagSet("user "+command, flag.ContinueOnError)
	driver := fs.String("driver", "", "postgres or sqlite")
	dsn := fs.String("dsn", "", "the database connection string")
	address := fs.String("email", "", "the email address of the user")
	name := fs.String("name", "", "the display name of the user")
	role := fs.String("role", "", "the role of the user")
	password := fs.String("password", "", "the password. An empty value generates one")
	temporary := fs.Bool("temporary", true, "the user must change the password")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *dsn == "" || *address == "" {
		return errors.New("--dsn and --email are required")
	}
	s, closeFn, err := openStore(*driver, *dsn)
	if err != nil {
		return err
	}
	defer closeFn()

	auth, adm, err := operatorAuth(s)
	if err != nil {
		return err
	}
	if err := auth.CheckSchema(context.Background()); err != nil {
		return err
	}
	ctx := context.Background()
	switch command {
	case "create":
		user, generated, err := adm.CreateUser(ctx, admin.CreateUserInput{
			Email: *address, Name: *name, Role: *role,
			Password: *password, TemporaryPassword: *temporary,
		})
		if err != nil {
			return err
		}
		fmt.Println("created " + user.ID + " " + user.Email)
		if generated != "" {
			fmt.Println("password " + generated)
		}
		return nil
	case "reset-password":
		user, err := s.Users().GetByNormalizedEmail(ctx, strings.ToLower(strings.TrimSpace(*address)))
		if err != nil {
			return err
		}
		generated, err := adm.ResetPassword(ctx, user.ID, admin.ResetOptions{
			Password: *password, Temporary: *temporary,
		})
		if err != nil {
			return err
		}
		fmt.Println("reset " + user.ID)
		if generated != "" {
			fmt.Println("password " + generated)
		}
		return nil
	default:
		return fmt.Errorf("unknown user command %q", command)
	}
}

// operatorAuth returns an Auth-All instance with the roles plugin and the
// admin plugin. It serves no HTTP request, so it needs no base URL of the
// application.
func operatorAuth(s store.Store) (*authall.Auth, *admin.Plugin, error) {
	adm := admin.New()
	auth, err := authall.New(
		authall.WithStore(s),
		authall.WithEmailPassword(),
		authall.WithRateLimiter(ratelimit.NewMemory(100, time.Minute)),
		authall.WithPlugins(
			roles.New(roles.Hierarchy(reference.RoleHierarchy...), roles.Default(reference.DefaultRole)),
			adm,
		),
	)
	if err != nil {
		return nil, nil, err
	}
	return auth, adm, nil
}

func printStatements(statements []schema.Statement) {
	for _, st := range statements {
		fmt.Printf("-- %s\n%s;\n\n", st.ID, st.SQL)
	}
}

func dialectOf(driver string) (schema.Dialect, error) {
	switch driver {
	case "postgres":
		return schema.Postgres, nil
	case "sqlite":
		return schema.SQLite, nil
	default:
		return "", fmt.Errorf("--driver must be postgres or sqlite")
	}
}

func openStore(driver, dsn string) (store.Store, func(), error) {
	switch driver {
	case "postgres":
		db, err := postgres.Open(dsn)
		if err != nil {
			return nil, nil, err
		}
		return postgres.New(db), func() { _ = db.Close() }, nil
	case "sqlite":
		db, err := sqlite.Open(dsn)
		if err != nil {
			return nil, nil, err
		}
		return sqlite.New(db), func() { _ = db.Close() }, nil
	default:
		return nil, nil, fmt.Errorf("--driver must be postgres or sqlite")
	}
}

func runOpenAPI(args []string) error {
	fs := flag.NewFlagSet("openapi", flag.ContinueOnError)
	out := fs.String("out", "", "write the document to a file instead of standard output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	auth, err := referenceAuth()
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(auth.OpenAPI(), "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return emit(*out, raw)
}

func runClient(args []string) error {
	fs := flag.NewFlagSet("client", flag.ContinueOnError)
	out := fs.String("out", "", "write the client to a file instead of standard output")
	// An application that holds host-owned columns or a plugin of its own
	// writes its own contract with auth.OpenAPI, and it generates the client
	// of that contract here.
	from := fs.String("openapi", "", "read the contract from a file instead of the reference configuration")
	if err := fs.Parse(args); err != nil {
		return err
	}
	document, err := clientDocument(*from)
	if err != nil {
		return err
	}
	source, err := clientgen.Generate(document)
	if err != nil {
		return err
	}
	return emit(*out, []byte(source))
}

// clientDocument returns the contract that the client describes. An empty path
// names the reference configuration.
func clientDocument(path string) (*openapi.Document, error) {
	if path == "" {
		auth, err := referenceAuth()
		if err != nil {
			return nil, err
		}
		return auth.OpenAPI(), nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("auth-all: cannot read the contract: %w", err)
	}
	var document openapi.Document
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, fmt.Errorf("auth-all: the contract %s is not a valid OpenAPI document: %w", path, err)
	}
	if len(document.Paths) == 0 {
		return nil, fmt.Errorf("auth-all: the contract %s holds no path", path)
	}
	return &document, nil
}

func emit(path string, content []byte) error {
	if path == "" {
		_, err := os.Stdout.Write(content)
		return err
	}
	return os.WriteFile(path, content, 0o644)
}
