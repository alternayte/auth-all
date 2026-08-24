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
	"strings"

	authall "github.com/alternayte/auth-all"
	"github.com/alternayte/auth-all/internal/clientgen"
	"github.com/alternayte/auth-all/internal/reference"
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
  auth-all openapi [--out <file>]
  auth-all client [--out <file>]
  auth-all version

Commands:
  schema    Print the effective Auth-All schema.
  migrate   Apply the schema, plan it, or emit the SQL.
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
	if err := fs.Parse(args); err != nil {
		return err
	}
	auth, err := referenceAuth()
	if err != nil {
		return err
	}
	source, err := clientgen.Generate(auth.OpenAPI())
	if err != nil {
		return err
	}
	return emit(*out, []byte(source))
}

func emit(path string, content []byte) error {
	if path == "" {
		_, err := os.Stdout.Write(content)
		return err
	}
	return os.WriteFile(path, content, 0o644)
}
