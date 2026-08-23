# Migrations and the command line tool

Auth-All never changes a database schema during normal startup. A schema
changes only when an operator or a deployment step asks for it.

## Install the tool

```bash
go install github.com/alternayte/auth-all/cmd/auth-all@latest
```

Run it from the module instead:

```bash
go run github.com/alternayte/auth-all/cmd/auth-all schema
```

## Commands

```bash
auth-all schema                                     # print the effective schema
auth-all schema --json                              # print it as JSON
auth-all migrate --driver postgres --dsn "$DSN"     # apply the schema
auth-all migrate --driver postgres --dsn "$DSN" --dry-run
auth-all migrate --driver postgres --sql            # emit the SQL, no database
auth-all openapi --out api/openapi.json             # emit the API contract
auth-all client --out src/generated.ts              # emit the TypeScript client
```

## SQL for source control

```bash
auth-all migrate --driver postgres --sql > auth_migration.sql
```

The output is deterministic. It renders the same statements in the same order
on every run, and it creates a referenced table before the table that
references it. The output needs no database connection.

## The migration record

Auth-All records every applied statement id in `auth_schema_migrations`. A
second run applies nothing. `--dry-run` prints the statements that the
database does not record yet.

## The startup check

```go
if err := auth.CheckSchema(ctx); err != nil {
    log.Fatal(err)
}
```

The error names the missing statements and the command that applies them:

```text
authall: the database schema is outdated. Missing: table:auth_users, ...
Run: auth-all migrate
```

## An application with its own plugins

The command line tool uses the canonical configuration, which enables every
first-party capability. An application that registers its own plugins calls
the Go API instead, because only the application knows its plugin set:

```go
statements, err := auth.Migrate(ctx)      // apply
pending, err := auth.MigrationPlan(ctx)   // plan
sql, err := auth.MigrationSQL(schema.Postgres) // emit
document := auth.OpenAPI()                // the effective contract
```
