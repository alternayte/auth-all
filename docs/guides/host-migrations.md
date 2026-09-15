# Host-owned migrations

Auth-All never runs a migration on its own. The application starts every schema
change.

An application with its own migration tool exports the Auth-All migration units
as files, and applies them with that tool.

## Export

```
auth-all migrate export --driver postgres --format goose --dir ./migrations
auth-all migrate export --driver sqlite --format plain --dir ./migrations
```

The Go API does the same for an application with its own plugins:

```go
files, err := auth.ExportMigrations(schema.Postgres, migrations.Goose)
```

The goose format writes one file for each unit with the `-- +goose Up` and
`-- +goose Down` markers. The plain format writes `<version>_<name>.up.sql` and
`<version>_<name>.down.sql`.

A tool that reads a migration set as `fs.FS` takes the plain files directly.
No committed copy is necessary:

```go
fsys, err := auth.Migrations(schema.Postgres)
```

## Inspection commands

A command that only lists routes, writes the OpenAPI document, or exports
migrations runs with no OAuth secrets. `New` refuses an OAuth provider with no
client id, no client secret, or no base URL. Pass `authall.WithoutProviderCheck()`
in that command only:

```go
opts := []authall.Option{authall.WithStore(s), authall.WithProvider(github.New(...))}
if avero.Inspecting(os.Args[1:]) {
    opts = append(opts, authall.WithoutProviderCheck())
}
```

The option does not remove the checks. They run on each OAuth request, and a
request to an unconfigured provider fails with an internal error.

## The units

| Version | Owner | Content |
|---|---|---|
| `20260101000000_authall_core` | core | The v1 tables. |
| `20260910000001_authall_user_admin_columns` | core | The columns `role`, `disabled_at`, and `must_change_password`. |
| `20260910000002_authall_apikeys` | apikeys | The API key table. |
| `20260910000003_authall_rate_limits` | ratelimit | The counter table of the store limiter. |
| `20260910000004_authall_bootstrap` | admin | The bootstrap guard table. |

The export holds the units of the enabled features only. A released unit never
changes, so a later release adds a new unit instead.

## A database that already holds the v1 tables

Mark the core unit as applied in the tool of the application, and apply the
later units. The goose command is:

```
goose -dir ./migrations postgres "$DSN" up-to 20260101000000
goose -dir ./migrations postgres "$DSN" up
```

The first command stops after the core unit. Use `goose ... up-to` only when
the tables exist already, because the statements use `CREATE TABLE IF NOT
EXISTS`.

## The schema check

A host tool writes no Auth-All record, so the record table names nothing. Read
the catalog instead:

```go
auth, err := authall.New(
    authall.WithStore(s),
    authall.WithSchemaCheck(authall.SchemaCheckCatalog),
)
err = auth.CheckSchema(ctx)
```

The error names every absent table and every absent column.

## The table prefix and the identifier type

```go
authall.WithSchema(schema.Options{Prefix: "iam_", IDType: schema.IDUUID})
```

The prefix names every table, every index, and the record table. It must match
`^[a-z][a-z0-9_]{0,30}$`. `IDUUID` gives PostgreSQL `uuid` columns for every
primary key and every foreign key. SQLite keeps text.

A store that does not accept the options fails the construction, so no query
ever runs against a wrong table.

## Host-owned user fields

```go
authall.WithUserFields(
    schema.UserField{Name: "team", Type: schema.TypeText, Nullable: true, Returned: true},
)
```

The field becomes a column of the users table. `Input` false makes every route
ignore the field. `Returned` false keeps the field out of every response. Both
default to false.

```go
team, err := authall.Field[string](user, "team")
```
