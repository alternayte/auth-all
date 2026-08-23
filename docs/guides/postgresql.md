# PostgreSQL

PostgreSQL is the primary production target.

```go
import (
    "github.com/alternayte/auth-all/store/postgres"
)

db, err := postgres.Open(os.Getenv("DATABASE_URL"))
if err != nil {
    log.Fatal(err)
}
defer db.Close()

auth, err := authall.New(
    authall.WithStore(postgres.New(db)),
    // ...
)
```

`postgres.New` accepts any `*sql.DB`. The application owns the handle, its
pool settings, and its lifetime. The adapter uses the pgx driver through
`database/sql`.

## Migration

```bash
auth-all migrate --driver postgres --dsn "$DATABASE_URL"
```

Emit the SQL for source control instead:

```bash
auth-all migrate --driver postgres --sql > auth_migration.sql
```

## Tables

```text
auth_users
auth_credentials
auth_accounts
auth_sessions
auth_tokens
auth_oauth_states
auth_schema_migrations
```

`auth_schema_migrations` records the applied statements, so a second migration
run changes nothing.

## Behavior

- A duplicate normalized address raises a unique violation, which Auth-All
  maps to `EMAIL_ALREADY_EXISTS`. Two concurrent sign-ups create one user.
- Token consumption is one `UPDATE ... RETURNING` statement, so a replay finds
  no row.
- Timestamps use `timestamptz` and Auth-All writes them in UTC.

## Tests

The PostgreSQL adapter runs the same storage contract suite as SQLite. The
verification command starts a PostgreSQL container and points the suite at it:

```bash
just verify
```

Each test runs in a private schema, so the tests do not interfere.
