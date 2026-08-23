# SQLite

SQLite is fully supported for tests, local development, local applications,
and production applications where SQLite is appropriate.

```go
import (
    "github.com/alternayte/auth-all/store/sqlite"
)

db, err := sqlite.Open("file:app.db")
if err != nil {
    log.Fatal(err)
}
defer db.Close()

auth, err := authall.New(
    authall.WithStore(sqlite.New(db)),
    // ...
)
```

The driver is `modernc.org/sqlite`, which is pure Go. The build needs no C
compiler and the race detector runs without extra work.

## What Open configures

`sqlite.Open` returns a handle with the recommended settings:

- write-ahead logging,
- foreign keys,
- a busy timeout of 10 seconds,
- one open connection, because SQLite allows one writer.

`sqlite.New` also accepts a handle that the application configured itself. The
handle must support the `RETURNING` clause, which SQLite provides from version
3.35.

## Migration

```bash
auth-all migrate --driver sqlite --dsn "file:app.db"
auth-all migrate --driver sqlite --sql > auth_migration.sql
```

## Behavior

- Timestamps are stored as fixed-width UTC text, so a comparison in SQL keeps
  the order of time.
- Token consumption is one `UPDATE ... RETURNING` statement.
- The adapter passes the same storage contract suite as PostgreSQL, including
  the concurrency requirements.

## Limits

One process owns the database file. SQLite is not the right choice when
several application instances must write at the same time.
