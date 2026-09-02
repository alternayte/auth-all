# Getting started

Auth-All needs Go 1.25 or newer.

This guide adds Auth-All to an existing Go application.

## 1. Install the module

```bash
go get github.com/alternayte/auth-all
```

## 2. Open the database

The application owns the database handle. Auth-All never opens or closes it.

```go
db, err := sqlite.Open("file:app.db")
if err != nil {
    log.Fatal(err)
}
defer db.Close()
```

Use `postgres.Open` for PostgreSQL. Read the [PostgreSQL guide](postgresql.md)
or the [SQLite guide](sqlite.md) for the details of each adapter.

## 3. Build the instance

```go
auth, err := authall.New(
    authall.WithStore(sqlite.New(db)),
    authall.WithBaseURL("http://localhost:8080"),
    authall.WithEmailPassword(),
    authall.WithEmailSender(sender),
)
if err != nil {
    log.Fatal(err)
}
```

`WithBaseURL` is the absolute public URL of the application. Auth-All uses it
to build links, to validate redirects, and to build OAuth callback URLs.

## 4. Create the tables

Auth-All never changes a schema during startup. Run the migration one time:

```bash
go run github.com/alternayte/auth-all/cmd/auth-all migrate \
    --driver sqlite --dsn "file:app.db"
```

Ask Auth-All to confirm the schema during startup:

```go
if err := auth.CheckSchema(context.Background()); err != nil {
    log.Fatal(err)
}
```

The error names the missing statements and the command that applies them.

## 5. Mount the handler

```go
mux := http.NewServeMux()
mux.Handle("/api/auth/", auth.Handler())
```

The base path is `/api/auth` by default. `WithBasePath` changes it. Mount the
handler at the same path.

## 6. Read the session in the application

```go
user, err := auth.User(r.Context(), r)
if err != nil {
    http.Error(w, "internal error", http.StatusInternalServerError)
    return
}
if user == nil {
    http.Error(w, "unauthorized", http.StatusUnauthorized)
    return
}
```

`auth.Session` returns the session record. Both functions return nil values
when the request carries no valid session.

## 7. Call the API from the browser

```ts
import { createAuthClient } from "@alternayte/auth-all-client"

const auth = createAuthClient({ baseUrl: window.location.origin })

await auth.signUp.email({ email, password })
const session = await auth.getSession()
```

Read the [TypeScript client guide](typescript-client.md) for the complete API.

## Next steps

- Add [Magic Link](magic-link.md) sign-in.
- Add [GitHub](github-oauth.md) or [Google](google-oauth.md) sign-in.
- Read the [security model](security-model.md) before the first release.
