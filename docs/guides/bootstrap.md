# Bootstrap the first administrator

A new deployment holds no user, so no person can sign in and no person can
create the first administrator. `admin.Bootstrap` creates that user.

Auth-All never calls it. Construction has no side effect, so a replica start
changes no user.

## Use

```go
created, err := adm.Bootstrap(ctx, admin.Credentials{
    Email:    os.Getenv("ADMIN_EMAIL"),
    Password: os.Getenv("ADMIN_PASSWORD"),
})
if err != nil {
    return err
}
if created {
    log.Info("the first administrator exists")
}
```

Call it after the migrations, and only when the admin plugin is enabled.

## Rules

- `Bootstrap` creates one administrator when the users table is empty.
- It does nothing and returns `false` when any user exists. It never changes a
  user.
- Ten replicas can call it at the same time, and at most one user appears. A
  guard row with one primary key decides the race.
- The password passes the configured policy. A weak password fails with
  `WEAK_PASSWORD`, and it creates no user.
- The first administrator keeps the password. Set `TemporaryPassword` to make
  the person change it at the first sign-in.

## The command line

```
auth-all user create --driver postgres --dsn "$DSN" \
    --email person@example.com --role admin
auth-all user reset-password --driver postgres --dsn "$DSN" \
    --email person@example.com
```

Both commands print a generated password one time. They call the same Go
methods, so they run the same hooks, guards, and audit events.

## Storage

The migration unit `20260910000004_authall_bootstrap` creates the guard table.
