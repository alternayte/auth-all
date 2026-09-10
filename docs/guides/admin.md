# User administration

The admin plugin serves the administrative routes, and it exports the same
operations as Go methods. The plugin needs the roles plugin.

## Configuration

```go
adm := admin.New(admin.AdminRole("admin"))
auth, err := authall.New(
    authall.WithStore(s),
    authall.WithPlugins(roles.New(roles.Hierarchy("viewer", "admin")), adm),
)
```

The administrator role must be part of the hierarchy.

## Routes

| Method | Path | Description |
|---|---|---|
| `GET` | `/admin/users` | List the users with a cursor, a limit of 1 to 200, an email prefix filter, a role filter, and a disabled filter. |
| `POST` | `/admin/users` | Create a user with a role and a temporary password. |
| `POST` | `/admin/users/{id}/role` | Set the role of a user. |
| `POST` | `/admin/users/{id}/disable` | Disable a user and revoke every session. |
| `POST` | `/admin/users/{id}/enable` | Enable a user. |
| `POST` | `/admin/users/{id}/password` | Set a new password and revoke every session. |

Every route needs a session principal with the administrator role. An API key
never reaches an administrative route. Every route runs the origin check.

## The temporary password

A created user gets a password of 20 characters from `crypto/rand` when the
administrator supplies none. The response carries it one time.

The user then holds `must_change_password`. Sign-in succeeds, and every
protected route answers `403 PASSWORD_CHANGE_REQUIRED` until the change. The
routes `GET /session`, `POST /sign-out`, and `POST /password/change` stay open,
because the user needs a session to leave the state.

## The last administrator

A disable and a change to a lower role fail with `409 LAST_ADMIN` when the
target is the last enabled administrator. The guard locks the enabled
administrator rows inside the write transaction, so two parallel demotions
leave one administrator.

An administrator cannot disable the own account. The route answers `403
FORBIDDEN`.

## The Go API

```go
user, password, err := adm.CreateUser(ctx, admin.CreateUserInput{
    Email: "person@example.com", Role: "operator", TemporaryPassword: true,
})
temporary, err := adm.ResetPassword(ctx, user.ID, admin.ResetOptions{Temporary: true})
_, err = adm.SetRole(ctx, user.ID, "editor")
_, err = adm.Disable(ctx, user.ID)
_, err = adm.Enable(ctx, user.ID)
```

The Go methods run the same hooks, the same guards, and the same audit events
as the routes. The actor of an event is `system` when no request started the
operation.
