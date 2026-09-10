# Roles

The roles plugin adds a host-defined role hierarchy. A route asks for a minimum
role, and the check compares the rank of the effective role with the rank of
that minimum.

The plugin is off until the application enables it.

## Configuration

```go
r := roles.New(
    roles.Hierarchy("viewer", "operator", "editor", "admin"),
    roles.Default("viewer"),
)
auth, err := authall.New(
    authall.WithStore(s),
    authall.WithPlugins(r),
)
```

The list runs from the lowest role to the highest role. Construction fails when
the list is empty, when a name repeats, or when the list does not hold the
default role.

The default role belongs to every user whose `role` column is empty. A new user
therefore starts at the default role, and a Before hook can set another
configured role.

## Protect a route

```go
mux.Handle("/deploy", r.Require("operator", deployHandler))
```

`Require` runs the Auth-All authentication first, so it also runs the origin
check of the host routes. A request with no principal gets `401
UNAUTHORIZED`. A principal with a lower role gets `403 INSUFFICIENT_ROLE`.

`Require` panics at construction when the minimum role is not configured,
because such a route can never pass.

## Read the role in a handler

```go
role := roles.From(r.Context())
if roles.AtLeast(r.Context(), "editor") {
    // The caller can edit.
}
```

`AtLeast` returns false for a context that no role check passed. This is
default deny.

## An unknown role

A role name that the configuration does not list ranks below every role. A
removed role therefore keeps no access. The `GET /session` response carries the
effective role while the plugin is enabled.

## Storage

The role lives in the `role` column of the users table. The migration unit
`20260910000001_authall_user_admin_columns` adds it. Apply that unit even when
no plugin is enabled.
