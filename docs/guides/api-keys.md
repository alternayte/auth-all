# API keys

The API keys plugin adds machine credentials. A key authenticates through the
`Authorization` header, so a host route under `RequireAuth` or under a role
check accepts it with no change.

The plugin needs the roles plugin, and it is off until the application enables
it.

## Configuration

```go
k := apikeys.New(
    apikeys.Prefix("ak_"),
    apikeys.MaxTTL(365*24*time.Hour),
    apikeys.TouchInterval(60*time.Second),
)
auth, err := authall.New(
    authall.WithStore(s),
    authall.WithPlugins(roles.New(roles.Hierarchy("viewer", "admin")), k),
)
```

The prefix must match `^[a-z][a-z0-9_]{1,15}$`. The default is `ak_`.

`MaxTTL` sets the highest accepted lifetime, and it makes an expiry mandatory.
`AllowNoExpiry` accepts a key with no expiry beside a maximum.

## The shape of a key

A key is the prefix and 32 random bytes from `crypto/rand`, encoded as unpadded
base64url. The store keeps the SHA-256 digest and a display start of the prefix
plus four characters. The plaintext exists one time, in the response of the
create route.

## Routes

| Method | Path | Description |
|---|---|---|
| `POST` | `/api-keys` | Create a key. The response carries the plaintext one time. |
| `GET` | `/api-keys` | List the keys of the caller. |
| `POST` | `/api-keys/{id}/revoke` | Revoke one key. |

A user with the administrator role adds `?userId=<id>` to the list route, and
revokes the key of any user.

Key management needs a person. A request that a key authenticated gets `403`
on every key route, on the password routes, on the email routes, on the TOTP
routes, and on the session routes.

## The effective role

A key carries a role. The effective role of a key request is the lower of the
key role and the current role of the owner, so a demoted owner keeps no
stronger key. A create with a role above the owner role fails with
`ROLE_NOT_ALLOWED`.

## Scopes

A scope limits one key below the role of its owner. Scopes do not form a rank,
so a key with `propose` and no `read` is valid. The application declares the
scopes:

```go
k := apikeys.New(
    apikeys.Scopes("read", "propose"),
    apikeys.DefaultScopes("read"),
)
```

A name must match `^[a-z][a-z0-9_:.-]{0,63}$`. `DefaultScopes` gives the scopes
of a key that is created with none. Without it, such a key holds every declared
scope. Each default must be a declared scope, and an empty default fails at
construction.

The create route takes `"scopes": ["read", "propose"]`. In Go, `CreateInput.Scopes`
and `APIKey.Scopes` hold the names separated by a space, and `APIKey.ScopeList`
returns them as a slice. The create and list routes return `scopes` as an array. A scope that is not
declared fails with `400 SCOPE_UNKNOWN`. The store keeps the scopes sorted and
without duplicates. Scopes never change after the create, so a different set
needs a new key. A Before hook reads the scopes on `ev.Key` and can refuse a
scope for one user.

Protect a route with the middleware of the plugin, after `authall.New` returns:

```go
mux.Handle("/findings", k.RequireScope("read")(listFindings))
```

A request with no principal gets `401 UNAUTHORIZED`. A key without the scope gets
`403 SCOPE_MISSING`. A scope that is not declared panics at this call, so a typing
error fails at startup. The huma form is `humaauth.RequireScope(api, "read")`, and
it needs the Auth-All middleware before it.

A handler checks a scope with `authall.PrincipalFrom(ctx).HasScope("read")`. A
plugin checks a `*plugin.Principal` with `apikeys.HasScope(p, "read")`.

| Credential | Result of the check |
|---|---|
| Session | Passes. |
| API key, with declared scopes | Passes when the key holds the scope. |
| API key, with no declared scope | Passes. |
| Any other credential, for example an OAuth access token | Fails. |

With no declared scope the plugin works as it did before scopes existed, and a
create with a non-empty `scopes` fails with `SCOPE_UNKNOWN`.

A key from before the scope column holds a null value, and it resolves with the
default scopes. Set `DefaultScopes` before an upgrade if the existing keys must
not receive every declared scope.

The scopes of an organization key apply in addition to the permission statements
of the membership. A request passes only when both allow it. Scopes do not add
permissions.

## Refuse a key

A Before hook decides whether one owner may hold a key. It runs inside the
transaction of the create, for the `POST /api-keys` route and for a call to
`Create` from Go. An error refuses the key, and an `apierr` error keeps its
status:

```go
auth.Hooks().OnBeforeAPIKeyCreate(func(ctx context.Context, ev *hook.APIKeyEvent) error {
    if !isAutomationAccount(ev.User) {
        return apierr.ErrForbidden.WithMessage("Only automation accounts hold keys.")
    }
    return nil
})
```

`ev.Key` is the row that the create is about to insert, with its role and its
organization. It never carries the plaintext. `ev.Tx` is the transactional
store.

## Failure responses

A revoked key, an expired key, an unknown key, and a key of a disabled owner
give one `401` response with one message. The caller therefore learns nothing
about the key.

## Storage

The migration unit `20260910000002_authall_apikeys` creates the key table. Unit
`20261101000007_authall_apikeys_org_column` adds the organization column, and
unit `20261215000001_authall_apikeys_scopes_column` adds the scope column.
Apply the scope unit before the release that reads it serves traffic, because a
key read names the column.
