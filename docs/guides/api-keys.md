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

## Failure responses

A revoked key, an expired key, an unknown key, and a key of a disabled owner
give one `401` response with one message. The caller therefore learns nothing
about the key.

## Storage

The migration unit `20260910000002_authall_apikeys` creates the key table.
