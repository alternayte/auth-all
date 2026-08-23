# Sessions

Auth-All uses database-backed opaque sessions. A JSON Web Token is not the
default session mechanism.

## Properties

- A session token carries 256 bits of cryptographic randomness.
- The plaintext token exists only in the response and in the browser cookie.
- The database stores the SHA-256 hash of the token.
- Every session has an expiry and can be revoked.

The stored record holds `id`, `user_id`, `token_hash`, `created_at`,
`expires_at`, and `last_seen_at`.

## Cookie defaults

```text
HttpOnly=true
Secure=true
SameSite=Lax
Path=/
Name=authall.session
```

```go
authall.WithCookie(authall.CookieOptions{
    Name:     "app_session",
    Domain:   ".example.com",
    SameSite: http.SameSiteLaxMode,
})
```

Set `Secure` to false only for local development over plain HTTP.

## Lifetime

```go
authall.WithSession(authall.SessionOptions{
    TTL:           14 * 24 * time.Hour,
    TouchInterval: 5 * time.Minute,
})
```

`TouchInterval` limits how often a session read updates `last_seen_at`.

## Reading a session

```go
session, err := auth.Session(ctx, r)
user, err := auth.User(ctx, r)
```

Auth-All reads the session cookie first and the `Authorization: Bearer` header
second, so a client that cannot use cookies still works.

An expired session never authenticates. Auth-All removes it when it sees it.

## Revoking a session

```go
err := auth.RevokeSession(ctx, sessionID)
count, err := auth.RevokeUserSessions(ctx, userID)
```

A revoked row is gone, so a concurrent read cannot bring it back. A later
write against the removed session reports that it does not exist.

## Session fixation

Authentication always issues a new token. When the request already carries a
session, Auth-All revokes that session first, so a token that an attacker
planted in the browser does not survive the sign-in.

## Cleanup

```go
err := auth.Cleanup(ctx)
```

`Cleanup` removes expired sessions, expired one-time tokens, and expired OAuth
states. Call it from a periodic job.
