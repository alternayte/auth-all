# Account management

A person owns their account. Auth-All supplies the endpoints that let them see
it, change it, and remove it.

| Subject | Guide |
| --- | --- |
| List and revoke sessions | [Sessions](sessions.md) |
| Change the password | [Email and password](email-password.md) |
| Change the email address | [Email and password](email-password.md) |
| Delete the account | This guide |

## Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/api/auth/user/delete` | Start or complete an account delete. |
| POST | `/api/auth/user/delete/verify` | Complete a delete with a token. |

Both endpoints run the origin check. `POST /api/auth/user/delete` needs a
session.

## The two paths

The endpoint chooses the path from the credentials of the account.

**A user with a password credential** supplies the password:

```json
{ "currentPassword": "the password of today" }
```

A correct password deletes the account at once:

```json
{ "success": true }
```

A wrong password answers `401` with the code `INVALID_CREDENTIALS`.

**A user with no password credential** has nothing to prove with. An account
that only signs in through a provider reaches this. Auth-All sends a
confirmation to the address of the user and answers:

```json
{ "success": false, "confirmationRequired": true }
```

The message carries the intent `delete-account` and a one-time token. The
person then completes the delete:

```http
POST /api/auth/user/delete/verify
{ "token": "the token from the message" }
```

The consumed token names the user, so this endpoint needs no session. The token
is single use, and a replay answers `INVALID_TOKEN`.

Set the application page that receives the token with
`EmailPasswordOptions.DeleteAccountURL`. The default is the base URL plus
`/delete-account`.

## What the delete removes

The delete removes the user and every owned row:

- the user,
- the password credential,
- every external provider account,
- every session,
- every one-time token.

The storage contract suite proves this for PostgreSQL and for SQLite. The
delete also clears the session cookie of the browser.

## Reacting to a delete

Auth-All emits `auth.user_deleted` **before** it removes the rows, so a handler
can still read the owned data of the user:

```go
authall.WithEventHandler(events.HandlerFunc(func(ctx context.Context, e events.Event) {
    if e.Name == events.UserDeleted {
        archiveTheDataOf(ctx, e.UserID)
    }
}))
```

A handler runs inside the request. Keep the work short, or hand it to a queue.

## Rate limits

The delete endpoint is rate-limited under the operation `user-delete`. It
verifies a password, so it needs the same protection as a sign-in.
