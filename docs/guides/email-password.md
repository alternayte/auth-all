# Email and password

`WithEmailPassword` enables the credential endpoints.

```go
authall.WithEmailPassword(authall.EmailPasswordOptions{
    RequireEmailVerification: true,
    VerifyEmailURL:           "https://app.example.com/verify-email",
    ResetPasswordURL:         "https://app.example.com/reset-password",
})
```

## Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/api/auth/sign-up/email` | Create an account. |
| POST | `/api/auth/sign-in/email` | Create a session. |
| POST | `/api/auth/sign-out` | Revoke the current session. |
| POST | `/api/auth/password/forgot` | Request a reset message. |
| POST | `/api/auth/password/reset` | Set a new password. |
| POST | `/api/auth/password/change` | Change the password of the current user. |
| POST | `/api/auth/email-verification/send` | Request a verification message. |
| POST | `/api/auth/email-verification/verify` | Verify an address. |
| POST | `/api/auth/email/change` | Request a change of the address. |
| POST | `/api/auth/email/change/verify` | Complete the change. |

## Password storage

Auth-All hashes a password with Argon2id. Each stored hash encodes the
parameters that produced it, so a later change of the cost is safe. A
successful sign-in rehashes the password when the configured parameters differ
from the stored parameters.

```go
authall.WithArgon2Params(authall.Argon2Params{
    Memory:      128 * 1024,
    Iterations:  3,
    Parallelism: 4,
    SaltLength:  16,
    KeyLength:   32,
})
```

Auth-All never writes a password, a password hash, or a token to a log, an
error, or an event.

## Password policy

The default policy accepts a password of 8 to 4096 characters. Auth-All does
not require a special character, because a length requirement protects better
and it produces fewer reused passwords.

```go
authall.WithPasswordPolicy(authall.PasswordPolicy{MinLength: 12, MaxLength: 4096})
```

A password outside the policy produces the error code `WEAK_PASSWORD`.

## Email verification

`RequireEmailVerification` blocks a sign-in until the address is verified.
Sign-up then returns the user without a session:

```json
{ "user": { "...": "..." }, "session": null, "emailVerificationRequired": true }
```

Auth-All asks the application to send a message with the intent
`verify-email`. The message carries the token and a ready-to-use URL. The
default URL is `BaseURL + /verify-email?token=...`. Set `VerifyEmailURL` when
the page lives somewhere else.

`SendVerificationOnSignUp` sends the message without blocking the sign-in.

An application that serves its own verification page consumes the token
without a call to the HTTP API:

```go
user, err := auth.VerifyEmailToken(ctx, r.URL.Query().Get("token"))
```

## Password reset

The reset flow never discloses whether an account exists. The response is
always:

```json
{ "message": "If an account exists, instructions have been sent." }
```

A successful reset revokes every session of the user, because the account
owner can have lost control of a session.

A reset token, a verification token, and a magic link token are single use.
Auth-All consumes a token with one atomic statement, so two concurrent
attempts produce at most one success.

## Password change

`POST /api/auth/password/change` changes the password of the person who is
signed in. It needs a session and it runs the origin check.

```json
{
  "currentPassword": "the password of today",
  "newPassword": "the password of tomorrow",
  "revokeOtherSessions": true
}
```

- A wrong current password answers `401` with the code `INVALID_CREDENTIALS`.
  The path performs the same hashing work as a correct password, so the
  response time discloses nothing.
- A success replaces the credential and keeps the current session. It revokes
  every other session, because the account owner can have lost control of one.
- Send `"revokeOtherSessions": false` to keep the other sessions.
- The new password must satisfy the password policy.
- A user with no password credential answers `400` with the code
  `NO_PASSWORD_CREDENTIAL`. An account that only signs in through a provider
  reaches this. Such a user sets a first password through the reset flow.
- The endpoint is rate-limited under the operation `password-change`.

## Email change

The change needs two steps, because the person must prove the new address
before it moves.

`POST /api/auth/email/change` needs a session and runs the origin check:

```json
{ "newEmail": "new@example.com", "currentPassword": "the password of today" }
```

- A user with a password credential must supply the correct password. A wrong
  password answers `401`.
- A user with no password credential skips the check. An account that only
  signs in through a provider reaches this, so it can still move its address.
- The response never discloses whether the new address is taken:

```json
{ "message": "If the address can receive a confirmation, one has been sent." }
```

- A taken address stops the flow before the send, so the owner of that address
  receives nothing.
- A free address receives a confirmation with the intent `email-change`. The
  message carries the token.
- The old address receives a notice with the intent `email-change-notice`. The
  notice carries no token and no link, so the old address cannot complete the
  change.
- The endpoint is rate-limited under the operation `email-change`.

`POST /api/auth/email/change/verify` completes the change:

```json
{ "token": "the token from the confirmation" }
```

- The endpoint consumes the token, writes the new address, and marks the
  address verified.
- The consumed token names the user, so the endpoint needs no session.
- The address moves in its normalized form. Normalization lowercases the
  address and changes nothing else.
- The change revokes every session of the user except the current one.
- A person who took the address between the two steps causes `409` with the
  code `EMAIL_ALREADY_EXISTS`.

Set the application page that receives the token with
`EmailPasswordOptions.ChangeEmailURL`. The default is the base URL plus
`/change-email`.

## Errors

| Code | Meaning |
| --- | --- |
| `INVALID_CREDENTIALS` | The email address or the password is wrong. |
| `EMAIL_ALREADY_EXISTS` | The normalized address is taken. |
| `WEAK_PASSWORD` | The password is outside the policy. |
| `EMAIL_NOT_VERIFIED` | The address needs verification first. |
| `INVALID_TOKEN` | The token is unknown, expired, or already used. |
| `NO_PASSWORD_CREDENTIAL` | The account has no password to change. |
| `EMAIL_ALREADY_EXISTS` | Somebody took the address before the confirmation. |

The sign-in response is identical for an unknown address and a wrong password,
and both paths perform the same hashing work.
