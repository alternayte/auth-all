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
| POST | `/api/auth/email-verification/send` | Request a verification message. |
| POST | `/api/auth/email-verification/verify` | Verify an address. |

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

## Errors

| Code | Meaning |
| --- | --- |
| `INVALID_CREDENTIALS` | The email address or the password is wrong. |
| `EMAIL_ALREADY_EXISTS` | The normalized address is taken. |
| `WEAK_PASSWORD` | The password is outside the policy. |
| `EMAIL_NOT_VERIFIED` | The address needs verification first. |
| `INVALID_TOKEN` | The token is unknown, expired, or already used. |

The sign-in response is identical for an unknown address and a wrong password,
and both paths perform the same hashing work.
