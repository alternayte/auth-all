# Two-factor authentication with TOTP

Auth-All supports the time-based one-time password of RFC 6238. A user reads a
code from an authenticator application and supplies it at sign-in.

Enable the second factor with one option:

```go
auth, err := authall.New(
    authall.WithStore(postgres.New(db)),
    authall.WithBaseURL("https://app.example.com"),
    authall.WithEmailPassword(),
    authall.WithTOTP(),
)
```

The option adds three endpoints. It does not change the sign-in of a user who
holds no second factor.

`WithTOTP` accepts an issuer name. The authenticator application shows it. The
default is the host of the base URL.

```go
authall.WithTOTP(authall.TOTPOptions{Issuer: "Example App"})
```

## Enrolment

Enrolment has two steps. The first step creates a secret. The second step
proves that the user can read a code from it.

**Step one.** Call `POST /totp/enrol` with a session.

```ts
const { secret, uri } = await client.totp.enrol({})
```

`uri` is an `otpauth://` URL. Show it as a QR code. Show `secret` as text for a
user who cannot scan.

The secret is not live at this point. A user who stops here keeps the sign-in
that they had before.

**Step two.** Call `POST /totp/confirm` with one code.

```ts
await client.totp.confirm({ code: "123456" })
```

The second factor is active from this point.

**The confirmation revokes the other sessions of the user.** A person who turns
on a second factor often suspects that somebody else holds a session. Tell the
user that their other devices must sign in again.

A user who abandons step one can call `POST /totp/enrol` a second time. The new
secret replaces the old one, and the old secret proves nothing.

A user who already holds a confirmed second factor receives
`TOTP_ALREADY_ENROLLED` from `POST /totp/enrol`. Remove the second factor
first.

## Sign in with a second factor

A user who holds a confirmed second factor never receives a session from a
password alone. The sign-in returns a challenge instead.

```ts
const out = await client.signIn.email({ email, password })
if (out.mfaRequired) {
  // out.user and out.session are null. No session cookie exists yet.
  const auth = await client.totp.verify({ mfaToken: out.mfaToken, code })
  // The session cookie exists now, and auth.user names the signed-in user.
}
```

The challenge token lives for five minutes and works one time. Auth-All
consumes it before it checks the code, so a wrong code costs the whole
challenge. The user restarts the sign-in.

One challenge stands per user. A second sign-in replaces the first, so an
abandoned attempt does not stay open.

**The gate covers every entry point.** A second factor that guards only the
password path is not a second factor, so the magic link and the OAuth callback
apply the same rule.

### The redirect flows

The OAuth callback and the magic-link GET redirect to the application, so they
carry no response body. Auth-All sets a short-lived cookie named
`<session cookie>.mfa` and redirects to the target with `?mfa=required`.

The cookie is `HttpOnly` and lives for five minutes. It holds no session and
authenticates nothing. It carries only the right to attempt the second step.

The token never appears in the URL. A query parameter reaches the browser
history, the server log, and any Referer header that the application leaks.

The [sessions guide](sessions.md) describes the cookie beside the other two
that Auth-All sets.

Read the marker and ask for a code. Send no token, because the cookie carries
it:

```ts
if (new URLSearchParams(location.search).get("mfa") === "required") {
  await client.totp.verify({ code })
}
```

## Remove the second factor

`POST /totp/disable` takes one current code.

```ts
await client.totp.disable({ code: "123456" })
```

A code is required. A session alone must not remove the factor that protects
the session.

## One code authenticates one time

Auth-All records the time step of every accepted code. A code that already
authenticated is refused for the rest of its window.

This stops a code that an attacker reads from a shoulder or from a phishing
page. It has one visible effect: a user who confirms an enrolment and then
disables it inside the same thirty seconds must wait for the next code.

## The error codes

| Code | Status | Meaning |
| --- | --- | --- |
| `INVALID_TOTP_CODE` | 400 | The code is wrong, expired, or already used. |
| `TOTP_NOT_ENROLLED` | 400 | The user holds no secret. |
| `TOTP_ALREADY_ENROLLED` | 409 | The user holds a confirmed secret. |
| `INVALID_RECOVERY_CODE` | 400 | The recovery code is wrong or already spent. |

`INVALID_TOTP_CODE` names no reason. A wrong code and a replayed code look
equal, so the response discloses nothing.

## Events

| Event | Emitted |
| --- | --- |
| `auth.totp_enabled` | A user confirmed an enrolment. |
| `auth.totp_disabled` | A user removed the second factor. A recovery sets the reason to `recovery_code`. |
| `auth.sign_in_failed` | A code was refused at `POST /totp/verify`. The reason is `invalid_totp_code`. |

```go
authall.WithEventHandler(events.HandlerFunc(func(ctx context.Context, e events.Event) {
    if e.Name == events.TOTPDisabled {
        notifyTheOwner(ctx, e.UserID)
    }
}))
```

An event never carries the secret or a code.

## Rate limits

The three endpoints run under the operation `totp`, keyed by user. A six-digit
code has one million values, and the accepted window offers three of them, so
an endpoint with no limit is guessable. Configure a limiter.

```go
authall.WithRateLimiter(myLimiter)
```

## The secret at rest

Auth-All stores the base32 secret in `auth_totp.secret`. It does not encrypt
it.

Auth-All holds no application key. A key that the library invents lives in the
same database as the secret, so it adds no protection. An application that
needs encryption at rest applies it at the column or at the volume.

An attacker who reads the table can generate codes. Treat `auth_totp` with the
same care as `auth_credentials`. The
[security model](security-model.md) states the complete threat position.

## A lost device

Auth-All issues ten recovery codes when a user confirms an enrolment. Each code
signs the user in one time.

```json
{ "success": true, "recoveryCodes": ["abcde-fghij", "..."] }
```

**The codes appear one time.** Auth-All stores only the SHA-256 hash, so it
cannot show them again. Tell the user to save them before they leave the page.

A recovery code is a first factor and a second factor at the same time. Treat
the list like a password.

### Use a recovery code

The sign-in returns the usual challenge. Send the challenge and one recovery
code to `POST /totp/recovery` instead of `POST /totp/verify`.

```ts
const out = await client.signIn.email({ email, password })
if (out.mfaRequired) {
  await client.totp.recovery({ mfaToken: out.mfaToken, code: "abcde-fghij" })
}
```

A redirect flow works the same way. The challenge cookie carries the token, so
send the code alone.

**A used recovery code removes the second factor.** The person who spent it lost
their authenticator, so the account must not keep a factor that its owner cannot
satisfy. Auth-All also removes every remaining code, so a leaked list is
worthless afterwards.

Send the user to enrolment again after a recovery. Their account holds no second
factor until they do.

### Replace the codes

A user who spent several codes, or who believes the list leaked, calls
`POST /totp/recovery-codes/regenerate` with a current TOTP code.

```ts
const { recoveryCodes } = await client.totp.regenerateRecoveryCodes({ code })
```

The old set stops working. A current code is required, because a stolen session
must not replace the list that recovers the account.

A user reads a code from paper, so Auth-All accepts any case and ignores the
separator and the spaces. `ABCDE-FGHIJ`, `abcdefghij`, and `abcde fghij` all
match `abcde-fghij`.

### When a user has no codes left

A user who loses their authenticator and their codes still needs an
administrator. The application owns the store, so an administrator tool can
remove the enrolment:

```go
// s is the store that the application passed to authall.WithStore.
_ = s.TOTP().Delete(ctx, userID)
_, _ = s.RecoveryCodes().DeleteByUser(ctx, userID)
_, _ = s.Sessions().DeleteByUser(ctx, userID)
```

Prove the identity of the person before you remove their second factor.
