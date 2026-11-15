# Passkeys

Passkeys is an official plugin. A signed-in user registers WebAuthn passkeys,
and then signs in with a passkey instead of a password.

```go
authall.WithPlugins(
    passkeys.New(
        passkeys.RPDisplayName("Example"),
    ),
)
```

The plugin owns two tables. `Migrate` creates them, and the operator tool
exports them with the other migrations.

## Options

| Option | Default | Purpose |
| --- | --- | --- |
| `RPID` | the host of the base URL | The domain that every passkey binds to. |
| `RPDisplayName` | the RP ID | The name that the browser shows. |
| `Origins` | the origin of the base URL | The origins that a response can come from. |
| `UserVerification` | `preferred` | `required`, `preferred`, or `discouraged`. |
| `FreshAge` | 10 minutes | The maximum session age to register or delete a passkey. |

A passkey of one RP ID never works under another RP ID. Do not change the RP ID
after the first registration.

The RP ID must be a domain. An IP address fails at construction. A base URL
source (`WithBaseURLSource`) needs both `RPID` and `Origins`, because a base URL
that changes cannot bind a passkey.

## Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/api/auth/passkeys/register/begin` | Start a registration. Needs a fresh session. |
| POST | `/api/auth/passkeys/register/finish` | Store the new passkey. Needs a fresh session. |
| POST | `/api/auth/passkeys/sign-in/begin` | Start a sign-in. |
| POST | `/api/auth/passkeys/sign-in/finish` | Verify the passkey and create the session. |
| GET | `/api/auth/passkeys` | List the passkeys of the session user. |
| DELETE | `/api/auth/passkeys/{id}` | Delete one passkey. Needs a fresh session. |

Each begin route returns a ceremony handle and the WebAuthn options:

```json
{"ceremony": "…", "options": {"publicKey": {…}}}
```

Send the handle back to the finish route with the credential. A handle works
one time, for five minutes.

## From the browser

```ts
const begin = await client.passkeys.registerBegin()
const created = await navigator.credentials.create({
  publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(begin.options.publicKey),
})
await client.passkeys.registerFinish({
  ceremony: begin.ceremony,
  name: "Laptop",
  credential: (created as PublicKeyCredential).toJSON(),
})
```

```ts
const begin = await client.passkeys.signInBegin()
const assertion = await navigator.credentials.get({
  publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(begin.options.publicKey),
})
const result = await client.passkeys.signInFinish({
  ceremony: begin.ceremony,
  credential: (assertion as PublicKeyCredential).toJSON(),
})
```

The sign-in finish route returns the AuthResponse of the password sign-in and
writes the session cookie.

## Behavior

- The sign-in is discoverable. The begin route takes no address, so the
  response never tells whether an account exists. Registration requires a
  discoverable credential, so every stored passkey can sign in this way.
- A response with the user-verified flag issues the session at once. The device
  checked a PIN or a biometric, so the sign-in has two factors.
- A response without the user-verified flag gives a user with confirmed TOTP
  the challenge of the password sign-in: `mfaRequired` and `mfaToken`.
- Registration and delete need a session that is younger than `FreshAge`. An
  older session gets 403 `SESSION_NOT_FRESH`. Send the user to sign in again.
  A stolen old cookie therefore cannot add a passkey.
- An API key cannot list, add, or delete a passkey.
- A sign counter that does not grow refuses the sign-in and emits
  `auth.passkey_clone_detected`. A counter that stays at zero is no warning,
  because a synced passkey always reports zero.
- A disabled user gets `USER_DISABLED`. An unverified address gets
  `EMAIL_NOT_VERIFIED` when the application requires a verified address.
- Both sign-in routes count against the rate limit operation
  `passkey-sign-in`, keyed by the client address.
- A failed check of any kind gives 400 `PASSKEY_INVALID`, so a response tells
  nothing about the reason.
- The session method is `passkey`. The sign-in hooks and the audit event name
  it.

## Cleanup

Auth-All runs no background work. Call `Cleanup` on your own schedule to remove
the ceremonies that expired more than one hour ago:

```go
removed, err := passkeyPlugin.Cleanup(ctx)
```

## Tests

`plugins/passkeys/passkeystest` is a virtual authenticator for Go tests. It
creates ES256 keys, uses the attestation format `none`, and keeps a sign
counter.

```go
device := passkeystest.New("example.com", "https://example.com")

credential, err := device.Register(begin.Options) // the "options" member
// post {"ceremony": begin.Ceremony, "name": "laptop", "credential": credential}

assertion, err := device.SignIn(signInBegin.Options)
// post {"ceremony": signInBegin.Ceremony, "credential": assertion}
```

`SetUserVerified(false)` acts as a security key with no PIN check.
`SetSynced(true)` acts as a synced passkey. `SetSignCount` sets the counter, so
a test can act as a cloned key.
