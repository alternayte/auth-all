# Magic Link

Magic Link is an official plugin. It signs a user in through an emailed
one-time link.

```go
authall.WithPlugins(
    magiclink.New(
        magiclink.WithTTL(15*time.Minute),
        magiclink.WithCreateUser(true),
        magiclink.WithCallbackURL("https://app.example.com/dashboard"),
    ),
)
```

## Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/api/auth/magic-link/send` | Send a sign-in link. |
| GET | `/api/auth/magic-link/verify` | Complete the sign-in. |

## Behavior

- The link is valid one time. Two concurrent uses produce at most one session.
- The default lifetime is 15 minutes.
- An unknown address creates an account, because a used link proves that the
  person controls the address. `WithCreateUser(false)` turns this off.
- A successful link marks the address as verified.
- A successful link on an address that is not verified yet also deletes the
  password credential of the user and revokes every session of the user. The
  link proves current control of the address, so a password that somebody set
  while the address was unverified is not trustworthy. See the
  [security model](security-model.md).
- A successful link on an address that is already verified changes no password
  and revokes no other session.
- The response never discloses whether the address has an account:

```json
{ "message": "If the address can receive a sign-in link, one has been sent." }
```

## Delivery

Auth-All asks the application to send a message with the intent `magic-link`.
The message carries the plaintext token, the ready-to-use URL, and the expiry.

```go
authall.WithEmailSender(email.SenderFunc(func(ctx context.Context, msg email.Message) error {
    if msg.Intent == email.IntentMagicLink {
        return mailer.Send(ctx, msg.To, "Your sign-in link", msg.URL)
    }
    return nil
}))
```

## Redirect

`callbackURL` in the request body and in the verification query decides where
the browser goes after success. Auth-All accepts a relative path or an
absolute URL of a trusted origin. Any other value falls back to the configured
callback URL.

## From the browser

```ts
await auth.magicLink.send({ email: "user@example.com" })
```

## Plugin parity

Magic Link uses only the public `plugin` package. It receives no private
extension path, so a third-party plugin has the same capabilities. The test
`TestPLUG006MagicLinkUsesPublicAPIsOnly` proves it.
