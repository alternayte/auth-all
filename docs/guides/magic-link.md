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
| GET | `/api/auth/magic-link/verify` | Return the confirmation page. |
| POST | `/api/auth/magic-link/verify` | Complete the sign-in. |

## The two-step flow

The emailed link points at the GET endpoint. That endpoint returns a small
confirmation page and does nothing else. It creates no session, and it consumes
no token. The page carries a form that posts to the same path. The POST
endpoint runs the origin check, consumes the token, and creates the session.

The step exists for three reasons.

- It stops a login cross-site request forgery. An attacker can ask for a link
  for the address of the attacker, and then make the browser of another person
  open that link. A GET that signs a person in accepts that attack. A form
  submission needs a deliberate action, and the origin check rejects a
  cross-site submission.
- It stops the loss of a link to a mail scanner. A scanner that pre-fetches the
  link receives the page and submits no form, so the one-time token survives.
- It keeps the token out of the `Referer` header of the callback host. Both
  endpoints also send `Referrer-Policy: no-referrer`, `Cache-Control:
  no-store`, and `Pragma: no-cache`.

The page carries no third-party asset and no script, so a strict content
security policy blocks nothing.

The POST endpoint answers in two ways. A form submission receives a `303`
redirect to the callback. A request with a JSON body receives status `200` and
the target in the field `redirectTo`. The generated TypeScript client uses the
JSON form through `auth.magicLink.verify({ token })`.

`magiclink.WithoutConfirmation()` lets the GET endpoint complete the sign-in on
its own. Use it only if you accept the three risks above.

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
