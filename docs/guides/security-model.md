# Security model and threat assumptions

## What the application must provide

- Transport security. Auth-All sets `Secure` cookies and expects HTTPS.
- Rate limiting in production. Auth-All exposes the integration point.
- Email delivery. Auth-All produces the intent and the token.
- Application authorization. Auth-All answers who the user is, not what the
  user may do.
- A protected database. Auth-All stores hashes, not plaintext secrets.

## Credentials

- Passwords use Argon2id. Every stored hash encodes its parameters, and a
  sign-in rehashes a password when the configured cost changed.
- A password of any supported length is accepted without truncation.
- A password never reaches a log, an error, an event, or a trace.
- The sign-in path performs the same hashing work for a known and an unknown
  address, and it returns one response for both, so the timing and the body do
  not disclose which field was wrong.

## Sessions

- The token carries 256 bits of randomness and is opaque.
- The database stores the SHA-256 hash of the token.
- Authentication issues a new token and revokes the token the request already
  carried, so session fixation fails.
- A revoked row is gone. A stale write cannot restore it.
- A password reset revokes every session of the user.

## One-time tokens

Password reset, email verification, and magic links use one-time tokens.

- The token carries 256 bits of randomness.
- The database stores the hash and an expiry.
- Consumption is one atomic statement. Two concurrent attempts produce at most
  one success.
- An expired, consumed, or malformed token produces `INVALID_TOKEN`.

## Pre-account hijacking

An attacker can sign up with the address of another person and a password of
their own choice. The address stays unverified. The attacker then waits until
the true owner proves the address.

Auth-All treats a passwordless proof of control as authoritative. A magic-link
sign-in on an address that is not verified yet runs three steps in one
transaction, and it runs them before it issues the new session.

1. Auth-All deletes the password credential of the user.
2. Auth-All revokes every session of the user.
3. Auth-All marks the address as verified.

The planted password and the planted session are therefore gone. A plugin
author reaches the same behavior through `plugin.UserService.ProveEmailOwnership`.

The steps do nothing for a user whose address is already verified. A normal
repeat sign-in keeps its password and keeps its other sessions.

The email verification endpoint applies step 2 and step 3, and it keeps the
password credential. That endpoint belongs to the password flow, so the server
cannot tell the account owner apart from the victim of a hijack. Both present
the same valid token for the same unverified account. A wipe would delete the
password that an honest user chose a moment earlier.

One risk therefore remains. A person who acts on a verification message that
they never requested proves an address for an account of somebody else, and
the password of that account survives. Two facts bound the risk. The attacker
holds no session after step 2. A victim who uses the password reset flow
replaces the credential and revokes every session, which locks the attacker
out.

## OAuth

- The authorization code flow is the only supported flow.
- Auth-All stores a hashed, single-use, short-lived state value, and it binds
  the state to the provider that created it.
- PKCE protects a provider that supports it. Google does. GitHub does not
  accept a challenge on its OAuth app endpoint.
- Auth-All always sends its own callback URL, so a provider cannot be told to
  redirect somewhere else.
- A short-lived `HttpOnly` cookie binds the pending request to the browser that
  started it. A callback from another browser is rejected, so a state value
  that an attacker obtained cannot be completed in the browser of another
  person.
- A provider link completes only when the callback request is authenticated as
  the user that started the link.
- An OpenID Connect identity token is accepted only after Auth-All validates
  the issuer, the audience, the nonce, the expiry, and the RS256 signature.

## Account linking

A matching email address alone never links an external account. Read the
[account linking guide](account-linking.md). A provider identity belongs to at
most one user, and the database enforces it.

## Browser security

- Cookies default to `HttpOnly`, `Secure`, `SameSite=Lax`, and `Path=/`.
- A state-changing request from a browser must come from a trusted origin.
  Auth-All reads `Origin`, and `Referer` when `Origin` is absent, and it
  answers `ORIGIN_NOT_ALLOWED` for any other value.
- A request without both headers comes from a client that is not a browser and
  passes the origin check. Such a client is not exposed to cross-site request
  forgery.
- A wildcard trusted origin is rejected during construction.
- A redirect target must be a relative path or a trusted origin.

## Client address

The rate limiter and the enumeration defense need one client address per
request. Any client can set the `X-Forwarded-For` header, so a key that trusts
that header is forgeable.

Auth-All therefore ignores every forwarded header by default. The key carries
the address of the direct peer.

Declare the reverse proxies of the deployment to change this:

```go
authall.WithTrustedProxies("10.0.0.0/8", "127.0.0.1")
```

- Each value is a CIDR block or a single IP address. An invalid value fails
  the construction.
- Auth-All reads `X-Forwarded-For` only when a declared block holds the direct
  peer.
- The walk goes from right to left, because a proxy appends the address that it
  saw. Auth-All returns the first address that no declared block contains, so a
  hop that the client prepends never wins.
- Auth-All returns the address of the direct peer when every hop is trusted,
  and also when a hop is malformed.
- Auth-All never returns an address that it cannot parse.

The [deployment guide](deployment.md) shows the option in a complete setup.

## User enumeration

Password reset, email verification, and magic-link requests answer the same
way for a known and an unknown address.

Sign-up must report a duplicate address, because the person needs to know that
the account exists. Protect the endpoint with a rate limit.

## Errors and observability

A public error carries a stable code and a safe message. Auth-All never
exposes SQL, a stack trace, a password hash, a session token, a one-time
token, or a provider secret. The private cause reaches the configured logger
and stays out of the response.

An event never carries a secret value.

## What Auth-All does not do

The following are outside v1: SAML, SCIM, enterprise single sign-on,
passkeys, time-based one-time passwords, API keys, organizations, roles, and
an administration interface.
