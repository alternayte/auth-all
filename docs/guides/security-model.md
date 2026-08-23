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

## OAuth

- The authorization code flow is the only supported flow.
- Auth-All stores a hashed, single-use, short-lived state value, and it binds
  the state to the provider that created it.
- PKCE protects a provider that supports it. Google does. GitHub does not
  accept a challenge on its OAuth app endpoint.
- Auth-All always sends its own callback URL, so a provider cannot be told to
  redirect somewhere else.
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
