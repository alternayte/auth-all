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
- A session ends at the first of two deadlines. The idle timeout runs from the
  last request, and the absolute lifetime runs from the creation. The defaults
  are 7 days and 30 days, so a stolen token that stays active still expires.
- A password reset revokes every session of the user.
- A password change and an email change revoke every session except the current
  one.
- A person can list and revoke their own sessions. No response carries a token
  or a token hash. A revoke of a session that another user owns answers `404`.

## One-time tokens

Password reset, email verification, magic links, an email change, and an
account delete use one-time tokens.

- The token carries 256 bits of randomness.
- The database stores the hash and an expiry.
- Consumption is one atomic statement. Two concurrent attempts produce at most
  one success.
- An expired, consumed, or malformed token produces `INVALID_TOKEN`.
- A magic link needs a confirmation step. `GET /magic-link/verify` returns a
  page and consumes nothing, so a mail scanner that pre-fetches the link
  destroys no token and signs nobody in. `POST /magic-link/verify` runs the
  origin check and creates the session, so a login cross-site request forgery
  fails. Both routes send `Referrer-Policy: no-referrer`, so the token in the
  query string stays out of the callback host.

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
- PKCE protects a provider that supports it. Every OpenID Connect provider
  does, and Google is one of them. GitHub does not accept a challenge on its
  OAuth app endpoint.
- Auth-All always sends its own callback URL, so a provider cannot be told to
  redirect somewhere else.
- A short-lived `HttpOnly` cookie binds the pending request to the browser that
  started it. A callback from another browser is rejected, so a state value
  that an attacker obtained cannot be completed in the browser of another
  person.

## OpenID Connect

- Auth-All verifies the RS256 signature of every identity token against the
  published key set of the issuer, and it checks `iss`, `aud`, `exp`, and
  `nonce`.
- The discovery document must name the configured issuer, and every endpoint
  it names must be HTTPS. A loopback host is the one exception, because a local
  development issuer cannot hold a certificate. The document is
  attacker-controlled input the moment the issuer is misconfigured.
- `sub` keys the account and never the address.
- A subject is unique inside one issuer and nowhere else, so the provider
  identifier is part of the account key. Two issuers that report one subject
  name two people, and they reach two accounts.
- Auth-All refuses two providers that share an identifier, so a generic
  provider cannot take over the accounts of a preset.
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
- A redirect target must be a relative path or a trusted origin. Auth-All
  checks the literal form and the percent-decoded form, and it rejects a
  backslash, a control character, a scheme-relative reference, and user
  information.
- A handler derives the subject of an operation from the session or from a
  consumed one-time token, and never from the request body. A contract test
  enumerates every mounted route that changes state and enforces the rule.

## Rate limiting

Auth-All exposes the integration point and ships no production limiter. The
application must supply one.

- A construction with no limiter writes one warning on the configured logger.
  The warning names the risk and the two options.
- `authall.WithStrictRateLimiting()` turns that warning into a construction
  error. Use it in production, so a deploy with no limiter fails fast.
- `ratelimit.Memory` counts inside one process. It serves a local run and a
  test. It does not bound a distributed deployment, because each process keeps
  its own counters.

```go
authall.WithRateLimiter(myRedisLimiter),
authall.WithStrictRateLimiting(),
```

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

Password reset, email verification, magic-link requests, and email change
requests answer the same way for a known and an unknown address. The email
change stops before the send for a taken address, so the owner of that address
receives nothing.

Sign-up must report a duplicate address, because the person needs to know that
the account exists. Protect the endpoint with a rate limit.

## Errors and observability

A public error carries a stable code and a safe message. Auth-All never
exposes SQL, a stack trace, a password hash, a session token, a one-time
token, or a provider secret. The private cause reaches the configured logger
and stays out of the response.

An event never carries a secret value.

## The second factor

A user who confirms a TOTP enrolment holds a second factor. See the
[two-factor guide](totp.md).

Auth-All records the time step of every accepted code and refuses a step that
is not greater than the stored one. One code authenticates one time, so a code
that an attacker reads from a shoulder or from a phishing page is worthless
after the user spends it.

The database performs that comparison and the write as one operation. An
attacker who sends one stolen code over many parallel requests therefore wins
at most one of them.

A password sign-in of an enrolled user writes no session and sets no session
cookie. It returns a five-minute single-use challenge instead, and only
`POST /totp/verify` creates the session. No half-authenticated session cookie
exists at any point.

The challenge is consumed before the code is checked, so a wrong code costs the
whole challenge. A stolen password buys no unlimited guessing window against
the second factor.

The magic link and the OAuth callback apply the same gate. A redirect flow
carries the challenge in a short-lived HttpOnly cookie, never in a query
parameter, because a URL reaches the browser history, the server log, and any
leaked Referer header.

`POST /totp/disable` needs a current code. A stolen session alone cannot remove
the factor that protects the session.

The confirmation revokes every other session of the user. A person who turns on
a second factor often suspects a compromise, so a session that existed before
the upgrade does not survive it.

`INVALID_TOTP_CODE` names no reason, so a wrong code and a replayed code look
equal.

The three endpoints run under the rate-limit operation `totp`, keyed by user. A
six-digit code has one million values, and the accepted window offers three of
them. An unlimited endpoint is guessable, so a limiter is mandatory in
production.

Auth-All stores the base32 secret in plaintext. Auth-All holds no application
key, and a key that the library invents lives in the same database as the
secret. An attacker who reads `auth_totp` can generate codes, so protect that
table like `auth_credentials`. Apply encryption at the column or at the volume
when you need it.

Auth-All issues ten recovery codes at the confirmation. A code signs the user in
one time and then removes the second factor, so a person who lost their
authenticator is not left with a factor that they cannot satisfy. The recovery
also removes every remaining code, so a leaked list is worthless afterwards.

A recovery code is a first factor and a second factor at the same time. The
store keeps only the SHA-256 hash, so a leaked database row is not a sign-in.
The hash is fast on purpose: a recovery code carries about 49 bits from a random
source, so it needs no slow password hash, and ten slow verifications per attempt
would give an attacker a cheap denial of service.

`POST /totp/recovery` names the user through the challenge token and the
statement, so a code of one user never authenticates another user. The match and
the removal are one operation, so one code signs in one time.

A user who loses the authenticator and the codes still needs an administrator.

## What Auth-All does not do

The following are outside v1: SAML, SCIM, enterprise single sign-on, passkeys,
API keys, organizations, roles, and an administration interface.
