# Deployment

Most production failures of an embedded authentication library are not
cryptographic. A browser silently drops a cookie, a deploy starts to answer
`403`, or a restart invalidates every session. This guide names each case and
its fix.

Read the [security model](security-model.md) for the threats behind these
settings.

## Decide the site relationship first

Every cookie decision follows from one question. Do the page and the API share
a registrable domain?

| Case | Example | SameSite | Cookie `Domain` |
| --- | --- | --- | --- |
| One host | `example.com` serves both | `Lax` | Leave it empty. |
| Same site, two hosts | `app.example.com` and `api.example.com` | `Lax` | `.example.com` |
| True cross-site | `app.vercel.app` and `api.example.com` | `None` plus `Secure` | Leave it empty. |

A registrable domain is the name plus its public suffix. `app.example.com` and
`api.example.com` share `example.com`, so they are the same site. `app.a.com`
and `api.b.com` do not.

## The same-site case

This is the common production setup, and it is the one to prefer.

```go
auth, err := authall.New(
    authall.WithStore(s),
    authall.WithBaseURL("https://api.example.com"),
    authall.WithTrustedOrigins("https://app.example.com"),
    authall.WithCookie(authall.CookieOptions{
        Domain:   ".example.com",
        SameSite: http.SameSiteLaxMode,
    }),
)
```

The `Domain` attribute is the part that people forget. Without it the browser
scopes the cookie to `api.example.com` alone, so `app.example.com` sends
nothing and every request looks signed out. With `.example.com` the browser
sends the cookie to both hosts.

Set `Domain` to the shared parent only. A browser rejects a `Domain` that the
sending host does not belong to, and it rejects a public suffix such as
`.com`.

## The true cross-site case

Use this only when the two hosts share no registrable domain.

```go
authall.WithCookieSameSite(http.SameSiteNoneMode),
```

Three facts apply.

- The cookie needs `SameSite=None` and `Secure`. Auth-All sets `Secure` by
  default. The pair `SameSite=None` without `Secure` fails the construction,
  because a browser refuses it.
- Both hosts need HTTPS. A plain HTTP page cannot set a `Secure` cookie.
- A browser that blocks third-party cookies still refuses the cookie. Safari
  blocks them by default, and Chrome restricts them. The person then appears
  signed out, and no server setting repairs it.

Prefer a same-site deployment. Put the API behind a path or a subdomain of the
application, for example through a reverse proxy. When that is impossible, use
the `Authorization: Bearer` header instead of the cookie. Auth-All reads the
cookie first and the header second, so a client that cannot use cookies still
works.

## Trusted origins

A state-changing request that carries an `Origin` or a `Referer` header must
name a trusted origin. Auth-All answers `403` with the code
`ORIGIN_NOT_ALLOWED` otherwise.

```go
authall.WithBaseURL("https://api.example.com"),
authall.WithTrustedOrigins("https://app.example.com", "https://admin.example.com"),
```

- The origin of `BaseURL` is always trusted. Every other browser origin needs
  an entry.
- An origin is a scheme, a host, and an optional port. It carries no path.
  Write `https://app.example.com`, not `https://app.example.com/`.
- A wildcard fails the construction. `https://*.example.com` is not valid.
- The scheme matters. `http://localhost:3000` and `https://localhost:3000` are
  two origins.
- The port matters. Add every development port that the application uses.

This is the most common cause of a `403` that appears only after a deploy. A
preview deployment of a frontend gets a new host on every build, so add the
stable production origins and handle preview hosts with a separate
configuration.

## The reverse proxy

Auth-All builds the rate-limit key from one client address. Any client can set
`X-Forwarded-For`, so Auth-All ignores that header by default and uses the
address of the direct peer.

Behind a proxy, every request then carries the address of the proxy, and one
rate-limit bucket serves every person. Declare the proxies:

```go
authall.WithTrustedProxies("10.0.0.0/8", "127.0.0.1"),
```

- Each value is a CIDR block or a single IP address. An invalid value fails the
  construction.
- Auth-All reads `X-Forwarded-For` only when a declared block holds the direct
  peer.
- The walk goes from right to left, so a hop that a client prepends never wins.

Declare the addresses that actually reach the application. Behind a managed
load balancer that is the internal subnet of the platform, not the public
address of the service.

Set `X-Forwarded-Proto` on the proxy as well. Auth-All reads it to build the
request origin for the origin check. Without it a proxy that terminates TLS
makes every request look like plain HTTP, and the origin comparison fails.

## Local development over HTTP

A browser refuses a `Secure` cookie over plain HTTP, so a local run needs the
override:

```go
insecure := false
authall.WithCookie(authall.CookieOptions{Secure: &insecure}),
```

Use it for local development only. Guard it with an environment check, so the
override cannot reach production:

```go
if os.Getenv("APP_ENV") == "development" {
    opts = append(opts, authall.WithCookie(authall.CookieOptions{Secure: &insecure}))
}
```

`localhost` is a secure context in a modern browser, so `Secure` cookies work
over `http://localhost` in Chrome and Firefox. The override stays useful for a
plain HTTP host that is not `localhost`.

## Rate limiting

Auth-All ships no production limiter. A construction with none writes one
warning. Make that failure loud instead:

```go
authall.WithRateLimiter(myRedisLimiter),
authall.WithStrictRateLimiting(),
```

`ratelimit.Memory` counts inside one process. Two application instances then
allow twice the attempts, so it does not bound a distributed deployment.

## Sessions across a restart

Auth-All stores every session in the database that the application owns, so a
restart invalidates nothing. A person stays signed in.

Two settings still end a session. The idle timeout ends a session that saw no
request, and the absolute lifetime ends it at a fixed age. The defaults are 7
days and 30 days. See the [sessions guide](sessions.md).

Run `auth.Cleanup(ctx)` from a periodic job. It removes expired sessions,
expired one-time tokens, and expired OAuth states.

## Migrations

Auth-All never migrates a schema on its own. Run the migration in the deploy
step, before the new version serves traffic:

```bash
auth-all migrate --database-url "$DATABASE_URL"
```

Call `auth.CheckSchema(ctx)` at startup. It returns an actionable error when
the schema is missing or outdated, so a broken deploy fails immediately. See
the [migrations guide](migrations-cli.md).

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| Sign-in succeeds, and the next request is signed out. | The browser stored no cookie. | Set the cookie `Domain` to the shared parent, for example `.example.com`. |
| Every request is signed out in Safari only. | Safari blocks third-party cookies, and the setup is cross-site. | Move to a same-site deployment, or use the bearer header. |
| The browser refuses the cookie over HTTP. | `Secure` is set and the page is plain HTTP. | Serve HTTPS, or set `Secure` to false for local development. |
| The construction fails with a `SameSite=None` message. | `SameSite=None` without `Secure`. | Remove the `Secure` override, or use `SameSiteLaxMode`. |
| `403 ORIGIN_NOT_ALLOWED` after a deploy. | The new frontend host is not a trusted origin. | Add the origin with `WithTrustedOrigins`. |
| `403 ORIGIN_NOT_ALLOWED` behind a TLS proxy. | The proxy sends no `X-Forwarded-Proto`. | Set the header on the proxy. |
| One person exhausts the rate limit for everybody. | Every request carries the address of the proxy. | Declare the proxy with `WithTrustedProxies`. |
| A brute-force attack runs without a bound. | No rate limiter is configured. | Set a limiter and add `WithStrictRateLimiting`. |
| A request fails with a schema error at startup. | The migration did not run. | Run `auth-all migrate` in the deploy step. |
| A magic link stops working before the person opens it. | A mail scanner pre-fetched the link. | Keep the default confirmation step. See the [magic link guide](magic-link.md). |
| A person loses their session after 7 quiet days. | The idle timeout fired. | Raise it with `WithSessionLifetime`. |
| A sign-in returns 200 with no user and no session. | The account holds a second factor. | Read `mfaRequired` and call `POST /totp/verify`. See the [two-factor guide](totp.md). |
| A code is refused right after it worked. | One code authenticates one time. | Wait for the next code. |
| A provider sign-in returns to the application signed out. | The account holds a second factor. | Read `?mfa=required` and ask for a code. |
| Every code is refused after a deploy to a second host. | The server clock drifted. | Auth-All accepts one step of skew, which is 30 seconds. Run NTP. |

## The two-factor cookie

A redirect flow that needs a second factor sets `<session cookie>.mfa`. It
follows the `Domain` and the `Secure` attribute of the session cookie, so the
same-site rules above apply to it without a separate decision.

Its `SameSite` is always `Lax`, because the provider redirects the browser to
your host from a different site. A `Strict` cookie would not survive that
redirect.

## A production checklist

- [ ] The application serves HTTPS, and `Secure` carries its default.
- [ ] The cookie `SameSite` and `Domain` match the site relationship.
- [ ] Every browser origin appears in `WithTrustedOrigins`.
- [ ] `WithTrustedProxies` names the proxies, and the proxy sets
      `X-Forwarded-Proto`.
- [ ] A distributed rate limiter is configured, and
      `WithStrictRateLimiting` is set.
- [ ] The deploy runs the migration, and startup calls `CheckSchema`.
- [ ] A periodic job calls `Cleanup`.
- [ ] The session lifetimes match the risk of the application.
- [ ] The server clock runs NTP, because a drifted clock refuses every TOTP
      code.
- [ ] The sign-up flow shows the recovery codes one time and tells the user to
      save them.
- [ ] An administrator tool can remove a second factor for a user who lost both
      the authenticator and the codes.
