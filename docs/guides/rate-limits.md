# Rate limits

Auth-All names the sensitive operations and asks a limiter for a decision. The
application chooses the limiter.

## The store-backed limiter

`ratelimit/storelimit` keeps the counters in the Auth-All database, so every
instance shares one count.

```go
limiter, err := storelimit.New(s, ratelimit.DefaultSignInRules())
if err != nil {
    return err
}
auth, err := authall.New(
    authall.WithStore(s),
    authall.WithRateLimiter(limiter),
)
```

The limiter owns the counter table, so `auth.Migrate` and the export carry the
unit `20260910000003_authall_rate_limits`.

## Rules

A rule names an operation, a scope, a limit, and a window.

```go
rules := []ratelimit.Rule{
    {Operation: ratelimit.OpSignIn, Scope: ratelimit.ScopeEmail, Limit: 5, Window: 15 * time.Minute},
    {Operation: ratelimit.OpSignIn, Scope: ratelimit.ScopeIP, Limit: 20, Window: time.Minute},
}
```

`DefaultSignInRules` returns exactly these two rules.

Every rule of the operation counts the attempt. The request fails when any rule
is over its limit. A refused request gets `429 RATE_LIMITED` and a `Retry-After`
header in whole seconds, rounded up.

## Scopes

- `ScopeIP` counts one client address. An IPv6 address counts per /64 block,
  because one customer owns a whole block. An IPv4-mapped address counts as the
  IPv4 address.
- `ScopeEmail` counts one address. The table holds the SHA-256 digest of the
  normalized address, so it holds no personal data.

## Failure behavior

The store limiter fails closed. A store error answers `500 INTERNAL`, because
the limiter uses the database that sign-in uses. A fail-open limiter would
remove the bound at the worst moment.

A v1 limiter that implements only `ratelimit.Limiter` keeps the v1 behavior. A
limiter error lets the request through, and a refusal sends `Retry-After: 60`.

## Cleanup

```go
removed, err := limiter.Cleanup(ctx, time.Now().Add(-time.Hour))
```

`Cleanup` removes the counters whose window ended. Run it from a periodic task.

## The memory limiter

`ratelimit.NewMemory` counts in process memory. Each instance then counts on
its own, so the effective limit grows with the number of instances. Use it for
local development and for tests.
