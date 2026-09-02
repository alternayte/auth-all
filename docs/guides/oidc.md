# Any OpenID Connect provider

Auth-All reaches every conformant OpenID Connect issuer with one generic
provider. Keycloak, Auth0, Okta, Entra ID, Authentik, and a self-hosted issuer
all work with the same three options.

```go
import "github.com/alternayte/auth-all/oauth/oidc"

authall.WithProvider(oidc.New(
    oidc.WithIssuer("https://id.example.com"),
    oidc.WithClientID(os.Getenv("OIDC_CLIENT_ID")),
    oidc.WithClientSecret(os.Getenv("OIDC_CLIENT_SECRET")),
))
```

Auth-All reads `https://id.example.com/.well-known/openid-configuration` to
find the endpoints. The issuer needs no other configuration.

## The provider identifier

The identifier names the routes and the rows of `auth_accounts`. It defaults to
the host of the issuer.

```text
GET /api/auth/oauth/id.example.com
GET /api/auth/oauth/id.example.com/callback
```

Set a shorter one when the route should read better:

```go
oidc.WithID("keycloak")
```

Register the redirect URI at the issuer with the identifier that you chose:

```text
https://app.example.com/api/auth/oauth/keycloak/callback
```

**Do not change the identifier of a live provider.** The account table keys on
it, so a change orphans every existing link and the affected people sign in to
a new account.

Auth-All refuses two providers that share an identifier. The construction fails
with a named error, so a clash with `google` or `github` cannot reach
production.

## When discovery is not available

An issuer that publishes no document takes its endpoints directly:

```go
oidc.New(
    oidc.WithIssuer("https://id.example.com"),
    oidc.WithEndpoints(authURL, tokenURL, jwksURL),
    oidc.WithClientID(id),
    oidc.WithClientSecret(secret),
)
```

## What Auth-All validates

Auth-All verifies the identity token on every sign-in:

| Check | Reason |
| --- | --- |
| The RS256 signature against the published key set | The token comes from the issuer. |
| `iss` | The token comes from the configured issuer. |
| `aud` | The token was issued for this application. |
| `exp`, with one minute of leeway | The token is current. |
| `nonce` | The token answers this sign-in and not an earlier one. |

Auth-All also validates the discovery document. The `issuer` field must equal
the configured issuer, and every endpoint must be HTTPS. A document that names
another issuer would send the sign-in to a server that the operator did not
choose.

A loopback host is the one exception to the HTTPS rule, because a local
development issuer cannot hold a certificate.

## The identity

`sub` keys the account and never the address. An address changes owner, and a
subject does not.

**A subject is unique inside one issuer and nowhere else.** Two issuers that
both report `subject-1` name two different people. The provider identifier is
part of the account key, so the two never meet.

Auth-All reads `email`, `email_verified`, `name`, and `picture` when the issuer
sends them. It links an existing user only for a verified address. See the
[account linking guide](account-linking.md).

## Scopes

The default scopes are `openid`, `email`, and `profile`. Replace them when the
issuer needs another set:

```go
oidc.WithScopes("openid", "email", "profile", "groups")
```

## Discovery timing

Auth-All fetches the discovery document on the first sign-in, not at startup.
An issuer that is briefly unreachable therefore does not fail the construction
of the application.

A failed fetch caches nothing, so the provider recovers with no restart once
the issuer answers again.

## Google and GitHub

[Google](google-oauth.md) is a preset over this provider, so the two share one
identity token verification. [GitHub](github-oauth.md) is not an OpenID Connect
issuer, so it keeps its own package.
