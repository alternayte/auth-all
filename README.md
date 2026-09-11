# Auth-All

Auth-All is an authentication framework that runs inside a Go application.

It provides the capabilities a developer normally assembles from several
libraries: users, accounts, database-backed sessions, email and password
authentication, email verification, password reset, TOTP two-factor
authentication, magic links, OAuth and OpenID Connect, account linking, roles,
API keys, user administration, rate limits, audit events, plugins, schema
tooling, an OpenAPI contract, and a generated TypeScript client.

Auth-All is not an identity server. The application keeps its database, its
HTTP server, and its user interface.

## Install

Auth-All needs Go 1.25 or newer.

```bash
go get github.com/alternayte/auth-all
```

Auth-All pulls no database driver that the application does not use. An
application that imports `store/postgres` gets `pgx` and no SQLite, and the
reverse holds too.

The TypeScript client is a separate npm package:

```bash
npm install @alternayte/auth-all-client
```

The operator tool is available as a prebuilt binary on the
[releases page](https://github.com/alternayte/auth-all/releases). A Go user can
also install it directly:

```bash
go install github.com/alternayte/auth-all/cmd/auth-all@latest
```

## Use

```go
auth, err := authall.New(
    authall.WithStore(postgres.New(db)),
    authall.WithBaseURL("https://app.example.com"),
    authall.WithEmailPassword(),
    authall.WithEmailSender(sender),
    authall.WithProvider(
        github.New(
            github.WithClientID(clientID),
            github.WithClientSecret(clientSecret),
        ),
    ),
    authall.WithPlugins(
        magiclink.New(),
    ),
)
if err != nil {
    log.Fatal(err)
}

mux.Handle("/api/auth/", auth.Handler())
```

Authorization, machine access, and administration are opt-in plugins:

```go
r := roles.New(roles.Hierarchy("viewer", "operator", "editor", "admin"))
adm := admin.New(admin.AdminRole("admin"))

auth, err := authall.New(
    authall.WithStore(postgres.New(db)),
    authall.WithBaseURL("https://app.example.com"),
    authall.WithEmailPassword(),
    authall.WithPlugins(r, adm, apikeys.New()),
)

// A route asks for a minimum role. A session and an API key both pass it.
mux.Handle("/deploy", r.Require("operator", deployHandler))

// The first administrator comes from the application, and never from a start.
created, err := adm.Bootstrap(ctx, admin.Credentials{Email: e, Password: p})
```

Create the tables one time before the first start:

```bash
go run github.com/alternayte/auth-all/cmd/auth-all migrate \
    --driver postgres --dsn "$DATABASE_URL"
```

## Properties

- `net/http` native and framework agnostic. It also serves under a router that
  removes the base path, and it merges into a huma OpenAPI document.
- The application owns the database. PostgreSQL and SQLite are supported. The
  PostgreSQL store runs over a `database/sql` handle or over a `pgxpool.Pool`,
  and it is safe behind a transaction pooler.
- Secure defaults. Opaque session tokens, hashed tokens at rest, Argon2id
  password hashing, OAuth state validation, PKCE where the provider supports
  it, and conservative account linking.
- TOTP two-factor authentication with recovery codes. One code authenticates
  one time. The gate covers the password, the magic link, and the OAuth
  callback.
- Authorization through an ordered role hierarchy. A route asks for a minimum
  role. A role that the configuration does not name ranks below every role.
- Organizations with fine-grained permissions. A person belongs to many
  organizations, a membership carries a role, and a route asks for a
  permission of the form `resource:action`. The check runs in the process and
  needs no round trip.
- Machine access through API keys. One key carries 32 random bytes, the store
  keeps the digest, and the current owner role always caps the key role.
- User administration with a temporary password, a disable that revokes every
  session, and a guard that keeps one enabled administrator.
- A rate limiter that counts in the database, so every instance shares one
  count. A refused request answers 429 with `Retry-After`.
- Audit events that name the actor, the target, the client address, and the
  authentication method. No event carries a secret.
- Cross-site protection for the application routes of a cookie request.
- Plugins are first class. Every official plugin uses the same public plugin
  API that a third-party plugin uses.
- One OpenAPI contract produces the official TypeScript client.

## What the application controls

- The table prefix, `uuid` primary keys, and host-owned columns on the users
  table.
- The migration files. Auth-All exports ordered units for goose or for any
  other tool, and it never runs a migration on its own.
- The public error envelope, the cookie attributes, and the Argon2id cost.
- The consistency bound. With no cache every request reads the store, so a
  disable, a role change, and a key revocation take effect at once.

## Documentation

| Guide | Content |
| --- | --- |
| [Getting started](docs/guides/getting-started.md) | The first integration, step by step. |
| [Email and password](docs/guides/email-password.md) | Sign-up, sign-in, verification, and reset. |
| [Sessions](docs/guides/sessions.md) | Session storage, cookies, and revocation. |
| [Two-factor authentication](docs/guides/totp.md) | TOTP enrolment and sign-in. |
| [Magic Link](docs/guides/magic-link.md) | The official sign-in link plugin. |
| [GitHub OAuth](docs/guides/github-oauth.md) | GitHub sign-in. |
| [Any OpenID Connect provider](docs/guides/oidc.md) | Keycloak, Auth0, Okta, Entra ID, and any conformant issuer. |
| [Google OAuth](docs/guides/google-oauth.md) | Google sign-in. |
| [Account management](docs/guides/account-management.md) | Password change, address change, and account delete. |
| [Account linking](docs/guides/account-linking.md) | The linking policy and its threats. |
| [Roles](docs/guides/roles.md) | The role hierarchy and the route checks. |
| [API keys](docs/guides/api-keys.md) | Machine credentials and their limits. |
| [Organizations](docs/guides/organizations.md) | Organizations, members, and the active organization. |
| [Permissions](docs/guides/permissions.md) | The statements, the roles, the custom roles, and the teams. |
| [Invitations](docs/guides/invitations.md) | The invitation token, the acceptance, and the message. |
| [External policy](docs/guides/external-policy.md) | The per-object boundary and the ObjectChecker seam. |
| [User administration](docs/guides/admin.md) | The administrative routes and the operator methods. |
| [Bootstrap](docs/guides/bootstrap.md) | The first administrator and the CLI user commands. |
| [Rate limits](docs/guides/rate-limits.md) | The rules and the store-backed limiter. |
| [PostgreSQL](docs/guides/postgresql.md) | The PostgreSQL adapter. |
| [SQLite](docs/guides/sqlite.md) | The SQLite adapter. |
| [Migrations and the CLI](docs/guides/migrations-cli.md) | Schema operations. |
| [Host-owned migrations](docs/guides/host-migrations.md) | The exported units, the table prefix, and the user fields. |
| [huma](docs/guides/huma.md) | The adapter for a huma OpenAPI application. |
| [Plugin authors](docs/guides/plugin-authors.md) | The public extension surface. |
| [TypeScript client](docs/guides/typescript-client.md) | The generated client. |
| [Deployment](docs/guides/deployment.md) | Cookies, origins, proxies, and a troubleshooting table. |
| [Security model](docs/guides/security-model.md) | Threat assumptions and defenses. |

Two official examples show a complete integration:

- [Go application](examples/go-app)
- [React application](examples/react-app)

## Development

The repository exposes one command:

```bash
just verify
```

It formats, analyses, tests, starts the PostgreSQL test container, runs the
race detector, checks the generated artifacts, tests the TypeScript client,
builds the examples, and writes `artifacts/verification.md`.

## License

MIT. See [LICENSE](LICENSE).
