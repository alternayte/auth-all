# Auth-All

Auth-All is an authentication framework that runs inside a Go application.

It provides the capabilities a developer normally assembles from several
libraries: users, accounts, database-backed sessions, email and password
authentication, email verification, password reset, magic links, OAuth,
account linking, plugins, schema tooling, an OpenAPI contract, and a generated
TypeScript client.

Auth-All is not an identity server. The application keeps its database, its
HTTP server, and its user interface.

## Install

```bash
go get github.com/alternayte/auth-all
```

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

Create the tables one time before the first start:

```bash
go run github.com/alternayte/auth-all/cmd/auth-all migrate \
    --driver postgres --dsn "$DATABASE_URL"
```

## Properties

- `net/http` native and framework agnostic.
- The application owns the database. PostgreSQL and SQLite are supported.
- Secure defaults. Opaque session tokens, hashed tokens at rest, Argon2id
  password hashing, OAuth state validation, PKCE where the provider supports
  it, and conservative account linking.
- Plugins are first class. The official Magic Link plugin uses the same public
  plugin API that a third-party plugin uses.
- One OpenAPI contract produces the official TypeScript client.

## Documentation

| Guide | Content |
| --- | --- |
| [Getting started](docs/guides/getting-started.md) | The first integration, step by step. |
| [Email and password](docs/guides/email-password.md) | Sign-up, sign-in, verification, and reset. |
| [Sessions](docs/guides/sessions.md) | Session storage, cookies, and revocation. |
| [Magic Link](docs/guides/magic-link.md) | The official sign-in link plugin. |
| [GitHub OAuth](docs/guides/github-oauth.md) | GitHub sign-in. |
| [Google OAuth](docs/guides/google-oauth.md) | Google sign-in. |
| [Account management](docs/guides/account-management.md) | Password change, address change, and account delete. |
| [Account linking](docs/guides/account-linking.md) | The linking policy and its threats. |
| [PostgreSQL](docs/guides/postgresql.md) | The PostgreSQL adapter. |
| [SQLite](docs/guides/sqlite.md) | The SQLite adapter. |
| [Migrations and the CLI](docs/guides/migrations-cli.md) | Schema operations. |
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
builds the examples, and writes `artifacts/v1-verification.md`.

## License

MIT. See [LICENSE](LICENSE).
