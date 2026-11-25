# Example Go application

The example shows a complete Auth-All integration: SQLite, email and password
authentication with verification, GitHub and Google sign-in, Magic Link,
passkeys, the OAuth provider for an MCP endpoint, an in-memory rate limit for
development, and structured events.

## Run

```bash
go run ./cmd/auth-all migrate --driver sqlite --dsn "file:example.db"

export APP_URL=http://localhost:8080
export GITHUB_CLIENT_ID=...
export GITHUB_CLIENT_SECRET=...
export GOOGLE_CLIENT_ID=...
export GOOGLE_CLIENT_SECRET=...

go run ./examples/go-app
```

The example prints every email it must deliver, including the verification
link and the sign-in link. A production application sends the message through
its own provider.

## Try it

```bash
curl -X POST http://localhost:8080/api/auth/sign-up/email \
  -H 'Content-Type: application/json' \
  -d '{"email":"user@example.com","password":"a long password"}'
```

Open the verification link from the log. The example serves the page at
`/verify-email` and consumes the token with `auth.VerifyEmailToken`:

```bash
curl "http://localhost:8080/verify-email?token=<the token from the log>"
```

Then sign in and call `/me`:

```bash
curl -i -c cookies.txt -X POST http://localhost:8080/api/auth/sign-in/email \
  -H 'Content-Type: application/json' \
  -d '{"email":"user@example.com","password":"a long password"}'

curl -b cookies.txt http://localhost:8080/me
```

## Passkeys

Open `http://localhost:8080/passkeys` in a browser. Use `localhost`, not
`127.0.0.1`, because a passkey binds to a domain. Sign in with the password of
a verified account, register a passkey, sign out, and sign in with the passkey.

## MCP authorization

The example is the authorization server of its `/mcp` endpoint. Set `OAUTH_KEY`
to 32 random bytes in standard base64. Without it the example uses a public
development key.

```bash
export OAUTH_KEY="$(openssl rand -base64 32)"
```

A call without a token names the metadata URL:

```bash
curl -i http://localhost:8080/mcp
# HTTP/1.1 401 Unauthorized
# Www-Authenticate: Bearer resource_metadata="http://localhost:8080/.well-known/oauth-protected-resource/mcp"

curl http://localhost:8080/.well-known/oauth-protected-resource/mcp
```

An MCP client then registers with a Client ID Metadata Document or through
`/api/auth/oauth2/register`, and the authorize route sends the browser to
`/oauth`. That page signs the user in, shows the client name and host, and
posts the decision. A client with a metadata document needs a public HTTPS
host, so connect a hosted client such as Claude through a tunnel that gives the
example an HTTPS `APP_URL`.
