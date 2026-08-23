# Example Go application

The example shows a complete Auth-All integration: SQLite, email and password
authentication with verification, GitHub and Google sign-in, Magic Link, an
in-memory rate limit for development, and structured events.

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
