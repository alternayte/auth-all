# TypeScript client

The official client is generated from the effective Auth-All OpenAPI contract.
An enabled plugin operation appears in the client automatically.

## Install

```bash
npm install @auth-all/client
```

The client version follows the version of the Go library. Install the client
version that matches the library version of the server.

## Use

```ts
import { createAuthClient, AuthAllError } from "@auth-all/client"

const auth = createAuthClient({
  baseUrl: window.location.origin,
})

await auth.signUp.email({ email, password, name })
await auth.signIn.email({ email, password })

const session = await auth.getSession()
if (session.user) {
  console.log(session.user.email)
}

await auth.magicLink.send({ email })
await auth.signOut()
```

## Options

| Option | Purpose |
| --- | --- |
| `baseUrl` | The origin of the application. The page origin is the default. |
| `fetch` | The fetch implementation. The global fetch is the default. |
| `credentials` | The credentials mode. `include` is the default, so the session cookie travels. |
| `headers` | Extra headers for every request. |

## Errors

A failed request throws `AuthAllError` with the stable code of the API:

```ts
try {
  await auth.signIn.email({ email, password })
} catch (error) {
  if (error instanceof AuthAllError && error.code === "INVALID_CREDENTIALS") {
    setMessage("Invalid email or password.")
  }
}
```

## Redirect operations

An operation that the browser must follow returns a URL instead of a promise:

```ts
location.href = auth.oauth.authorize("github", { redirect_to: "/dashboard" })
```

## Cross-origin applications

A browser application on another origin needs two settings:

- `authall.WithTrustedOrigins("https://app.example.com")` on the server,
- `credentials: "include"` in the client, which is the default.

Auth-All rejects a state-changing request from an origin that is not trusted
and answers `ORIGIN_NOT_ALLOWED`. A credentialed wildcard origin is never
allowed.

## Regeneration

```bash
just generate
```

The command rewrites `api/openapi.json` and
`clients/typescript/src/generated.ts`. `just verify` fails when a generated
file is stale.
