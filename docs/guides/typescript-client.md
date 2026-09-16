# TypeScript client

The official client is generated from the effective Auth-All OpenAPI contract.
An enabled plugin operation appears in the client automatically.

## Install

```bash
npm install @alternayte/auth-all-client
```

The client version follows the version of the Go library. Install the client
version that matches the library version of the server.

## Use

```ts
import { createAuthClient, AuthAllError } from "@alternayte/auth-all-client"

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
| `baseUrl` | The origin of the application, and never the Auth-All base path. Every generated method already carries the base path, so `https://app.example.com` is right and `https://app.example.com/api/auth` produces a 404. The page origin is the default. |
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

## The session of the current person

The client holds one session store. The store reads the session again after
every call that can change it, so a sign-in, a sign-out, and an organization
switch all reach the user interface with no extra code.

```ts
import { createAuthClient, createSessionStore } from "@alternayte/auth-all-client"

const auth = createAuthClient({ baseUrl: "https://app.example.com" })
const session = createSessionStore(auth)

session.subscribe(() => {
  const { user, isPending } = session.get()
  render(user, isPending)
})
```

The state holds `user`, `session`, `isPending`, and `error`. `isPending` is
true for the first read only, so a later refresh shows no loading state to a
person who is already signed in.

- `session.refresh()` reads the session again.
- `session.set(result)` writes a session that the caller already holds, for
  example the answer of a sign-in. It saves one round trip.
- `session.close()` stops the listeners.

In a browser the store reads the session at creation, and it reads it again
when the window takes the focus, so a sign-out in another tab reaches this tab.
`fetchOnCreate` and `refreshOnFocus` turn the two rules off.

### React

```tsx
import { createAuthClient } from "@alternayte/auth-all-client"
import { createSessionStore, useSession } from "@alternayte/auth-all-client/react"

const auth = createAuthClient({ baseUrl: "https://app.example.com" })
const session = createSessionStore(auth)

export function Header() {
  const { user, isPending } = useSession(session)
  if (isPending) return <Spinner />
  return user ? <Account user={user} /> : <SignInLink />
}
```

React is a peer dependency, and it is optional. An application that imports no
React entry point installs none.

On a server that renders the page, read the session once and pass it to the
store, so the first paint shows no loading state:

```ts
const initial = await auth.getSession()
const session = createSessionStore(auth, { initial, fetchOnCreate: false })
```

## A bearer token and a server that serves many people

A browser sends the session cookie, and it needs no token. A mobile
application and a server that calls Auth-All for one person send the token of
that person instead:

```ts
const auth = createAuthClient({
  baseUrl: "https://app.example.com",
  // A function runs before each request, so a refreshed token reaches the
  // next call.
  token: () => store.readToken(),
})
```

`authall.SignIn` returns the plaintext session token, so a host route that
serves a mobile application answers with it. See the Go API of the email and
password guide.

`headers` accepts a function as well, so a server that serves many people
builds the header of the current request.

## Hooks

```ts
const auth = createAuthClient({
  baseUrl: "https://app.example.com",
  onRequest: (request) => {
    request.headers["X-Request-Id"] = newRequestID()
  },
  onError: (error) => {
    if (error.code === "UNAUTHORIZED") {
      window.location.href = "/sign-in"
    }
  },
})
```

`onRequest` runs before each request, and it can change the headers.
`onResponse` runs after every answer, including a failed one. `onError` runs
when a request fails, and the call still throws `AuthAllError`.

## Regeneration

```bash
just generate
```

The command rewrites `api/openapi.json` and
`clients/typescript/src/generated.ts`. `just verify` fails when a generated
file is stale.

### The client of one application

The published package describes the reference configuration. An application
that adds host-owned columns with `authall.WithUserFields` or
`authall.WithOrganizationFields`, or that enables a plugin of its own, holds
another contract. Such an application generates its own client from its own
instance:

A small program of the application writes the contract of its own instance:

```go
auth, err := authall.New(options...)
if err != nil {
    log.Fatal(err)
}
document, err := json.MarshalIndent(auth.OpenAPI(), "", "  ")
if err != nil {
    log.Fatal(err)
}
if err := os.WriteFile("openapi.json", document, 0o644); err != nil {
    log.Fatal(err)
}
```

The command line tool then turns that contract into a client:

```bash
auth-all client --openapi openapi.json --out src/auth-client.ts
```

The generated types name the host columns, so the application reads them with
no cast. Run the two steps in the build of the application, so the client never
drifts from the server.
