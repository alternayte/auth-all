import assert from "node:assert/strict"
import test from "node:test"

import { AuthAllError, createAuthClient } from "../src/index.ts"

interface RecordedRequest {
  url: string
  method: string
  body: unknown
  headers: Record<string, string>
  credentials: RequestCredentials | undefined
}

function stubFetch(status: number, payload: unknown): { fetch: typeof fetch; calls: RecordedRequest[] } {
  const calls: RecordedRequest[] = []
  const impl = (async (input: string | URL | Request, init?: RequestInit) => {
    calls.push({
      url: String(input),
      method: init?.method ?? "GET",
      body: init?.body === undefined ? undefined : JSON.parse(String(init.body)),
      headers: (init?.headers ?? {}) as Record<string, string>,
      credentials: init?.credentials,
    })
    return new Response(JSON.stringify(payload), {
      status,
      headers: { "Content-Type": "application/json" },
    })
  }) as typeof fetch
  return { fetch: impl, calls }
}

test("signIn.email posts the credentials to the sign-in endpoint", async () => {
  const { fetch, calls } = stubFetch(200, {
    user: { id: "u1", email: "user@example.com", emailVerified: true, name: "User", image: "", createdAt: "", updatedAt: "" },
    session: { id: "s1", userId: "u1", createdAt: "", expiresAt: "" },
  })
  const auth = createAuthClient({ baseUrl: "https://app.example.com", fetch })
  const result = await auth.signIn.email({ email: "user@example.com", password: "a long password" })

  assert.equal(calls.length, 1)
  assert.equal(calls[0]?.url, "https://app.example.com/api/auth/sign-in/email")
  assert.equal(calls[0]?.method, "POST")
  assert.equal(calls[0]?.credentials, "include")
  assert.deepEqual(calls[0]?.body, { email: "user@example.com", password: "a long password" })
  assert.equal(result.user?.id, "u1")
  assert.equal(result.session?.id, "s1")
})

test("getSession reads the current session", async () => {
  const { fetch, calls } = stubFetch(200, { user: null, session: null })
  const auth = createAuthClient({ baseUrl: "https://app.example.com", fetch })
  const result = await auth.getSession()

  assert.equal(calls[0]?.url, "https://app.example.com/api/auth/session")
  assert.equal(calls[0]?.method, "GET")
  assert.equal(result.user, null)
})

test("magicLink.send reaches the plugin operation", async () => {
  const { fetch, calls } = stubFetch(200, { message: "If the address can receive a sign-in link, one has been sent." })
  const auth = createAuthClient({ baseUrl: "https://app.example.com", fetch })
  const result = await auth.magicLink.send({ email: "user@example.com" })

  assert.equal(calls[0]?.url, "https://app.example.com/api/auth/magic-link/send")
  assert.match(result.message, /sign-in link/)
})

test("oauth.authorize builds a redirect URL instead of fetching", () => {
  const { fetch, calls } = stubFetch(200, {})
  const auth = createAuthClient({ baseUrl: "https://app.example.com", fetch })
  const url = auth.oauth.authorize("github", { redirect_to: "/dashboard" })

  assert.equal(url, "https://app.example.com/api/auth/oauth/github?redirect_to=%2Fdashboard")
  assert.equal(calls.length, 0)
})

test("account.link uses the provider path parameter", async () => {
  const { fetch, calls } = stubFetch(200, { url: "https://github.com/login/oauth/authorize" })
  const auth = createAuthClient({ baseUrl: "https://app.example.com", fetch })
  await auth.account.link("google")

  assert.equal(calls[0]?.url, "https://app.example.com/api/auth/account/link/google")
})

test("an Auth-All error keeps its stable code", async () => {
  const { fetch } = stubFetch(401, { error: { code: "INVALID_CREDENTIALS", message: "Invalid email or password." } })
  const auth = createAuthClient({ baseUrl: "https://app.example.com", fetch })

  await assert.rejects(
    () => auth.signIn.email({ email: "user@example.com", password: "wrong password" }),
    (error: unknown) => {
      assert.ok(error instanceof AuthAllError)
      assert.equal(error.code, "INVALID_CREDENTIALS")
      assert.equal(error.status, 401)
      assert.equal(error.message, "Invalid email or password.")
      return true
    },
  )
})

test("the client sends extra headers", async () => {
  const { fetch, calls } = stubFetch(200, { success: true })
  const auth = createAuthClient({
    baseUrl: "https://app.example.com/",
    fetch,
    headers: { "X-Request-Id": "abc" },
  })
  await auth.signOut()

  assert.equal(auth.baseUrl, "https://app.example.com")
  assert.equal(calls[0]?.headers["X-Request-Id"], "abc")
})
