import assert from "node:assert/strict"
import test from "node:test"

import { AuthAllError, createAuthClient } from "../src/index.ts"

interface RecordedRequest {
  url: string
  method: string
  headers: Record<string, string>
}

function recorder(status = 200, payload: unknown = { user: null, session: null }) {
  const calls: RecordedRequest[] = []
  const fetchImpl = (async (input: string | URL | Request, init?: RequestInit) => {
    calls.push({
      url: String(input),
      method: init?.method ?? "GET",
      headers: { ...((init?.headers ?? {}) as Record<string, string>) },
    })
    return new Response(JSON.stringify(payload), {
      status,
      headers: { "Content-Type": "application/json" },
    })
  }) as typeof fetch
  return { fetch: fetchImpl, calls }
}

test("a token reaches the authorization header", async () => {
  const { fetch, calls } = recorder()
  const auth = createAuthClient({ baseUrl: "https://app.example.com", fetch, token: "ak_value" })
  await auth.getSession()
  assert.equal(calls[0]?.headers["Authorization"], "Bearer ak_value")
})

test("a token function runs before each request", async () => {
  const { fetch, calls } = recorder()
  const tokens = ["first", "second"]
  let index = 0
  const auth = createAuthClient({
    baseUrl: "https://app.example.com",
    fetch,
    token: () => tokens[index++],
  })
  await auth.getSession()
  await auth.getSession()
  assert.equal(calls[0]?.headers["Authorization"], "Bearer first")
  assert.equal(calls[1]?.headers["Authorization"], "Bearer second")
})

test("an absent token sends no authorization header", async () => {
  const { fetch, calls } = recorder()
  const auth = createAuthClient({ baseUrl: "https://app.example.com", fetch, token: () => undefined })
  await auth.getSession()
  assert.equal(calls[0]?.headers["Authorization"], undefined)
})

test("a header function serves one request of one person", async () => {
  const { fetch, calls } = recorder()
  const people = ["alice", "bob"]
  let index = 0
  const auth = createAuthClient({
    baseUrl: "https://app.example.com",
    fetch,
    headers: async () => ({ "X-Person": people[index++] ?? "" }),
  })
  await auth.getSession()
  await auth.getSession()
  assert.equal(calls[0]?.headers["X-Person"], "alice")
  assert.equal(calls[1]?.headers["X-Person"], "bob")
})

test("onRequest changes the headers of one request", async () => {
  const { fetch, calls } = recorder()
  const seen: string[] = []
  const auth = createAuthClient({
    baseUrl: "https://app.example.com",
    fetch,
    onRequest: (request) => {
      seen.push(`${request.method} ${request.url}`)
      request.headers["X-Trace"] = "trace-1"
    },
  })
  await auth.getSession()
  assert.deepEqual(seen, ["GET https://app.example.com/api/auth/session"])
  assert.equal(calls[0]?.headers["X-Trace"], "trace-1")
})

test("onError sees the failure and the request still throws", async () => {
  const { fetch } = recorder(401, { error: { code: "UNAUTHORIZED", message: "Authentication is required." } })
  const seen: AuthAllError[] = []
  const auth = createAuthClient({
    baseUrl: "https://app.example.com",
    fetch,
    onError: (error) => {
      seen.push(error)
    },
  })
  await assert.rejects(() => auth.getSession(), (error: unknown) => {
    assert.ok(error instanceof AuthAllError)
    assert.equal(error.code, "UNAUTHORIZED")
    return true
  })
  assert.equal(seen.length, 1)
  assert.equal(seen[0]?.status, 401)
})

test("onResponse sees every answer, including a failed one", async () => {
  const { fetch } = recorder(403, { error: { code: "FORBIDDEN", message: "The operation is not permitted." } })
  const statuses: number[] = []
  const auth = createAuthClient({
    baseUrl: "https://app.example.com",
    fetch,
    onResponse: (response) => {
      statuses.push(response.status)
    },
  })
  await assert.rejects(() => auth.getSession())
  assert.deepEqual(statuses, [403])
})

test("the default fetch keeps the global receiver", async () => {
  const original = globalThis.fetch
  // A browser fetch rejects a call with any other receiver. The stub holds the
  // same rule, so an unbound default fails here too.
  globalThis.fetch = function (this: unknown) {
    if (this !== globalThis) {
      throw new TypeError("Failed to execute 'fetch' on 'Window': Illegal invocation")
    }
    return Promise.resolve(
      new Response(JSON.stringify({ user: null, session: null }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    )
  } as typeof fetch
  try {
    const auth = createAuthClient({ baseUrl: "https://app.example.com" })
    await auth.getSession()
  } finally {
    globalThis.fetch = original
  }
})
