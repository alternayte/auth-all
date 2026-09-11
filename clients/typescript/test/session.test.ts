import assert from "node:assert/strict"
import test from "node:test"

import { AuthAllError, createAuthClient, createSessionStore } from "../src/index.ts"

interface Reply {
  status: number
  payload: unknown
}

/** queueFetch answers each call with the next reply, and it counts the calls. */
function queueFetch(replies: Reply[]): { fetch: typeof fetch; calls: string[] } {
  const calls: string[] = []
  let index = 0
  const impl = (async (input: string | URL | Request, init?: RequestInit) => {
    calls.push(`${init?.method ?? "GET"} ${String(input)}`)
    const reply = replies[Math.min(index, replies.length - 1)]
    index++
    return new Response(JSON.stringify(reply?.payload), {
      status: reply?.status ?? 200,
      headers: { "Content-Type": "application/json" },
    })
  }) as typeof fetch
  return { fetch: impl, calls }
}

const person = {
  user: { id: "u1", email: "user@example.com", emailVerified: true, name: "User", image: "", createdAt: "", updatedAt: "" },
  session: { id: "s1", userId: "u1", createdAt: "", expiresAt: "" },
}
const visitor = { user: null, session: null }

/** settle lets every pending promise of the store run. */
const settle = () => new Promise((resolve) => setTimeout(resolve, 0))

test("the store starts empty and reads the session on demand", async () => {
  const { fetch, calls } = queueFetch([{ status: 200, payload: person }])
  const auth = createAuthClient({ baseUrl: "https://app.example.com", fetch })
  // Node is no browser, so the store reads nothing until the caller asks.
  const store = createSessionStore(auth)
  assert.equal(store.get().isPending, false)
  assert.equal(store.get().user, null)
  assert.equal(calls.length, 0)

  const state = await store.refresh()
  assert.equal(state.user?.id, "u1")
  assert.equal(state.session?.id, "s1")
  assert.equal(state.error, null)
  assert.equal(calls.length, 1)
  store.close()
})

test("a call that changes the session reads it again", async () => {
  const { fetch, calls } = queueFetch([
    { status: 200, payload: person },
    { status: 200, payload: person },
  ])
  const auth = createAuthClient({ baseUrl: "https://app.example.com", fetch })
  const store = createSessionStore(auth)

  let changes = 0
  store.subscribe(() => {
    changes++
  })

  await auth.signIn.email({ email: "user@example.com", password: "a long password" })
  await settle()

  // The sign-in and the session read, so the store holds the person with no
  // extra code in the application.
  assert.deepEqual(calls, [
    "POST https://app.example.com/api/auth/sign-in/email",
    "GET https://app.example.com/api/auth/session",
  ])
  assert.equal(store.get().user?.id, "u1")
  assert.ok(changes >= 1)
  store.close()
})

test("a read changes nothing, so it starts no second read", async () => {
  const { fetch, calls } = queueFetch([{ status: 200, payload: person }])
  const auth = createAuthClient({ baseUrl: "https://app.example.com", fetch })
  const store = createSessionStore(auth)
  await auth.getSession()
  await settle()
  assert.equal(calls.length, 1)
  store.close()
})

test("a refused read leaves no person and keeps the error", async () => {
  const { fetch } = queueFetch([
    { status: 401, payload: { error: { code: "UNAUTHORIZED", message: "Authentication is required." } } },
  ])
  const auth = createAuthClient({ baseUrl: "https://app.example.com", fetch })
  const store = createSessionStore(auth)
  const state = await store.refresh()
  assert.equal(state.user, null)
  assert.equal(state.session, null)
  assert.equal(state.isPending, false)
  assert.ok(state.error instanceof AuthAllError)
  assert.equal(state.error?.code, "UNAUTHORIZED")
  store.close()
})

test("a rendered session needs no first read", async () => {
  const { fetch, calls } = queueFetch([{ status: 200, payload: person }])
  const auth = createAuthClient({ baseUrl: "https://app.example.com", fetch })
  const store = createSessionStore(auth, { initial: person })
  assert.equal(store.get().user?.id, "u1")
  assert.equal(store.get().isPending, false)
  assert.equal(calls.length, 0)
  store.close()
})

test("set writes a session that the caller already holds", async () => {
  const { fetch, calls } = queueFetch([{ status: 200, payload: person }])
  const auth = createAuthClient({ baseUrl: "https://app.example.com", fetch })
  const store = createSessionStore(auth)
  let changes = 0
  store.subscribe(() => {
    changes++
  })
  store.set(person)
  assert.equal(store.get().user?.id, "u1")
  assert.equal(changes, 1)
  assert.equal(calls.length, 0)

  store.set(visitor)
  assert.equal(store.get().user, null)
  store.close()
})

test("a closed store reads nothing and notifies nobody", async () => {
  const { fetch, calls } = queueFetch([{ status: 200, payload: person }])
  const auth = createAuthClient({ baseUrl: "https://app.example.com", fetch })
  const store = createSessionStore(auth)
  let changes = 0
  store.subscribe(() => {
    changes++
  })
  store.close()

  await auth.signIn.email({ email: "user@example.com", password: "a long password" })
  await settle()
  // Only the sign-in ran. The store followed no change after it closed.
  assert.equal(calls.length, 1)
  assert.equal(changes, 0)
})
