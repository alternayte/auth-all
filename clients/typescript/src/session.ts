// The session store of the Auth-All client.
//
// The store holds the session of the current person, and it reads it again
// after every call that can change it. It depends on no framework, and it
// follows the subscribe and snapshot shape that React, Vue, Svelte, and Solid
// all accept.

import type { AuthAllClient, Session, SessionResponse, User } from "./generated.ts"
import { AuthAllError } from "./generated.ts"

/** The state of the session store. */
export interface SessionState {
  /** user is the signed-in person. It is null for a visitor. */
  user: User | null
  /** session is the session row of the person. It is null for a visitor. */
  session: Session | null
  /**
   * isPending reports that the first read is still open. It is false for
   * every later read, so a refresh shows no loading state to a person who is
   * already signed in.
   */
  isPending: boolean
  /** error holds the failure of the last read. */
  error: AuthAllError | null
}

/** Options for the session store. */
export interface SessionStoreOptions {
  /**
   * fetchOnCreate reads the session when the store is created. The default is
   * true in a browser. A server renders one request, so it passes false and
   * calls refresh itself.
   */
  fetchOnCreate?: boolean
  /**
   * refreshOnFocus reads the session again when the window takes the focus,
   * so a sign-out in another tab reaches this tab. The default is true in a
   * browser.
   */
  refreshOnFocus?: boolean
  /**
   * initial seeds the store with a session that the server rendered, so the
   * first paint shows no loading state.
   */
  initial?: SessionResponse
}

/** The session store. */
export interface SessionStore {
  /** get returns the current state. */
  get(): SessionState
  /**
   * subscribe registers a listener that runs on every change. It returns the
   * function that removes the listener.
   */
  subscribe(listener: () => void): () => void
  /** refresh reads the session again. */
  refresh(): Promise<SessionState>
  /**
   * set writes a session that the caller already holds, for example the
   * result of a sign-in. It saves one round trip.
   */
  set(value: SessionResponse | null): void
  /** close stops the listeners of the store. */
  close(): void
}

/** inBrowser reports whether the code runs in a browser. */
function inBrowser(): boolean {
  return typeof window !== "undefined" && typeof document !== "undefined"
}

/**
 * createSessionStore returns a store that holds the session of the current
 * person.
 *
 * The store reads the session again after every call of the client that can
 * change it, so a sign-in, a sign-out, and an organization switch all reach
 * the user interface with no extra code.
 *
 *     const auth = createAuthClient({ baseUrl: "https://app.example.com" })
 *     const session = createSessionStore(auth)
 *     session.subscribe(() => render(session.get()))
 */
export function createSessionStore(
  client: AuthAllClient,
  options: SessionStoreOptions = {},
): SessionStore {
  const browser = inBrowser()
  const listeners = new Set<() => void>()
  let state: SessionState = {
    user: options.initial?.user ?? null,
    session: options.initial?.session ?? null,
    isPending: options.initial === undefined && (options.fetchOnCreate ?? browser),
    error: null,
  }
  // A later answer of an earlier read must never replace a newer one.
  let latest = 0
  let closed = false

  const emit = () => {
    for (const listener of listeners) listener()
  }

  const write = (next: SessionState) => {
    state = next
    emit()
  }

  const refresh = async (): Promise<SessionState> => {
    const run = ++latest
    try {
      const out = await client.getSession()
      if (run !== latest || closed) return state
      write({ user: out.user ?? null, session: out.session ?? null, isPending: false, error: null })
    } catch (cause) {
      if (run !== latest || closed) return state
      const error = cause instanceof AuthAllError
        ? cause
        : new AuthAllError("INTERNAL", "The session read failed.", 0)
      // A refused read means that no session exists, so the store holds no
      // person. Every other failure keeps the error for the caller.
      write({ user: null, session: null, isPending: false, error })
    }
    return state
  }

  const removeChange = client.onChange(() => {
    void refresh()
  })

  let removeFocus = () => {}
  if (browser && (options.refreshOnFocus ?? true)) {
    const onFocus = () => {
      if (document.visibilityState === "visible") void refresh()
    }
    document.addEventListener("visibilitychange", onFocus)
    removeFocus = () => document.removeEventListener("visibilitychange", onFocus)
  }

  if (options.initial === undefined && (options.fetchOnCreate ?? browser)) {
    void refresh()
  }

  return {
    get: () => state,
    subscribe(listener) {
      listeners.add(listener)
      return () => listeners.delete(listener)
    },
    refresh,
    set(value) {
      // A caller that already holds the session skips the read, so the answer
      // of a running read must not replace it.
      latest++
      write({
        user: value?.user ?? null,
        session: value?.session ?? null,
        isPending: false,
        error: null,
      })
    },
    close() {
      closed = true
      removeChange()
      removeFocus()
      listeners.clear()
    },
  }
}
