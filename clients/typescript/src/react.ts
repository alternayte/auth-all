// The React entry point of the Auth-All client.
//
// It holds one hook over the framework-agnostic session store. React is a peer
// dependency, so an application that imports no React entry point installs
// none.

import { useCallback, useDebugValue, useMemo, useSyncExternalStore } from "react"

import type { AuthAllClient } from "./generated.ts"
import { createSessionStore } from "./session.ts"
import type { SessionState, SessionStore, SessionStoreOptions } from "./session.ts"

export type { SessionState, SessionStore, SessionStoreOptions }
export { createSessionStore }

/**
 * useSession returns the session of the current person from a store.
 *
 * The store reads the session again after every call that can change it, so a
 * sign-in and a sign-out reach every component with no extra code.
 *
 *     const session = createSessionStore(auth)
 *
 *     function Header() {
 *       const { user, isPending } = useSession(session)
 *       if (isPending) return <Spinner />
 *       return user ? <Account user={user} /> : <SignInLink />
 *     }
 *
 * The server snapshot is the current state, so a rendered page shows the
 * session that the server passed in SessionStoreOptions.initial.
 */
export function useSession(store: SessionStore): SessionState {
  const subscribe = useCallback((listener: () => void) => store.subscribe(listener), [store])
  const snapshot = useCallback(() => store.get(), [store])
  const state = useSyncExternalStore(subscribe, snapshot, snapshot)
  useDebugValue(state.user ? state.user.email : "no session")
  return state
}

/**
 * useSessionStore returns a store for one client. The store lives as long as
 * the component, so a component that owns the client uses it instead of a
 * store of the module.
 */
export function useSessionStore(
  client: AuthAllClient,
  options: SessionStoreOptions = {},
): SessionStore {
  // The options of the first render configure the store. A later change of the
  // object identity must not build a second store.
  return useMemo(() => createSessionStore(client, options), [client])
}
