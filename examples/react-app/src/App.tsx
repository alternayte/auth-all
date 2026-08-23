// The example application shell. It reads the session on the first render and
// shows either the sign-in form or the signed-in user.
import { useEffect, useState } from "react"
import type { User } from "@auth-all/client"

import { auth } from "./auth.ts"
import { SignInForm } from "./SignInForm.tsx"

export function App() {
  const [user, setUser] = useState<User | null>(null)
  const [loaded, setLoaded] = useState(false)

  useEffect(() => {
    auth
      .getSession()
      .then((result) => setUser(result.user))
      .finally(() => setLoaded(true))
  }, [])

  if (!loaded) return <p>Loading</p>
  if (!user) return <SignInForm onSignedIn={setUser} />

  return (
    <main>
      <h1>Welcome {user.name || user.email}</h1>
      <button
        onClick={async () => {
          await auth.signOut()
          setUser(null)
        }}
      >
        Sign out
      </button>
    </main>
  )
}
