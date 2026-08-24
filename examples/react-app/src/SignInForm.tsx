// A sign-in form that uses the generated Auth-All client.
import { useState } from "react"
import { AuthAllError, type User } from "@alternayte/auth-all-client"

import { auth } from "./auth.ts"

export function SignInForm({ onSignedIn }: { onSignedIn: (user: User) => void }) {
  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [error, setError] = useState<string | null>(null)
  const [pending, setPending] = useState(false)

  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setPending(true)
    setError(null)
    try {
      const result = await auth.signIn.email({ email, password })
      if (result.user) onSignedIn(result.user)
    } catch (cause) {
      // Every Auth-All error carries a stable machine-readable code.
      setError(cause instanceof AuthAllError ? cause.message : "The sign-in failed.")
    } finally {
      setPending(false)
    }
  }

  async function sendMagicLink() {
    await auth.magicLink.send({ email })
    setError(null)
  }

  return (
    <form onSubmit={submit}>
      <label>
        Email
        <input value={email} onChange={(event) => setEmail(event.target.value)} type="email" />
      </label>
      <label>
        Password
        <input value={password} onChange={(event) => setPassword(event.target.value)} type="password" />
      </label>
      {error ? <p role="alert">{error}</p> : null}
      <button type="submit" disabled={pending}>
        Sign in
      </button>
      <button type="button" onClick={sendMagicLink}>
        Send a sign-in link
      </button>
      <a href={auth.oauth.authorize("github", { redirect_to: "/" })}>Continue with GitHub</a>
      <a href={auth.oauth.authorize("google", { redirect_to: "/" })}>Continue with Google</a>
    </form>
  )
}
