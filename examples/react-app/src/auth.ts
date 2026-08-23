// The shared Auth-All client of the example React application.
import { createAuthClient } from "@auth-all/client"

export const auth = createAuthClient({
  // The API and the application share an origin in this example, so the client
  // sends the session cookie with every request.
  baseUrl: window.location.origin,
})
