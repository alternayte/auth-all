// The public entry point of the official Auth-All TypeScript client.
//
// The client is generated from the effective Auth-All OpenAPI contract, so an
// enabled plugin operation appears here automatically.
export * from "./generated.ts"

// The session store holds the session of the current person and reads it again
// after every call that can change it. It depends on no framework. The React
// hook lives in the entry point "@alternayte/auth-all-client/react".
export * from "./session.ts"
