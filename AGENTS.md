# AGENTS.md

## What this is

Auth-All is a Go authentication framework that a host application imports as a
library and mounts into its own HTTP server. It ships a generated TypeScript
client, an OpenAPI contract, an operator binary, and a separate huma adapter
module.

## Run

- `go run ./examples/go-app` runs the example host application.
- `go run ./cmd/auth-all` runs the operator tool. It emits the schema, the
  migrations, the OpenAPI contract, and the TypeScript client.
- `just generate` rewrites `api/openapi.json` and
  `clients/typescript/src/generated.ts`. Run it after any change to a route or
  an operation.
- `just db-up` starts the test databases. `just db-down` stops them.

## Test

- `just verify` is the gate. It runs every required check and starts the
  databases it needs.
- `just --list` shows the single checks. Each one records its result in
  `artifacts/checks.tsv`.
- A test name carries the specification scenario it covers, and the justfile
  selects a suite by a regular expression over those names. A new test either
  matches an existing prefix or the justfile gains the prefix.
- `internal/testsupport` holds the harness, the fake sender, the fake OAuth
  provider, and the database helpers. Use it instead of a new fixture.
- `store/storetest` holds the storage contract. Both adapters run it.

## Stack rules

- The module is a library. It builds no binary except `cmd/auth-all`.
- `docs/sdd.md` decides the product. `docs/decisions.md` records the
  implementation choices the specification left open.
- A plugin reaches the core only through the `plugin` package. Widen `Services`
  before you widen anything else.
- A new capability of a storage adapter arrives as an optional interface in
  `store/ext.go`. A new method on `Store` breaks every third-party adapter.
- A released migration unit never changes. A change arrives as a new unit with
  a later version.
- Auth-All applies no migration and runs no background work on its own. The
  host calls it.
- A credential is stored as a digest. The plaintext exists once, in the
  response that creates it.
- A development tool lives in `tools.go.mod`, so `go.mod` never requires it.
- The exported API stays compatible. `just apidiff` compares it with the last
  release.

## Domain words

- grant: the standing authorization of one user for one client, which owns the access tokens and the refresh tokens. Avoid: session, consent record.
- authorization request: the server-side row the authorize route writes before it redirects to the host pages. Avoid: authorize query, request blob, pending request.
- resource indicator: the value a client sends to name the resource server the access token is for, which becomes the aud claim. Avoid: audience, resource server, API.
- static first-party client: a client declared in host source at construction, which holds no row and skips consent. Avoid: trusted client, internal client.
