# MCP authorization

## What it does
An Auth-All host becomes the authorization server for its own MCP endpoint, as the MCP authorization spec of 2026-07-28 describes (#12). An MCP client such as Claude, ChatGPT or an IDE finds the server from a 401, registers with a Client ID Metadata Document (CIMD) or dynamic registration, and gets an access token for that one resource. The host route accepts the token, and the request principal carries the user and the granted scopes.

## Decisions
- The release is v0.10.0 — the change adds exported API.
- `AllowClientIDMetadataDocuments(CIMDOptions{MaxBytes, Timeout, CacheTTL})` turns on CIMD. The RFC 8414 metadata then adds `client_id_metadata_document_supported: true` and `none` in `token_endpoint_auth_methods_supported` — Claude uses CIMD only when both are present.
- A `client_id` that is an HTTPS URL is a CIMD client. The authorize route fetches the document. It allows https only, refuses private, loopback and link-local addresses after DNS resolution, follows no redirect, and stops at 5 KiB and 5 seconds by default — the fetch target comes from an unknown client.
- The cache honours `Cache-Control` and `ETag`, with a floor of 5 minutes and a ceiling of 24 hours. A fetch failure on a cached document uses the cached copy until the ceiling.
- The authorize route refuses a document whose `client_id` differs from the URL, and a `redirect_uri` that the document does not list. A CIMD client is public: token endpoint auth `none`, PKCE S256 required.
- The request DTO of the consent page gains `ClientHost` and `ClientKind` (`static`, `dynamic`, `cimd`). The plugin always asks for consent for a `dynamic` or `cimd` client — no admin vetted it.
- Dynamic registration stays as it is — the MCP spec keeps it for backwards compatibility, and clients fall back to it.
- `ProtectedResourceHandler(Resource)` serves RFC 9728 metadata at `/.well-known/oauth-protected-resource` and at the path-suffixed form, such as `/.well-known/oauth-protected-resource/mcp`. It names the issuer as the only entry of `authorization_servers`, and lists the resource scopes in `scopes_supported` — Claude reads only the first entry.
- `RequireAudience(identifier string, next http.Handler)` accepts an access token only when `aud` equals the identifier. On a missing or bad token it answers 401 with `WWW-Authenticate: Bearer resource_metadata="<metadata URL>"`, and on a scope shortfall 403 `insufficient_scope` — this header is how an MCP client finds the server.
- `RequireAudience` passes a request with no `Bearer` OAuth access token to a fallback handler that the host names in `RequireAudienceOptions{Fallback}` — a host keeps its API key bearer tokens on the same route.
- `Principal` gains `OAuth *OAuthGrant{ClientID, Scopes, Audience}` and the method `MethodOAuth`. `HasScope` returns true for an OAuth principal when the token carries the scope — today an OAuth token fails every scope check.
- A token of a disabled user, or of a revoked grant, fails `RequireAudience`. The check reads the user on each request, as the API key check does.
- The authorization response adds RFC 9207 `iss` — the MCP spec says servers should send it, and clients must check it.
- The token route requires `resource` for a CIMD client — the MCP spec requires clients to send it, and one audience per token holds.

## Out
- Opaque access tokens.
- A CIMD document signed with `private_key_jwt`.
- Resource servers on another origin than the issuer.

## How I know it works
- `examples/go-app` serves `/mcp` behind `RequireAudience`. A GET to `/mcp` with no token returns 401 with `resource_metadata`, and that URL returns the metadata document.
- A test client with a CIMD document on a local TLS server completes authorize, consent and token, and calls `/mcp` with the token. `PrincipalFrom` gives `MethodOAuth` and the granted scopes.
- A token for another resource gets 401 on `/mcp`. An API key on `/mcp` reaches the fallback handler.
- A CIMD URL that resolves to 127.0.0.1 or 10.0.0.1 is refused. A document over 5 KiB is refused. A `redirect_uri` not in the document is refused.
- Disable the user. The next `/mcp` call with the token gets 401.
- `just verify` passes. `just apidiff` reports additions only.
