# OAuth provider

## What it does
The plugin turns an Auth-All instance into an OAuth 2.1 and OpenID Connect
authorization server. A relying party runs the authorization code flow with
PKCE, receives an ID token and a signed access token, and reads claims from
userinfo. A relying party registers itself through dynamic client registration
or the host registers it through an authenticated route. The host renders the
login page and the consent page, and the plugin holds every request as server
state.

## Decisions
- One plugin covers authorization code with PKCE, refresh, client credentials, discovery, JWKS, userinfo, revocation, introspection, dynamic registration, DPoP and resource indicators — each part is correct on the first pass, and each excluded part is a later option, not a rewrite.
- PKCE uses S256 only — `plain` gives no protection.
- The access token is always a signed `at+jwt`, never opaque — a resource server validates offline and never guesses the token format.
- `aud` carries the named resource indicator, or the issuer identifier when the request names none — the audience is always present to check.
- The store keeps one row per `jti` with the grant link, the expiry and a revoked flag — introspection and revocation work with no token material at rest.
- The plugin owns the signing keys, serves JWKS, and keeps the previous key in the set — one owner means the ID token, the access token and introspection agree.
- No fallback algorithm exists and no client secret signs a token — a plugin that degrades to a shared secret fails open.
- The default algorithm is ES256. The host selects RS256 at construction — some relying parties accept RS256 only.
- Key rotation is a Go method the host calls — Auth-All runs nothing on its own.
- The host supplies 32 bytes of key encryption key, and the plugin wraps each private key with AES-256-GCM. Construction fails without it — a database dump must hand the attacker no signing key.
- The authorize route writes the validated authorization request to its own table under an opaque request id, and redirects with that id alone — the URL carries no request state, so nothing leaks through the referer or the history.
- The authorization request and the authorization code are separate rows with separate lifetimes — one time to live cannot govern both.
- The host page reads the request and posts the decision through JSON routes with client bindings — the TypeScript client gets the methods with no extra work.
- The client row carries a nullable owner subject and a nullable organization id — the three client populations hold three different authorities, and the plugin imports no other plugin.
- A dynamically registered client has both null, and RFC 7592 governs its management — the registration access token is the only authority it holds.
- A static first-party client is declared at construction, is not a row, and skips consent — source code is the authority, and runtime edits must not reach it.
- The plugin registers a credential resolver for a token whose `aud` names the issuer itself — a token issued for an external resource server must not open the host API.
- The resolver enforces the DPoP proof of a bound token, and grants the intersection of the user roles with the token scopes — a scope narrows authority and never widens it.
- Claims come from stored fields only. `sub` is the user id, `name` is the display name, `picture` is the image URL — a derived claim is a guess.
- The host maps a user field marked `Returned` to a claim name under a scope, at construction. A claims function adds further claims. The plugin rejects a reserved name at construction — a late strip hides the mistake.
- Scope-granted claims appear at userinfo. The ID token carries the authentication claims only — OIDC Core section 5.4 puts them there.
- A redirect URI matches by exact string. The plugin rewrites no host, so `localhost` and `127.0.0.1` register separately — normalization breaks native clients.
- A loopback URI ignores the port, per RFC 8252 — a native app picks its port at run time.
- A private-use scheme registers with or without an authority — a desktop client sends both forms.
- `https` is required, and loopback and private-use schemes are exempt. A construction option names the plain-`http` origins — a self-hosted deployment needs one escape, not an open door.
- Registration rejects a redirect URI that fails a rule — the client learns at registration, not at the authorize step.
- The issuer identifier is the base URL plus the base path, so metadata belongs at `/.well-known/oauth-authorization-server/<base path>` and `/.well-known/openid-configuration/<base path>` — RFC 8414 section 3 puts metadata at the origin root.
- The plugin exports one handler for the host to mount at the origin root, and serves the same document under the base path — a relying party that ignores the path insertion still finds it.
- A refresh token rotates. The rotated token stays valid for a short grace window and returns the same successor pair — a client that lost the response recovers.
- A rotated token presented after the window revokes every token of the grant and returns `invalid_grant` — a late replay is theft.
- The refresh row holds the rotation time, the successor id and a grant id. It holds no response body — the successor row already answers the retry.
- A grant belongs to the user and the client. Revoking one session revokes no token — a browser sign-out must not end offline access.
- Disabling a user, deleting a user, or withdrawing consent revokes every token of the affected grants — the authority of the user changed.
- The grant records `auth_time` and the originating session id for `max_age` and `prompt=login`. Nothing resolves the recorded session id later — a dead reference must not affect a live token.
- The client secret is stored as a digest — the repository stores no credential in plain form.

## Out
- Device authorization grant.
- Back-channel and front-channel logout.
- `private_key_jwt` and `client_secret_jwt` client authentication.
- Pairwise subject identifiers.
- Implicit grant, password grant and token exchange.
- Pushed authorization requests and request objects.
- Response modes other than `query`. Response types other than `code`.
- Mutual TLS client certificate binding.
- Login and consent pages. The host renders both.

## How I know it works
- `go run ./cmd/auth-all openapi` lists the authorize, token, userinfo, register, introspect, revoke and JWKS operations.
- A relying party completes the code flow against the running example app and receives an ID token that verifies against the published JWKS.
- `curl <base URL>/.well-known/openid-configuration/<base path>` returns metadata whose `issuer` equals the base URL plus the base path.
- An access token issued for an external resource indicator returns 401 on a host route behind `RequireAuth`. A token issued for the issuer returns 200.
- A refresh token replayed after the grace window returns `invalid_grant`, and a later call with the successor token also returns `invalid_grant`.
- A registration that names `http://example.com/callback` as a redirect URI fails, and one that names `myapp://callback` succeeds.
- A row in the key table holds no readable private key.
- `just verify` passes.
