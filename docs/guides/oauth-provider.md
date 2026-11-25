# OAuth provider

The OAuth provider plugin turns an Auth-All instance into an OAuth 2.1 and
OpenID Connect authorization server. Another application signs its users in
with your application.

Auth-All is the authorization server. Your application keeps its database, its
HTTP server, and its pages.

## Enable the plugin

```go
provider := oauthprovider.New(
    oauthprovider.KeyEncryptionKey(key),      // 32 bytes from your secret store
    oauthprovider.LoginPath("/sign-in"),
    oauthprovider.ConsentPath("/consent"),
    oauthprovider.Clients(oauthprovider.StaticClient{
        ClientID:     "internal-dashboard",
        Secret:       secret,
        Name:         "Dashboard",
        RedirectURIs: []string{"https://dashboard.example.com/callback"},
    }),
)

auth, err := authall.New(
    authall.WithStore(postgres.New(db)),
    authall.WithBaseURL("https://app.example.com"),
    authall.WithPlugins(roles.New(...), provider),
)

mux.Handle("/api/auth/", auth.Handler())
// RFC 8414 puts the metadata at the origin root, and a plugin route cannot
// reach it. One line mounts it.
mux.Handle("/.well-known/", provider.MetadataHandler())
```

The issuer is the base URL plus the base path, and every token carries it. The
plugin therefore refuses `authall.WithBaseURLSource`. Use `authall.WithBaseURL`.

The plugin refuses to register without the key encryption key. It wraps every
signing key with AES-256-GCM before it writes the row, so a database dump hands
out no signing key.

## The key encryption key

Supply 32 bytes from your secret store. Keep the value for the life of the
deployment. A lost key makes every stored signing key unreadable, and the
plugin then issues a new one.

`provider.Rotate(ctx)` issues a new signing key and retires the earlier key.
The retired key stays in the published key set, so a relying party with a
cached key set keeps verifying the tokens it holds. Auth-All runs no background
work, so your application calls `Rotate` on the cadence it chooses.

## The login page and the consent page

The authorize route writes the request to its own table and redirects to your
page with the identifier of that row:

```
GET /sign-in?request_id=<opaque>
```

Nothing of the request travels in the URL. Your page reads the request and
posts the decision through the generated client:

```ts
const request = await auth.oauthProvider.request({ request_id })
// request.clientName, request.scopes, request.resources, request.needsSignIn

const { redirectTo } = await auth.oauthProvider.decide({
  requestId: request.requestId,
  approve: true,
})
window.location.href = redirectTo
```

A static first-party client needs no consent page. Your source declares it, so
the flow completes at the authorize route.

`request.clientKind` is `static`, `dynamic`, or `cimd`. No administrator
checked a `dynamic` or a `cimd` client, so the plugin always sends the user to
the consent page before the first grant of such a client. Show
`request.clientHost` beside `request.clientName`. A `cimd` client chooses its
own name, and its host is the part that it cannot fake. The host of a `cimd`
client is the host of its client identifier URL. The host of any other client
is the host of the redirect URI of the request.

## Clients

Three populations of clients exist, and each holds a different authority.

| Population | Declared by | Managed with |
| --- | --- | --- |
| Static first-party | `oauthprovider.Clients(...)` in host source | A code change |
| Dynamic | `POST /oauth2/register` (RFC 7591) | The registration access token (RFC 7592) |
| Owned | `POST /oauth2/clients` as a signed-in user | The session of the owner |

`oauthprovider.AllowDynamicRegistration()` opens the registration route. Leave
it closed when only your own clients exist.

`oauthprovider.AllowClientIDMetadataDocuments(...)` adds a fourth population:
a client whose `client_id` is the HTTPS URL of its metadata document. See
[MCP authorization](#mcp-authorization).

## Redirect URIs

The comparison is exact. The plugin rewrites no host, so `localhost` and
`127.0.0.1` are separate registrations. A loopback URI ignores the port,
because a native application picks its port at run time. A private-use scheme
registers with an authority and without one. `https` is required, and loopback
and private-use schemes are exempt.

A deployment without TLS names its hosts:

```go
oauthprovider.AllowPlainHTTP("intranet.example")
```

## Tokens

The access token is always a signed `at+jwt` of RFC 9068. A resource server
validates it offline against the published key set. The `aud` claim carries the
resource indicator that the client named, or the issuer identifier when the
client named none.

The plugin also accepts its own access tokens on your routes, and only when the
`aud` claim names the issuer itself. `HasScope` of such a principal reports the
scopes of the token. `RequireAudience` accepts a token for one of your declared
resources. See [MCP authorization](#mcp-authorization). A token that a third-party relying party
holds for another resource server therefore opens no route of your
application.

A refresh token rotates. The rotated token answers a retry inside a short grace
window with the same successor pair, so a client that lost the response
recovers. A presentation after the window revokes every token of the grant.

## Resource indicators

Declare every resource a client may name:

```go
oauthprovider.Resources(oauthprovider.Resource{
    Identifier:     "https://api.example.com",
    Scopes:         []string{"openid", "email"},
    AccessTokenTTL: 5 * time.Minute,
})
```

A request that names an undeclared resource fails with `invalid_target`. One
request names one resource, because one access token carries one audience.

## DPoP

A client binds its tokens to a key with a DPoP proof of RFC 9449. The plugin
accepts a proof at the token endpoint and at every protected route, and it
rejects a bound token that arrives as a bearer token. Set `DPoPRequired` on a
client to refuse a bearer presentation of its tokens. A proof identifier is
single use, so a captured proof reaches no second request.

## Claims

Every claim comes from a stored field. `sub` is the user id, `name` is the
display name, and `picture` is the image URL. The plugin derives no claim from
another claim, so a user with one name gets no invented given name.

Map a host-declared user field to a claim:

```go
oauthprovider.Claims(oauthprovider.ClaimMapping{
    Scope: "profile", Claim: "nickname", Field: "nickname",
})
```

A scope-granted claim appears at the userinfo route. The ID token carries the
authentication claims and nothing else, as OIDC Core section 5.4 asks.

## Revocation

| Event | Effect |
| --- | --- |
| A user signs out of the browser | No token changes |
| A user revokes one session | No token changes |
| A user withdraws consent | Every grant of that client dies |
| An administrator disables the user | Every grant of the user dies |
| A client calls `POST /oauth2/revoke` | The named grant dies |

A grant belongs to the user and the client, not to the browser session that
approved it.

## MCP authorization

The plugin is the authorization server of your MCP endpoint, as the MCP
authorization specification of 2026-07-28 describes. An MCP client such as
Claude, ChatGPT, or an IDE finds the server from a 401, registers with a Client
ID Metadata Document or with dynamic registration, and gets an access token for
your MCP endpoint only.

```go
const mcp = "https://app.example.com/mcp"

provider := oauthprovider.New(
    oauthprovider.KeyEncryptionKey(key),
    oauthprovider.LoginPath("/sign-in"),
    oauthprovider.ConsentPath("/consent"),
    oauthprovider.Scopes("openid", "email", "offline_access", "mcp"),
    oauthprovider.Resources(oauthprovider.Resource{
        Identifier: mcp,
        Scopes:     []string{"mcp", "offline_access"},
    }),
    oauthprovider.AllowClientIDMetadataDocuments(oauthprovider.CIMDOptions{}),
    oauthprovider.AllowDynamicRegistration(),
)

mux.Handle("/.well-known/", provider.MetadataHandler())
resourceMetadata := provider.ProtectedResourceHandler(mcp)
mux.Handle("/.well-known/oauth-protected-resource", resourceMetadata)
mux.Handle("/.well-known/oauth-protected-resource/", resourceMetadata)
mux.Handle("/mcp", provider.RequireAudience(mcp, mcpServer,
    oauthprovider.RequireAudienceOptions{
        Scopes:   []string{"mcp"},
        Fallback: auth.RequireAuth(mcpServer), // keeps API keys on /mcp
    }))
```

`RequireAudience` runs in the process of the issuer. A resource server in
another process validates the token itself against the published key set.

### Discovery

1. The client calls `/mcp` with no token. `RequireAudience` answers 401 with
   `WWW-Authenticate: Bearer resource_metadata="https://app.example.com/.well-known/oauth-protected-resource/mcp"`.
2. The client reads that URL. `ProtectedResourceHandler` serves RFC 9728
   metadata. `authorization_servers` holds the issuer as its only entry, and
   `scopes_supported` holds the scopes of the resource.
3. The client reads the RFC 8414 metadata of the issuer from
   `MetadataHandler`.

`ProtectedResourceHandler` answers the path-suffixed location of the resource
and the plain location `/.well-known/oauth-protected-resource`, which an older
client reads. When you serve two resources, mount each handler at its
path-suffixed location only. `oauthprovider.ResourceMetadataURL(identifier)`
returns the location.

### Client ID Metadata Documents

With `AllowClientIDMetadataDocuments`, the metadata carries
`client_id_metadata_document_supported: true`, and
`token_endpoint_auth_methods_supported` lists `none`. Claude uses a metadata
document only when both are present.

A `client_id` that is an HTTPS URL names a metadata document. The authorize
route fetches it, and the server sends the client nothing until the document
passes these rules:

- The URL uses `https`, names a path, and carries no fragment, no user
  information, and no dot segment.
- The fetch connects to a public address only. The check runs on the address
  after the name resolution, so a name that resolves to a loopback, private,
  link-local, shared, or reserved address reaches nothing. The fetch uses no
  proxy and follows no redirect.
- The document is at most `MaxBytes` (default 5 KiB), and the fetch ends after
  `Timeout` (default 5 seconds).
- The `client_id` of the document equals the URL. The document lists the
  `redirect_uri` of the request. It carries no client secret, and its
  `token_endpoint_auth_method` is `none` or absent.

The cache honours `Cache-Control`, `Expires`, `ETag`, and `Last-Modified`. A
document stays at least 5 minutes and at most `CacheTTL` (default 24 hours).
When a fetch of a cached document fails with a network error, a 5xx status, or
429, the cached copy serves until `CacheTTL` after its last successful fetch. A
404, a redirect, or an invalid document removes the client at once.

A metadata document client is public. It presents no secret, and PKCE with
S256 is required, as it is for every client. It must send the `resource`
parameter at the authorize route and at every token call, so its access token
never carries the issuer as its audience.

### The audience check

`RequireAudience` accepts an access token of this server only when its `aud`
claim equals the identifier. It reads the token, the grant, and the user on
each request:

| Request | Answer |
| --- | --- |
| No token of this server, with a fallback | The fallback serves it |
| No token of this server, no fallback | 401 with `resource_metadata` |
| A token for another resource, or for the issuer | 401 `invalid_token` |
| A revoked token or grant, a disabled user | 401 `invalid_token` |
| A token without a scope of `Scopes` | 403 `insufficient_scope` |
| A valid token | The handler, with the principal |

`authall.PrincipalFrom(ctx)` then returns a principal with the method
`authall.MethodOAuth`. `principal.OAuth` holds the client identifier, the
granted scopes, and the audience. `principal.HasScope("mcp")` reports whether
the token carries the scope. A handler that checks a scope of one tool calls
`oauthprovider.WriteChallenge` with `oauthprovider.ErrorInsufficientScope`, so
the client learns which scope to ask for:

```go
if !authall.PrincipalFrom(r.Context()).HasScope("mcp:write") {
    oauthprovider.WriteChallenge(w, oauthprovider.Challenge{
        Resource: mcp, Status: http.StatusForbidden,
        Error:    oauthprovider.ErrorInsufficientScope,
        Scopes:   []string{"mcp:write"},
    })
    return
}
```

The authorization response carries the RFC 9207 `iss` parameter, so a client
detects a mix-up of two authorization servers.

## Cleanup

`provider.Cleanup(ctx)` removes the spent and expired rows of the plugin. Call
it from the same job that calls `auth.Cleanup`.

## What the plugin does not do

The device authorization grant, back-channel logout, `private_key_jwt`,
pairwise subject identifiers, pushed authorization requests, request objects,
the implicit grant, the password grant, token exchange, and mutual TLS client
certificate binding are out of scope.
