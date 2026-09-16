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

## Clients

Three populations of clients exist, and each holds a different authority.

| Population | Declared by | Managed with |
| --- | --- | --- |
| Static first-party | `oauthprovider.Clients(...)` in host source | A code change |
| Dynamic | `POST /oauth2/register` (RFC 7591) | The registration access token (RFC 7592) |
| Owned | `POST /oauth2/clients` as a signed-in user | The session of the owner |

`oauthprovider.AllowDynamicRegistration()` opens the registration route. Leave
it closed when only your own clients exist.

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
`aud` claim names the issuer itself. A token that a third-party relying party
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

## Cleanup

`provider.Cleanup(ctx)` removes the spent and expired rows of the plugin. Call
it from the same job that calls `auth.Cleanup`.

## What the plugin does not do

The device authorization grant, back-channel logout, `private_key_jwt`,
pairwise subject identifiers, pushed authorization requests, request objects,
the implicit grant, the password grant, token exchange, and mutual TLS client
certificate binding are out of scope.
