# Google OAuth

Google is a preset over the [generic OpenID Connect provider](oidc.md). The two
share one identity token verification, so this package holds the endpoints and
nothing else.

```go
authall.WithBaseURL("https://app.example.com"),
authall.WithProvider(
    google.New(
        google.WithClientID(os.Getenv("GOOGLE_CLIENT_ID")),
        google.WithClientSecret(os.Getenv("GOOGLE_CLIENT_SECRET")),
    ),
),
```

## Register the application at Google

Set the authorized redirect URI to:

```text
https://app.example.com/api/auth/oauth/google/callback
```

## Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/auth/oauth/google` | Start the sign-in. |
| GET | `/api/auth/oauth/google/callback` | Complete the sign-in. |

## OpenID Connect validation

Google is an OpenID Connect provider. Auth-All validates the identity token
before it trusts any claim:

- the issuer,
- the audience, which is the configured client id,
- the nonce that Auth-All generated for this request,
- the expiry, with one minute of leeway,
- the RS256 signature against the published key set.

Auth-All accepts RS256 only. A token with another algorithm is rejected.

## PKCE

Google supports PKCE. Auth-All creates a code verifier for each request,
stores it with the state, and sends the S256 challenge. A code that an
attacker injects cannot be redeemed without the stored verifier.

## State binding

Auth-All stores a hashed, single-use state value and sets a short-lived
`HttpOnly` cookie that binds the pending request to the browser that started
it. A callback from another browser is rejected with `OAUTH_STATE_INVALID`.

## Scopes

The default scopes are `openid`, `email`, and `profile`.
`google.WithScopes` replaces them.

## Errors

| Code | Meaning |
| --- | --- |
| `OAUTH_STATE_INVALID` | The state is unknown, expired, replayed, or foreign. |
| `OAUTH_FAILED` | The exchange failed or the identity token is invalid. |
| `EMAIL_ALREADY_EXISTS` | The address belongs to an existing account. |

## Tests

The test suite drives the complete flow against a deterministic fake Google
server that signs identity tokens with a generated RSA key. Tests cover a
wrong issuer, a wrong nonce, an expired token, and a wrong PKCE verifier.
