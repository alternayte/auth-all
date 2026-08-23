# GitHub OAuth

```go
authall.WithBaseURL("https://app.example.com"),
authall.WithProvider(
    github.New(
        github.WithClientID(os.Getenv("GITHUB_CLIENT_ID")),
        github.WithClientSecret(os.Getenv("GITHUB_CLIENT_SECRET")),
    ),
),
```

## Register the application at GitHub

Set the authorization callback URL to:

```text
https://app.example.com/api/auth/oauth/github/callback
```

Auth-All always sends this URL, so GitHub cannot be told to redirect the
browser somewhere else.

## Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/auth/oauth/github` | Start the sign-in. |
| GET | `/api/auth/oauth/github/callback` | Complete the sign-in. |

Send the browser to the start endpoint. `redirect_to` decides where the
browser goes after success:

```text
/api/auth/oauth/github?redirect_to=/dashboard
```

Auth-All accepts a relative path or an absolute URL of a trusted origin.

## Flow

1. Auth-All stores a hashed state value with a 15 minute lifetime, and it
   sets a short-lived `HttpOnly` cookie that binds the request to this browser.
2. GitHub returns the browser with a code and the state.
3. Auth-All consumes the state one time. It rejects an unknown, expired,
   replayed, or foreign state, and a state that another browser presents, with
   `OAUTH_STATE_INVALID`.
4. Auth-All exchanges the code, reads the account, and reads the verified
   primary address.
5. Auth-All resolves the user and creates a session.

GitHub does not accept a PKCE challenge on the OAuth app authorization
endpoint, so Auth-All relies on the state value, the browser binding cookie,
and the exact callback URL.

One browser runs one provider flow at a time. A second start replaces the
binding cookie, so the first flow can no longer complete.

## Scopes

The default scopes are `read:user` and `user:email`. `github.WithScopes`
replaces them. The email scope lets Auth-All read the verified address, which
account linking needs.

## Errors

| Code | Meaning |
| --- | --- |
| `OAUTH_STATE_INVALID` | The state is unknown, expired, replayed, or foreign. |
| `OAUTH_FAILED` | GitHub refused the exchange or returned no usable account. |
| `EMAIL_ALREADY_EXISTS` | The address belongs to an existing account. Read the [account linking guide](account-linking.md). |

## Tests

The test suite drives the complete flow against a deterministic fake GitHub
server. No test reaches the real service.
