# Account linking security

One user can own several authentication accounts:

```text
User
 ├── email and password
 ├── GitHub
 └── Google
```

## The threat

A provider that reports an address it never verified can claim an address that
belongs to another person. An authentication framework that links accounts on
a matching address alone hands the existing account to the attacker.

## The default policy

Auth-All never links an external account to an existing user because the
addresses match. A provider sign-in that reports an address of an existing
account fails with:

```json
{
  "error": {
    "code": "EMAIL_ALREADY_EXISTS",
    "message": "An account with this email address already exists. Sign in and link the provider."
  }
}
```

The safe path is the explicit link: the person signs in with the method they
already own, and then links the provider.

## The explicit link

```text
POST /api/auth/account/link/{provider}
```

The request needs a valid session. The response carries the provider
authorization URL:

```json
{ "url": "https://github.com/login/oauth/authorize?..." }
```

Auth-All stores the id of the signed-in user with the state, so the callback
links the identity to that user and to no other user.

## The opt-in auto-link

```go
authall.WithAccountLinking(authall.AccountLinkingOptions{
    AllowVerifiedEmailAutoLink: true,
})
```

The option links an external account to an existing user only when every
condition holds:

- the provider states that it verified the address,
- the existing user has a verified address,
- the addresses are equal after normalization.

Enable it only for providers that verify addresses.

## Ownership invariant

A provider identity, which is the pair of the provider id and the provider
account id, belongs to at most one user. The database enforces it with a
unique index, so two concurrent link attempts produce one link and one
`ACCOUNT_ALREADY_LINKED` error.

## Unlinking

```text
POST /api/auth/account/unlink/{provider}
```

Auth-All refuses to remove the last remaining authentication method and
answers `LAST_AUTH_METHOD`. A user with a password or with a second provider
can unlink.

## Listing the methods

```text
GET /api/auth/account/providers
```

```json
{ "providers": [{ "provider": "github", "accountId": "12345", "linkedAt": "..." }], "hasPassword": true }
```
