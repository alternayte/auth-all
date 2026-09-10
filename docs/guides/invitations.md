# Invitations

An invitation brings one email address into one organization with a role.
Auth-All creates the invitation and answers the acceptance. Auth-All sends no
message. The application sends it.

## Create an invitation

```go
invitation, token, err := orgs.Invite(ctx, actor, organizations.InviteInput{
    OrgID: org.ID, Email: "new@example.com", Role: "admin",
})
```

The HTTP route is `POST /organizations/{id}/invitations`.

The token holds 32 random bytes from `crypto/rand`. The plaintext appears one
time, in this return value. The store keeps the SHA-256 digest only, so a
reader of the database cannot accept an invitation.

The default expiry is 7 days. `organizations.InvitationTTL(48 * time.Hour)`
changes it.

An invitation never names a role above the role of the person who invites. Such
a request fails with `ROLE_NOT_ALLOWED`.

An address that already holds a membership fails with `ALREADY_MEMBER`.

## Send the message

Auth-All emits the intent, and the application sends the invitation:

```go
auth := authall.New(
    authall.WithEventHandler(events.HandlerFunc(func(ctx context.Context, e events.Event) {
        if e.Name != events.InvitationCreated {
            return
        }
        // The event carries the address, the role, the organization, and the
        // expiry. It never carries the token.
        send(e.Fields["email"].(string), e.Fields["orgId"].(string))
    })),
)
```

The event carries no token, because an event reaches a log. The application
holds the plaintext from the return value of `Invite`, and it builds the link:

```text
https://app.example.com/invitations/accept?token=<the plaintext>
```

## Accept an invitation

```go
member, err := orgs.AcceptInvitation(ctx, user, token)
```

The HTTP route is `POST /organizations/invitations/accept`.

The acceptance needs a signed-in user whose normalized address matches the
invitation. An invitation that any holder can accept is a link that leaks a
membership, so another user never spends it.

One conditional update spends the invitation, so ten parallel acceptances
create one membership.

## One message for every invalid case

An unknown, an accepted, a revoked, and an expired invitation all give the same
body:

```json
{"error":{"code":"INVITATION_INVALID","message":"The invitation is invalid."}}
```

A holder of a token therefore learns nothing about it.

## Revoke an invitation

```text
POST /organizations/{id}/invitations/{invitationId}/revoke
```

The route ends a pending invitation. A second revocation gives
`INVITATION_INVALID`.

## List the invitations

```text
GET /organizations/{id}/invitations?status=pending&limit=50&cursor=...
```

The list never carries the token and never the digest.
