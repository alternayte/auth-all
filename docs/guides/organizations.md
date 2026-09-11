# Organizations

A person belongs to one or more organizations. A membership carries a role, and
a role carries a set of permissions. The plugin is off until the application
enables it.

The v0.3.0 release gives one global role for each user. That model serves a
single-tenant application. This plugin serves a business application, where one
person is an administrator of one company and a viewer of another.

## Configuration

```go
orgs := organizations.New(
    organizations.Roles(
        organizations.Role("owner",  "*"),
        organizations.Role("admin",  "member:*", "role:*", "team:*",
            "organization:read", "organization:update", "project:*", "billing:read"),
        organizations.Role("member", "organization:read", "project:read", "project:write"),
        organizations.Role("viewer", "organization:read", "project:read"),
    ),
    organizations.DefaultRole("member"),
    organizations.OwnerRole("owner"),
)
auth, err := authall.New(
    authall.WithStore(postgres.New(db)),
    authall.WithPlugins(orgs),
)
```

The first declared role is the owner role, and the last declared role is the
default role. `DefaultRole` and `OwnerRole` name another role. Construction
fails when the list is empty, when a name repeats, or when it does not hold the
named roles.

## The tables

The plugin owns six migration units, `20261101000001` to `20261101000006`. They
create the organizations, the memberships, the invitations, the custom roles,
and the two team tables. Unit `20261101000006` adds the nullable column
`active_org_id` to the sessions table.

Auth-All never runs a migration on its own. Call `auth.Migrate`, or export the
files with the command line tool.

## Create an organization

```go
org, err := orgs.Create(ctx, user, organizations.CreateInput{
    Name: "Acme", Slug: "acme",
})
```

A slug is unique, and it matches `^[a-z0-9][a-z0-9-]{0,62}$`. A duplicate slug
fails with `SLUG_TAKEN`. The creator becomes a member with the owner role, so
an organization never starts without an owner.

The HTTP route is `POST /organizations`.

## The active organization

The active organization lives in the session row. Every instance reads it, and
a revocation removes it with the session. A header and a query parameter never
set it.

```go
err = orgs.SetActive(ctx, w, r, org.ID)
```

The route `POST /organizations/{id}/activate` does the same. The switch fails
when the caller holds no active membership of that organization.

`POST /organizations/deactivate` ends the active organization.

A request with no active organization gets 403 `NO_ACTIVE_ORGANIZATION` on
every organization route.

## Read the active organization

```go
active, ok := organizations.From(ctx)
if ok {
    log.Info("the request works in", "organization", active.Organization.Slug,
        "role", active.Membership.Role)
}
```

The credential read loads the session, the user, the organization, and the
membership in one statement, so a check costs no round trip.

## Members

```go
err = orgs.SetRole(ctx, actor, org.ID, userID, "viewer")
err = orgs.Suspend(ctx, actor, org.ID, userID)
err = orgs.Restore(ctx, actor, org.ID, userID)
err = orgs.Remove(ctx, actor, org.ID, userID)
```

A member never grants a role that holds a permission the member does not hold.
Such a change fails with `ROLE_NOT_ALLOWED`.

A change that removes the last active owner fails with `LAST_OWNER`. The guard
locks the owner rows inside the write transaction, so two parallel demotions
leave one owner.

A suspended membership keeps the row, and it holds no permission. A removal
also ends the active organization of every session of that member in that
organization, so the next request of every instance refuses.

The member list uses the cursor of the administrative list, and it accepts a
role filter and a status filter:

```text
GET /organizations/{id}/members?role=admin&status=active&limit=50&cursor=...
```

## A member limit

```go
orgs := organizations.New(..., organizations.MaxMembers(50))
```

The count holds the active members and the pending invitations, and it runs
inside the write transaction. A batch of invitations therefore cannot pass the
limit together. The next invitation fails with `MEMBER_LIMIT`.

## Personal organizations

```go
orgs := organizations.New(..., organizations.WithPersonalOrganizations())
```

The option is off by default, because many applications need none. With the
option on, a sign-up creates one organization in the same transaction, and the
person owns it.

## Delete an organization

```go
err = orgs.Delete(ctx, actor, org.ID)
```

The deletion removes the organization, every membership, every invitation,
every custom role, every team, and every organization-scoped key in one
transaction. A Before hook receives the transactional store, so the application
removes its own rows of the organization at the same time:

```go
auth.Hooks().OnBeforeOrganizationDelete(func(ctx context.Context, ev *hook.OrganizationEvent) error {
    return deleteProjects(ctx, ev.Tx, ev.Org.ID)
})
```

The hook can reject the deletion. The transaction then rolls back, and the
organization stays.

## Administrative routes

An administrator of the application lists and deletes any organization:

```go
adm := admin.New(admin.Organizations(orgs))
```

The routes are `GET /admin/organizations` and
`DELETE /admin/organizations/{id}`. They stay absent when the application wires
no organizations plugin.

## The global role of v0.3.0

The global role keeps its behavior. When an active organization exists, the
organization role decides the permission check. Otherwise the global role
decides the role check. An application that adds organizations therefore keeps
its administrative routes with no change.

## Audit events

Every organization change and every membership change emits an event with the
actor and the field `orgId`:

```text
auth.organization_created   auth.organization_updated   auth.organization_deleted
auth.member_added           auth.member_removed         auth.member_role_changed
auth.member_suspended       auth.member_restored        auth.active_organization_set
auth.invitation_created     auth.invitation_accepted    auth.invitation_revoked
auth.custom_role_created    auth.custom_role_deleted
auth.team_created           auth.team_deleted
auth.team_member_added      auth.team_member_removed
```

No event carries an invitation token.
