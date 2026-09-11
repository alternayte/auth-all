# Permissions

A permission is the string `resource:action`. A route asks for one permission,
and the check runs in the process of the application. It needs no store access
and no network call.

## The grammar

```text
project:read      one action of one resource
project:*         every action of the resource
*:read            the read action of every resource
*                 every permission
```

A wildcard replaces one whole segment. A segment holds at least one character
of `[a-z0-9_.-]`, or it is the single asterisk. Every other input fails at
construction.

The evaluation runs no regular expression, and it reads no pattern from a
request. A regular expression in a permission is a denial-of-service risk, and
it is hard to audit.

A check costs a small, fixed number of map lookups. A set of 100 statements
answers one check in well under 2 microseconds.

## Declare the roles

```go
organizations.Roles(
    organizations.Role("owner",  "*"),
    organizations.Role("admin",  "member:*", "project:*", "billing:read"),
    organizations.Role("member", "project:read", "project:write"),
    organizations.Role("viewer", "project:read"),
)
```

The declaration is code, so a review sees it and a test covers it.

## Protect a route

```go
mux.Handle("POST /projects", orgs.Require("project:write", createProject))
```

`Require` panics at construction when the statement is invalid, and when no
declared role holds it. A route that no role can reach is a fault of the
application, and it must fail at the start and not on a request.

A request with no principal gets 401 `UNAUTHORIZED`. A request with no active
organization gets 403 `NO_ACTIVE_ORGANIZATION`. A member without the permission
gets 403 `PERMISSION_DENIED`.

## Ask inside a handler

```go
if orgs.Can(ctx, "billing:read") {
    renderInvoices(w, r)
}
```

`Can` returns false when no organization is active, when the membership is
suspended, and when the statement is unknown. Every decision is default deny.

## The permission statements of Auth-All

The built-in routes ask for these statements. Name them in the role
declaration:

| Statement | Route |
|---|---|
| `organization:read` | Read one organization, list the members, the roles, and the teams. |
| `organization:update` | Change the name, the slug, and the host-owned fields. |
| `organization:delete` | Delete the organization. |
| `member:read` | List the members and the invitations. |
| `member:write` | Change a role, suspend a member, and remove a member. |
| `member:invite` | Create and revoke an invitation. |
| `role:write` | Declare and remove a custom role. |
| `team:write` | Create a team, remove a team, and change its members. |

## Custom roles

```go
orgs := organizations.New(..., organizations.AllowCustomRoles(true))
```

An organization then declares a role at run time:

```text
POST /organizations/{id}/roles
{"name": "auditor", "permissions": ["project:read", "billing:read"]}
```

A custom role never holds a permission that its creator lacks. The guard
compares the whole reach of each statement, so a member with `billing:read`
cannot declare a role with `billing:*`. Such a request fails with
`ROLE_NOT_ALLOWED`.

A custom role name never shadows a built-in role name.

A custom role stores its own statements. A later change of a built-in role
therefore never widens it.

## Teams

A team groups members inside one organization, and it can carry a role. The
effective permission set is the union of the organization role and of every
team role:

```text
POST /organizations/{id}/teams
{"name": "platform", "role": "admin"}

POST /organizations/{id}/teams/{teamId}/members
{"userId": "..."}
```

A team member must already hold a membership of the organization. The deletion
of a team removes its team memberships, and it keeps the organization
memberships.

The credential read resolves every team role in the same statement, so the
union costs no extra round trip.

## Organization-scoped API keys

```go
keys := apikeys.New(apikeys.Organizations(orgs))
```

A key can name an organization:

```text
POST /api-keys
{"name": "ci", "role": "admin", "orgId": "..."}
```

The permissions of that key are the intersection of the key permissions and the
live permissions of the owner in that organization. A demoted member therefore
keeps no stronger key, and a key of an organization that the owner left gets
401.
