# The external policy boundary

Auth-All answers a role question and a permission question. It answers no
per-object question.

A per-object rule needs a relationship graph: "the people of the team of the
folder of this document can read it". A graph needs a Zanzibar-style store, a
consistency token, and a service. Ory Keto, SpiceDB, and OpenFGA already do
that work, and none of them holds an identity.

Auth-All supplies the subject that those services need, and it sends the
question to them.

## The interface

```go
// ObjectChecker answers a question about one object.
type ObjectChecker interface {
    Allowed(ctx context.Context, q organizations.Query) (bool, error)
}

type Query struct {
    SubjectID   string   // the person of the request
    OrgID       string   // the active organization
    Role        string   // the role of the membership
    Permissions []string // the effective statements of the member
    Action      string   // "document:read"
    Object      string   // "document:abc123"
}
```

## Wire a service

```go
orgs := organizations.New(
    organizations.Roles(...),
    organizations.WithObjectChecker(keto),
)

allowed, err := orgs.CanObject(ctx, "document:read", "document:abc123")
```

The option is off by default. `CanObject` reports `ErrNoObjectChecker` until
the application wires a checker, so an application never believes that Auth-All
answers an object question of its own.

## The rules of the boundary

1. An error of the checker denies the request. A policy service that is
   unreachable never grants access.
2. A context with no active organization denies the request, and the plugin
   asks the checker nothing.
3. The checker receives the resolved subject, so it needs no second identity
   store.

## What stays inside Auth-All

Auth-All keeps the answer to these questions:

1. Which organizations does this person belong to?
2. What role does the membership carry?
3. Does the effective permission set hold `project:write`?

The application applies the answer to its own queries. Auth-All isolates its
own tables, and it answers the question. It does not filter the rows of the
application.
