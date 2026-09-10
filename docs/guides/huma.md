# The huma adapter

`github.com/alternayte/auth-all/humaauth` merges the Auth-All API into a huma
document, and it protects a huma operation with a role.

The adapter is a separate module. The core module therefore adds no huma
dependency to the module graph of an application.

## Install

```
go get github.com/alternayte/auth-all/humaauth
```

## Merge the document

```go
mux := http.NewServeMux()
mux.Handle(auth.BasePath()+"/", auth.Handler())

api := humago.New(mux, huma.DefaultConfig("Example", "1.0.0"))
if err := humaauth.Register(api, auth); err != nil {
    return err
}
```

`Register` adds every Auth-All operation and every Auth-All component schema to
the document. It mounts no route, because the router already serves
`auth.Handler()`.

`Register` fails when an operation identifier, a route, or a schema name
collides with a name of the application. A silent overwrite would give two
shapes for one name, so the merge stops instead.

## Protect an operation

```go
huma.Register(api, huma.Operation{
    OperationID: "deploy",
    Method:      http.MethodPost,
    Path:        "/deploy",
    Middlewares: huma.Middlewares{humaauth.RequireRole(api, auth, "operator")},
}, deployHandler)
```

The middleware reads the principal of the request context, so the route runs
behind `auth.RequireAuth` or behind another Auth-All middleware.

A request with no principal gets `401 UNAUTHORIZED`. A lower role gets `403
INSUFFICIENT_ROLE`. `RequireRole` panics at construction when the minimum role
is not configured.
