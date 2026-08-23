# Plugin authors

A plugin contributes HTTP routes, schema tables, lifecycle hooks, and OpenAPI
operations. A plugin reaches Auth-All only through the `plugin` package.

The official Magic Link plugin uses this surface and nothing else, so a
third-party plugin has the same capabilities.

## The interface

```go
type Plugin interface {
    ID() string
    Register(r *plugin.Registry) error
}
```

Register the plugin with `authall.WithPlugins(myplugin.New())`.

## The registry

```go
func (p *Notes) Register(r *plugin.Registry) error {
    p.svc = r.Services()

    r.Schema(schema.Table{
        Name: "notes",
        Columns: []schema.Column{
            {Name: "id", Type: schema.TypeText, PrimaryKey: true},
            {Name: "user_id", Type: schema.TypeText},
            {Name: "body", Type: schema.TypeText},
            {Name: "created_at", Type: schema.TypeTimestamp},
        },
        Indexes: []schema.Index{{Name: "notes_user_id_idx", Columns: []string{"user_id"}}},
    })

    r.Route(plugin.Route{
        Method:  http.MethodPost,
        Path:    "/notes",
        Handler: http.HandlerFunc(p.create),
        Operation: &openapi.Operation{
            OperationID: "notesCreate",
            Summary:     "Create a note",
            Responses:   map[string]openapi.Response{"200": openapi.JSONResponse("The note", noteSchema)},
            Client:      &openapi.ClientBinding{Namespace: "notes", Method: "create"},
        },
    })

    r.Hooks().OnAfterUserCreate(func(ctx context.Context, ev *hook.UserCreate) error {
        return p.welcome(ctx, ev.User)
    })
    return nil
}
```

A route path is relative to the configured base path. An operation with a
client binding appears in the OpenAPI document and in the generated
TypeScript client, so `auth.notes.create(...)` exists without extra work.

## The services

`r.Services()` returns the complete extension surface:

| Service | Purpose |
| --- | --- |
| `Store()` | The storage adapter, including transactions. |
| `Users()` | Look a user up, create a user, mark an address as verified. |
| `Sessions()` | Issue a session with its cookie, read the current session, revoke. |
| `Tokens()` | Issue and atomically consume a one-time token. |
| `Email()` | The configured sender. |
| `HTTP()` | Origin checks, JSON helpers, safe redirects, the client IP. |
| `Events()` | The observability emitter. |
| `RateLimiter()` | The configured limiter. |
| `Logger()`, `Now()`, `BasePath()`, `BaseURL()` | Configuration and context. |

A plugin receives no other access to Auth-All internals.

## Hooks

| Hook | Runs | Can reject |
| --- | --- | --- |
| `OnBeforeUserCreate` | Inside the transaction | Yes |
| `OnAfterUserCreate` | After the commit | No |
| `OnBeforeSessionCreate` | Inside the transaction | Yes |
| `OnAfterSessionCreate` | After the commit | No |
| `OnAfterSignIn` | After the commit | No |
| `OnAfterSignOut` | After the commit | No |
| `OnAfterAccountLink` | After the commit | No |
| `OnAfterPasswordChange` | After the commit | No |

A Before hook receives the transactional store in `ev.Tx`. Auth-All never
keeps a transaction open while it calls an external system, so a call to a
mail provider or to a queue belongs in an After hook. An error from an After
hook reaches the logger and does not undo the operation.

## Rules

- The plugin id must be unique and stable. It names the plugin in errors.
- A schema table name must be unique in the effective schema.
- Two operations must not claim the same client binding.
- Keep the plaintext of a token inside the flow that issued it. Auth-All
  stores only the hash.
