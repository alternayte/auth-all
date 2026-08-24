// Package plugin is the public extension surface of Auth-All.
//
// A plugin contributes HTTP routes, schema tables, lifecycle hooks, and
// OpenAPI operations. A plugin reaches Auth-All only through the Services
// interface. The official Magic Link plugin uses this package and nothing else,
// so a third-party plugin has the same capabilities.
package plugin

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/alternayte/auth-all/email"
	"github.com/alternayte/auth-all/events"
	"github.com/alternayte/auth-all/hook"
	"github.com/alternayte/auth-all/openapi"
	"github.com/alternayte/auth-all/ratelimit"
	"github.com/alternayte/auth-all/schema"
	"github.com/alternayte/auth-all/store"
)

// Plugin is one Auth-All extension.
type Plugin interface {
	// ID returns the stable plugin identifier.
	ID() string
	// Register contributes routes, schema, hooks, and OpenAPI operations.
	Register(r *Registry) error
}

// Route is one HTTP route contributed by a plugin.
type Route struct {
	// Method is the HTTP method.
	Method string
	// Path is relative to the configured Auth-All base path and starts with /.
	Path string
	// Handler serves the route.
	Handler http.Handler
	// Operation documents the route. A route without an operation stays out of
	// the OpenAPI document and out of the generated client.
	Operation *openapi.Operation
}

// Registry receives the contributions of one plugin.
type Registry struct {
	id       string
	services Services
	hooks    *hook.Hooks

	routes  []Route
	tables  []schema.Table
	schemas map[string]*openapi.Schema
}

// NewRegistry returns a registry for one plugin. Auth-All calls this during
// construction.
func NewRegistry(id string, services Services, hooks *hook.Hooks) *Registry {
	return &Registry{id: id, services: services, hooks: hooks, schemas: map[string]*openapi.Schema{}}
}

// PluginID returns the identifier of the registering plugin.
func (r *Registry) PluginID() string { return r.id }

// Services returns the Auth-All capabilities available to the plugin.
func (r *Registry) Services() Services { return r.services }

// Hooks returns the lifecycle hook registry.
func (r *Registry) Hooks() *hook.Hooks { return r.hooks }

// Route contributes one HTTP route.
func (r *Registry) Route(rt Route) { r.routes = append(r.routes, rt) }

// Schema contributes one table to the effective Auth-All schema.
func (r *Registry) Schema(t schema.Table) { r.tables = append(r.tables, t) }

// OpenAPISchema contributes one reusable component schema.
func (r *Registry) OpenAPISchema(name string, s *openapi.Schema) { r.schemas[name] = s }

// Routes returns the contributed routes.
func (r *Registry) Routes() []Route { return r.routes }

// Tables returns the contributed schema tables.
func (r *Registry) Tables() []schema.Table { return r.tables }

// ComponentSchemas returns the contributed component schemas.
func (r *Registry) ComponentSchemas() map[string]*openapi.Schema { return r.schemas }

// Services is everything Auth-All exposes to a plugin. A plugin gets no other
// access to Auth-All internals.
type Services interface {
	// Store returns the configured storage adapter.
	Store() store.Store
	// Email returns the configured email sender.
	Email() email.Sender
	// Events returns the observability emitter.
	Events() *events.Emitter
	// Now returns the configured clock.
	Now() time.Time
	// BasePath returns the mounted base path, for example /api/auth.
	BasePath() string
	// BaseURL returns the absolute public base URL of the application.
	BaseURL() string
	// RateLimiter returns the configured limiter. It is never nil.
	RateLimiter() ratelimit.Limiter
	// Logger returns the configured logger.
	Logger() *slog.Logger

	// Users exposes user operations that run the configured hooks.
	Users() UserService
	// Sessions exposes session operations.
	Sessions() SessionService
	// Tokens exposes one-time token operations.
	Tokens() TokenService
	// HTTP exposes the request helpers Auth-All uses for its own routes.
	HTTP() HTTPService
}

// CreateUserInput describes a new user.
type CreateUserInput struct {
	Email       string
	DisplayName string
	ImageURL    string
	// EmailVerified marks the address as proven by the calling flow.
	EmailVerified bool
}

// UserService exposes user operations.
type UserService interface {
	ByID(ctx context.Context, id string) (*store.User, error)
	// ByEmail looks a user up by the normalized form of the address.
	ByEmail(ctx context.Context, address string) (*store.User, error)
	// Create inserts a user and runs the user creation hooks.
	Create(ctx context.Context, in CreateUserInput) (*store.User, error)
	// MarkEmailVerified records proven ownership of the user email address. It
	// changes no other row. A passwordless flow calls ProveEmailOwnership
	// instead.
	MarkEmailVerified(ctx context.Context, userID string) error
	// DeleteCredential removes the password credential of a user. It succeeds
	// for a user that has no password credential.
	DeleteCredential(ctx context.Context, userID string) error
	// ProveEmailOwnership records proven control of the address of a user.
	//
	// A passwordless flow calls it after the flow proves that the person
	// controls the address. When the address was not verified yet, somebody can
	// have set a password and started a session before the proof. The method
	// therefore deletes the password credential of the user, revokes every
	// session of the user, and marks the address verified. It performs the
	// three steps in one transaction.
	//
	// The method does nothing for a user whose address is already verified, so
	// a normal repeat sign-in keeps its password and its sessions.
	//
	// A plugin that proves control of an address must call this method before
	// it issues a session.
	ProveEmailOwnership(ctx context.Context, userID string) error
}

// SessionService exposes session operations.
type SessionService interface {
	// Issue creates a session for the user and writes the session cookie.
	// Method names the authentication method for hooks and events.
	Issue(ctx context.Context, w http.ResponseWriter, r *http.Request, user *store.User, method string) (*store.Session, error)
	// Current resolves the session of a request. It returns nil values when no
	// valid session exists.
	Current(ctx context.Context, r *http.Request) (*store.Session, *store.User, error)
	// Revoke deletes one session.
	Revoke(ctx context.Context, sessionID string) error
	// RevokeAll deletes every session of one user and returns the count.
	RevokeAll(ctx context.Context, userID string) (int, error)
	// Clear removes the session cookie.
	Clear(w http.ResponseWriter)
}

// IssueTokenInput describes a one-time token.
type IssueTokenInput struct {
	// Kind separates token namespaces, for example "magic-link".
	Kind string
	// UserID is optional. A flow for an unknown address leaves it nil.
	UserID *string
	// Identifier is the subject of the token, normally a normalized email.
	Identifier string
	// TTL is the token lifetime.
	TTL time.Duration
	// ReplaceExisting removes outstanding tokens of the same kind and
	// identifier before it issues the new token.
	ReplaceExisting bool
}

// TokenService exposes one-time token operations. The plaintext token exists
// only in the return value of Issue. Auth-All stores only its hash.
type TokenService interface {
	Issue(ctx context.Context, in IssueTokenInput) (plaintext string, token *store.Token, err error)
	// Consume atomically consumes a token. Two concurrent calls for the same
	// token produce at most one success.
	Consume(ctx context.Context, kind, plaintext string) (*store.Token, error)
}

// HTTPService exposes the request helpers of Auth-All.
type HTTPService interface {
	// CheckOrigin rejects a state-changing request from an untrusted origin.
	CheckOrigin(r *http.Request) error
	// DecodeJSON reads a JSON request body.
	DecodeJSON(r *http.Request, dst any) error
	// WriteJSON writes a JSON response.
	WriteJSON(w http.ResponseWriter, status int, body any)
	// WriteError writes the public error envelope.
	WriteError(w http.ResponseWriter, err error)
	// SafeRedirect returns candidate when it points at a trusted origin, and
	// fallback otherwise.
	SafeRedirect(candidate, fallback string) string
	// ClientIP returns the request IP for rate-limit keys.
	ClientIP(r *http.Request) string
}
