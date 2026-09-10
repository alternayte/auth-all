// Package events defines the structured observability events of Auth-All.
// Auth-All does not dictate the logging or tracing backend of the application.
package events

import (
	"context"
	"sync"
	"time"
)

// Name identifies an event type.
type Name string

// Expected v1 events.
const (
	SignUp                 Name = "auth.sign_up"
	SignIn                 Name = "auth.sign_in"
	SignInFailed           Name = "auth.sign_in_failed"
	SignOut                Name = "auth.sign_out"
	PasswordResetRequested Name = "auth.password_reset_requested"
	PasswordChanged        Name = "auth.password_changed"
	EmailVerified          Name = "auth.email_verified"
	EmailChangeRequested   Name = "auth.email_change_requested"
	EmailChanged           Name = "auth.email_changed"
	// UserDeleted arrives before Auth-All removes the rows, so a handler can
	// still read the owned data.
	UserDeleted        Name = "auth.user_deleted"
	MagicLinkRequested Name = "auth.magic_link_requested"
	MagicLinkUsed      Name = "auth.magic_link_used"
	OAuthCompleted     Name = "auth.oauth_completed"
	AccountLinked      Name = "auth.account_linked"
	AccountUnlinked    Name = "auth.account_unlinked"
	TOTPEnabled        Name = "auth.totp_enabled"
	TOTPDisabled       Name = "auth.totp_disabled"

	// Events of the v0.3.0 release.
	UserCreated          Name = "auth.user_created"
	UserUpdated          Name = "auth.user_updated"
	UserDisabled         Name = "auth.user_disabled"
	UserEnabled          Name = "auth.user_enabled"
	PasswordResetByAdmin Name = "auth.password_reset_by_admin"
	RoleChanged          Name = "auth.role_changed"
	APIKeyCreated        Name = "auth.api_key_created"
	APIKeyRevoked        Name = "auth.api_key_revoked"

	// Names of the v0.4.0 release. Every organization event carries the
	// organization identifier in the field "orgId".
	OrganizationCreated   Name = "auth.organization_created"
	OrganizationUpdated   Name = "auth.organization_updated"
	OrganizationDeleted   Name = "auth.organization_deleted"
	MemberAdded           Name = "auth.member_added"
	MemberRemoved         Name = "auth.member_removed"
	MemberRoleChanged     Name = "auth.member_role_changed"
	MemberSuspended       Name = "auth.member_suspended"
	MemberRestored        Name = "auth.member_restored"
	InvitationCreated     Name = "auth.invitation_created"
	InvitationAccepted    Name = "auth.invitation_accepted"
	InvitationRevoked     Name = "auth.invitation_revoked"
	CustomRoleCreated     Name = "auth.custom_role_created"
	CustomRoleDeleted     Name = "auth.custom_role_deleted"
	TeamCreated           Name = "auth.team_created"
	TeamDeleted           Name = "auth.team_deleted"
	TeamMemberAdded       Name = "auth.team_member_added"
	TeamMemberRemoved     Name = "auth.team_member_removed"
	ActiveOrganizationSet Name = "auth.active_organization_set"
)

// ActorSystem names the actor of an operation that no request started, for
// example a call of the operator Go API or of the command line tool.
const ActorSystem = "system"

// Actor names the caller of one operation.
type Actor struct {
	// ID is the user identifier of the caller, or ActorSystem.
	ID string
	// Method names the authentication method, for example "session" or
	// "api_key". It is empty for the system actor.
	Method string
	// IP is the client address of the request. It is empty for the system
	// actor.
	IP string
}

// contextKey is the private context key type of this package.
type contextKey int

const actorContextKey contextKey = iota

// WithActor returns a context that names the caller of the operation. Auth-All
// puts it in the request context, and an admin operation replaces it.
func WithActor(ctx context.Context, a Actor) context.Context {
	return context.WithValue(ctx, actorContextKey, a)
}

// ActorFrom returns the caller of the context.
func ActorFrom(ctx context.Context) (Actor, bool) {
	a, ok := ctx.Value(actorContextKey).(Actor)
	return a, ok
}

// Event is one structured observability event.
//
// An event must never carry a password, a password hash, a session token, a
// one-time token, or a provider secret.
type Event struct {
	Name Name
	Time time.Time
	// UserID is the user that the event is about. It equals Target.
	UserID string
	Fields map[string]any
	// Actor is the user that started the operation, or ActorSystem. It equals
	// UserID for a self-service operation.
	Actor string
	// Target is the user that the operation changed.
	Target string
	// IP is the client address of the request. It is empty when no request
	// started the operation.
	IP string
	// Method names the authentication method of the actor.
	Method string
}

// Handler receives events.
type Handler interface {
	HandleEvent(ctx context.Context, event Event)
}

// HandlerFunc adapts a function to the Handler interface.
type HandlerFunc func(ctx context.Context, event Event)

// HandleEvent implements Handler.
func (f HandlerFunc) HandleEvent(ctx context.Context, e Event) { f(ctx, e) }

// Emitter fans one event out to every registered handler.
type Emitter struct {
	mu       sync.RWMutex
	handlers []Handler
	now      func() time.Time
}

// NewEmitter returns an emitter.
func NewEmitter(now func() time.Time) *Emitter {
	if now == nil {
		now = time.Now
	}
	return &Emitter{now: now}
}

// Add registers a handler.
func (e *Emitter) Add(h Handler) {
	if h == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.handlers = append(e.handlers, h)
}

// Emit sends one event to every handler.
func (e *Emitter) Emit(ctx context.Context, name Name, userID string, fields map[string]any) {
	ev := Event{Name: name, Time: e.now(), UserID: userID, Target: userID, Fields: fields}
	// A self-service operation has no separate actor, so the target is the
	// actor. An admin operation and the operator API name the actor in the
	// context.
	ev.Actor = userID
	if actor, ok := ActorFrom(ctx); ok {
		if actor.ID != "" {
			ev.Actor = actor.ID
		}
		ev.Method = actor.Method
		ev.IP = actor.IP
	}
	e.dispatch(ctx, ev)
}

// EmitEvent sends one prepared event to every handler. The emitter fills the
// time and the actor fields that the event leaves empty.
func (e *Emitter) EmitEvent(ctx context.Context, ev Event) {
	if ev.Time.IsZero() {
		ev.Time = e.now()
	}
	if ev.Target == "" {
		ev.Target = ev.UserID
	}
	if ev.UserID == "" {
		ev.UserID = ev.Target
	}
	if actor, ok := ActorFrom(ctx); ok {
		if ev.Actor == "" {
			ev.Actor = actor.ID
		}
		if ev.Method == "" {
			ev.Method = actor.Method
		}
		if ev.IP == "" {
			ev.IP = actor.IP
		}
	}
	if ev.Actor == "" {
		ev.Actor = ev.Target
	}
	e.dispatch(ctx, ev)
}

// dispatch sends one event to every handler. An error of a handler never
// changes the response, because a handler returns none.
func (e *Emitter) dispatch(ctx context.Context, ev Event) {
	e.mu.RLock()
	handlers := make([]Handler, len(e.handlers))
	copy(handlers, e.handlers)
	e.mu.RUnlock()
	for _, h := range handlers {
		h.HandleEvent(ctx, ev)
	}
}
