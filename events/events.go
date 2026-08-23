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
	MagicLinkRequested     Name = "auth.magic_link_requested"
	MagicLinkUsed          Name = "auth.magic_link_used"
	OAuthCompleted         Name = "auth.oauth_completed"
	AccountLinked          Name = "auth.account_linked"
	AccountUnlinked        Name = "auth.account_unlinked"
)

// Event is one structured observability event.
//
// An event must never carry a password, a password hash, a session token, a
// one-time token, or a provider secret.
type Event struct {
	Name   Name
	Time   time.Time
	UserID string
	Fields map[string]any
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
	ev := Event{Name: name, Time: e.now(), UserID: userID, Fields: fields}
	e.mu.RLock()
	handlers := make([]Handler, len(e.handlers))
	copy(handlers, e.handlers)
	e.mu.RUnlock()
	for _, h := range handlers {
		h.HandleEvent(ctx, ev)
	}
}
