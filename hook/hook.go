// Package hook defines the typed lifecycle hooks of Auth-All.
//
// Hook semantics:
//
//   - A Before hook runs inside the database transaction of the operation. It
//     can reject the operation by returning an error.
//   - An After hook runs after the transaction commits. It cannot reject the
//     operation. An error from an After hook is reported to the logger.
//
// Auth-All never keeps a database transaction open while it calls an external
// system, so arbitrary side effects belong in an After hook.
package hook

import (
	"context"
	"sync"

	"github.com/alternayte/auth-all/store"
)

// UserCreate carries a user creation.
//
// Tx is the transactional store in a Before hook. Tx is nil in an After hook.
type UserCreate struct {
	User *store.User
	Tx   store.Store
}

// SessionCreate carries a session creation.
type SessionCreate struct {
	Session *store.Session
	User    *store.User
	Tx      store.Store
}

// SignIn carries a completed sign-in. Method names the authentication method,
// for example "email", "magic-link", or a provider id.
type SignIn struct {
	User    *store.User
	Session *store.Session
	Method  string
}

// SignOut carries a completed sign-out.
type SignOut struct {
	UserID    string
	SessionID string
}

// AccountLink carries a completed external account link.
type AccountLink struct {
	User    *store.User
	Account *store.Account
}

// PasswordChange carries a completed password change.
type PasswordChange struct {
	User *store.User
}

// Hook function types.
type (
	// BeforeUserCreateFunc runs in the transaction and can reject.
	BeforeUserCreateFunc func(ctx context.Context, ev *UserCreate) error
	// AfterUserCreateFunc runs after commit.
	AfterUserCreateFunc func(ctx context.Context, ev *UserCreate) error
	// BeforeSessionCreateFunc runs in the transaction and can reject.
	BeforeSessionCreateFunc func(ctx context.Context, ev *SessionCreate) error
	// AfterSessionCreateFunc runs after commit.
	AfterSessionCreateFunc func(ctx context.Context, ev *SessionCreate) error
	// AfterSignInFunc runs after commit.
	AfterSignInFunc func(ctx context.Context, ev *SignIn) error
	// AfterSignOutFunc runs after commit.
	AfterSignOutFunc func(ctx context.Context, ev *SignOut) error
	// AfterAccountLinkFunc runs after commit.
	AfterAccountLinkFunc func(ctx context.Context, ev *AccountLink) error
	// AfterPasswordChangeFunc runs after commit.
	AfterPasswordChangeFunc func(ctx context.Context, ev *PasswordChange) error
)

// Hooks holds every registered lifecycle hook.
type Hooks struct {
	mu sync.RWMutex

	beforeUserCreate    []BeforeUserCreateFunc
	afterUserCreate     []AfterUserCreateFunc
	beforeSessionCreate []BeforeSessionCreateFunc
	afterSessionCreate  []AfterSessionCreateFunc
	afterSignIn         []AfterSignInFunc
	afterSignOut        []AfterSignOutFunc
	afterAccountLink    []AfterAccountLinkFunc
	afterPasswordChange []AfterPasswordChangeFunc

	onError func(ctx context.Context, name string, err error)
}

// New returns an empty hook set. onError reports an error from an After hook.
func New(onError func(ctx context.Context, name string, err error)) *Hooks {
	return &Hooks{onError: onError}
}

// OnBeforeUserCreate registers a hook that runs in the transaction and can reject.
func (h *Hooks) OnBeforeUserCreate(fn BeforeUserCreateFunc) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.beforeUserCreate = append(h.beforeUserCreate, fn)
}

// OnAfterUserCreate registers a hook that runs after commit.
func (h *Hooks) OnAfterUserCreate(fn AfterUserCreateFunc) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.afterUserCreate = append(h.afterUserCreate, fn)
}

// OnBeforeSessionCreate registers a hook that runs in the transaction and can reject.
func (h *Hooks) OnBeforeSessionCreate(fn BeforeSessionCreateFunc) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.beforeSessionCreate = append(h.beforeSessionCreate, fn)
}

// OnAfterSessionCreate registers a hook that runs after commit.
func (h *Hooks) OnAfterSessionCreate(fn AfterSessionCreateFunc) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.afterSessionCreate = append(h.afterSessionCreate, fn)
}

// OnAfterSignIn registers a hook that runs after commit.
func (h *Hooks) OnAfterSignIn(fn AfterSignInFunc) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.afterSignIn = append(h.afterSignIn, fn)
}

// OnAfterSignOut registers a hook that runs after commit.
func (h *Hooks) OnAfterSignOut(fn AfterSignOutFunc) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.afterSignOut = append(h.afterSignOut, fn)
}

// OnAfterAccountLink registers a hook that runs after commit.
func (h *Hooks) OnAfterAccountLink(fn AfterAccountLinkFunc) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.afterAccountLink = append(h.afterAccountLink, fn)
}

// OnAfterPasswordChange registers a hook that runs after commit.
func (h *Hooks) OnAfterPasswordChange(fn AfterPasswordChangeFunc) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.afterPasswordChange = append(h.afterPasswordChange, fn)
}

// RunBeforeUserCreate runs the registered hooks and stops at the first error.
func (h *Hooks) RunBeforeUserCreate(ctx context.Context, ev *UserCreate) error {
	h.mu.RLock()
	fns := append([]BeforeUserCreateFunc(nil), h.beforeUserCreate...)
	h.mu.RUnlock()
	for _, fn := range fns {
		if err := fn(ctx, ev); err != nil {
			return err
		}
	}
	return nil
}

// RunBeforeSessionCreate runs the registered hooks and stops at the first error.
func (h *Hooks) RunBeforeSessionCreate(ctx context.Context, ev *SessionCreate) error {
	h.mu.RLock()
	fns := append([]BeforeSessionCreateFunc(nil), h.beforeSessionCreate...)
	h.mu.RUnlock()
	for _, fn := range fns {
		if err := fn(ctx, ev); err != nil {
			return err
		}
	}
	return nil
}

// RunAfterUserCreate runs the registered hooks after commit.
func (h *Hooks) RunAfterUserCreate(ctx context.Context, ev *UserCreate) {
	h.mu.RLock()
	fns := append([]AfterUserCreateFunc(nil), h.afterUserCreate...)
	h.mu.RUnlock()
	for _, fn := range fns {
		h.report(ctx, "AfterUserCreate", fn(ctx, ev))
	}
}

// RunAfterSessionCreate runs the registered hooks after commit.
func (h *Hooks) RunAfterSessionCreate(ctx context.Context, ev *SessionCreate) {
	h.mu.RLock()
	fns := append([]AfterSessionCreateFunc(nil), h.afterSessionCreate...)
	h.mu.RUnlock()
	for _, fn := range fns {
		h.report(ctx, "AfterSessionCreate", fn(ctx, ev))
	}
}

// RunAfterSignIn runs the registered hooks after commit.
func (h *Hooks) RunAfterSignIn(ctx context.Context, ev *SignIn) {
	h.mu.RLock()
	fns := append([]AfterSignInFunc(nil), h.afterSignIn...)
	h.mu.RUnlock()
	for _, fn := range fns {
		h.report(ctx, "AfterSignIn", fn(ctx, ev))
	}
}

// RunAfterSignOut runs the registered hooks after commit.
func (h *Hooks) RunAfterSignOut(ctx context.Context, ev *SignOut) {
	h.mu.RLock()
	fns := append([]AfterSignOutFunc(nil), h.afterSignOut...)
	h.mu.RUnlock()
	for _, fn := range fns {
		h.report(ctx, "AfterSignOut", fn(ctx, ev))
	}
}

// RunAfterAccountLink runs the registered hooks after commit.
func (h *Hooks) RunAfterAccountLink(ctx context.Context, ev *AccountLink) {
	h.mu.RLock()
	fns := append([]AfterAccountLinkFunc(nil), h.afterAccountLink...)
	h.mu.RUnlock()
	for _, fn := range fns {
		h.report(ctx, "AfterAccountLink", fn(ctx, ev))
	}
}

// RunAfterPasswordChange runs the registered hooks after commit.
func (h *Hooks) RunAfterPasswordChange(ctx context.Context, ev *PasswordChange) {
	h.mu.RLock()
	fns := append([]AfterPasswordChangeFunc(nil), h.afterPasswordChange...)
	h.mu.RUnlock()
	for _, fn := range fns {
		h.report(ctx, "AfterPasswordChange", fn(ctx, ev))
	}
}

func (h *Hooks) report(ctx context.Context, name string, err error) {
	if err == nil || h.onError == nil {
		return
	}
	h.onError(ctx, name, err)
}
