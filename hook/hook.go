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

// UserUpdate carries a user change.
//
// Before holds the user as it was, and User holds the user after the change. A
// Before hook can change User, and it can reject the operation.
//
// Tx is the transactional store in a Before hook. Tx is nil in an After hook.
type UserUpdate struct {
	User   *store.User
	Before *store.User
	Tx     store.Store
}

// RoleChange carries a role change of one user.
//
// Tx is the transactional store in a Before hook. Tx is nil in an After hook.
type RoleChange struct {
	User *store.User
	// From is the role before the change.
	From string
	// To is the role after the change.
	To string
	Tx store.Store
}

// APIKeyEvent carries a created or a revoked API key. The plaintext key is
// never part of it.
type APIKeyEvent struct {
	Key  *store.APIKey
	User *store.User
	Tx   store.Store
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
	// BeforeUserUpdateFunc runs in the transaction and can reject.
	BeforeUserUpdateFunc func(ctx context.Context, ev *UserUpdate) error
	// AfterUserUpdateFunc runs after commit.
	AfterUserUpdateFunc func(ctx context.Context, ev *UserUpdate) error
	// BeforeRoleChangeFunc runs in the transaction and can reject.
	BeforeRoleChangeFunc func(ctx context.Context, ev *RoleChange) error
	// AfterRoleChangeFunc runs after commit.
	AfterRoleChangeFunc func(ctx context.Context, ev *RoleChange) error
	// AfterAPIKeyCreateFunc runs after commit.
	AfterAPIKeyCreateFunc func(ctx context.Context, ev *APIKeyEvent) error
	// AfterAPIKeyRevokeFunc runs after commit.
	AfterAPIKeyRevokeFunc func(ctx context.Context, ev *APIKeyEvent) error
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
	beforeUserUpdate    []BeforeUserUpdateFunc
	afterUserUpdate     []AfterUserUpdateFunc
	beforeRoleChange    []BeforeRoleChangeFunc
	afterRoleChange     []AfterRoleChangeFunc
	afterAPIKeyCreate   []AfterAPIKeyCreateFunc
	afterAPIKeyRevoke   []AfterAPIKeyRevokeFunc

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

// OnBeforeUserUpdate registers a hook that runs in the transaction and can
// reject.
func (h *Hooks) OnBeforeUserUpdate(fn BeforeUserUpdateFunc) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.beforeUserUpdate = append(h.beforeUserUpdate, fn)
}

// OnAfterUserUpdate registers a hook that runs after commit.
func (h *Hooks) OnAfterUserUpdate(fn AfterUserUpdateFunc) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.afterUserUpdate = append(h.afterUserUpdate, fn)
}

// OnBeforeRoleChange registers a hook that runs in the transaction and can
// reject.
func (h *Hooks) OnBeforeRoleChange(fn BeforeRoleChangeFunc) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.beforeRoleChange = append(h.beforeRoleChange, fn)
}

// OnAfterRoleChange registers a hook that runs after commit.
func (h *Hooks) OnAfterRoleChange(fn AfterRoleChangeFunc) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.afterRoleChange = append(h.afterRoleChange, fn)
}

// OnAfterAPIKeyCreate registers a hook that runs after commit.
func (h *Hooks) OnAfterAPIKeyCreate(fn AfterAPIKeyCreateFunc) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.afterAPIKeyCreate = append(h.afterAPIKeyCreate, fn)
}

// OnAfterAPIKeyRevoke registers a hook that runs after commit.
func (h *Hooks) OnAfterAPIKeyRevoke(fn AfterAPIKeyRevokeFunc) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.afterAPIKeyRevoke = append(h.afterAPIKeyRevoke, fn)
}

// RunBeforeUserUpdate runs the registered hooks and stops at the first error.
func (h *Hooks) RunBeforeUserUpdate(ctx context.Context, ev *UserUpdate) error {
	h.mu.RLock()
	fns := append([]BeforeUserUpdateFunc(nil), h.beforeUserUpdate...)
	h.mu.RUnlock()
	for _, fn := range fns {
		if err := fn(ctx, ev); err != nil {
			return err
		}
	}
	return nil
}

// RunAfterUserUpdate runs the registered hooks after commit.
func (h *Hooks) RunAfterUserUpdate(ctx context.Context, ev *UserUpdate) {
	h.mu.RLock()
	fns := append([]AfterUserUpdateFunc(nil), h.afterUserUpdate...)
	h.mu.RUnlock()
	for _, fn := range fns {
		h.report(ctx, "AfterUserUpdate", fn(ctx, ev))
	}
}

// RunBeforeRoleChange runs the registered hooks and stops at the first error.
func (h *Hooks) RunBeforeRoleChange(ctx context.Context, ev *RoleChange) error {
	h.mu.RLock()
	fns := append([]BeforeRoleChangeFunc(nil), h.beforeRoleChange...)
	h.mu.RUnlock()
	for _, fn := range fns {
		if err := fn(ctx, ev); err != nil {
			return err
		}
	}
	return nil
}

// RunAfterRoleChange runs the registered hooks after commit.
func (h *Hooks) RunAfterRoleChange(ctx context.Context, ev *RoleChange) {
	h.mu.RLock()
	fns := append([]AfterRoleChangeFunc(nil), h.afterRoleChange...)
	h.mu.RUnlock()
	for _, fn := range fns {
		h.report(ctx, "AfterRoleChange", fn(ctx, ev))
	}
}

// RunAfterAPIKeyCreate runs the registered hooks after commit.
func (h *Hooks) RunAfterAPIKeyCreate(ctx context.Context, ev *APIKeyEvent) {
	h.mu.RLock()
	fns := append([]AfterAPIKeyCreateFunc(nil), h.afterAPIKeyCreate...)
	h.mu.RUnlock()
	for _, fn := range fns {
		h.report(ctx, "AfterAPIKeyCreate", fn(ctx, ev))
	}
}

// RunAfterAPIKeyRevoke runs the registered hooks after commit.
func (h *Hooks) RunAfterAPIKeyRevoke(ctx context.Context, ev *APIKeyEvent) {
	h.mu.RLock()
	fns := append([]AfterAPIKeyRevokeFunc(nil), h.afterAPIKeyRevoke...)
	h.mu.RUnlock()
	for _, fn := range fns {
		h.report(ctx, "AfterAPIKeyRevoke", fn(ctx, ev))
	}
}
