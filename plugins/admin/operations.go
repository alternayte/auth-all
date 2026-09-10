package admin

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/alternayte/auth-all/apierr"
	"github.com/alternayte/auth-all/events"
	"github.com/alternayte/auth-all/hook"
	"github.com/alternayte/auth-all/plugin"
	"github.com/alternayte/auth-all/store"
)

// userDTO is the public shape of a user in an administrative response.
type userDTO struct {
	ID                 string     `json:"id"`
	Email              string     `json:"email"`
	EmailVerified      bool       `json:"emailVerified"`
	Name               string     `json:"name"`
	Role               string     `json:"role"`
	DisabledAt         *time.Time `json:"disabledAt"`
	MustChangePassword bool       `json:"mustChangePassword"`
	CreatedAt          time.Time  `json:"createdAt"`
	UpdatedAt          time.Time  `json:"updatedAt"`
}

// listResponse is the body of GET /admin/users.
type listResponse struct {
	Users []userDTO `json:"users"`
	// NextCursor continues the list. It is empty on the last page.
	NextCursor string `json:"nextCursor"`
}

// userResponse is the body of an operation that returns one user.
type userResponse struct {
	User userDTO `json:"user"`
}

// createRequest is the body of POST /admin/users.
type createRequest struct {
	Email    string `json:"email"`
	Name     string `json:"name"`
	Role     string `json:"role"`
	Password string `json:"password"`
	// TemporaryPassword defaults to true. A pointer separates an absent field
	// from an explicit false.
	TemporaryPassword *bool `json:"temporaryPassword"`
}

// createResponse is the body of POST /admin/users. The temporary password
// appears one time.
type createResponse struct {
	User              userDTO `json:"user"`
	TemporaryPassword string  `json:"temporaryPassword,omitempty"`
}

// roleRequest is the body of the role route.
type roleRequest struct {
	Role string `json:"role"`
}

// passwordRequest is the body of the password route.
type passwordRequest struct {
	Password  string `json:"password"`
	Temporary *bool  `json:"temporary"`
}

// passwordResponse carries a generated temporary password one time.
type passwordResponse struct {
	TemporaryPassword string `json:"temporaryPassword,omitempty"`
}

// CreateUserInput describes a new user of an administrative operation.
type CreateUserInput struct {
	Email string
	Name  string
	// Role is the role of the new user. An empty value takes the default role.
	Role string
	// Password is the first password. An empty value generates one.
	Password string
	// TemporaryPassword makes the user change the password before it reaches
	// any protected route.
	TemporaryPassword bool
}

// ResetOptions describe a password reset by an administrator.
type ResetOptions struct {
	// Password is the new password. An empty value generates one.
	Password string
	// Temporary makes the user change the password before it reaches any
	// protected route.
	Temporary bool
}

// CreateUser creates a user with a role and a password.
//
// It returns the generated password when the caller supplied none. The
// password exists in this return value only.
func (p *Plugin) CreateUser(ctx context.Context, in CreateUserInput) (*store.User, string, error) {
	if err := p.ready(); err != nil {
		return nil, "", err
	}
	role := in.Role
	if role == "" {
		role = p.roles.Default()
	}
	if p.roles.Rank(role) < 0 {
		return nil, "", apierr.ErrRoleUnknown
	}
	password := in.Password
	generated := ""
	if password == "" {
		value, err := newPassword()
		if err != nil {
			return nil, "", apierr.ErrInternal.WithCause(err)
		}
		password = value
		generated = value
	}
	user, err := p.users.Create(ctx, plugin.CreateUserInput{
		Email: in.Email, DisplayName: in.Name,
	})
	if err != nil {
		return nil, "", err
	}
	now := p.now()
	err = p.store.Transaction(ctx, func(tx store.Store) error {
		hash, err := p.hashPassword(password)
		if err != nil {
			return err
		}
		if err := tx.Users().SetCredential(ctx, &store.Credential{
			UserID: user.ID, PasswordHash: hash, CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			return err
		}
		before := *user
		user.Role = role
		user.MustChangePassword = in.TemporaryPassword
		user.UpdatedAt = now
		ev := &hook.UserUpdate{User: user, Before: &before, Tx: tx}
		if err := p.hooks.RunBeforeUserUpdate(ctx, ev); err != nil {
			return err
		}
		return tx.Users().Update(ctx, user)
	})
	if err != nil {
		return nil, "", publicError(err)
	}
	p.hooks.RunAfterUserUpdate(ctx, &hook.UserUpdate{User: user})
	p.emit(ctx, events.UserCreated, user, map[string]any{"role": role})
	return user, generated, nil
}

// SetRole sets the role of one user.
func (p *Plugin) SetRole(ctx context.Context, userID, role string) (*store.User, error) {
	if err := p.ready(); err != nil {
		return nil, err
	}
	if p.roles.Rank(role) < 0 {
		return nil, apierr.ErrRoleUnknown
	}
	var updated *store.User
	var from string
	err := p.store.Transaction(ctx, func(tx store.Store) error {
		user, err := tx.Users().GetByID(ctx, userID)
		if err != nil {
			return err
		}
		from = p.roleOf(user)
		if from == role {
			updated = user
			return nil
		}
		// A change to a lower role can remove the last administrator.
		if p.roles.AtLeast(from, p.adminRole) && !p.roles.AtLeast(role, p.adminRole) {
			if err := p.guardLastAdmin(ctx, tx, userID); err != nil {
				return err
			}
		}
		before := *user
		user.Role = role
		user.UpdatedAt = p.now()
		change := &hook.RoleChange{User: user, From: from, To: role, Tx: tx}
		if err := p.hooks.RunBeforeRoleChange(ctx, change); err != nil {
			return err
		}
		if err := p.hooks.RunBeforeUserUpdate(ctx,
			&hook.UserUpdate{User: user, Before: &before, Tx: tx}); err != nil {
			return err
		}
		if err := tx.Users().Update(ctx, user); err != nil {
			return err
		}
		updated = user
		return nil
	})
	if err != nil {
		return nil, publicError(err)
	}
	if from != role {
		p.hooks.RunAfterRoleChange(ctx, &hook.RoleChange{User: updated, From: from, To: role})
		p.hooks.RunAfterUserUpdate(ctx, &hook.UserUpdate{User: updated})
		p.emitChange(ctx, events.RoleChanged, updated, map[string]any{"from": from, "to": role})
	}
	return updated, nil
}

// Disable blocks every credential of one user and revokes every session of the
// user in the same transaction.
func (p *Plugin) Disable(ctx context.Context, userID string) (*store.User, error) {
	if err := p.ready(); err != nil {
		return nil, err
	}
	var updated *store.User
	err := p.store.Transaction(ctx, func(tx store.Store) error {
		user, err := tx.Users().GetByID(ctx, userID)
		if err != nil {
			return err
		}
		if user.DisabledAt != nil {
			updated = user
			return nil
		}
		if p.roles.AtLeast(p.roleOf(user), p.adminRole) {
			if err := p.guardLastAdmin(ctx, tx, userID); err != nil {
				return err
			}
		}
		now := p.now()
		before := *user
		user.DisabledAt = &now
		user.UpdatedAt = now
		if err := p.hooks.RunBeforeUserUpdate(ctx,
			&hook.UserUpdate{User: user, Before: &before, Tx: tx}); err != nil {
			return err
		}
		if err := tx.Users().Update(ctx, user); err != nil {
			return err
		}
		// The session rows go in the same transaction, so every instance
		// refuses the user as soon as the change is visible.
		if _, err := tx.Sessions().DeleteByUser(ctx, userID); err != nil {
			return err
		}
		updated = user
		return nil
	})
	if err != nil {
		return nil, publicError(err)
	}
	p.hooks.RunAfterUserUpdate(ctx, &hook.UserUpdate{User: updated})
	p.emitChange(ctx, events.UserDisabled, updated, nil)
	return updated, nil
}

// Enable removes the disabled state of one user.
func (p *Plugin) Enable(ctx context.Context, userID string) (*store.User, error) {
	if err := p.ready(); err != nil {
		return nil, err
	}
	var updated *store.User
	err := p.store.Transaction(ctx, func(tx store.Store) error {
		user, err := tx.Users().GetByID(ctx, userID)
		if err != nil {
			return err
		}
		if user.DisabledAt == nil {
			updated = user
			return nil
		}
		before := *user
		user.DisabledAt = nil
		user.UpdatedAt = p.now()
		if err := p.hooks.RunBeforeUserUpdate(ctx,
			&hook.UserUpdate{User: user, Before: &before, Tx: tx}); err != nil {
			return err
		}
		if err := tx.Users().Update(ctx, user); err != nil {
			return err
		}
		updated = user
		return nil
	})
	if err != nil {
		return nil, publicError(err)
	}
	p.hooks.RunAfterUserUpdate(ctx, &hook.UserUpdate{User: updated})
	p.emitChange(ctx, events.UserEnabled, updated, nil)
	return updated, nil
}

// ResetPassword sets a new password for one user and revokes every session of
// the user. It returns the generated password when the caller supplied none.
func (p *Plugin) ResetPassword(ctx context.Context, userID string, opts ResetOptions) (string, error) {
	if err := p.ready(); err != nil {
		return "", err
	}
	password := opts.Password
	generated := ""
	if password == "" {
		value, err := newPassword()
		if err != nil {
			return "", apierr.ErrInternal.WithCause(err)
		}
		password = value
		generated = value
	}
	hash, err := p.hashPassword(password)
	if err != nil {
		return "", err
	}
	var updated *store.User
	err = p.store.Transaction(ctx, func(tx store.Store) error {
		user, err := tx.Users().GetByID(ctx, userID)
		if err != nil {
			return err
		}
		now := p.now()
		if err := tx.Users().SetCredential(ctx, &store.Credential{
			UserID: user.ID, PasswordHash: hash, CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			return err
		}
		before := *user
		user.MustChangePassword = opts.Temporary
		user.UpdatedAt = now
		if err := p.hooks.RunBeforeUserUpdate(ctx,
			&hook.UserUpdate{User: user, Before: &before, Tx: tx}); err != nil {
			return err
		}
		if err := tx.Users().Update(ctx, user); err != nil {
			return err
		}
		// A reset by an administrator ends every session, because the person
		// who knew the old password must not keep access.
		if _, err := tx.Sessions().DeleteByUser(ctx, userID); err != nil {
			return err
		}
		updated = user
		return nil
	})
	if err != nil {
		return "", publicError(err)
	}
	p.hooks.RunAfterUserUpdate(ctx, &hook.UserUpdate{User: updated})
	p.emitChange(ctx, events.PasswordResetByAdmin, updated, map[string]any{"temporary": opts.Temporary})
	return generated, nil
}

// guardLastAdmin refuses a change that removes the last enabled administrator.
//
// The lock holds the enabled administrator rows until the transaction ends, so
// two parallel changes cannot both pass the count.
func (p *Plugin) guardLastAdmin(ctx context.Context, tx store.Store, userID string) error {
	admins, ok := tx.(store.UserAdminStore)
	if !ok {
		return apierr.ErrInternal.WithCause(errors.New("authall/admin: the store locks no user row"))
	}
	// An empty role column means the default role, so a hierarchy whose
	// default is the administrator role counts those rows too.
	roleNames := []string{p.adminRole}
	if p.roles.Default() == p.adminRole {
		roleNames = append(roleNames, "")
	}
	remaining := 0
	for _, name := range roleNames {
		ids, err := admins.LockEnabledUsersWithRole(ctx, name)
		if err != nil {
			return err
		}
		for _, id := range ids {
			if id != userID {
				remaining++
			}
		}
	}
	if remaining == 0 {
		return apierr.ErrLastAdmin
	}
	return nil
}

// roleOf returns the effective role of one user.
func (p *Plugin) roleOf(u *store.User) string {
	if u.Role == "" {
		return p.roles.Default()
	}
	return u.Role
}

// emitChange sends the specific event of one change and the generic
// UserUpdated event. The generic name gives one audit stream for every change
// of a user row, and the specific name keeps the detail.
func (p *Plugin) emitChange(ctx context.Context, name events.Name, user *store.User, fields map[string]any) {
	p.emit(ctx, name, user, fields)
	p.emit(ctx, events.UserUpdated, user, map[string]any{"change": string(name)})
}

// emit sends one audit event with the caller as the actor.
func (p *Plugin) emit(ctx context.Context, name events.Name, user *store.User, fields map[string]any) {
	actor, ok := events.ActorFrom(ctx)
	if !ok || actor.ID == "" {
		actor.ID = events.ActorSystem
	}
	p.svc.Events().EmitEvent(ctx, events.Event{
		Name:   name,
		UserID: user.ID,
		Target: user.ID,
		Actor:  actor.ID,
		Method: actor.Method,
		IP:     actor.IP,
		Fields: fields,
	})
}

// ready reports whether the plugin is registered.
func (p *Plugin) ready() error {
	if p.store == nil {
		return errors.New("authall/admin: the plugin is not registered. Use authall.WithPlugins")
	}
	return nil
}

// hashPassword hashes a password with the configured parameters of Auth-All.
func (p *Plugin) hashPassword(password string) (string, error) {
	hasher, ok := p.svc.(interface {
		HashPassword(password string) (string, error)
		CheckPassword(password string) error
	})
	if !ok {
		return "", apierr.ErrInternal.WithCause(errors.New("authall/admin: this Auth-All version hashes no password"))
	}
	if err := hasher.CheckPassword(password); err != nil {
		return "", err
	}
	return hasher.HashPassword(password)
}

// passwordAlphabet holds the characters of a generated password. It has no
// character that a person confuses with another one.
const passwordAlphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// newPassword returns a password from crypto/rand.
func newPassword() (string, error) {
	var b strings.Builder
	raw := make([]byte, temporaryPasswordLength)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	for _, value := range raw {
		b.WriteByte(passwordAlphabet[int(value)%len(passwordAlphabet)])
	}
	return b.String(), nil
}

// publicError maps a store error to the public contract.
func publicError(err error) error {
	if err == nil {
		return nil
	}
	var public *apierr.Error
	if errors.As(err, &public) {
		return public
	}
	if errors.Is(err, store.ErrNotFound) {
		return apierr.ErrNotFound
	}
	if errors.Is(err, store.ErrConflict) {
		return apierr.ErrEmailAlreadyExists
	}
	return apierr.ErrInternal.WithCause(fmt.Errorf("authall/admin: %w", err))
}
