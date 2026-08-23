package authall

import (
	"context"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/alternayte/auth-all/apierr"
	"github.com/alternayte/auth-all/email"
	"github.com/alternayte/auth-all/events"
	"github.com/alternayte/auth-all/hook"
	"github.com/alternayte/auth-all/store"
)

// checkPassword applies the configured password policy.
func (a *Auth) checkPassword(password string) error {
	n := utf8.RuneCountInString(password)
	if n < a.cfg.passwordPolicy.MinLength || n > a.cfg.passwordPolicy.MaxLength {
		return apierr.ErrWeakPassword
	}
	return nil
}

// createUser inserts a user and an optional password credential in one
// transaction.
func (a *Auth) createUser(ctx context.Context, in CreateUserInput, passwordHash string) (*store.User, error) {
	normalized := email.Normalize(in.Email)
	if normalized == "" || !email.Valid(normalized) {
		return nil, apierr.ErrInvalidRequest.WithMessage("The email address is invalid.")
	}
	now := a.cfg.now()
	user := &store.User{
		ID:              uuid.NewString(),
		Email:           in.Email,
		EmailNormalized: normalized,
		DisplayName:     in.DisplayName,
		ImageURL:        in.ImageURL,
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	if in.EmailVerified {
		verified := now
		user.EmailVerifiedAt = &verified
	}
	ev := &hook.UserCreate{User: user}
	err := a.cfg.store.Transaction(ctx, func(tx store.Store) error {
		ev.Tx = tx
		if err := a.hooks.RunBeforeUserCreate(ctx, ev); err != nil {
			return err
		}
		if err := tx.Users().Create(ctx, user); err != nil {
			return err
		}
		if passwordHash != "" {
			return tx.Users().SetCredential(ctx, &store.Credential{
				UserID: user.ID, PasswordHash: passwordHash, CreatedAt: now, UpdatedAt: now,
			})
		}
		return nil
	})
	if err != nil {
		if isConflict(err) {
			return nil, apierr.ErrEmailAlreadyExists
		}
		return nil, publicError(err)
	}
	ev.Tx = nil
	a.hooks.RunAfterUserCreate(ctx, ev)
	a.emitter.Emit(ctx, events.SignUp, user.ID, map[string]any{"email_verified": in.EmailVerified})
	return user, nil
}

// markEmailVerified records proven ownership of the user email address.
func (a *Auth) markEmailVerified(ctx context.Context, userID string) error {
	user, err := a.cfg.store.Users().GetByID(ctx, userID)
	if err != nil {
		return publicError(err)
	}
	if user.EmailVerifiedAt != nil {
		return nil
	}
	now := a.cfg.now()
	user.EmailVerifiedAt = &now
	user.UpdatedAt = now
	if err := a.cfg.store.Users().Update(ctx, user); err != nil {
		return publicError(err)
	}
	a.emitter.Emit(ctx, events.EmailVerified, user.ID, nil)
	return nil
}
