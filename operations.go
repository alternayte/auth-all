package authall

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/alternayte/auth-all/apierr"
	"github.com/alternayte/auth-all/email"
	"github.com/alternayte/auth-all/events"
	"github.com/alternayte/auth-all/hook"
	"github.com/alternayte/auth-all/internal/crypto"
	"github.com/alternayte/auth-all/ratelimit"
	"github.com/alternayte/auth-all/store"
)

// The operations in this file are the Go form of the sign-in, the sign-out,
// and the password change. An application that serves its own routes calls
// them, so it keeps its own paths, its own body shape, and its own error
// envelope. The HTTP routes of Auth-All call the same code, so the two forms
// never drift.

// RateLimitError reports a refused attempt and the time to wait. It wraps
// apierr.ErrRateLimited, so a caller that maps the public error contract keeps
// the code RATE_LIMITED.
type RateLimitError struct {
	// RetryAfter is the time until the next attempt. A limiter that names none
	// gives one minute.
	RetryAfter time.Duration
}

// Error implements the error interface.
func (e *RateLimitError) Error() string { return apierr.ErrRateLimited.Error() }

// Unwrap returns the public error of the contract.
func (e *RateLimitError) Unwrap() error { return apierr.ErrRateLimited }

// SignInInput names one password sign-in.
type SignInInput struct {
	// Email is the address of the account. The comparison uses the normalized
	// form.
	Email string
	// Password is the plaintext password of the attempt.
	Password string
	// ClientIP is the address of the caller. The rate limit counts the attempt
	// against it. An empty value counts the address only.
	ClientIP string
	// PreviousSessionToken names a session of the caller that the sign-in
	// replaces. The HTTP route passes the token of the request, so no old
	// session survives a new sign-in.
	PreviousSessionToken string
}

// SignInResult is the outcome of one password sign-in.
type SignInResult struct {
	// User is the account of the sign-in. It is never nil on success.
	User *store.User
	// Session is the new session. It is nil when a second factor is required.
	Session *store.Session
	// Token is the plaintext session token. It exists one time, here. A host
	// that serves a browser writes it with SetSessionCookie. A host that
	// serves a bearer client returns it to the client.
	Token string
	// MFARequired reports that the user holds a confirmed second factor. No
	// session exists until the second proof.
	MFARequired bool
	// MFAToken is the challenge of the second factor. It is empty when no
	// second factor is required.
	MFAToken string
}

// SignIn verifies an email address and a password.
//
// It returns a session, or a challenge when the user holds a confirmed second
// factor. It writes no cookie and no response, so the caller owns the
// transport. SetSessionCookie writes the cookie of a browser.
//
// An unknown address and a wrong password give one error, and they cost equal
// work, so neither the response nor the response time discloses whether the
// account exists.
func (a *Auth) SignIn(ctx context.Context, in SignInInput) (*SignInResult, error) {
	normalized := email.Normalize(in.Email)
	if err := a.checkLimit(ctx, ratelimit.Key{
		Operation: ratelimit.OpSignIn, IP: in.ClientIP, Email: normalized,
	}); err != nil {
		return nil, err
	}

	user, err := a.cfg.store.Users().GetByNormalizedEmail(ctx, normalized)
	if err != nil && !isNotFound(err) {
		return nil, apierr.ErrInternal.WithCause(err)
	}
	var cred *store.Credential
	if user != nil {
		cred, err = a.cfg.store.Users().GetCredential(ctx, user.ID)
		if err != nil && !isNotFound(err) {
			return nil, apierr.ErrInternal.WithCause(err)
		}
	}
	if cred == nil {
		// The work is equal for a known and an unknown address, so the
		// response time does not disclose whether the account exists.
		_, _, _ = crypto.VerifyPassword(in.Password, a.dummyPasswordHash())
		a.emitter.Emit(ctx, events.SignInFailed, "", map[string]any{
			"reason": "unknown_credential", "email_digest": crypto.HashToken(normalized)})
		return nil, apierr.ErrInvalidCredentials
	}
	ok, params, err := crypto.VerifyPassword(in.Password, cred.PasswordHash)
	if err != nil {
		return nil, apierr.ErrInternal.WithCause(err)
	}
	if !ok {
		a.emitter.Emit(ctx, events.SignInFailed, user.ID, map[string]any{
			"reason": "invalid_password", "email_digest": crypto.HashToken(normalized)})
		return nil, apierr.ErrInvalidCredentials
	}
	if user.DisabledAt != nil {
		// The response names the disabled account only after a correct
		// password, so it tells nothing to a caller without the password.
		a.emitter.Emit(ctx, events.SignInFailed, user.ID, map[string]any{
			"reason": "user_disabled", "email_digest": crypto.HashToken(normalized)})
		return nil, apierr.ErrUserDisabled
	}
	if a.cfg.emailPassword.RequireEmailVerification && user.EmailVerifiedAt == nil {
		a.emitter.Emit(ctx, events.SignInFailed, user.ID, map[string]any{
			"reason": "email_not_verified", "email_digest": crypto.HashToken(normalized)})
		return nil, apierr.ErrEmailNotVerified
	}
	if crypto.NeedsRehash(params, a.cfg.argon) {
		if fresh, err := crypto.HashPassword(in.Password, a.cfg.argon); err == nil {
			cred.PasswordHash = fresh
			cred.UpdatedAt = a.cfg.now()
			if err := a.cfg.store.Users().SetCredential(ctx, cred); err != nil {
				a.cfg.logger.Error("authall: cannot rehash the password", "error", err.Error())
			}
		}
	}

	// The password is proven. A user with a live second factor receives a
	// challenge instead of a session, so no credential exists before the
	// second proof.
	challenge, required, err := a.mfaChallenge(ctx, user)
	if err != nil {
		return nil, err
	}
	if required {
		return &SignInResult{User: user, MFARequired: true, MFAToken: challenge}, nil
	}
	sess, token, err := a.createSession(ctx, user, "email", in.PreviousSessionToken)
	if err != nil {
		return nil, err
	}
	return &SignInResult{User: user, Session: sess, Token: token}, nil
}

// SignOut ends one session.
//
// It runs the sign-out hook and emits the audit event, which RevokeSession
// does not. A nil session and a session that is already gone are no error, so
// a repeated sign-out is safe. The caller removes the cookie with
// ClearSessionCookie.
func (a *Auth) SignOut(ctx context.Context, session *store.Session) error {
	if session == nil {
		return nil
	}
	if err := a.cfg.store.Sessions().Delete(ctx, session.ID); err != nil && !isNotFound(err) {
		return apierr.ErrInternal.WithCause(err)
	}
	a.hooks.RunAfterSignOut(ctx, &hook.SignOut{UserID: session.UserID, SessionID: session.ID})
	a.emitter.Emit(ctx, events.SignOut, session.UserID, map[string]any{"session_id": session.ID})
	return nil
}

// SignOutToken ends the session of one plaintext session token. An unknown
// token is no error, so a repeated sign-out is safe.
func (a *Auth) SignOutToken(ctx context.Context, token string) error {
	if token == "" {
		return nil
	}
	sess, err := a.cfg.store.Sessions().GetByTokenHash(ctx, crypto.HashToken(token))
	if err != nil {
		if isNotFound(err) {
			return nil
		}
		return apierr.ErrInternal.WithCause(err)
	}
	return a.SignOut(ctx, sess)
}

// ChangePasswordInput names one password change of the owner of the account.
type ChangePasswordInput struct {
	// UserID is the owner of the password.
	UserID string
	// CurrentPassword is the password of the account. The change needs it, so
	// a stolen session alone cannot replace a password.
	CurrentPassword string
	// NewPassword must meet the configured password policy.
	NewPassword string
	// KeepSessionID keeps one session when the change revokes the others. The
	// caller names the session of the request here.
	KeepSessionID string
	// KeepOtherSessions keeps every other session of the user. The zero value
	// revokes them, because a password change must end a stolen session.
	KeepOtherSessions bool
	// ClientIP is the address of the caller. The rate limit counts the attempt
	// against it.
	ClientIP string
}

// ChangePassword replaces the password of the owner of the account.
//
// The change needs the current password. It revokes every other session of the
// user, and it clears the temporary password state in the same transaction.
func (a *Auth) ChangePassword(ctx context.Context, in ChangePasswordInput) error {
	user, err := a.GetUser(ctx, in.UserID)
	if err != nil {
		return err
	}
	if err := a.checkLimit(ctx, ratelimit.Key{
		Operation: ratelimit.OpPasswordChange, IP: in.ClientIP, UserID: user.ID,
	}); err != nil {
		return err
	}
	if err := a.checkPassword(in.NewPassword); err != nil {
		return err
	}
	cred, err := a.cfg.store.Users().GetCredential(ctx, user.ID)
	if err != nil {
		if isNotFound(err) {
			// An OAuth-only user has no password to replace. The reset flow
			// sets the first one.
			return apierr.ErrNoPasswordCredential
		}
		return apierr.ErrInternal.WithCause(err)
	}
	ok, _, err := crypto.VerifyPassword(in.CurrentPassword, cred.PasswordHash)
	if err != nil {
		return apierr.ErrInternal.WithCause(err)
	}
	if !ok {
		a.emitter.Emit(ctx, events.SignInFailed, user.ID, map[string]any{"reason": "password_change_denied"})
		return apierr.ErrInvalidCredentials
	}
	hash, err := crypto.HashPassword(in.NewPassword, a.cfg.argon)
	if err != nil {
		return apierr.ErrInternal.WithCause(err)
	}
	now := a.cfg.now()
	err = a.cfg.store.Transaction(ctx, func(tx store.Store) error {
		if err := tx.Users().SetCredential(ctx, &store.Credential{
			UserID: user.ID, PasswordHash: hash, CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			return err
		}
		if !user.MustChangePassword {
			return nil
		}
		// The user leaves the temporary password state in the same
		// transaction, so no instance sees a changed password with the flag.
		user.MustChangePassword = false
		user.UpdatedAt = now
		return tx.Users().Update(ctx, user)
	})
	if err != nil {
		return publicError(err)
	}
	if !in.KeepOtherSessions {
		a.revokeOtherSessions(ctx, user.ID, in.KeepSessionID)
	}
	a.hooks.RunAfterPasswordChange(ctx, &hook.PasswordChange{User: user})
	a.emitter.Emit(ctx, events.PasswordChanged, user.ID, nil)
	return nil
}

// SetSessionCookie writes the session cookie of one token. A host that serves
// a browser calls it with the token of a SignInResult.
func (a *Auth) SetSessionCookie(w http.ResponseWriter, token string, expiresAt time.Time) {
	http.SetCookie(w, a.sessionCookie(token, expiresAt))
}

// ClearSessionCookie removes the session cookie. A host calls it after a
// sign-out.
func (a *Auth) ClearSessionCookie(w http.ResponseWriter) { a.clearCookie(w) }

// checkLimit asks the configured limiter about one attempt. It returns a
// RateLimitError when the limiter refuses it.
//
// A limiter that names a retry time fails closed, because it uses the database
// that the flow uses, and a failure fails the flow anyway. A v1 limiter keeps
// the v1 behavior, so a limiter failure lets the attempt through.
func (a *Auth) checkLimit(ctx context.Context, key ratelimit.Key) error {
	if decider, ok := a.cfg.limiter.(ratelimit.Decider); ok {
		decision, err := decider.Decide(ctx, key)
		if err != nil {
			a.cfg.logger.Error("authall: the rate limiter failed", "error", err.Error())
			return apierr.ErrInternal.WithCause(err)
		}
		if decision.Allowed {
			return nil
		}
		return &RateLimitError{RetryAfter: decision.RetryAfter}
	}
	ok, err := a.cfg.limiter.Allow(ctx, key)
	if err != nil {
		// A v1 limiter keeps the v1 behavior. A limiter failure lets the
		// attempt through.
		a.cfg.logger.Error("authall: the rate limiter failed", "error", err.Error())
		return nil
	}
	if ok {
		return nil
	}
	// A v1 limiter names no retry time, so the caller asks for one minute.
	// REQ-RL-011 keeps this value.
	return &RateLimitError{RetryAfter: time.Minute}
}

// asRateLimit reports whether err is a RateLimitError, and it stores it.
func asRateLimit(err error, target **RateLimitError) bool {
	return errors.As(err, target)
}
