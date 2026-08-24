package authall

import (
	"context"
	"net/http"

	"github.com/alternayte/auth-all/apierr"
	"github.com/alternayte/auth-all/email"
	"github.com/alternayte/auth-all/events"
	"github.com/alternayte/auth-all/hook"
	"github.com/alternayte/auth-all/internal/crypto"
	"github.com/alternayte/auth-all/openapi"
	"github.com/alternayte/auth-all/plugin"
	"github.com/alternayte/auth-all/ratelimit"
	"github.com/alternayte/auth-all/store"
)

// registerAccountRoutes mounts the account management endpoints of the email
// and password flow.
func (a *Auth) registerAccountRoutes() {
	tag := []string{"email-password"}

	a.handle(http.MethodPost, "/password/change", a.handlePasswordChange, operation(
		"passwordChange", "Change the password of the current user", tag,
		openapi.JSONBody(openapi.Object([]string{"currentPassword", "newPassword"},
			map[string]*openapi.Schema{
				"currentPassword":     openapi.String(),
				"newPassword":         openapi.String(),
				"revokeOtherSessions": openapi.Bool(),
			})),
		"The password is changed", openapi.Ref("SuccessResponse"),
		&openapi.ClientBinding{Namespace: "password", Method: "change"},
		"400", "401", "403", "429"))

	a.handle(http.MethodPost, "/email/change", a.handleEmailChange, operation(
		"emailChange", "Request a change of the email address", tag,
		openapi.JSONBody(openapi.Object([]string{"newEmail"},
			map[string]*openapi.Schema{
				"newEmail":        openapi.String(),
				"currentPassword": openapi.String(),
			})),
		"An enumeration-safe acknowledgement", openapi.Ref("MessageResponse"),
		&openapi.ClientBinding{Namespace: "email", Method: "change"},
		"400", "401", "403", "429"))

	a.handle(http.MethodPost, "/email/change/verify", a.handleEmailChangeVerify, operation(
		"emailChangeVerify", "Complete a change of the email address", tag,
		openapi.JSONBody(openapi.Object([]string{"token"},
			map[string]*openapi.Schema{"token": openapi.String()})),
		"The address is changed", openapi.Ref("SuccessResponse"),
		&openapi.ClientBinding{Namespace: "email", Method: "changeVerify"},
		"400", "403", "409"))

	a.handle(http.MethodPost, "/user/delete", a.handleUserDelete, operation(
		"userDelete", "Delete the account of the current user", []string{"user"},
		openapi.JSONBody(openapi.Object(nil,
			map[string]*openapi.Schema{"currentPassword": openapi.String()})),
		"The account is deleted, or a confirmation is sent", openapi.Ref("DeleteResponse"),
		&openapi.ClientBinding{Namespace: "user", Method: "delete"},
		"400", "401", "403", "429"))

	a.handle(http.MethodPost, "/user/delete/verify", a.handleUserDeleteVerify, operation(
		"userDeleteVerify", "Complete an account delete with a token", []string{"user"},
		openapi.JSONBody(openapi.Object([]string{"token"},
			map[string]*openapi.Schema{"token": openapi.String()})),
		"The account is deleted", openapi.Ref("DeleteResponse"),
		&openapi.ClientBinding{Namespace: "user", Method: "deleteVerify"},
		"400", "403"))
}

type userDeleteRequest struct {
	// CurrentPassword is required for a user that has a password credential.
	CurrentPassword string `json:"currentPassword"`
}

func (a *Auth) handleUserDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := a.checkOrigin(r); err != nil {
		a.writeError(w, err)
		return
	}
	sess, user := a.requireSession(w, r)
	if sess == nil {
		return
	}
	var req userDeleteRequest
	if err := a.decodeJSON(r, &req); err != nil {
		a.writeError(w, err)
		return
	}
	if !a.allow(ctx, w, ratelimit.Key{
		Operation: ratelimit.OpUserDelete, IP: a.clientIP(r), UserID: user.ID,
	}) {
		return
	}
	cred, err := a.cfg.store.Users().GetCredential(ctx, user.ID)
	if err != nil && !isNotFound(err) {
		a.writeError(w, apierr.ErrInternal.WithCause(err))
		return
	}
	if cred == nil {
		// A user with no password proves control of the address instead.
		if err := a.sendDeleteConfirmation(ctx, user); err != nil {
			a.writeError(w, err)
			return
		}
		a.writeJSON(w, http.StatusOK, deleteResponse{ConfirmationRequired: true})
		return
	}
	ok, _, err := crypto.VerifyPassword(req.CurrentPassword, cred.PasswordHash)
	if err != nil {
		a.writeError(w, apierr.ErrInternal.WithCause(err))
		return
	}
	if !ok {
		a.emitter.Emit(ctx, events.SignInFailed, user.ID, map[string]any{"reason": "user_delete_denied"})
		a.writeError(w, apierr.ErrInvalidCredentials)
		return
	}
	if err := a.deleteUser(ctx, user); err != nil {
		a.writeError(w, err)
		return
	}
	a.clearCookie(w)
	a.writeJSON(w, http.StatusOK, deleteResponse{Success: true})
}

type userDeleteVerifyRequest struct {
	Token string `json:"token"`
}

func (a *Auth) handleUserDeleteVerify(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := a.checkOrigin(r); err != nil {
		a.writeError(w, err)
		return
	}
	var req userDeleteVerifyRequest
	if err := a.decodeJSON(r, &req); err != nil {
		a.writeError(w, err)
		return
	}
	// The consumed token names the user, so the endpoint needs no session.
	tok, err := a.consumeToken(ctx, tokenKindDeleteAccount, req.Token)
	if err != nil {
		a.writeError(w, err)
		return
	}
	if tok.UserID == nil {
		a.writeError(w, apierr.ErrInvalidToken)
		return
	}
	user, err := a.cfg.store.Users().GetByID(ctx, *tok.UserID)
	if err != nil {
		a.writeError(w, publicError(err))
		return
	}
	if err := a.deleteUser(ctx, user); err != nil {
		a.writeError(w, err)
		return
	}
	a.clearCookie(w)
	a.writeJSON(w, http.StatusOK, deleteResponse{Success: true})
}

// sendDeleteConfirmation issues a delete token and sends it to the address of
// the user.
func (a *Auth) sendDeleteConfirmation(ctx context.Context, user *store.User) error {
	if a.cfg.sender == nil {
		a.cfg.logger.Error("authall: an account delete confirmation needs an email sender")
		return apierr.ErrInternal
	}
	token, tok, err := a.issueToken(ctx, plugin.IssueTokenInput{
		Kind:            tokenKindDeleteAccount,
		UserID:          &user.ID,
		Identifier:      user.EmailNormalized,
		TTL:             a.cfg.tokenTTL.PasswordReset,
		ReplaceExisting: true,
	})
	if err != nil {
		return err
	}
	msg := email.Message{
		Intent:    email.IntentDeleteAccount,
		To:        user.Email,
		UserID:    user.ID,
		Token:     token,
		URL:       a.actionURL(a.cfg.emailPassword.DeleteAccountURL, "/delete-account", token, ""),
		ExpiresAt: tok.ExpiresAt,
	}
	if err := a.cfg.sender.Send(ctx, msg); err != nil {
		return apierr.ErrInternal.WithCause(err)
	}
	return nil
}

// deleteUser removes a user and every owned row. It emits the event first, so
// an application can still read the owned data.
func (a *Auth) deleteUser(ctx context.Context, user *store.User) error {
	a.emitter.Emit(ctx, events.UserDeleted, user.ID, map[string]any{"email": user.Email})
	if err := a.cfg.store.Users().Delete(ctx, user.ID); err != nil {
		return publicError(err)
	}
	return nil
}

// messageEmailChangeSent is the enumeration-safe response of a change request.
const messageEmailChangeSent = "If the address can receive a confirmation, one has been sent."

type emailChangeRequest struct {
	NewEmail string `json:"newEmail"`
	// CurrentPassword is required for a user that has a password credential.
	CurrentPassword string `json:"currentPassword"`
}

func (a *Auth) handleEmailChange(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := a.checkOrigin(r); err != nil {
		a.writeError(w, err)
		return
	}
	sess, user := a.requireSession(w, r)
	if sess == nil {
		return
	}
	var req emailChangeRequest
	if err := a.decodeJSON(r, &req); err != nil {
		a.writeError(w, err)
		return
	}
	if !a.allow(ctx, w, ratelimit.Key{
		Operation: ratelimit.OpEmailChange, IP: a.clientIP(r), UserID: user.ID,
	}) {
		return
	}
	normalized := email.Normalize(req.NewEmail)
	if !email.Valid(normalized) {
		// The format of an address is public knowledge, so this answer
		// discloses nothing about another account.
		a.writeError(w, apierr.ErrInvalidRequest.WithMessage("The email address is invalid."))
		return
	}
	// A user with a password proves the password. A user without one, for
	// example an account that only signs in through a provider, skips the
	// check. See docs/guides/email-password.md.
	cred, err := a.cfg.store.Users().GetCredential(ctx, user.ID)
	if err != nil && !isNotFound(err) {
		a.writeError(w, apierr.ErrInternal.WithCause(err))
		return
	}
	if cred != nil {
		ok, _, err := crypto.VerifyPassword(req.CurrentPassword, cred.PasswordHash)
		if err != nil {
			a.writeError(w, apierr.ErrInternal.WithCause(err))
			return
		}
		if !ok {
			a.emitter.Emit(ctx, events.SignInFailed, user.ID, map[string]any{"reason": "email_change_denied"})
			a.writeError(w, apierr.ErrInvalidCredentials)
			return
		}
	}

	// The response never discloses whether the new address is taken.
	defer a.writeJSON(w, http.StatusOK, messageResponse{Message: messageEmailChangeSent})

	if a.cfg.sender == nil {
		a.cfg.logger.Error("authall: an email change needs an email sender")
		return
	}
	if _, err := a.cfg.store.Users().GetByNormalizedEmail(ctx, normalized); err == nil {
		// The address belongs to somebody, and it can be the caller. The flow
		// stops here, so no message reaches the owner of the address.
		return
	} else if !isNotFound(err) {
		a.cfg.logger.Error("authall: cannot read the user", "error", err.Error())
		return
	}
	token, tok, err := a.issueToken(ctx, plugin.IssueTokenInput{
		Kind:            tokenKindChangeEmail,
		UserID:          &user.ID,
		Identifier:      normalized,
		TTL:             a.cfg.tokenTTL.EmailVerification,
		ReplaceExisting: true,
	})
	if err != nil {
		a.cfg.logger.Error("authall: cannot issue a change token", "error", err.Error())
		return
	}
	confirmation := email.Message{
		Intent:    email.IntentEmailChange,
		To:        normalized,
		UserID:    user.ID,
		Token:     token,
		URL:       a.actionURL(a.cfg.emailPassword.ChangeEmailURL, "/change-email", token, ""),
		ExpiresAt: tok.ExpiresAt,
		Data:      map[string]string{"oldEmail": user.Email, "newEmail": normalized},
	}
	if err := a.cfg.sender.Send(ctx, confirmation); err != nil {
		a.cfg.logger.Error("authall: cannot send the change confirmation", "error", err.Error())
		return
	}
	// The old address learns about the request. The message carries no token
	// and no link, so it cannot complete the change.
	notice := email.Message{
		Intent: email.IntentEmailChangeNotice,
		To:     user.Email,
		UserID: user.ID,
		Data:   map[string]string{"oldEmail": user.Email, "newEmail": normalized},
	}
	if err := a.cfg.sender.Send(ctx, notice); err != nil {
		a.cfg.logger.Error("authall: cannot send the change notice", "error", err.Error())
	}
	a.emitter.Emit(ctx, events.EmailChangeRequested, user.ID, nil)
}

type emailChangeVerifyRequest struct {
	Token string `json:"token"`
}

func (a *Auth) handleEmailChangeVerify(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := a.checkOrigin(r); err != nil {
		a.writeError(w, err)
		return
	}
	var req emailChangeVerifyRequest
	if err := a.decodeJSON(r, &req); err != nil {
		a.writeError(w, err)
		return
	}
	// The consumed token names the user, so the endpoint needs no session.
	tok, err := a.consumeToken(ctx, tokenKindChangeEmail, req.Token)
	if err != nil {
		a.writeError(w, err)
		return
	}
	if tok.UserID == nil {
		a.writeError(w, apierr.ErrInvalidToken)
		return
	}
	user, err := a.cfg.store.Users().GetByID(ctx, *tok.UserID)
	if err != nil {
		a.writeError(w, publicError(err))
		return
	}
	now := a.cfg.now()
	// The address stays in its normalized form, because the token carries only
	// that form. Normalization lowercases the address and changes nothing else.
	updated := *user
	updated.Email = tok.Identifier
	updated.EmailNormalized = tok.Identifier
	updated.EmailVerifiedAt = &now
	updated.UpdatedAt = now
	if err := a.cfg.store.Users().Update(ctx, &updated); err != nil {
		if isConflict(err) {
			// Somebody took the address between the request and the
			// confirmation.
			a.writeError(w, apierr.ErrEmailAlreadyExists)
			return
		}
		a.writeError(w, publicError(err))
		return
	}
	// The address changed, so every session except the current one ends.
	current, _, err := a.resolveSession(ctx, r)
	keep := ""
	if err == nil && current != nil && current.UserID == updated.ID {
		keep = current.ID
	}
	a.revokeOtherSessions(ctx, updated.ID, keep)
	a.emitter.Emit(ctx, events.EmailChanged, updated.ID, nil)
	a.writeJSON(w, http.StatusOK, successResponse{Success: true})
}

type passwordChangeRequest struct {
	CurrentPassword string `json:"currentPassword"`
	NewPassword     string `json:"newPassword"`
	// RevokeOtherSessions defaults to true. A pointer separates an absent
	// field from an explicit false.
	RevokeOtherSessions *bool `json:"revokeOtherSessions"`
}

func (a *Auth) handlePasswordChange(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := a.checkOrigin(r); err != nil {
		a.writeError(w, err)
		return
	}
	sess, user := a.requireSession(w, r)
	if sess == nil {
		return
	}
	var req passwordChangeRequest
	if err := a.decodeJSON(r, &req); err != nil {
		a.writeError(w, err)
		return
	}
	if !a.allow(ctx, w, ratelimit.Key{
		Operation: ratelimit.OpPasswordChange, IP: a.clientIP(r), UserID: user.ID,
	}) {
		return
	}
	if err := a.checkPassword(req.NewPassword); err != nil {
		a.writeError(w, err)
		return
	}
	cred, err := a.cfg.store.Users().GetCredential(ctx, user.ID)
	if err != nil {
		if isNotFound(err) {
			// An OAuth-only user has no password to replace. The reset flow
			// sets the first one.
			a.writeError(w, apierr.ErrNoPasswordCredential)
			return
		}
		a.writeError(w, apierr.ErrInternal.WithCause(err))
		return
	}
	ok, _, err := crypto.VerifyPassword(req.CurrentPassword, cred.PasswordHash)
	if err != nil {
		a.writeError(w, apierr.ErrInternal.WithCause(err))
		return
	}
	if !ok {
		a.emitter.Emit(ctx, events.SignInFailed, user.ID, map[string]any{"reason": "password_change_denied"})
		a.writeError(w, apierr.ErrInvalidCredentials)
		return
	}
	hash, err := crypto.HashPassword(req.NewPassword, a.cfg.argon)
	if err != nil {
		a.writeError(w, apierr.ErrInternal.WithCause(err))
		return
	}
	now := a.cfg.now()
	err = a.cfg.store.Transaction(ctx, func(tx store.Store) error {
		return tx.Users().SetCredential(ctx, &store.Credential{
			UserID: user.ID, PasswordHash: hash, CreatedAt: now, UpdatedAt: now,
		})
	})
	if err != nil {
		a.writeError(w, publicError(err))
		return
	}
	if req.RevokeOtherSessions == nil || *req.RevokeOtherSessions {
		a.revokeOtherSessions(ctx, user.ID, sess.ID)
	}
	a.hooks.RunAfterPasswordChange(ctx, &hook.PasswordChange{User: user})
	a.emitter.Emit(ctx, events.PasswordChanged, user.ID, nil)
	a.writeJSON(w, http.StatusOK, successResponse{Success: true})
}

// revokeOtherSessions deletes every session of a user except one. It logs a
// failure and does not fail the request, because the main change succeeded.
func (a *Auth) revokeOtherSessions(ctx context.Context, userID, keepID string) int {
	list, err := a.cfg.store.Sessions().ListByUser(ctx, userID)
	if err != nil {
		a.cfg.logger.Error("authall: cannot read the sessions", "error", err.Error())
		return 0
	}
	revoked := 0
	for _, item := range list {
		if item.ID == keepID {
			continue
		}
		if err := a.cfg.store.Sessions().Delete(ctx, item.ID); err != nil && !isNotFound(err) {
			a.cfg.logger.Error("authall: cannot revoke a session", "error", err.Error())
			continue
		}
		revoked++
		a.hooks.RunAfterSignOut(ctx, &hook.SignOut{UserID: userID, SessionID: item.ID})
	}
	return revoked
}
