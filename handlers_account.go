package authall

import (
	"context"
	"net/http"

	"github.com/alternayte/auth-all/apierr"
	"github.com/alternayte/auth-all/events"
	"github.com/alternayte/auth-all/hook"
	"github.com/alternayte/auth-all/internal/crypto"
	"github.com/alternayte/auth-all/openapi"
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
