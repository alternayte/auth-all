package authall

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/alternayte/auth-all/apierr"
	"github.com/alternayte/auth-all/email"
	"github.com/alternayte/auth-all/events"
	"github.com/alternayte/auth-all/hook"
	"github.com/alternayte/auth-all/internal/crypto"
	"github.com/alternayte/auth-all/plugin"
	"github.com/alternayte/auth-all/ratelimit"
	"github.com/alternayte/auth-all/store"
)

// actionURL builds the application link that carries a one-time token.
func (a *Auth) actionURL(configured, defaultPath, token, redirectTo string) string {
	base := configured
	if base == "" {
		base = a.cfg.baseURL + defaultPath
	}
	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	link := base + sep + "token=" + url.QueryEscape(token)
	if redirectTo != "" {
		link += "&redirectTo=" + url.QueryEscape(redirectTo)
	}
	return link
}

func (a *Auth) sendVerificationEmail(ctx context.Context, user *store.User, redirectTo string) error {
	if a.cfg.sender == nil {
		return apierr.ErrInternal.WithMessage("An internal error occurred.")
	}
	token, tok, err := a.issueToken(ctx, plugin.IssueTokenInput{
		Kind:            tokenKindVerifyEmail,
		UserID:          &user.ID,
		Identifier:      user.EmailNormalized,
		TTL:             a.cfg.tokenTTL.EmailVerification,
		ReplaceExisting: true,
	})
	if err != nil {
		return err
	}
	msg := email.Message{
		Intent:    email.IntentVerifyEmail,
		To:        user.Email,
		UserID:    user.ID,
		Token:     token,
		URL:       a.actionURL(a.cfg.emailPassword.VerifyEmailURL, "/verify-email", token, redirectTo),
		ExpiresAt: tok.ExpiresAt,
	}
	if err := a.cfg.sender.Send(ctx, msg); err != nil {
		return apierr.ErrInternal.WithCause(err)
	}
	return nil
}

type emailOnlyRequest struct {
	Email      string `json:"email"`
	RedirectTo string `json:"redirectTo"`
}

func (a *Auth) handlePasswordForgot(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := a.checkOrigin(r); err != nil {
		a.writeError(w, err)
		return
	}
	var req emailOnlyRequest
	if err := a.decodeJSON(r, &req); err != nil {
		a.writeError(w, err)
		return
	}
	normalized := email.Normalize(req.Email)
	if !a.allow(ctx, w, ratelimit.Key{Operation: ratelimit.OpPasswordForgot, IP: clientIP(r), Email: normalized}) {
		return
	}
	// The response never discloses whether the account exists.
	defer a.writeJSON(w, http.StatusOK, messageResponse{Message: messageResetSent})

	if !email.Valid(normalized) {
		return
	}
	user, err := a.cfg.store.Users().GetByNormalizedEmail(ctx, normalized)
	if err != nil {
		if !isNotFound(err) {
			a.cfg.logger.Error("authall: cannot read the user", "error", err.Error())
		}
		return
	}
	if a.cfg.sender == nil {
		a.cfg.logger.Error("authall: a password reset needs an email sender")
		return
	}
	token, tok, err := a.issueToken(ctx, plugin.IssueTokenInput{
		Kind:            tokenKindResetPassword,
		UserID:          &user.ID,
		Identifier:      user.EmailNormalized,
		TTL:             a.cfg.tokenTTL.PasswordReset,
		ReplaceExisting: true,
	})
	if err != nil {
		a.cfg.logger.Error("authall: cannot issue a reset token", "error", err.Error())
		return
	}
	redirect := a.safeRedirect(req.RedirectTo, "")
	msg := email.Message{
		Intent:    email.IntentResetPassword,
		To:        user.Email,
		UserID:    user.ID,
		Token:     token,
		URL:       a.actionURL(a.cfg.emailPassword.ResetPasswordURL, "/reset-password", token, redirect),
		ExpiresAt: tok.ExpiresAt,
	}
	if err := a.cfg.sender.Send(ctx, msg); err != nil {
		a.cfg.logger.Error("authall: cannot send the reset message", "error", err.Error())
		return
	}
	a.emitter.Emit(ctx, events.PasswordResetRequested, user.ID, nil)
}

type passwordResetRequest struct {
	Token    string `json:"token"`
	Password string `json:"password"`
}

func (a *Auth) handlePasswordReset(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := a.checkOrigin(r); err != nil {
		a.writeError(w, err)
		return
	}
	var req passwordResetRequest
	if err := a.decodeJSON(r, &req); err != nil {
		a.writeError(w, err)
		return
	}
	if err := a.checkPassword(req.Password); err != nil {
		a.writeError(w, err)
		return
	}
	tok, err := a.consumeToken(ctx, tokenKindResetPassword, req.Token)
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
	hash, err := crypto.HashPassword(req.Password, a.cfg.argon)
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
	// Every existing session ends, because the password owner can have lost
	// control of the account.
	if _, err := a.cfg.store.Sessions().DeleteByUser(ctx, user.ID); err != nil {
		a.cfg.logger.Error("authall: cannot revoke the sessions", "error", err.Error())
	}
	a.hooks.RunAfterPasswordChange(ctx, &hook.PasswordChange{User: user})
	a.emitter.Emit(ctx, events.PasswordChanged, user.ID, nil)
	a.clearCookie(w)
	a.writeJSON(w, http.StatusOK, successResponse{Success: true})
}

func (a *Auth) handleVerificationSend(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := a.checkOrigin(r); err != nil {
		a.writeError(w, err)
		return
	}
	var req emailOnlyRequest
	if err := a.decodeJSON(r, &req); err != nil {
		a.writeError(w, err)
		return
	}
	normalized := email.Normalize(req.Email)
	if !a.allow(ctx, w, ratelimit.Key{Operation: ratelimit.OpEmailVerify, IP: clientIP(r), Email: normalized}) {
		return
	}
	defer a.writeJSON(w, http.StatusOK, messageResponse{Message: messageVerifySent})

	if !email.Valid(normalized) {
		return
	}
	user, err := a.cfg.store.Users().GetByNormalizedEmail(ctx, normalized)
	if err != nil {
		return
	}
	if user.EmailVerifiedAt != nil {
		return
	}
	if err := a.sendVerificationEmail(ctx, user, a.safeRedirect(req.RedirectTo, "")); err != nil {
		a.cfg.logger.Error("authall: cannot send the verification message", "error", err.Error())
	}
}

type verificationVerifyRequest struct {
	Token string `json:"token"`
}

func (a *Auth) handleVerificationVerify(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := a.checkOrigin(r); err != nil {
		a.writeError(w, err)
		return
	}
	var req verificationVerifyRequest
	if err := a.decodeJSON(r, &req); err != nil {
		a.writeError(w, err)
		return
	}
	if _, err := a.VerifyEmailToken(ctx, req.Token); err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, successResponse{Success: true})
}
