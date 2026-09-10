package authall

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/alternayte/auth-all/apierr"
	"github.com/alternayte/auth-all/email"
	"github.com/alternayte/auth-all/events"
	"github.com/alternayte/auth-all/hook"
	"github.com/alternayte/auth-all/internal/crypto"
	"github.com/alternayte/auth-all/openapi"
	"github.com/alternayte/auth-all/ratelimit"
	"github.com/alternayte/auth-all/store"
)

// enumerationSafeMessages are the responses of flows that must not disclose
// whether an account exists.
const (
	messageResetSent  = "If an account exists, instructions have been sent."
	messageVerifySent = "If the address needs verification, a message has been sent."
)

// dummyPasswordHash returns a hash used to equalize the sign-in timing of a
// known and an unknown address. The hash uses the parameters of this instance,
// so the work of both paths is equal.
func (a *Auth) dummyPasswordHash() string {
	a.dummyHashOnce.Do(func() {
		h, err := crypto.HashPassword("auth-all-timing-equalizer", a.cfg.argon)
		if err == nil {
			a.dummyHash = h
		}
	})
	return a.dummyHash
}

func (a *Auth) allow(ctx context.Context, w http.ResponseWriter, r *http.Request, key ratelimit.Key) bool {
	// A limiter that names a retry time fails closed. It uses the database
	// that the flow uses, so a failure fails the flow anyway.
	if decider, ok := a.cfg.limiter.(ratelimit.Decider); ok {
		decision, err := decider.Decide(ctx, key)
		if err != nil {
			a.cfg.logger.Error("authall: the rate limiter failed", "error", err.Error())
			a.writeError(w, r, apierr.ErrInternal.WithCause(err))
			return false
		}
		if decision.Allowed {
			return true
		}
		w.Header().Set("Retry-After", retryAfterSeconds(decision.RetryAfter))
		a.writeError(w, r, apierr.ErrRateLimited)
		return false
	}
	ok, err := a.cfg.limiter.Allow(ctx, key)
	if err != nil {
		// A v1 limiter keeps the v1 behavior. A limiter failure lets the
		// request through.
		a.cfg.logger.Error("authall: the rate limiter failed", "error", err.Error())
		return true
	}
	if !ok {
		// A v1 limiter names no retry time, so the response asks for one
		// minute. REQ-RL-011 keeps this value.
		w.Header().Set("Retry-After", "60")
		a.writeError(w, r, apierr.ErrRateLimited)
		return false
	}
	return true
}

// retryAfterSeconds returns the Retry-After value in whole seconds, rounded
// up. A refused request always waits at least one second.
func retryAfterSeconds(d time.Duration) string {
	seconds := int64((d + time.Second - 1) / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	return strconv.FormatInt(seconds, 10)
}

// registerCoreRoutes mounts the enabled core endpoints.
func (a *Auth) registerCoreRoutes() {
	tagSession := []string{"session"}

	a.handle(http.MethodGet, "/session", a.handleGetSession, operation(
		"getSession", "Return the current session and user", tagSession, nil,
		"The current session", openapi.Ref("SessionResponse"),
		&openapi.ClientBinding{Method: "getSession"}))

	a.handle(http.MethodPost, "/sign-out", a.handleSignOut, operation(
		"signOut", "Revoke the current session", tagSession, nil,
		"The session is revoked", openapi.Ref("SuccessResponse"),
		&openapi.ClientBinding{Method: "signOut"}, "403"))

	a.registerSessionRoutes()

	if a.cfg.emailPasswordEnabled {
		tag := []string{"email-password"}
		a.handle(http.MethodPost, "/sign-up/email", a.handleSignUpEmail, operation(
			"signUpEmail", "Create an account with an email address and a password", tag,
			openapi.JSONBody(openapi.Object([]string{"email", "password"}, map[string]*openapi.Schema{
				"email":    openapi.String(),
				"password": openapi.String(),
				"name":     openapi.String(),
			})),
			"The account is created", openapi.Ref("AuthResponse"),
			&openapi.ClientBinding{Namespace: "signUp", Method: "email"}, "400", "409", "429"))

		a.handle(http.MethodPost, "/sign-in/email", a.handleSignInEmail, operation(
			"signInEmail", "Sign in with an email address and a password", tag,
			openapi.JSONBody(openapi.Object([]string{"email", "password"}, map[string]*openapi.Schema{
				"email":    openapi.String(),
				"password": openapi.String(),
			})),
			"The session is created", openapi.Ref("AuthResponse"),
			&openapi.ClientBinding{Namespace: "signIn", Method: "email"}, "400", "401", "403", "429"))

		a.handle(http.MethodPost, "/password/forgot", a.handlePasswordForgot, operation(
			"passwordForgot", "Request a password reset message", tag,
			openapi.JSONBody(openapi.Object([]string{"email"}, map[string]*openapi.Schema{
				"email":      openapi.String(),
				"redirectTo": openapi.String(),
			})),
			"An enumeration-safe acknowledgement", openapi.Ref("MessageResponse"),
			&openapi.ClientBinding{Namespace: "password", Method: "forgot"}, "400", "429"))

		a.handle(http.MethodPost, "/password/reset", a.handlePasswordReset, operation(
			"passwordReset", "Set a new password with a reset token", tag,
			openapi.JSONBody(openapi.Object([]string{"token", "password"}, map[string]*openapi.Schema{
				"token":    openapi.String(),
				"password": openapi.String(),
			})),
			"The password is changed", openapi.Ref("SuccessResponse"),
			&openapi.ClientBinding{Namespace: "password", Method: "reset"}, "400"))

		a.handle(http.MethodPost, "/email-verification/send", a.handleVerificationSend, operation(
			"emailVerificationSend", "Request an email verification message", tag,
			openapi.JSONBody(openapi.Object([]string{"email"}, map[string]*openapi.Schema{
				"email":      openapi.String(),
				"redirectTo": openapi.String(),
			})),
			"An enumeration-safe acknowledgement", openapi.Ref("MessageResponse"),
			&openapi.ClientBinding{Namespace: "emailVerification", Method: "send"}, "400", "429"))

		a.handle(http.MethodPost, "/email-verification/verify", a.handleVerificationVerify, operation(
			"emailVerificationVerify", "Verify an email address with a token", tag,
			openapi.JSONBody(openapi.Object([]string{"token"}, map[string]*openapi.Schema{
				"token": openapi.String(),
			})),
			"The address is verified", openapi.Ref("SuccessResponse"),
			&openapi.ClientBinding{Namespace: "emailVerification", Method: "verify"}, "400"))

		a.registerAccountRoutes()
	}

	if a.cfg.totpEnabled {
		a.registerTOTPRoutes()
	}

	if len(a.providers) > 0 {
		a.registerOAuthRoutes()
	}
}

func (a *Auth) handleGetSession(w http.ResponseWriter, r *http.Request) {
	sess, user, err := a.resolveSession(r.Context(), r)
	if err != nil {
		a.writeError(w, r, err)
		return
	}
	if sess == nil && a.requestToken(r) != "" {
		// The request carried a token that no longer resolves. The row is gone,
		// so the browser must drop the cookie as well.
		a.clearCookie(w)
	}
	a.writeJSON(w, http.StatusOK, struct {
		User    *userDTO    `json:"user"`
		Session *sessionDTO `json:"session"`
	}{User: a.toUserDTO(user), Session: toSessionDTO(sess)})
}

func (a *Auth) handleSignOut(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := a.checkOrigin(r); err != nil {
		a.writeError(w, r, err)
		return
	}
	sess, user, err := a.resolveSession(ctx, r)
	if err != nil {
		a.writeError(w, r, err)
		return
	}
	if sess != nil {
		if err := a.cfg.store.Sessions().Delete(ctx, sess.ID); err != nil && !isNotFound(err) {
			a.writeError(w, r, apierr.ErrInternal.WithCause(err))
			return
		}
		a.hooks.RunAfterSignOut(ctx, &hook.SignOut{UserID: sess.UserID, SessionID: sess.ID})
		userID := ""
		if user != nil {
			userID = user.ID
		}
		a.emitter.Emit(ctx, events.SignOut, userID, map[string]any{"session_id": sess.ID})
	}
	a.clearCookie(w)
	a.writeJSON(w, http.StatusOK, successResponse{Success: true})
}

type signUpEmailRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name"`
}

func (a *Auth) handleSignUpEmail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := a.checkOrigin(r); err != nil {
		a.writeError(w, r, err)
		return
	}
	var req signUpEmailRequest
	if err := a.decodeJSON(r, &req); err != nil {
		a.writeError(w, r, err)
		return
	}
	normalized := email.Normalize(req.Email)
	if !a.allow(ctx, w, r, ratelimit.Key{Operation: ratelimit.OpSignUp, IP: a.clientIP(r), Email: normalized}) {
		return
	}
	if !email.Valid(normalized) {
		a.writeError(w, r, apierr.ErrInvalidRequest.WithMessage("The email address is invalid."))
		return
	}
	if err := a.checkPassword(req.Password); err != nil {
		a.writeError(w, r, err)
		return
	}
	hash, err := crypto.HashPassword(req.Password, a.cfg.argon)
	if err != nil {
		a.writeError(w, r, apierr.ErrInternal.WithCause(err))
		return
	}
	user, err := a.createUser(ctx, CreateUserInput{
		Email:       strings.TrimSpace(req.Email),
		DisplayName: strings.TrimSpace(req.Name),
	}, hash)
	if err != nil {
		a.writeError(w, r, err)
		return
	}

	opts := a.cfg.emailPassword
	if opts.RequireEmailVerification || opts.SendVerificationOnSignUp {
		if err := a.sendVerificationEmail(ctx, user, ""); err != nil {
			a.writeError(w, r, err)
			return
		}
	}
	if opts.RequireEmailVerification {
		a.writeJSON(w, http.StatusCreated, authResponse{
			User: a.toUserDTO(user), Session: nil, EmailVerificationRequired: true,
		})
		return
	}
	sess, err := a.issueSession(ctx, w, r, user, "email")
	if err != nil {
		a.writeError(w, r, err)
		return
	}
	a.writeJSON(w, http.StatusCreated, authResponse{User: a.toUserDTO(user), Session: toSessionDTO(sess)})
}

type signInEmailRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (a *Auth) handleSignInEmail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := a.checkOrigin(r); err != nil {
		a.writeError(w, r, err)
		return
	}
	var req signInEmailRequest
	if err := a.decodeJSON(r, &req); err != nil {
		a.writeError(w, r, err)
		return
	}
	normalized := email.Normalize(req.Email)
	if !a.allow(ctx, w, r, ratelimit.Key{Operation: ratelimit.OpSignIn, IP: a.clientIP(r), Email: normalized}) {
		return
	}
	user, err := a.cfg.store.Users().GetByNormalizedEmail(ctx, normalized)
	if err != nil && !isNotFound(err) {
		a.writeError(w, r, apierr.ErrInternal.WithCause(err))
		return
	}
	var cred *store.Credential
	if user != nil {
		cred, err = a.cfg.store.Users().GetCredential(ctx, user.ID)
		if err != nil && !isNotFound(err) {
			a.writeError(w, r, apierr.ErrInternal.WithCause(err))
			return
		}
	}
	if cred == nil {
		// The work is equal for a known and an unknown address, so the response
		// time does not disclose whether the account exists.
		_, _, _ = crypto.VerifyPassword(req.Password, a.dummyPasswordHash())
		a.emitter.Emit(ctx, events.SignInFailed, "", map[string]any{
			"reason": "unknown_credential", "email_digest": crypto.HashToken(normalized)})
		a.writeError(w, r, apierr.ErrInvalidCredentials)
		return
	}
	ok, params, err := crypto.VerifyPassword(req.Password, cred.PasswordHash)
	if err != nil {
		a.writeError(w, r, apierr.ErrInternal.WithCause(err))
		return
	}
	if !ok {
		a.emitter.Emit(ctx, events.SignInFailed, user.ID, map[string]any{
			"reason": "invalid_password", "email_digest": crypto.HashToken(normalized)})
		a.writeError(w, r, apierr.ErrInvalidCredentials)
		return
	}
	if a.cfg.emailPassword.RequireEmailVerification && user.EmailVerifiedAt == nil {
		a.emitter.Emit(ctx, events.SignInFailed, user.ID, map[string]any{
			"reason": "email_not_verified", "email_digest": crypto.HashToken(normalized)})
		a.writeError(w, r, apierr.ErrEmailNotVerified)
		return
	}
	if crypto.NeedsRehash(params, a.cfg.argon) {
		if fresh, err := crypto.HashPassword(req.Password, a.cfg.argon); err == nil {
			cred.PasswordHash = fresh
			cred.UpdatedAt = a.cfg.now()
			if err := a.cfg.store.Users().SetCredential(ctx, cred); err != nil {
				a.cfg.logger.Error("authall: cannot rehash the password", "error", err.Error())
			}
		}
	}
	// The password is proven. A user with a live second factor receives a
	// challenge instead of a session, so no cookie exists before the second
	// proof.
	challenge, required, err := a.mfaChallenge(ctx, user)
	if err != nil {
		a.writeError(w, r, err)
		return
	}
	if required {
		a.writeJSON(w, http.StatusOK, authResponse{MFARequired: true, MFAToken: challenge})
		return
	}
	sess, err := a.issueSession(ctx, w, r, user, "email")
	if err != nil {
		a.writeError(w, r, err)
		return
	}
	a.writeJSON(w, http.StatusOK, authResponse{User: a.toUserDTO(user), Session: toSessionDTO(sess)})
}
