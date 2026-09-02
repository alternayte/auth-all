package authall

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"github.com/alternayte/auth-all/apierr"
	"github.com/alternayte/auth-all/events"
	"github.com/alternayte/auth-all/internal/crypto"
	"github.com/alternayte/auth-all/internal/totp"
	"github.com/alternayte/auth-all/openapi"
	"github.com/alternayte/auth-all/plugin"
	"github.com/alternayte/auth-all/ratelimit"
	"github.com/alternayte/auth-all/store"
)

// registerTOTPRoutes mounts the enrolment endpoints of the second factor.
func (a *Auth) registerTOTPRoutes() {
	tag := []string{"totp"}

	a.handle(http.MethodPost, "/totp/enrol", a.handleTOTPEnrol, operation(
		"totpEnrol", "Start the enrolment of a second factor", tag,
		openapi.JSONBody(openapi.Object(nil, map[string]*openapi.Schema{})),
		"The secret and the enrolment URI", openapi.Ref("TOTPEnrolResponse"),
		&openapi.ClientBinding{Namespace: "totp", Method: "enrol"},
		"401", "403", "409", "429"))

	a.handle(http.MethodPost, "/totp/confirm", a.handleTOTPConfirm, operation(
		"totpConfirm", "Complete the enrolment of a second factor", tag,
		openapi.JSONBody(openapi.Object([]string{"code"},
			map[string]*openapi.Schema{"code": openapi.String()})),
		"The second factor is active and the recovery codes are returned",
		openapi.Ref("TOTPConfirmResponse"),
		&openapi.ClientBinding{Namespace: "totp", Method: "confirm"},
		"400", "401", "403", "429"))

	a.handle(http.MethodPost, "/totp/verify", a.handleTOTPVerify, operation(
		"totpVerify", "Complete a sign-in with a second factor", tag,
		openapi.JSONBody(openapi.Object([]string{"code"},
			map[string]*openapi.Schema{
				"code":     openapi.String(),
				"mfaToken": openapi.String(),
			})),
		"The session is created", openapi.Ref("AuthResponse"),
		&openapi.ClientBinding{Namespace: "totp", Method: "verify"},
		"400", "401", "429"))

	a.handle(http.MethodPost, "/totp/recovery", a.handleTOTPRecovery, operation(
		"totpRecovery", "Complete a sign-in with a recovery code", tag,
		openapi.JSONBody(openapi.Object([]string{"code"},
			map[string]*openapi.Schema{
				"code":     openapi.String(),
				"mfaToken": openapi.String(),
			})),
		"The session is created and the second factor is removed",
		openapi.Ref("AuthResponse"),
		&openapi.ClientBinding{Namespace: "totp", Method: "recovery"},
		"400", "401", "429"))

	a.handle(http.MethodPost, "/totp/recovery-codes/regenerate", a.handleTOTPRegenerate, operation(
		"totpRegenerateRecoveryCodes", "Replace the recovery codes of the current user", tag,
		openapi.JSONBody(openapi.Object([]string{"code"},
			map[string]*openapi.Schema{"code": openapi.String()})),
		"A new set of recovery codes", openapi.Ref("RecoveryCodesResponse"),
		&openapi.ClientBinding{Namespace: "totp", Method: "regenerateRecoveryCodes"},
		"400", "401", "403", "429"))

	a.handle(http.MethodPost, "/totp/disable", a.handleTOTPDisable, operation(
		"totpDisable", "Remove the second factor of the current user", tag,
		openapi.JSONBody(openapi.Object([]string{"code"},
			map[string]*openapi.Schema{"code": openapi.String()})),
		"The second factor is removed", openapi.Ref("SuccessResponse"),
		&openapi.ClientBinding{Namespace: "totp", Method: "disable"},
		"400", "401", "403", "429"))
}

// totpIssuer returns the name that the authenticator application shows. It
// defaults to the host of the base URL, which names the application without
// configuration.
func (a *Auth) totpIssuer() string {
	if a.cfg.totp.Issuer != "" {
		return a.cfg.totp.Issuer
	}
	if u, err := url.Parse(a.cfg.baseURL); err == nil && u.Host != "" {
		return u.Host
	}
	return "Auth-All"
}

// totpEnrolment returns the enrolment of a user and the decoded secret. The
// row can be unconfirmed, because the confirmation step reads it too. A caller
// that needs a live second factor tests ConfirmedAt.
//
// It returns ErrTOTPNotEnrolled when the user holds no row.
func (a *Auth) totpEnrolment(ctx context.Context, userID string) (*store.TOTP, []byte, error) {
	rec, err := a.cfg.store.TOTP().Get(ctx, userID)
	if err != nil {
		if isNotFound(err) {
			return nil, nil, apierr.ErrTOTPNotEnrolled
		}
		return nil, nil, apierr.ErrInternal.WithCause(err)
	}
	secret, err := totp.DecodeSecret(rec.Secret)
	if err != nil {
		// A stored secret that does not decode is a corrupt row, not a wrong
		// code. The user cannot repair it, so the error names an internal
		// failure.
		return nil, nil, apierr.ErrInternal.WithCause(err)
	}
	return rec, secret, nil
}

// verifyTOTPCode checks a code against an enrolment and records the accepted
// step.
//
// The step guard refuses a code whose step is not greater than the stored one,
// so a code that an attacker reads cannot be used a second time inside its own
// window.
func (a *Auth) verifyTOTPCode(ctx context.Context, rec *store.TOTP, secret []byte, code string) error {
	step, ok := totp.Validate(secret, code, a.cfg.now(), totp.Default())
	if !ok {
		return apierr.ErrInvalidTOTPCode
	}
	// The store performs the comparison and the write as one operation. A
	// comparison here would let two concurrent requests that carry one stolen
	// code both pass the guard.
	advanced, err := a.cfg.store.TOTP().AdvanceStep(ctx, rec.UserID, step)
	if err != nil {
		if isNotFound(err) {
			return apierr.ErrTOTPNotEnrolled
		}
		return apierr.ErrInternal.WithCause(err)
	}
	if !advanced {
		// The code is valid for its window, and that window already
		// authenticated. A replay looks exactly like a wrong code.
		return apierr.ErrInvalidTOTPCode
	}
	return nil
}

func (a *Auth) handleTOTPEnrol(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := a.checkOrigin(r); err != nil {
		a.writeError(w, err)
		return
	}
	sess, user := a.requireSession(w, r)
	if sess == nil {
		return
	}
	if !a.allow(ctx, w, ratelimit.Key{
		Operation: ratelimit.OpTOTP, IP: a.clientIP(r), UserID: user.ID,
	}) {
		return
	}
	// A confirmed enrolment is never replaced without a proof. A silent
	// replacement would drop a working second factor.
	switch existing, err := a.cfg.store.TOTP().Get(ctx, user.ID); {
	case err != nil && !isNotFound(err):
		a.writeError(w, apierr.ErrInternal.WithCause(err))
		return
	case err == nil && existing.ConfirmedAt != nil:
		a.writeError(w, apierr.ErrTOTPAlreadyEnrolled)
		return
	}
	secret, err := totp.NewSecret()
	if err != nil {
		a.writeError(w, apierr.ErrInternal.WithCause(err))
		return
	}
	now := a.cfg.now()
	// Upsert clears the confirmation and the step of an abandoned enrolment,
	// so a user who never finished the flow can restart it.
	if err := a.cfg.store.TOTP().Upsert(ctx, &store.TOTP{
		UserID: user.ID, Secret: totp.EncodeSecret(secret), CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		a.writeError(w, publicError(err))
		return
	}
	a.writeJSON(w, http.StatusOK, totpEnrolResponse{
		Secret: totp.EncodeSecret(secret),
		URI:    totp.URI(secret, a.totpIssuer(), user.Email, totp.Default()),
	})
}

func (a *Auth) handleTOTPConfirm(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := a.checkOrigin(r); err != nil {
		a.writeError(w, err)
		return
	}
	sess, user := a.requireSession(w, r)
	if sess == nil {
		return
	}
	var req totpCodeRequest
	if err := a.decodeJSON(r, &req); err != nil {
		a.writeError(w, err)
		return
	}
	if !a.allow(ctx, w, ratelimit.Key{
		Operation: ratelimit.OpTOTP, IP: a.clientIP(r), UserID: user.ID,
	}) {
		return
	}
	rec, secret, err := a.totpEnrolment(ctx, user.ID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	if rec.ConfirmedAt != nil {
		a.writeError(w, apierr.ErrTOTPAlreadyEnrolled)
		return
	}
	if err := a.verifyTOTPCode(ctx, rec, secret, req.Code); err != nil {
		a.writeError(w, err)
		return
	}
	if err := a.cfg.store.TOTP().Confirm(ctx, user.ID, a.cfg.now()); err != nil {
		a.writeError(w, publicError(err))
		return
	}
	// The codes arrive with the confirmation, so every enrolled user holds a
	// way back by construction. A separate endpoint would let a user finish
	// the enrolment and never call it.
	codes, err := a.issueRecoveryCodes(ctx, user.ID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	// A user who turns on a second factor usually suspects a compromise, so a
	// session that existed before the upgrade must not survive it.
	a.revokeOtherSessions(ctx, user.ID, sess.ID)
	a.emitter.Emit(ctx, events.TOTPEnabled, user.ID, nil)
	a.writeJSON(w, http.StatusOK, totpConfirmResponse{Success: true, RecoveryCodes: codes})
}

func (a *Auth) handleTOTPDisable(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := a.checkOrigin(r); err != nil {
		a.writeError(w, err)
		return
	}
	sess, user := a.requireSession(w, r)
	if sess == nil {
		return
	}
	var req totpCodeRequest
	if err := a.decodeJSON(r, &req); err != nil {
		a.writeError(w, err)
		return
	}
	if !a.allow(ctx, w, ratelimit.Key{
		Operation: ratelimit.OpTOTP, IP: a.clientIP(r), UserID: user.ID,
	}) {
		return
	}
	rec, secret, err := a.totpEnrolment(ctx, user.ID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	// A current code is required. A session alone must not remove the factor
	// that protects the session.
	if err := a.verifyTOTPCode(ctx, rec, secret, req.Code); err != nil {
		a.writeError(w, err)
		return
	}
	if err := a.cfg.store.TOTP().Delete(ctx, user.ID); err != nil && !isNotFound(err) {
		a.writeError(w, publicError(err))
		return
	}
	// The codes belong to the enrolment, so they go with it. A list that
	// outlives its enrolment would authenticate a later one.
	if _, err := a.cfg.store.RecoveryCodes().DeleteByUser(ctx, user.ID); err != nil {
		a.cfg.logger.Error("authall: cannot remove the recovery codes", "error", err.Error())
	}
	a.emitter.Emit(ctx, events.TOTPDisabled, user.ID, nil)
	a.writeJSON(w, http.StatusOK, successResponse{Success: true})
}

// RecoveryCodeCount is the number of recovery codes of one enrolment.
const RecoveryCodeCount = 10

// issueRecoveryCodes writes a new set of recovery codes for a user and returns
// the plaintext values. The plaintext exists only in the return value, and the
// database keeps the SHA-256 hash.
func (a *Auth) issueRecoveryCodes(ctx context.Context, userID string) ([]string, error) {
	codes, err := crypto.NewRecoveryCodes(RecoveryCodeCount)
	if err != nil {
		return nil, apierr.ErrInternal.WithCause(err)
	}
	hashes := make([]string, 0, len(codes))
	for _, c := range codes {
		hashes = append(hashes, crypto.HashToken(crypto.NormalizeRecoveryCode(c)))
	}
	if err := a.cfg.store.RecoveryCodes().ReplaceAll(ctx, userID, hashes); err != nil {
		return nil, publicError(err)
	}
	return codes, nil
}

// MFATokenKind names the one-time token of a pending second factor.
const MFATokenKind = "mfa"

// mfaChallengeTTL is the lifetime of a pending second factor. It is short,
// because the challenge stands between a proven password and a session.
const mfaChallengeTTL = 5 * time.Minute

// mfaCookieSuffix names the cookie that carries a challenge across a redirect
// flow. The cookie holds no session and authenticates nothing. It carries only
// the right to attempt the second step.
const mfaCookieSuffix = ".mfa"

// mfaCookieName returns the name of the challenge cookie.
func (a *Auth) mfaCookieName() string { return a.cfg.cookie.Name + mfaCookieSuffix }

// totpConfirmed reports whether a user holds a live second factor.
func (a *Auth) totpConfirmed(ctx context.Context, userID string) (bool, error) {
	if !a.cfg.totpEnabled {
		return false, nil
	}
	rec, err := a.cfg.store.TOTP().Get(ctx, userID)
	if err != nil {
		if isNotFound(err) {
			return false, nil
		}
		return false, apierr.ErrInternal.WithCause(err)
	}
	return rec.ConfirmedAt != nil, nil
}

// mfaChallenge reports whether a user must pass a second factor, and returns a
// challenge token when so.
//
// The caller must not create a session while required is true. The challenge
// token is a one-time token, so the store gives it a hash at rest and an
// atomic single consume.
func (a *Auth) mfaChallenge(ctx context.Context, user *store.User) (token string, required bool, err error) {
	confirmed, err := a.totpConfirmed(ctx, user.ID)
	if err != nil || !confirmed {
		return "", false, err
	}
	userID := user.ID
	plaintext, _, err := a.issueToken(ctx, plugin.IssueTokenInput{
		Kind:   MFATokenKind,
		UserID: &userID,
		// One pending challenge per user. A second sign-in replaces the first,
		// so an abandoned attempt cannot stay open for its full lifetime.
		Identifier:      userID,
		ReplaceExisting: true,
		TTL:             mfaChallengeTTL,
	})
	if err != nil {
		return "", false, err
	}
	return plaintext, true, nil
}

// setMFACookie writes the challenge cookie of a redirect flow.
func (a *Auth) setMFACookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     a.mfaCookieName(),
		Value:    token,
		Path:     a.cfg.cookie.Path,
		Domain:   a.cfg.cookie.Domain,
		MaxAge:   int(mfaChallengeTTL.Seconds()),
		HttpOnly: true,
		Secure:   a.cookieSecure(),
		SameSite: http.SameSiteLaxMode,
	})
}

// clearMFACookie removes the challenge cookie.
func (a *Auth) clearMFACookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     a.mfaCookieName(),
		Value:    "",
		Path:     a.cfg.cookie.Path,
		Domain:   a.cfg.cookie.Domain,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   a.cookieSecure(),
		SameSite: http.SameSiteLaxMode,
	})
}

// requestMFAToken returns the challenge token of a request. The body carries it
// for a JSON flow, and the challenge cookie carries it for a redirect flow.
func (a *Auth) requestMFAToken(r *http.Request, body string) string {
	if body != "" {
		return body
	}
	if c, err := r.Cookie(a.mfaCookieName()); err == nil {
		return c.Value
	}
	return ""
}

func (a *Auth) handleTOTPVerify(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := a.checkOrigin(r); err != nil {
		a.writeError(w, err)
		return
	}
	var req totpVerifyRequest
	if err := a.decodeJSON(r, &req); err != nil {
		a.writeError(w, err)
		return
	}
	challenge := a.requestMFAToken(r, req.MFAToken)
	if challenge == "" {
		a.writeError(w, apierr.ErrInvalidToken)
		return
	}
	if !a.allow(ctx, w, ratelimit.Key{
		Operation: ratelimit.OpTOTP, IP: a.clientIP(r),
	}) {
		return
	}
	// The challenge is consumed before the code is checked. A wrong code
	// therefore costs the attacker the whole challenge, so the endpoint gives
	// no unlimited guessing window against one stolen password.
	tok, err := a.consumeToken(ctx, MFATokenKind, challenge)
	if err != nil {
		a.clearMFACookie(w)
		a.writeError(w, err)
		return
	}
	a.clearMFACookie(w)
	if tok.UserID == nil {
		a.writeError(w, apierr.ErrInvalidToken)
		return
	}
	user, err := a.cfg.store.Users().GetByID(ctx, *tok.UserID)
	if err != nil {
		a.writeError(w, publicError(err))
		return
	}
	rec, secret, err := a.totpEnrolment(ctx, user.ID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	if rec.ConfirmedAt == nil {
		a.writeError(w, apierr.ErrTOTPNotEnrolled)
		return
	}
	if err := a.verifyTOTPCode(ctx, rec, secret, req.Code); err != nil {
		a.emitter.Emit(ctx, events.SignInFailed, user.ID, map[string]any{"reason": "invalid_totp_code"})
		a.writeError(w, err)
		return
	}
	sess, err := a.issueSession(ctx, w, r, user, "totp")
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, authResponse{User: toUserDTO(user), Session: toSessionDTO(sess)})
}

func (a *Auth) handleTOTPRecovery(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := a.checkOrigin(r); err != nil {
		a.writeError(w, err)
		return
	}
	var req totpVerifyRequest
	if err := a.decodeJSON(r, &req); err != nil {
		a.writeError(w, err)
		return
	}
	challenge := a.requestMFAToken(r, req.MFAToken)
	if challenge == "" {
		a.writeError(w, apierr.ErrInvalidToken)
		return
	}
	if !a.allow(ctx, w, ratelimit.Key{
		Operation: ratelimit.OpTOTP, IP: a.clientIP(r),
	}) {
		return
	}
	tok, err := a.consumeToken(ctx, MFATokenKind, challenge)
	if err != nil {
		a.clearMFACookie(w)
		a.writeError(w, err)
		return
	}
	a.clearMFACookie(w)
	if tok.UserID == nil {
		a.writeError(w, apierr.ErrInvalidToken)
		return
	}
	user, err := a.cfg.store.Users().GetByID(ctx, *tok.UserID)
	if err != nil {
		a.writeError(w, publicError(err))
		return
	}
	// The statement names the user, so a code of another user never matches.
	// The match and the removal are one operation, so one code authenticates
	// one time.
	ok, err := a.cfg.store.RecoveryCodes().Consume(ctx, user.ID,
		crypto.HashToken(crypto.NormalizeRecoveryCode(req.Code)))
	if err != nil {
		a.writeError(w, apierr.ErrInternal.WithCause(err))
		return
	}
	if !ok {
		a.emitter.Emit(ctx, events.SignInFailed, user.ID, map[string]any{"reason": "invalid_recovery_code"})
		a.writeError(w, apierr.ErrInvalidRecoveryCode)
		return
	}
	// A person who spends a recovery code lost their authenticator. The
	// enrolment goes with it, so the account is not left with a factor that
	// the owner cannot satisfy. The remaining codes go too, so a leaked list
	// is worthless afterwards.
	if err := a.cfg.store.TOTP().Delete(ctx, user.ID); err != nil && !isNotFound(err) {
		a.writeError(w, publicError(err))
		return
	}
	if _, err := a.cfg.store.RecoveryCodes().DeleteByUser(ctx, user.ID); err != nil {
		a.cfg.logger.Error("authall: cannot remove the recovery codes", "error", err.Error())
	}
	a.emitter.Emit(ctx, events.TOTPDisabled, user.ID, map[string]any{"reason": "recovery_code"})
	sess, err := a.issueSession(ctx, w, r, user, "totp-recovery")
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, authResponse{User: toUserDTO(user), Session: toSessionDTO(sess)})
}

func (a *Auth) handleTOTPRegenerate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := a.checkOrigin(r); err != nil {
		a.writeError(w, err)
		return
	}
	sess, user := a.requireSession(w, r)
	if sess == nil {
		return
	}
	var req totpCodeRequest
	if err := a.decodeJSON(r, &req); err != nil {
		a.writeError(w, err)
		return
	}
	if !a.allow(ctx, w, ratelimit.Key{
		Operation: ratelimit.OpTOTP, IP: a.clientIP(r), UserID: user.ID,
	}) {
		return
	}
	rec, secret, err := a.totpEnrolment(ctx, user.ID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	if rec.ConfirmedAt == nil {
		a.writeError(w, apierr.ErrTOTPNotEnrolled)
		return
	}
	// A current code proves the device. A session alone must not replace the
	// list that recovers the account.
	if err := a.verifyTOTPCode(ctx, rec, secret, req.Code); err != nil {
		a.writeError(w, err)
		return
	}
	codes, err := a.issueRecoveryCodes(ctx, user.ID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, recoveryCodesResponse{RecoveryCodes: codes})
}
