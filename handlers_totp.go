package authall

import (
	"context"
	"net/http"
	"net/url"

	"github.com/alternayte/auth-all/apierr"
	"github.com/alternayte/auth-all/events"
	"github.com/alternayte/auth-all/internal/totp"
	"github.com/alternayte/auth-all/openapi"
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
		"The second factor is active", openapi.Ref("SuccessResponse"),
		&openapi.ClientBinding{Namespace: "totp", Method: "confirm"},
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
	// A user who turns on a second factor usually suspects a compromise, so a
	// session that existed before the upgrade must not survive it.
	a.revokeOtherSessions(ctx, user.ID, sess.ID)
	a.emitter.Emit(ctx, events.TOTPEnabled, user.ID, nil)
	a.writeJSON(w, http.StatusOK, successResponse{Success: true})
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
	a.emitter.Emit(ctx, events.TOTPDisabled, user.ID, nil)
	a.writeJSON(w, http.StatusOK, successResponse{Success: true})
}
