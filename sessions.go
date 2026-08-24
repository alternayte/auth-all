package authall

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/alternayte/auth-all/apierr"
	"github.com/alternayte/auth-all/events"
	"github.com/alternayte/auth-all/hook"
	"github.com/alternayte/auth-all/internal/crypto"
	"github.com/alternayte/auth-all/store"
)

func (a *Auth) cookieSecure() bool {
	if a.cfg.cookie.Secure != nil {
		return *a.cfg.cookie.Secure
	}
	return true
}

func (a *Auth) sessionCookie(token string, expires time.Time) *http.Cookie {
	return &http.Cookie{
		Name:     a.cfg.cookie.Name,
		Value:    token,
		Path:     a.cfg.cookie.Path,
		Domain:   a.cfg.cookie.Domain,
		Expires:  expires,
		HttpOnly: true,
		Secure:   a.cookieSecure(),
		SameSite: a.cfg.cookie.SameSite,
	}
}

// clearCookie removes the session cookie from the browser.
func (a *Auth) clearCookie(w http.ResponseWriter) {
	c := a.sessionCookie("", time.Unix(0, 0))
	c.MaxAge = -1
	http.SetCookie(w, c)
}

// requestToken returns the plaintext session token of a request. It reads the
// session cookie first and the bearer header second.
func (a *Auth) requestToken(r *http.Request) string {
	if c, err := r.Cookie(a.cfg.cookie.Name); err == nil && c.Value != "" {
		return c.Value
	}
	header := r.Header.Get("Authorization")
	if len(header) > 7 && strings.EqualFold(header[:7], "Bearer ") {
		return strings.TrimSpace(header[7:])
	}
	return ""
}

// resolveSession returns the valid session and user of a request.
func (a *Auth) resolveSession(ctx context.Context, r *http.Request) (*store.Session, *store.User, error) {
	token := a.requestToken(r)
	if token == "" {
		return nil, nil, nil
	}
	sess, err := a.cfg.store.Sessions().GetByTokenHash(ctx, crypto.HashToken(token))
	if err != nil {
		if isNotFound(err) {
			return nil, nil, nil
		}
		return nil, nil, apierr.ErrInternal.WithCause(err)
	}
	now := a.cfg.now()
	// A session ends at the first of three deadlines. ExpiresAt carries the
	// absolute lifetime, and the idle timeout runs from the last request. One
	// value cannot serve both, because a stolen token that stays active would
	// never expire.
	if !now.Before(sess.ExpiresAt) ||
		!now.Before(sess.CreatedAt.Add(a.cfg.session.TTL)) ||
		!now.Before(sess.LastSeenAt.Add(a.cfg.session.IdleTimeout)) {
		// An expired session never authenticates. Remove it eagerly.
		_ = a.cfg.store.Sessions().Delete(ctx, sess.ID)
		return nil, nil, nil
	}
	user, err := a.cfg.store.Users().GetByID(ctx, sess.UserID)
	if err != nil {
		if isNotFound(err) {
			return nil, nil, nil
		}
		return nil, nil, apierr.ErrInternal.WithCause(err)
	}
	if now.Sub(sess.LastSeenAt) >= a.cfg.session.TouchInterval {
		// A revoked session returns ErrNotFound here, so a stale write cannot
		// bring it back.
		if err := a.cfg.store.Sessions().Touch(ctx, sess.ID, now); err == nil {
			sess.LastSeenAt = now
		}
	}
	return sess, user, nil
}

// issueSession creates a session for a user and writes the session cookie.
//
// A session token exists in plaintext only in the response. The database keeps
// the hash. Any session that the request already carried is revoked first, so a
// fixed token cannot survive authentication.
func (a *Auth) issueSession(ctx context.Context, w http.ResponseWriter, r *http.Request, user *store.User, method string) (*store.Session, error) {
	if r != nil {
		if old := a.requestToken(r); old != "" {
			if prev, err := a.cfg.store.Sessions().GetByTokenHash(ctx, crypto.HashToken(old)); err == nil {
				_ = a.cfg.store.Sessions().Delete(ctx, prev.ID)
			}
		}
	}
	token, err := crypto.NewToken()
	if err != nil {
		return nil, apierr.ErrInternal.WithCause(err)
	}
	now := a.cfg.now()
	sess := &store.Session{
		ID:         uuid.NewString(),
		UserID:     user.ID,
		TokenHash:  crypto.HashToken(token),
		CreatedAt:  now,
		ExpiresAt:  now.Add(a.cfg.session.TTL),
		LastSeenAt: now,
	}
	ev := &hook.SessionCreate{Session: sess, User: user}
	err = a.cfg.store.Transaction(ctx, func(tx store.Store) error {
		ev.Tx = tx
		if err := a.hooks.RunBeforeSessionCreate(ctx, ev); err != nil {
			return err
		}
		return tx.Sessions().Create(ctx, sess)
	})
	if err != nil {
		return nil, publicError(err)
	}
	ev.Tx = nil
	a.hooks.RunAfterSessionCreate(ctx, ev)
	a.hooks.RunAfterSignIn(ctx, &hook.SignIn{User: user, Session: sess, Method: method})
	a.emitter.Emit(ctx, events.SignIn, user.ID, map[string]any{"method": method, "session_id": sess.ID})
	if w != nil {
		http.SetCookie(w, a.sessionCookie(token, sess.ExpiresAt))
	}
	return sess, nil
}

// publicError maps an internal error to the public contract without leaking
// the cause.
func publicError(err error) error {
	if err == nil {
		return nil
	}
	var public *apierr.Error
	if asPublic(err, &public) {
		return public
	}
	if isConflict(err) {
		return apierr.ErrEmailAlreadyExists.WithCause(err)
	}
	if isNotFound(err) {
		return apierr.ErrNotFound.WithCause(err)
	}
	return apierr.ErrInternal.WithCause(err)
}
