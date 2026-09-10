package authall

import (
	"context"
	"net/http"

	"github.com/alternayte/auth-all/apierr"
	"github.com/alternayte/auth-all/store"
)

// contextKey is the private key type of the request context values. A private
// type stops a collision with a key of the application.
type contextKey int

const (
	sessionContextKey contextKey = iota
	userContextKey
	principalContextKey
	roleContextKey
)

// SessionFrom returns the session that RequireAuth or LoadSession attached to
// the request context. It returns nil for any other context.
func SessionFrom(ctx context.Context) *store.Session {
	sess, _ := ctx.Value(sessionContextKey).(*store.Session)
	return sess
}

// UserFrom returns the user that RequireAuth or LoadSession attached to the
// request context. It returns nil for any other context.
func UserFrom(ctx context.Context) *store.User {
	user, _ := ctx.Value(userContextKey).(*store.User)
	return user
}

// RequireAuth protects an application route. It resolves the session one time,
// puts the session and the user in the request context, and calls next.
//
// A request with no valid session never reaches next. RequireAuth answers it
// with the Auth-All error contract and status 401.
//
//	mux.Handle("/api/me", auth.RequireAuth(meHandler))
//
// The handler reads the result with SessionFrom and UserFrom, which cost no
// second database lookup.
func (a *Auth) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, err := a.resolvePrincipal(r.Context(), r)
		if err != nil {
			a.writeError(w, r, err)
			return
		}
		if p == nil || p.User == nil {
			a.writeError(w, r, apierr.ErrUnauthorized)
			return
		}
		if err := a.checkHostOrigin(r, p); err != nil {
			a.writeError(w, r, err)
			return
		}
		next.ServeHTTP(w, a.withPrincipal(r, p))
	})
}

// RequireAuthFunc is the http.HandlerFunc form of RequireAuth.
func (a *Auth) RequireAuthFunc(next http.HandlerFunc) http.Handler {
	return a.RequireAuth(next)
}

// LoadSession attaches the session and the user when the request carries a
// valid one, and calls next either way.
//
// Use LoadSession for a route that serves an anonymous visitor and a signed-in
// user from one handler. The handler tests the result with UserFrom.
//
// A storage failure never blocks the request. LoadSession logs it and treats
// the request as anonymous.
func (a *Auth) LoadSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, err := a.resolvePrincipal(r.Context(), r)
		if err != nil {
			a.cfg.logger.Error("authall: the credential lookup failed", "error", err.Error())
			next.ServeHTTP(w, r)
			return
		}
		if p == nil || p.User == nil {
			next.ServeHTTP(w, r)
			return
		}
		if err := a.checkHostOrigin(r, p); err != nil {
			a.writeError(w, r, err)
			return
		}
		next.ServeHTTP(w, a.withPrincipal(r, p))
	})
}

// LoadSessionFunc is the http.HandlerFunc form of LoadSession.
func (a *Auth) LoadSessionFunc(next http.HandlerFunc) http.Handler {
	return a.LoadSession(next)
}

// checkHostOrigin refuses an unsafe cross-site request that a cookie
// authenticated.
//
// A bearer credential is not ambient, so a cross-site page cannot send it. Only
// a cookie request therefore needs the check.
func (a *Auth) checkHostOrigin(r *http.Request, p *Principal) error {
	if a.crossOrigin == nil || p == nil || !p.ViaCookie {
		return nil
	}
	if err := a.crossOrigin.Check(r); err != nil {
		return apierr.ErrOriginNotAllowed.WithCause(err)
	}
	return nil
}
