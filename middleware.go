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

// withSession returns a request that carries the session and the user.
func withSession(r *http.Request, sess *store.Session, user *store.User) *http.Request {
	ctx := context.WithValue(r.Context(), sessionContextKey, sess)
	ctx = context.WithValue(ctx, userContextKey, user)
	return r.WithContext(ctx)
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
		sess, user, err := a.resolveSession(r.Context(), r)
		if err != nil {
			a.writeError(w, err)
			return
		}
		if sess == nil || user == nil {
			a.writeError(w, apierr.ErrUnauthorized)
			return
		}
		next.ServeHTTP(w, withSession(r, sess, user))
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
		sess, user, err := a.resolveSession(r.Context(), r)
		if err != nil {
			a.cfg.logger.Error("authall: the session lookup failed", "error", err.Error())
			next.ServeHTTP(w, r)
			return
		}
		if sess == nil || user == nil {
			next.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, withSession(r, sess, user))
	})
}

// LoadSessionFunc is the http.HandlerFunc form of LoadSession.
func (a *Auth) LoadSessionFunc(next http.HandlerFunc) http.Handler {
	return a.LoadSession(next)
}
