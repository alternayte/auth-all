package authall

import (
	"context"
	"net/http"
	"strings"

	"github.com/alternayte/auth-all/apierr"
	"github.com/alternayte/auth-all/events"
	"github.com/alternayte/auth-all/internal/crypto"
	"github.com/alternayte/auth-all/plugin"
	"github.com/alternayte/auth-all/store"
)

// Authentication methods of a principal.
const (
	// MethodSession names a request that a session token authenticated.
	MethodSession = "session"
	// MethodAPIKey names a request that an API key authenticated.
	MethodAPIKey = "api_key"
)

// Principal is the authenticated caller of one request.
type Principal struct {
	// User is the owner of the credential. It is never nil.
	User *store.User
	// Session is nil for an API key request.
	Session *store.Session
	// APIKey is nil for a session request.
	APIKey *store.APIKey
	// Role is the effective role of the request.
	Role string
	// Method is MethodSession or MethodAPIKey.
	Method string
	// ViaCookie reports whether a cookie carried the credential. Only a cookie
	// request needs the origin check.
	ViaCookie bool
}

// PrincipalFrom returns the principal that RequireAuth, LoadSession, or a role
// check attached to the request context. It returns nil for any other context.
func PrincipalFrom(ctx context.Context) *Principal {
	p, _ := ctx.Value(principalContextKey).(*Principal)
	return p
}

// withPrincipal returns a request that carries the principal, the session, and
// the user.
func (a *Auth) withPrincipal(r *http.Request, p *Principal) *http.Request {
	ctx := context.WithValue(r.Context(), principalContextKey, p)
	ctx = context.WithValue(ctx, sessionContextKey, p.Session)
	ctx = context.WithValue(ctx, userContextKey, p.User)
	// Every event of the request now names the caller.
	actor, _ := events.ActorFrom(ctx)
	if actor.IP == "" {
		actor.IP = a.clientIP(r)
	}
	if p.User != nil {
		actor.ID = p.User.ID
	}
	actor.Method = p.Method
	ctx = events.WithActor(ctx, actor)
	return r.WithContext(ctx)
}

// bearerToken returns the bearer value of a request.
func bearerToken(r *http.Request) string {
	header := r.Header.Get("Authorization")
	if len(header) > 7 && strings.EqualFold(header[:7], "Bearer ") {
		return strings.TrimSpace(header[7:])
	}
	return ""
}

// resolvePrincipal returns the principal of a request.
//
// A cookie carries a session token. A bearer value goes to each registered
// credential resolver in registration order. When no resolver claims it, the
// value is a session token, which keeps every v1 bearer client working.
func (a *Auth) resolvePrincipal(ctx context.Context, r *http.Request) (*Principal, error) {
	if c, err := r.Cookie(a.cfg.cookie.Name); err == nil && c.Value != "" {
		sess, user, err := a.sessionByToken(ctx, c.Value)
		if err != nil || sess == nil {
			return nil, err
		}
		return a.sessionPrincipal(sess, user, true), nil
	}
	bearer := bearerToken(r)
	if bearer == "" {
		return nil, nil
	}
	for _, res := range a.resolvers {
		if !res.Claims(bearer) {
			continue
		}
		p, err := res.Resolve(ctx, bearer)
		if err != nil {
			return nil, err
		}
		if p == nil {
			return nil, apierr.ErrUnauthorized
		}
		return fromPluginPrincipal(p), nil
	}
	sess, user, err := a.sessionByToken(ctx, bearer)
	if err != nil || sess == nil {
		return nil, err
	}
	return a.sessionPrincipal(sess, user, false), nil
}

// sessionPrincipal returns the principal of a session request.
func (a *Auth) sessionPrincipal(sess *store.Session, user *store.User, viaCookie bool) *Principal {
	return &Principal{
		User:      user,
		Session:   sess,
		Role:      a.effectiveRole(user),
		Method:    MethodSession,
		ViaCookie: viaCookie,
	}
}

// fromPluginPrincipal converts the principal of a credential resolver.
func fromPluginPrincipal(p *plugin.Principal) *Principal {
	return &Principal{
		User:    p.User,
		Session: p.Session,
		APIKey:  p.APIKey,
		Role:    p.Role,
		Method:  p.Method,
	}
}

// effectiveRole returns the role of a user. An empty value means the default
// role of the roles plugin.
func (a *Auth) effectiveRole(user *store.User) string {
	if user == nil {
		return ""
	}
	if user.Role == "" {
		return a.defaultRole
	}
	return user.Role
}

// sessionByToken returns the valid session of one plaintext token.
func (a *Auth) sessionByToken(ctx context.Context, token string) (*store.Session, *store.User, error) {
	return a.lookupSession(ctx, crypto.HashToken(token))
}
