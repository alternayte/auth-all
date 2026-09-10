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
	// Organization is the active organization of the session. It is nil when
	// the session names none, and when the organizations plugin is off.
	Organization *store.Organization
	// Membership is the membership of the active organization. It is nil when
	// no organization is active, and when the membership is gone.
	Membership *store.Membership
	// Permissions holds the extra statements that the credential read
	// resolved, for a custom role and for every team role of the member.
	Permissions []string
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
	if p.Organization != nil && p.Membership != nil {
		ctx = plugin.WithOrganization(ctx, plugin.OrganizationContext{
			Organization: p.Organization,
			Membership:   p.Membership,
			Permissions:  p.Permissions,
		})
	}
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
	credential := a.requestToken(r)
	if credential != "" {
		if cached, ok := a.principals.get(credential); ok {
			// The entry cannot outlive the consistency bound, so the cached
			// principal is fresh enough for every check.
			return cached, nil
		}
	}
	p, err := a.readPrincipal(ctx, r)
	if err != nil || p == nil {
		return p, err
	}
	if credential != "" {
		a.principals.put(credential, p)
	}
	return p, nil
}

// readPrincipal resolves the principal from the store.
func (a *Auth) readPrincipal(ctx context.Context, r *http.Request) (*Principal, error) {
	if c, err := r.Cookie(a.cfg.cookie.Name); err == nil && c.Value != "" {
		sess, user, org, member, err := a.sessionByToken(ctx, c.Value)
		if err != nil || sess == nil {
			return nil, err
		}
		return withOrganization(a.sessionPrincipal(sess, user, true), org, member), nil
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
	sess, user, org, member, err := a.sessionByToken(ctx, bearer)
	if err != nil || sess == nil {
		return nil, err
	}
	return withOrganization(a.sessionPrincipal(sess, user, false), org, member), nil
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

// withOrganization returns the principal with the active organization of the
// session. A removed or a suspended membership carries no organization, so the
// next request of every instance refuses.
func withOrganization(p *Principal, org *store.Organization, member *store.Membership) *Principal {
	if p == nil || org == nil || member == nil || member.Status != store.MembershipActive {
		return p
	}
	p.Organization = org
	p.Membership = member
	return p
}

// fromPluginPrincipal converts the principal of a credential resolver.
func fromPluginPrincipal(p *plugin.Principal) *Principal {
	return &Principal{
		User:         p.User,
		Session:      p.Session,
		APIKey:       p.APIKey,
		Role:         p.Role,
		Method:       p.Method,
		Organization: p.Organization,
		Membership:   p.Membership,
		Permissions:  p.Permissions,
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
func (a *Auth) sessionByToken(ctx context.Context, token string) (
	*store.Session, *store.User, *store.Organization, *store.Membership, error) {
	return a.lookupSession(ctx, crypto.HashToken(token))
}
