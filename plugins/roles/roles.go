// Package roles adds a host-defined role hierarchy to Auth-All.
//
// The host names the roles from the lowest to the highest. A check compares
// the rank of the effective role with the rank of a minimum role, so a route
// asks for "at least operator" and not for a list of permissions.
//
//	r := roles.New(roles.Hierarchy("viewer", "operator", "editor", "admin"),
//	    roles.Default("viewer"))
//	auth, err := authall.New(authall.WithStore(s), authall.WithPlugins(r))
//	mux.Handle("/deploy", r.Require("operator", deployHandler))
package roles

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/alternayte/auth-all/apierr"
	"github.com/alternayte/auth-all/plugin"
)

// ID is the stable plugin identifier.
const ID = "roles"

// Plugin is the roles plugin.
type Plugin struct {
	names       []string
	defaultRole string

	roles    plugin.RoleService
	protect  func(http.Handler) http.Handler
	current  func(ctx context.Context) *plugin.Principal
	writeErr func(w http.ResponseWriter, r *http.Request, err error)
}

// Option configures the plugin.
type Option func(*Plugin)

// Hierarchy names the roles from the lowest to the highest.
func Hierarchy(names ...string) Option {
	return func(p *Plugin) { p.names = append([]string(nil), names...) }
}

// Default names the role of a user whose role is empty. The default is the
// lowest role of the hierarchy.
func Default(name string) Option {
	return func(p *Plugin) { p.defaultRole = name }
}

// New returns the roles plugin. Registration fails when the hierarchy is
// empty, holds a duplicate, or does not hold the default role.
func New(opts ...Option) *Plugin {
	p := &Plugin{}
	for _, o := range opts {
		o(p)
	}
	return p
}

// ID implements plugin.Plugin.
func (p *Plugin) ID() string { return ID }

// Register implements plugin.Plugin.
func (p *Plugin) Register(r *plugin.Registry) error {
	if len(p.names) == 0 {
		return errors.New("authall/roles: the hierarchy needs at least one role. Use roles.Hierarchy")
	}
	if p.defaultRole == "" {
		p.defaultRole = p.names[0]
	}
	svc := r.Services()
	configurator, ok := svc.(plugin.RoleConfigurator)
	if !ok {
		return errors.New("authall/roles: this Auth-All version has no role service")
	}
	if err := configurator.SetRoles(p.names, p.defaultRole); err != nil {
		return err
	}
	reader, ok := svc.(plugin.RoleServices)
	if !ok {
		return errors.New("authall/roles: this Auth-All version has no role service")
	}
	principals, ok := svc.(plugin.PrincipalServices)
	if !ok {
		return errors.New("authall/roles: this Auth-All version has no principal service")
	}
	protector, ok := svc.(plugin.ProtectService)
	if !ok {
		return errors.New("authall/roles: this Auth-All version has no authentication middleware")
	}
	p.roles = reader.Roles()
	p.current = principals.Principals().Current
	p.protect = protector.Protect
	p.writeErr = func(w http.ResponseWriter, r *http.Request, err error) {
		if writer, ok := svc.HTTP().(interface {
			WriteErrorFor(http.ResponseWriter, *http.Request, error)
		}); ok {
			writer.WriteErrorFor(w, r, err)
			return
		}
		svc.HTTP().WriteError(w, err)
	}
	return nil
}

// Names returns the configured roles from the lowest to the highest.
func (p *Plugin) Names() []string { return append([]string(nil), p.names...) }

// Require protects a handler with a minimum role.
//
// A request with no principal gets 401 UNAUTHORIZED. A principal whose role
// ranks below min gets 403 INSUFFICIENT_ROLE. Require panics when min is not a
// configured role, because a route with an unknown minimum can never pass.
func (p *Plugin) Require(min string, next http.Handler) http.Handler {
	if !p.known(min) {
		panic(fmt.Sprintf("authall/roles: the minimum role %q is not configured. Configured: %v", min, p.names))
	}
	gate := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal := p.current(r.Context())
		if principal == nil {
			p.writeErr(w, r, apierr.ErrUnauthorized)
			return
		}
		if !p.roles.AtLeast(principal.Role, min) {
			p.writeErr(w, r, apierr.ErrInsufficientRole)
			return
		}
		next.ServeHTTP(w, withRole(r, roleContext{role: principal.Role, ranker: p.roles}))
	})
	// Protect resolves the principal and runs the origin check of the host
	// routes, so a role route needs no second middleware.
	return p.protect(gate)
}

// RequireFunc is the http.HandlerFunc form of Require.
func (p *Plugin) RequireFunc(min string, next http.HandlerFunc) http.Handler {
	return p.Require(min, next)
}

// known reports whether the configuration names the role.
func (p *Plugin) known(role string) bool {
	for _, name := range p.names {
		if name == role {
			return true
		}
	}
	return false
}

// contextKey is the private context key type of this package.
type contextKey int

const roleContextKey contextKey = iota

// roleContext carries the effective role and the configured hierarchy, so a
// package function can answer a role question with no plugin value.
type roleContext struct {
	role   string
	ranker plugin.RoleService
}

// withRole returns a request that carries the effective role.
func withRole(r *http.Request, value roleContext) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), roleContextKey, value))
}

// fromContext returns the role value of the context.
func fromContext(ctx context.Context) (roleContext, bool) {
	value, ok := ctx.Value(roleContextKey).(roleContext)
	return value, ok
}

// From returns the effective role of the request context. It returns an empty
// value when no role check ran.
func From(ctx context.Context) string {
	value, _ := fromContext(ctx)
	return value.role
}

// AtLeast reports whether the effective role of the context ranks equal to or
// above min. A handler uses it for a decision inside one route.
//
// It returns false when no role check ran, which is default deny.
func AtLeast(ctx context.Context, min string) bool {
	value, ok := fromContext(ctx)
	if !ok || value.ranker == nil {
		return false
	}
	return value.ranker.AtLeast(value.role, min)
}
