// Package organizations adds organizations, memberships, and fine-grained
// permissions to Auth-All.
//
// A person belongs to one or more organizations. A membership carries a role,
// and a role carries a set of permission statements. A route asks for one
// permission, and the check runs in the process of the application.
//
//	orgs := organizations.New(
//	    organizations.Roles(
//	        organizations.Role("owner", "*"),
//	        organizations.Role("admin", "member:*", "project:*", "billing:read"),
//	        organizations.Role("member", "project:read", "project:write"),
//	        organizations.Role("viewer", "project:read"),
//	    ),
//	    organizations.DefaultRole("member"),
//	    organizations.OwnerRole("owner"),
//	)
//	auth, err := authall.New(authall.WithStore(s), authall.WithPlugins(orgs))
//	mux.Handle("POST /projects", orgs.Require("project:write", createProject))
//
// Every decision is default deny. A request with no active organization, a
// suspended membership, and an unknown permission all refuse.
package organizations

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/alternayte/auth-all/apierr"
	"github.com/alternayte/auth-all/events"
	"github.com/alternayte/auth-all/hook"
	"github.com/alternayte/auth-all/plugin"
	"github.com/alternayte/auth-all/plugins/organizations/permission"
	"github.com/alternayte/auth-all/schema"
	"github.com/alternayte/auth-all/store"
)

// ID is the stable plugin identifier.
const ID = "organizations"

// RoleDefinition is one built-in role of the application. Role builds it.
type RoleDefinition struct {
	name        string
	permissions permission.Set
}

// Name returns the name of the role.
func (r RoleDefinition) Name() string { return r.name }

// Permissions returns the permission set of the role.
func (r RoleDefinition) Permissions() permission.Set { return r.permissions }

// Role declares one built-in role and its permission statements.
//
// The declaration is code, so a review sees it and a test covers it. Role
// panics on an invalid statement, because a wrong declaration must fail at the
// start of the application and not on a request.
func Role(name string, statements ...string) RoleDefinition {
	if name == "" {
		panic("authall/organizations: a role needs a name")
	}
	return RoleDefinition{name: name, permissions: permission.MustNewSet(statements...)}
}

// Plugin is the organizations plugin.
type Plugin struct {
	roles            []RoleDefinition
	defaultRole      string
	ownerRole        string
	allowCustomRoles bool
	maxMembers       int

	// declared holds the union of every built-in role, so Require answers the
	// construction guard with no allocation.
	declared permission.Set

	svc           plugin.Services
	store         store.Store
	orgs          store.OrganizationStore
	members       store.MembershipStore
	principals    plugin.PrincipalService
	hooks         *hook.Hooks
	events        *events.Emitter
	clock         func() time.Time
	schemaOptions schema.Options

	protect  func(http.Handler) http.Handler
	writeErr func(w http.ResponseWriter, r *http.Request, err error)
}

// Option configures the plugin.
type Option func(*Plugin)

// Roles declares the built-in roles of the application.
func Roles(defs ...RoleDefinition) Option {
	return func(p *Plugin) { p.roles = append(p.roles, defs...) }
}

// DefaultRole names the role of a new member. The default is the last declared
// role, which is the weakest role of a declaration that starts at the owner.
func DefaultRole(name string) Option {
	return func(p *Plugin) { p.defaultRole = name }
}

// OwnerRole names the highest role of an organization. The owner guard keeps
// one enabled member with this role.
func OwnerRole(name string) Option {
	return func(p *Plugin) { p.ownerRole = name }
}

// AllowCustomRoles lets an organization declare its own role at run time. A
// custom role never holds a permission that its creator lacks.
func AllowCustomRoles(allow bool) Option {
	return func(p *Plugin) { p.allowCustomRoles = allow }
}

// MaxMembers limits the members of one organization. The count holds the
// active members and the pending invitations. A value of 0 sets no limit.
func MaxMembers(limit int) Option {
	return func(p *Plugin) { p.maxMembers = limit }
}

// New returns the organizations plugin. Registration fails when the roles are
// empty, hold a duplicate name, or do not hold the default role and the owner
// role.
func New(opts ...Option) *Plugin {
	p := &Plugin{}
	// The default writer serializes the public error envelope. Register
	// replaces it with the writer of the instance, which also logs the
	// private cause.
	p.writeErr = func(w http.ResponseWriter, _ *http.Request, err error) { apierr.Write(w, err) }
	for _, o := range opts {
		o(p)
	}
	for _, def := range p.roles {
		p.declared = p.declared.Union(def.permissions)
	}
	return p
}

// ID implements plugin.Plugin.
func (p *Plugin) ID() string { return ID }

// Register implements plugin.Plugin.
func (p *Plugin) Register(r *plugin.Registry) error {
	if err := p.validate(); err != nil {
		return err
	}
	svc := r.Services()
	protector, ok := svc.(plugin.ProtectService)
	if !ok {
		return errors.New("authall/organizations: this Auth-All version has no authentication middleware")
	}
	principals, ok := svc.(plugin.PrincipalServices)
	if !ok {
		return errors.New("authall/organizations: this Auth-All version has no principal service")
	}
	orgs, members, err := orgStores(svc.Store())
	if err != nil {
		return err
	}
	configurator, ok := svc.(plugin.OrganizationConfigurator)
	if !ok {
		return errors.New("authall/organizations: this Auth-All version has no organization service")
	}
	if err := configurator.EnableOrganizations(); err != nil {
		return err
	}
	p.svc = svc
	p.store = svc.Store()
	p.orgs = orgs
	p.members = members
	p.principals = principals.Principals()
	p.hooks = r.Hooks()
	p.events = svc.Events()
	p.clock = svc.Now
	p.protect = protector.Protect
	p.schemaOptions = schema.DefaultOptions()
	if reporter, ok := svc.(plugin.SchemaService); ok {
		p.schemaOptions = reporter.SchemaOptions()
	}
	for _, table := range schema.OrganizationTables(p.schemaOptions) {
		r.Schema(table)
	}
	// The session row carries the active organization, so the plugin extends
	// the sessions table that the core owns.
	r.Extend(schema.SessionOrganizationExtension(p.schemaOptions))
	units, err := schema.OrganizationUnits(ID, p.schemaOptions)
	if err != nil {
		return err
	}
	for _, unit := range units {
		r.Unit(unit)
	}
	registerSchemas(r)
	p.registerRoutes(r)
	p.registerMemberRoutes(r)
	p.registerActiveRoutes(r)
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

// validate checks the declaration of the roles.
func (p *Plugin) validate() error {
	if len(p.roles) == 0 {
		return errors.New("authall/organizations: the plugin needs at least one role. Use organizations.Roles")
	}
	seen := make(map[string]struct{}, len(p.roles))
	for _, def := range p.roles {
		if _, held := seen[def.name]; held {
			return fmt.Errorf("authall/organizations: the role %q is declared twice", def.name)
		}
		seen[def.name] = struct{}{}
	}
	if p.defaultRole == "" {
		p.defaultRole = p.roles[len(p.roles)-1].name
	}
	if _, held := seen[p.defaultRole]; !held {
		return fmt.Errorf("authall/organizations: the default role %q is not declared", p.defaultRole)
	}
	if p.ownerRole == "" {
		p.ownerRole = p.roles[0].name
	}
	if _, held := seen[p.ownerRole]; !held {
		return fmt.Errorf("authall/organizations: the owner role %q is not declared", p.ownerRole)
	}
	if p.maxMembers < 0 {
		return fmt.Errorf("authall/organizations: the member limit %d is negative", p.maxMembers)
	}
	return nil
}

// RoleNames returns the declared role names, in declaration order.
func (p *Plugin) RoleNames() []string {
	out := make([]string, 0, len(p.roles))
	for _, def := range p.roles {
		out = append(out, def.name)
	}
	return out
}

// PermissionsOf returns the permission set of a declared role. The second
// result reports whether the configuration declares the role.
func (p *Plugin) PermissionsOf(role string) (permission.Set, bool) {
	for _, def := range p.roles {
		if def.name == role {
			return def.permissions, true
		}
	}
	return permission.Set{}, false
}

// Require protects a handler with one permission of the active organization.
//
// A request with no principal gets 401 UNAUTHORIZED. A request with no active
// organization gets 403 NO_ACTIVE_ORGANIZATION. A principal whose permission
// set does not hold the statement gets 403 PERMISSION_DENIED.
//
// Require panics at construction when the statement is invalid, and when no
// declared role holds it. A route that no role can reach is a fault of the
// application, and it must fail at the start.
func (p *Plugin) Require(statement string, next http.Handler) http.Handler {
	stmt, err := permission.Parse(statement)
	if err != nil {
		panic(fmt.Sprintf("authall/organizations: the permission %q is invalid: %v", statement, err))
	}
	if !p.declared.Covers(stmt) {
		panic(fmt.Sprintf("authall/organizations: no declared role holds the permission %q. Declared roles: %v", statement, p.RoleNames()))
	}
	gate := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		set, ok := p.activePermissions(r.Context())
		if !ok {
			p.writeErr(w, r, apierr.ErrNoActiveOrganization)
			return
		}
		if !set.Covers(stmt) {
			p.writeErr(w, r, apierr.ErrPermissionDenied)
			return
		}
		next.ServeHTTP(w, r)
	})
	if p.protect == nil {
		return gate
	}
	return p.protect(gate)
}

// RequireFunc is the http.HandlerFunc form of Require.
func (p *Plugin) RequireFunc(statement string, next http.HandlerFunc) http.Handler {
	return p.Require(statement, next)
}

// Can reports whether the active organization of the request holds the
// permission. It returns false when no organization is active, which is
// default deny.
func (p *Plugin) Can(ctx context.Context, statement string) bool {
	set, ok := p.activePermissions(ctx)
	if !ok {
		return false
	}
	return set.Allows(statement)
}

// activePermissions returns the effective permission set of the request.
//
// The set is the union of the organization role and of every statement that
// the credential read resolved, which holds a custom role and every team role.
// A suspended membership holds no permission.
func (p *Plugin) activePermissions(ctx context.Context) (permission.Set, bool) {
	value, ok := plugin.OrganizationFrom(ctx)
	if !ok {
		return permission.Set{}, false
	}
	if value.Membership.Status != store.MembershipActive {
		return permission.Set{}, true
	}
	set, _ := p.PermissionsOf(value.Membership.Role)
	if len(value.Permissions) > 0 {
		// A statement of the store is data of the organization, so an invalid
		// statement is dropped and never widens the set.
		extra, err := permission.NewSet(value.Permissions...)
		if err == nil {
			set = set.Union(extra)
		}
	}
	return set, true
}

// Active carries the active organization of one request.
type Active struct {
	// Organization is the active organization of the session.
	Organization *store.Organization
	// Membership is the membership of that organization.
	Membership *store.Membership
}

// From returns the active organization and the membership of the request
// context. The second result is false when no organization is active.
func From(ctx context.Context) (Active, bool) {
	value, ok := plugin.OrganizationFrom(ctx)
	if !ok {
		return Active{}, false
	}
	return Active{Organization: value.Organization, Membership: value.Membership}, true
}
