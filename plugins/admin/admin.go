// Package admin adds user administration to Auth-All.
//
// The plugin serves the administrative HTTP routes, and it exports the same
// operations as Go methods, so an operator task needs no HTTP request.
//
//	adm := admin.New(admin.AdminRole("admin"))
//	auth, err := authall.New(authall.WithStore(s),
//	    authall.WithPlugins(roles.New(roles.Hierarchy("viewer", "admin")), adm))
//	created, err := adm.Bootstrap(ctx, admin.Credentials{Email: e, Password: p})
package admin

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/alternayte/auth-all/apierr"
	"github.com/alternayte/auth-all/events"
	"github.com/alternayte/auth-all/hook"
	"github.com/alternayte/auth-all/openapi"
	"github.com/alternayte/auth-all/plugin"
	"github.com/alternayte/auth-all/schema"
	"github.com/alternayte/auth-all/store"
)

// ID is the stable plugin identifier.
const ID = "admin"

// DefaultAdminRole is the role that every administrative route requires.
const DefaultAdminRole = "admin"

// temporaryPasswordLength is the number of characters of a generated
// temporary password.
const temporaryPasswordLength = 20

// Plugin is the admin plugin.
type Plugin struct {
	adminRole string

	svc        plugin.Services
	roles      plugin.RoleService
	principals plugin.PrincipalService
	protect    func(http.Handler) http.Handler
	hooks      *hook.Hooks
	store      store.Store
	users      plugin.UserService
	now        func() time.Time
	// schemaOptions carry the physical table names of the host.
	schemaOptions schema.Options
}

// Option configures the plugin.
type Option func(*Plugin)

// AdminRole names the role that every administrative route requires. The
// default is "admin".
func AdminRole(name string) Option {
	return func(p *Plugin) { p.adminRole = name }
}

// New returns the admin plugin.
func New(opts ...Option) *Plugin {
	p := &Plugin{adminRole: DefaultAdminRole}
	for _, o := range opts {
		o(p)
	}
	return p
}

// ID implements plugin.Plugin.
func (p *Plugin) ID() string { return ID }

// AdminRoleName returns the configured administrator role.
func (p *Plugin) AdminRoleName() string { return p.adminRole }

// Register implements plugin.Plugin.
func (p *Plugin) Register(r *plugin.Registry) error {
	svc := r.Services()
	reader, ok := svc.(plugin.RoleServices)
	if !ok {
		return errors.New("authall/admin: the roles plugin must be enabled before the admin plugin")
	}
	principals, ok := svc.(plugin.PrincipalServices)
	if !ok {
		return errors.New("authall/admin: this Auth-All version has no principal service")
	}
	protector, ok := svc.(plugin.ProtectService)
	if !ok {
		return errors.New("authall/admin: this Auth-All version has no authentication middleware")
	}
	p.svc = svc
	p.roles = reader.Roles()
	p.principals = principals.Principals()
	p.protect = protector.Protect
	p.hooks = r.Hooks()
	p.store = svc.Store()
	p.users = svc.Users()
	p.now = svc.Now
	if len(p.roles.Names()) == 0 {
		return errors.New("authall/admin: the roles plugin must be enabled before the admin plugin")
	}
	if p.roles.Rank(p.adminRole) < 0 {
		return fmt.Errorf("authall/admin: the administrator role %q is not in the role hierarchy", p.adminRole)
	}

	// The plugin owns the bootstrap guard table. It takes the physical schema
	// options of the host, so the table carries the host prefix.
	p.schemaOptions = schema.DefaultOptions()
	if reporter, ok := svc.(plugin.SchemaService); ok {
		p.schemaOptions = reporter.SchemaOptions()
	}
	r.Schema(bootstrapTable(p.schemaOptions))
	unit, err := bootstrapUnit(p.schemaOptions)
	if err != nil {
		return err
	}
	r.Unit(unit)

	registerSchemas(r)
	p.registerRoutes(r)
	return nil
}

// registerSchemas adds the component schemas of the administrative responses.
func registerSchemas(r *plugin.Registry) {
	user := openapi.Object(
		[]string{"id", "email", "emailVerified", "name", "role", "mustChangePassword", "createdAt", "updatedAt"},
		map[string]*openapi.Schema{
			"id":                 openapi.String(),
			"email":              openapi.String(),
			"emailVerified":      openapi.Bool(),
			"name":               openapi.String(),
			"role":               openapi.String(),
			"disabledAt":         {Type: "string", Format: "date-time", Nullable: true},
			"mustChangePassword": openapi.Bool(),
			"createdAt":          {Type: "string", Format: "date-time"},
			"updatedAt":          {Type: "string", Format: "date-time"},
		})
	r.OpenAPISchema("AdminUser", user)
	r.OpenAPISchema("AdminUserResponse", openapi.Object([]string{"user"},
		map[string]*openapi.Schema{"user": openapi.Ref("AdminUser")}))
	r.OpenAPISchema("AdminUserListResponse", openapi.Object([]string{"users", "nextCursor"},
		map[string]*openapi.Schema{
			"users":      {Type: "array", Items: openapi.Ref("AdminUser")},
			"nextCursor": openapi.String(),
		}))
	r.OpenAPISchema("AdminCreateUserResponse", openapi.Object([]string{"user"},
		map[string]*openapi.Schema{
			"user":              openapi.Ref("AdminUser"),
			"temporaryPassword": openapi.String(),
		}))
	r.OpenAPISchema("AdminPasswordResponse", openapi.Object(nil,
		map[string]*openapi.Schema{"temporaryPassword": openapi.String()}))
}

// registerRoutes mounts every administrative route.
func (p *Plugin) registerRoutes(r *plugin.Registry) {
	tag := []string{"admin"}
	r.Route(plugin.Route{
		Method: http.MethodGet, Path: "/admin/users", Handler: p.guard(p.handleList),
		Operation: listOperation(tag),
	})
	r.Route(plugin.Route{
		Method: http.MethodPost, Path: "/admin/users", Handler: p.guard(p.handleCreate),
		Operation: createOperation(tag),
	})
	r.Route(plugin.Route{
		Method: http.MethodPost, Path: "/admin/users/{id}/role", Handler: p.guard(p.handleRole),
		Operation: roleOperation(tag),
	})
	r.Route(plugin.Route{
		Method: http.MethodPost, Path: "/admin/users/{id}/disable", Handler: p.guard(p.handleDisable),
		Operation: simpleOperation(tag, "adminDisableUser", "Disable a user", "disable"),
	})
	r.Route(plugin.Route{
		Method: http.MethodPost, Path: "/admin/users/{id}/enable", Handler: p.guard(p.handleEnable),
		Operation: simpleOperation(tag, "adminEnableUser", "Enable a user", "enable"),
	})
	r.Route(plugin.Route{
		Method: http.MethodPost, Path: "/admin/users/{id}/password", Handler: p.guard(p.handlePassword),
		Operation: passwordOperation(tag),
	})
}

// guard requires a session principal with the administrator role. An API key
// never reaches an administrative route.
func (p *Plugin) guard(fn http.HandlerFunc) http.Handler {
	gate := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal := p.principals.Current(r.Context())
		if principal == nil {
			p.writeError(w, r, apierr.ErrUnauthorized)
			return
		}
		if principal.Method != "session" {
			// Key management and user administration need a person, so an API
			// key never reaches these routes.
			p.writeError(w, r, apierr.ErrForbidden)
			return
		}
		if !p.roles.AtLeast(principal.Role, p.adminRole) {
			p.writeError(w, r, apierr.ErrInsufficientRole)
			return
		}
		fn(w, r)
	})
	// Protect resolves the principal and runs the origin check of the host
	// routes, so every administrative route passes it.
	return p.protect(gate)
}

// writeError writes the public error envelope of one request.
func (p *Plugin) writeError(w http.ResponseWriter, r *http.Request, err error) {
	if writer, ok := p.svc.HTTP().(interface {
		WriteErrorFor(http.ResponseWriter, *http.Request, error)
	}); ok {
		writer.WriteErrorFor(w, r, err)
		return
	}
	p.svc.HTTP().WriteError(w, err)
}

// actorOf returns the caller of one request.
func (p *Plugin) actorOf(ctx context.Context) string {
	if principal := p.principals.Current(ctx); principal != nil && principal.User != nil {
		return principal.User.ID
	}
	return events.ActorSystem
}

// handleList serves GET /admin/users.
func (p *Plugin) handleList(w http.ResponseWriter, r *http.Request) {
	admin, ok := p.store.(store.UserAdminStore)
	if !ok {
		p.writeError(w, r, apierr.ErrInternal.WithCause(errors.New("the store lists no users")))
		return
	}
	q := r.URL.Query()
	filter := store.UserListFilter{EmailPrefix: q.Get("email"), Cursor: q.Get("cursor"), Limit: 50}
	if raw := q.Get("limit"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > 200 {
			p.writeError(w, r, apierr.ErrInvalidRequest.WithMessage("The limit must be between 1 and 200."))
			return
		}
		filter.Limit = value
	}
	if raw := q.Get("role"); raw != "" {
		if p.roles.Rank(raw) < 0 {
			p.writeError(w, r, apierr.ErrRoleUnknown)
			return
		}
		role := raw
		filter.Role = &role
	}
	if raw := q.Get("disabled"); raw != "" {
		value, err := strconv.ParseBool(raw)
		if err != nil {
			p.writeError(w, r, apierr.ErrInvalidRequest.WithMessage("The disabled filter must be true or false."))
			return
		}
		filter.Disabled = &value
	}
	users, next, err := admin.ListUsers(r.Context(), filter)
	if err != nil {
		p.writeError(w, r, apierr.ErrInvalidRequest.WithMessage("The cursor is invalid.").WithCause(err))
		return
	}
	out := make([]userDTO, 0, len(users))
	for i := range users {
		out = append(out, p.toDTO(&users[i]))
	}
	p.svc.HTTP().WriteJSON(w, http.StatusOK, listResponse{Users: out, NextCursor: next})
}

// handleCreate serves POST /admin/users.
func (p *Plugin) handleCreate(w http.ResponseWriter, r *http.Request) {
	var req createRequest
	if err := p.svc.HTTP().DecodeJSON(r, &req); err != nil {
		p.writeError(w, r, err)
		return
	}
	ctx := p.actorContext(r)
	user, password, err := p.CreateUser(ctx, CreateUserInput{
		Email:             req.Email,
		Name:              req.Name,
		Role:              req.Role,
		Password:          req.Password,
		TemporaryPassword: req.TemporaryPassword == nil || *req.TemporaryPassword,
	})
	if err != nil {
		p.writeError(w, r, err)
		return
	}
	p.svc.HTTP().WriteJSON(w, http.StatusCreated, createResponse{
		User: p.toDTO(user), TemporaryPassword: password,
	})
}

// handleRole serves POST /admin/users/{id}/role.
func (p *Plugin) handleRole(w http.ResponseWriter, r *http.Request) {
	var req roleRequest
	if err := p.svc.HTTP().DecodeJSON(r, &req); err != nil {
		p.writeError(w, r, err)
		return
	}
	user, err := p.SetRole(p.actorContext(r), r.PathValue("id"), req.Role)
	if err != nil {
		p.writeError(w, r, err)
		return
	}
	p.svc.HTTP().WriteJSON(w, http.StatusOK, userResponse{User: p.toDTO(user)})
}

// handleDisable serves POST /admin/users/{id}/disable.
func (p *Plugin) handleDisable(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if principal := p.principals.Current(r.Context()); principal != nil &&
		principal.User != nil && principal.User.ID == id {
		// An administrator that disables the own account locks the last door
		// from the inside.
		p.writeError(w, r, apierr.ErrForbidden.WithMessage("An administrator cannot disable the own account."))
		return
	}
	user, err := p.Disable(p.actorContext(r), id)
	if err != nil {
		p.writeError(w, r, err)
		return
	}
	p.svc.HTTP().WriteJSON(w, http.StatusOK, userResponse{User: p.toDTO(user)})
}

// handleEnable serves POST /admin/users/{id}/enable.
func (p *Plugin) handleEnable(w http.ResponseWriter, r *http.Request) {
	user, err := p.Enable(p.actorContext(r), r.PathValue("id"))
	if err != nil {
		p.writeError(w, r, err)
		return
	}
	p.svc.HTTP().WriteJSON(w, http.StatusOK, userResponse{User: p.toDTO(user)})
}

// handlePassword serves POST /admin/users/{id}/password.
func (p *Plugin) handlePassword(w http.ResponseWriter, r *http.Request) {
	var req passwordRequest
	if err := p.svc.HTTP().DecodeJSON(r, &req); err != nil && !errors.Is(err, apierr.ErrInvalidRequest) {
		p.writeError(w, r, err)
		return
	}
	password, err := p.ResetPassword(p.actorContext(r), r.PathValue("id"), ResetOptions{
		Password:  req.Password,
		Temporary: req.Temporary == nil || *req.Temporary,
	})
	if err != nil {
		p.writeError(w, r, err)
		return
	}
	p.svc.HTTP().WriteJSON(w, http.StatusOK, passwordResponse{TemporaryPassword: password})
}

// actorContext returns the request context with the caller as the actor of
// every event.
func (p *Plugin) actorContext(r *http.Request) context.Context {
	ctx := r.Context()
	actor, _ := events.ActorFrom(ctx)
	actor.ID = p.actorOf(ctx)
	return events.WithActor(ctx, actor)
}

// toDTO returns the public shape of one user.
func (p *Plugin) toDTO(u *store.User) userDTO {
	dto := userDTO{
		ID:                 u.ID,
		Email:              u.Email,
		EmailVerified:      u.EmailVerifiedAt != nil,
		Name:               u.DisplayName,
		Role:               u.Role,
		MustChangePassword: u.MustChangePassword,
		CreatedAt:          u.CreatedAt,
		UpdatedAt:          u.UpdatedAt,
	}
	if dto.Role == "" {
		dto.Role = p.roles.Default()
	}
	if u.DisabledAt != nil {
		value := *u.DisabledAt
		dto.DisabledAt = &value
	}
	return dto
}

// operation builds one administrative operation with the standard error
// responses.
func operation(id, summary string, tag []string, body *openapi.RequestBody,
	okSchema *openapi.Schema, method string, codes ...string) *openapi.Operation {
	return withParameters(id, summary, tag, body, okSchema, method, nil, codes...)
}

// userOperation builds one operation that names a user in the path.
func userOperation(id, summary string, tag []string, body *openapi.RequestBody,
	okSchema *openapi.Schema, method string, codes ...string) *openapi.Operation {
	parameters := []openapi.Parameter{
		{Name: "id", In: "path", Required: true, Schema: openapi.String()},
	}
	return withParameters(id, summary, tag, body, okSchema, method, parameters, codes...)
}

// withParameters builds one operation with the standard error responses.
func withParameters(id, summary string, tag []string, body *openapi.RequestBody,
	okSchema *openapi.Schema, method string, parameters []openapi.Parameter,
	codes ...string) *openapi.Operation {
	responses := map[string]openapi.Response{
		"200": openapi.JSONResponse("The operation succeeded", okSchema),
	}
	for _, c := range append([]string{"401", "403"}, codes...) {
		responses[c] = openapi.JSONResponse("Auth-All error", openapi.Ref("ErrorResponse"))
	}
	return &openapi.Operation{
		OperationID: id,
		Summary:     summary,
		Tags:        tag,
		Parameters:  parameters,
		RequestBody: body,
		Responses:   responses,
		Client:      &openapi.ClientBinding{Namespace: "admin", Method: method},
	}
}

func listOperation(tag []string) *openapi.Operation {
	return operation("adminListUsers", "List the users", tag, nil,
		openapi.Ref("AdminUserListResponse"), "listUsers", "400")
}

func createOperation(tag []string) *openapi.Operation {
	body := openapi.JSONBody(openapi.Object([]string{"email"}, map[string]*openapi.Schema{
		"email":             openapi.String(),
		"name":              openapi.String(),
		"role":              openapi.String(),
		"password":          openapi.String(),
		"temporaryPassword": openapi.Bool(),
	}))
	return operation("adminCreateUser", "Create a user", tag, body,
		openapi.Ref("AdminCreateUserResponse"), "createUser", "400", "409")
}

func roleOperation(tag []string) *openapi.Operation {
	body := openapi.JSONBody(openapi.Object([]string{"role"}, map[string]*openapi.Schema{
		"role": openapi.String(),
	}))
	return userOperation("adminSetUserRole", "Set the role of a user", tag, body,
		openapi.Ref("AdminUserResponse"), "setUserRole", "400", "404", "409")
}

func passwordOperation(tag []string) *openapi.Operation {
	body := openapi.JSONBody(openapi.Object(nil, map[string]*openapi.Schema{
		"password":  openapi.String(),
		"temporary": openapi.Bool(),
	}))
	return userOperation("adminResetUserPassword", "Set a new password for a user", tag, body,
		openapi.Ref("AdminPasswordResponse"), "resetUserPassword", "400", "404")
}

func simpleOperation(tag []string, id, summary, method string) *openapi.Operation {
	return userOperation(id, summary, tag, nil, openapi.Ref("AdminUserResponse"), method+"User", "404", "409")
}
