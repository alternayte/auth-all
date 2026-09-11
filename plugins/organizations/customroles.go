package organizations

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/alternayte/auth-all/apierr"
	"github.com/alternayte/auth-all/events"
	"github.com/alternayte/auth-all/openapi"
	"github.com/alternayte/auth-all/plugin"
	"github.com/alternayte/auth-all/plugins/organizations/permission"
	"github.com/alternayte/auth-all/store"
)

// customRoleNamePattern is the accepted form of a custom role name.
var customRoleNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

// CreateRole declares one role of one organization at run time.
//
// The name never shadows a built-in role, and the new role never holds a
// permission that the creator lacks. The role stores its own statements, so a
// later change of a built-in role never widens it.
func (p *Plugin) CreateRole(ctx context.Context, actor *store.User, orgID, name string, statements []string) (*store.CustomRole, error) {
	if !p.allowCustomRoles {
		return nil, apierr.ErrForbidden.WithMessage("This application allows no custom role.")
	}
	name = strings.TrimSpace(name)
	if !customRoleNamePattern.MatchString(name) {
		return nil, apierr.ErrInvalidRequest.WithMessage("The role name must match ^[a-z0-9][a-z0-9_-]{0,62}$.")
	}
	// A custom role never shadows a built-in role name.
	if _, built := p.PermissionsOf(name); built {
		return nil, apierr.ErrInvalidRequest.WithMessage("The role name belongs to a built-in role.")
	}
	granted, err := permission.NewSet(statements...)
	if err != nil {
		return nil, apierr.ErrInvalidRequest.WithMessage("A permission statement is invalid.")
	}
	if granted.Empty() {
		return nil, apierr.ErrInvalidRequest.WithMessage("A role needs at least one permission.")
	}
	if actor != nil {
		_, held, err := p.authorize(ctx, orgID, actor.ID, PermissionRoleWrite)
		if err != nil {
			return nil, err
		}
		// HC-04. A member never grants a permission that the member does not
		// hold.
		if !held.CoversSet(granted) {
			return nil, apierr.ErrRoleNotAllowed
		}
	}

	role := &store.CustomRole{
		ID: uuid.NewString(), OrgID: orgID, Name: name,
		Permissions: strings.Join(granted.Statements(), " "), CreatedAt: p.now(),
	}
	roles, err := customRoleStore(p.store)
	if err != nil {
		return nil, err
	}
	if _, err := p.orgs.OrganizationByID(ctx, orgID); err != nil {
		return nil, notFound(err)
	}
	if err := roles.CreateCustomRole(ctx, role); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return nil, apierr.ErrInvalidRequest.WithMessage("The organization already holds a role of that name.")
		}
		return nil, err
	}
	p.emit(ctx, events.CustomRoleCreated, actorID(actor), orgID, map[string]any{
		"role": name, "permissions": role.Permissions,
	})
	return role, nil
}

// DeleteRole removes one custom role of one organization.
func (p *Plugin) DeleteRole(ctx context.Context, actor *store.User, orgID, name string) error {
	if actor != nil {
		if _, _, err := p.authorize(ctx, orgID, actor.ID, PermissionRoleWrite); err != nil {
			return err
		}
	}
	roles, err := customRoleStore(p.store)
	if err != nil {
		return err
	}
	if err := roles.DeleteCustomRole(ctx, orgID, name); err != nil {
		return notFound(err)
	}
	p.emit(ctx, events.CustomRoleDeleted, actorID(actor), orgID, map[string]any{"role": name})
	return nil
}

// ListRoles returns the custom roles of one organization.
func (p *Plugin) ListRoles(ctx context.Context, orgID string) ([]store.CustomRole, error) {
	roles, err := customRoleStore(p.store)
	if err != nil {
		return nil, err
	}
	return roles.ListCustomRoles(ctx, orgID)
}

// customRoleStore returns the custom role store of one store value.
func customRoleStore(s store.Store) (store.CustomRoleStore, error) {
	roles, ok := s.(store.CustomRoleStore)
	if !ok {
		return nil, errors.New("authall/organizations: the configured store holds no custom role")
	}
	return roles, nil
}

// customRoleDTO is the public shape of one custom role.
type customRoleDTO struct {
	Name        string    `json:"name"`
	Permissions []string  `json:"permissions"`
	CreatedAt   time.Time `json:"createdAt"`
}

// roleListResponse carries the custom roles of one organization.
type roleListResponse struct {
	Roles []customRoleDTO `json:"roles"`
}

// roleResponse carries one custom role.
type roleResponse struct {
	Role customRoleDTO `json:"role"`
}

// createRoleRequest is the body of the create role route.
type createRoleRequest struct {
	Name        string   `json:"name"`
	Permissions []string `json:"permissions"`
}

// toRoleDTO returns the public shape of one custom role.
func toRoleDTO(r *store.CustomRole) customRoleDTO {
	return customRoleDTO{
		Name: r.Name, Permissions: strings.Fields(r.Permissions), CreatedAt: r.CreatedAt,
	}
}

// registerRoleRoutes mounts the custom role routes.
func (p *Plugin) registerRoleRoutes(r *plugin.Registry) {
	tag := []string{"organizations"}
	r.Route(plugin.Route{
		Method: http.MethodGet, Path: "/organizations/{id}/roles", Handler: p.guard(p.handleListRoles),
		Operation: orgOperation("listOrganizationRoles", "List the custom roles of one organization", tag, nil,
			openapi.Ref("OrganizationRoleListResponse"), "listRoles", "404"),
	})
	r.Route(plugin.Route{
		Method: http.MethodPost, Path: "/organizations/{id}/roles", Handler: p.guard(p.handleCreateRole),
		Operation: orgOperation("createOrganizationRole", "Declare one custom role", tag,
			openapi.JSONBody(openapi.Object([]string{"name", "permissions"}, map[string]*openapi.Schema{
				"name":        openapi.String(),
				"permissions": {Type: "array", Items: openapi.String()},
			})),
			openapi.Ref("OrganizationRoleResponse"), "createRole", "400", "404"),
	})
	r.Route(plugin.Route{
		Method: http.MethodDelete, Path: "/organizations/{id}/roles/{name}", Handler: p.guard(p.handleDeleteRole),
		Operation: roleOperation("deleteOrganizationRole", "Remove one custom role", tag, nil,
			openapi.Ref("SuccessResponse"), "deleteRole", "404"),
	})
}

// roleOperation builds one operation that names an organization and a role in
// the path.
func roleOperation(id, summary string, tag []string, body *openapi.RequestBody,
	okSchema *openapi.Schema, method string, codes ...string) *openapi.Operation {
	parameters := []openapi.Parameter{
		{Name: "id", In: "path", Required: true, Schema: openapi.String()},
		{Name: "name", In: "path", Required: true, Schema: openapi.String()},
	}
	return withParameters(id, summary, tag, body, okSchema, method, parameters, codes...)
}

// registerRoleSchemas adds the component schemas of the custom role responses.
func registerRoleSchemas(r *plugin.Registry) {
	r.OpenAPISchema("OrganizationRole", openapi.Object(
		[]string{"name", "permissions", "createdAt"},
		map[string]*openapi.Schema{
			"name":        openapi.String(),
			"permissions": {Type: "array", Items: openapi.String()},
			"createdAt":   {Type: "string", Format: "date-time"},
		}))
	r.OpenAPISchema("OrganizationRoleResponse", openapi.Object([]string{"role"},
		map[string]*openapi.Schema{"role": openapi.Ref("OrganizationRole")}))
	r.OpenAPISchema("OrganizationRoleListResponse", openapi.Object([]string{"roles"},
		map[string]*openapi.Schema{"roles": {Type: "array", Items: openapi.Ref("OrganizationRole")}}))
}

// handleCreateRole serves POST /organizations/{id}/roles.
func (p *Plugin) handleCreateRole(w http.ResponseWriter, r *http.Request, principal *plugin.Principal) {
	var req createRoleRequest
	if err := p.svc.HTTP().DecodeJSON(r, &req); err != nil {
		p.writeErr(w, r, err)
		return
	}
	role, err := p.CreateRole(r.Context(), principal.User, r.PathValue("id"), req.Name, req.Permissions)
	if err != nil {
		p.writeErr(w, r, err)
		return
	}
	p.svc.HTTP().WriteJSON(w, http.StatusCreated, roleResponse{Role: toRoleDTO(role)})
}

// handleListRoles serves GET /organizations/{id}/roles.
func (p *Plugin) handleListRoles(w http.ResponseWriter, r *http.Request, principal *plugin.Principal) {
	orgID := r.PathValue("id")
	if _, _, err := p.authorize(r.Context(), orgID, principal.User.ID, PermissionMemberRead); err != nil {
		p.writeErr(w, r, err)
		return
	}
	roles, err := p.ListRoles(r.Context(), orgID)
	if err != nil {
		p.writeErr(w, r, err)
		return
	}
	out := make([]customRoleDTO, 0, len(roles))
	for i := range roles {
		out = append(out, toRoleDTO(&roles[i]))
	}
	p.svc.HTTP().WriteJSON(w, http.StatusOK, roleListResponse{Roles: out})
}

// handleDeleteRole serves DELETE /organizations/{id}/roles/{name}.
func (p *Plugin) handleDeleteRole(w http.ResponseWriter, r *http.Request, principal *plugin.Principal) {
	if err := p.DeleteRole(r.Context(), principal.User, r.PathValue("id"), r.PathValue("name")); err != nil {
		p.writeErr(w, r, err)
		return
	}
	p.svc.HTTP().WriteJSON(w, http.StatusOK, map[string]bool{"success": true})
}

// KeyCredential returns the organization credential of one API key.
//
// The permissions are the intersection of the key permissions and the live
// permissions of the owner in that organization, so a demoted member keeps no
// stronger key. A key of an organization that the owner left authenticates
// nothing.
func (p *Plugin) KeyCredential(ctx context.Context, orgID, ownerID, keyRole string) (
	*store.Organization, *store.Membership, []string, error) {
	org, err := p.orgs.OrganizationByID(ctx, orgID)
	if err != nil {
		return nil, nil, nil, notFound(err)
	}
	member, err := p.membershipOf(ctx, orgID, ownerID)
	if err != nil {
		return nil, nil, nil, err
	}
	if member.Status != store.MembershipActive {
		return nil, nil, nil, apierr.ErrNotAMember
	}
	live, err := p.permissionsOfMembership(ctx, p.store, member)
	if err != nil {
		return nil, nil, nil, err
	}
	granted, known, err := p.knownRole(ctx, p.store, orgID, keyRole)
	if err != nil {
		return nil, nil, nil, err
	}
	if !known {
		// A key of a role that the organization does not hold carries no
		// permission, which is default deny.
		granted = permission.Set{}
	}
	return org, member, intersect(granted, live), nil
}

// KnownRole reports whether the organization holds the role.
func (p *Plugin) KnownRole(ctx context.Context, orgID, role string) (bool, error) {
	_, known, err := p.knownRole(ctx, p.store, orgID, role)
	return known, err
}

// intersect returns the statements that both sets hold. A statement of the key
// survives only when the live set of the owner covers its whole reach.
func intersect(key, live permission.Set) []string {
	var out []string
	for _, statement := range key.Statements() {
		stmt, err := permission.Parse(statement)
		if err != nil {
			continue
		}
		if live.Covers(stmt) {
			out = append(out, statement)
		}
	}
	return out
}

// AdminList returns one page of every organization of the application. An
// administrator of the application uses it.
func (p *Plugin) AdminList(ctx context.Context, limit int, cursor string) ([]store.Organization, string, error) {
	return p.orgs.ListOrganizations(ctx, store.OrganizationFilter{Limit: limit, Cursor: cursor})
}

// AdminDelete removes one organization and every row that belongs to it. An
// administrator of the application uses it, so it runs no membership check.
func (p *Plugin) AdminDelete(ctx context.Context, actor *store.User, orgID string) error {
	return p.Delete(ctx, actor, orgID)
}
