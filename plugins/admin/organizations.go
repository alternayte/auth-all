package admin

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/alternayte/auth-all/openapi"
	"github.com/alternayte/auth-all/plugin"
	"github.com/alternayte/auth-all/store"
)

// OrganizationService lists and removes the organizations of the whole
// application. The organizations plugin implements it.
type OrganizationService interface {
	// AdminList returns one page of every organization of the application.
	AdminList(ctx context.Context, limit int, cursor string) ([]store.Organization, string, error)
	// AdminDelete removes one organization and every row that belongs to it.
	AdminDelete(ctx context.Context, actor *store.User, orgID string) error
}

// Organizations adds the administrative organization routes. The value is the
// organizations plugin.
//
//	orgs := organizations.New(...)
//	adm := admin.New(admin.Organizations(orgs))
func Organizations(s OrganizationService) Option {
	return func(p *Plugin) { p.organizations = s }
}

// organizationDTO is the public shape of one organization in an
// administrative list.
type organizationDTO struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	CreatedAt time.Time `json:"createdAt"`
}

// organizationListResponse carries one page of organizations.
type organizationListResponse struct {
	Organizations []organizationDTO `json:"organizations"`
	NextCursor    string            `json:"nextCursor"`
}

// registerOrganizationRoutes mounts the administrative organization routes.
// The plugin registers them only when the host wired the organizations plugin.
func (p *Plugin) registerOrganizationRoutes(r *plugin.Registry) {
	if p.organizations == nil {
		return
	}
	tag := []string{"admin"}
	r.Route(plugin.Route{
		Method: http.MethodGet, Path: "/admin/organizations", Handler: p.guard(p.handleListOrganizations),
		Operation: organizationListOperation(tag),
	})
	r.Route(plugin.Route{
		Method: http.MethodDelete, Path: "/admin/organizations/{id}", Handler: p.guard(p.handleDeleteOrganization),
		Operation: organizationDeleteOperation(tag),
	})
	r.OpenAPISchema("AdminOrganization", openapi.Object(
		[]string{"id", "name", "slug", "createdAt"},
		map[string]*openapi.Schema{
			"id":        openapi.String(),
			"name":      openapi.String(),
			"slug":      openapi.String(),
			"createdAt": {Type: "string", Format: "date-time"},
		}))
	r.OpenAPISchema("AdminOrganizationListResponse", openapi.Object([]string{"organizations"},
		map[string]*openapi.Schema{
			"organizations": {Type: "array", Items: openapi.Ref("AdminOrganization")},
			"nextCursor":    openapi.String(),
		}))
}

// organizationListOperation documents the administrative list.
func organizationListOperation(tag []string) *openapi.Operation {
	return &openapi.Operation{
		OperationID: "adminListOrganizations",
		Summary:     "List every organization of the application",
		Tags:        tag,
		Parameters: []openapi.Parameter{
			{Name: "limit", In: "query", Schema: openapi.String()},
			{Name: "cursor", In: "query", Schema: openapi.String()},
		},
		Responses: map[string]openapi.Response{
			"200": openapi.JSONResponse("The organizations of one page",
				openapi.Ref("AdminOrganizationListResponse")),
			"401": openapi.JSONResponse("Auth-All error", openapi.Ref("ErrorResponse")),
			"403": openapi.JSONResponse("Auth-All error", openapi.Ref("ErrorResponse")),
		},
		Client: &openapi.ClientBinding{Namespace: "admin", Method: "listOrganizations"},
	}
}

// organizationDeleteOperation documents the administrative deletion.
func organizationDeleteOperation(tag []string) *openapi.Operation {
	return &openapi.Operation{
		OperationID: "adminDeleteOrganization",
		Summary:     "Delete one organization of the application",
		Tags:        tag,
		Parameters: []openapi.Parameter{
			{Name: "id", In: "path", Required: true, Schema: openapi.String()},
		},
		Responses: map[string]openapi.Response{
			"200": openapi.JSONResponse("The operation succeeded", openapi.Ref("SuccessResponse")),
			"401": openapi.JSONResponse("Auth-All error", openapi.Ref("ErrorResponse")),
			"403": openapi.JSONResponse("Auth-All error", openapi.Ref("ErrorResponse")),
			"404": openapi.JSONResponse("Auth-All error", openapi.Ref("ErrorResponse")),
		},
		Client: &openapi.ClientBinding{Namespace: "admin", Method: "deleteOrganization"},
	}
}

// handleListOrganizations serves GET /admin/organizations.
func (p *Plugin) handleListOrganizations(w http.ResponseWriter, r *http.Request) {
	limit := 0
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if value, err := strconv.Atoi(raw); err == nil {
			limit = value
		}
	}
	orgs, next, err := p.organizations.AdminList(r.Context(), limit, r.URL.Query().Get("cursor"))
	if err != nil {
		p.writeError(w, r, err)
		return
	}
	out := make([]organizationDTO, 0, len(orgs))
	for i := range orgs {
		out = append(out, organizationDTO{
			ID: orgs[i].ID, Name: orgs[i].Name, Slug: orgs[i].Slug, CreatedAt: orgs[i].CreatedAt,
		})
	}
	p.svc.HTTP().WriteJSON(w, http.StatusOK, organizationListResponse{Organizations: out, NextCursor: next})
}

// handleDeleteOrganization serves DELETE /admin/organizations/{id}.
func (p *Plugin) handleDeleteOrganization(w http.ResponseWriter, r *http.Request) {
	principal := p.principals.Current(r.Context())
	var actor *store.User
	if principal != nil {
		actor = principal.User
	}
	if err := p.organizations.AdminDelete(r.Context(), actor, r.PathValue("id")); err != nil {
		p.writeError(w, r, err)
		return
	}
	p.svc.HTTP().WriteJSON(w, http.StatusOK, map[string]bool{"success": true})
}
