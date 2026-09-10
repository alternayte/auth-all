package organizations

import (
	"net/http"
	"strconv"
	"time"

	"github.com/alternayte/auth-all/apierr"
	"github.com/alternayte/auth-all/openapi"
	"github.com/alternayte/auth-all/plugin"
	"github.com/alternayte/auth-all/store"
)

// maxPageSize is the highest accepted page size of a list route.
const maxPageSize = 200

// organizationDTO is the public shape of one organization.
type organizationDTO struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	Slug      string         `json:"slug"`
	CreatedAt time.Time      `json:"createdAt"`
	UpdatedAt time.Time      `json:"updatedAt"`
	Extra     map[string]any `json:"extra,omitempty"`
}

// organizationResponse carries one organization.
type organizationResponse struct {
	Organization organizationDTO `json:"organization"`
}

// organizationListResponse carries one page of organizations.
type organizationListResponse struct {
	Organizations []organizationDTO `json:"organizations"`
	// NextCursor continues the list. An empty value means that no page
	// follows.
	NextCursor string `json:"nextCursor"`
}

// createRequest is the body of the create route.
type createRequest struct {
	Name  string         `json:"name"`
	Slug  string         `json:"slug"`
	Extra map[string]any `json:"extra"`
}

// updateRequest is the body of the update route. A nil field keeps the stored
// value.
type updateRequest struct {
	Name  *string        `json:"name"`
	Slug  *string        `json:"slug"`
	Extra map[string]any `json:"extra"`
}

// toOrganizationDTO returns the public shape of one organization.
func (p *Plugin) toOrganizationDTO(o *store.Organization) organizationDTO {
	out := organizationDTO{
		ID: o.ID, Name: o.Name, Slug: o.Slug,
		CreatedAt: o.CreatedAt, UpdatedAt: o.UpdatedAt,
	}
	if len(p.schemaOptions.OrgFields) == 0 {
		return out
	}
	extra := map[string]any{}
	for _, f := range p.schemaOptions.OrgFields {
		if !f.Returned {
			continue
		}
		if value, ok := o.Extra.Get(f.Name); ok {
			extra[f.Name] = value
		}
	}
	if len(extra) > 0 {
		out.Extra = extra
	}
	return out
}

// registerRoutes mounts the organization routes.
func (p *Plugin) registerRoutes(r *plugin.Registry) {
	tag := []string{"organizations"}
	r.Route(plugin.Route{
		Method: http.MethodGet, Path: "/organizations", Handler: p.guard(p.handleList),
		Operation: operation("listOrganizations", "List the organizations of the caller", tag, nil,
			openapi.Ref("OrganizationListResponse"), "list"),
	})
	r.Route(plugin.Route{
		Method: http.MethodPost, Path: "/organizations", Handler: p.guard(p.handleCreate),
		Operation: operation("createOrganization", "Create an organization", tag,
			openapi.JSONBody(openapi.Object([]string{"name", "slug"}, map[string]*openapi.Schema{
				"name":  openapi.String(),
				"slug":  openapi.String(),
				"extra": {Type: "object"},
			})),
			openapi.Ref("OrganizationResponse"), "create", "400", "409"),
	})
	r.Route(plugin.Route{
		Method: http.MethodGet, Path: "/organizations/{id}", Handler: p.guard(p.handleGet),
		Operation: orgOperation("getOrganization", "Read one organization", tag, nil,
			openapi.Ref("OrganizationResponse"), "get", "404"),
	})
	r.Route(plugin.Route{
		Method: http.MethodPatch, Path: "/organizations/{id}", Handler: p.guard(p.handleUpdate),
		Operation: orgOperation("updateOrganization", "Update one organization", tag,
			openapi.JSONBody(openapi.Object(nil, map[string]*openapi.Schema{
				"name":  openapi.String(),
				"slug":  openapi.String(),
				"extra": {Type: "object"},
			})),
			openapi.Ref("OrganizationResponse"), "update", "400", "404", "409"),
	})
	r.Route(plugin.Route{
		Method: http.MethodDelete, Path: "/organizations/{id}", Handler: p.guard(p.handleDelete),
		Operation: orgOperation("deleteOrganization", "Delete one organization", tag, nil,
			openapi.Ref("SuccessResponse"), "delete", "404"),
	})
}

// operation builds one organization operation with the standard error
// responses.
func operation(id, summary string, tag []string, body *openapi.RequestBody,
	okSchema *openapi.Schema, method string, codes ...string) *openapi.Operation {
	return withParameters(id, summary, tag, body, okSchema, method, nil, codes...)
}

// orgOperation builds one operation that names an organization in the path.
func orgOperation(id, summary string, tag []string, body *openapi.RequestBody,
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
		Client:      &openapi.ClientBinding{Namespace: "organizations", Method: method},
	}
}

// registerSchemas adds the component schemas of the organization responses.
func registerSchemas(r *plugin.Registry) {
	r.OpenAPISchema("Organization", openapi.Object(
		[]string{"id", "name", "slug", "createdAt", "updatedAt"},
		map[string]*openapi.Schema{
			"id":        openapi.String(),
			"name":      openapi.String(),
			"slug":      openapi.String(),
			"createdAt": {Type: "string", Format: "date-time"},
			"updatedAt": {Type: "string", Format: "date-time"},
			"extra":     {Type: "object"},
		}))
	r.OpenAPISchema("OrganizationResponse", openapi.Object([]string{"organization"},
		map[string]*openapi.Schema{"organization": openapi.Ref("Organization")}))
	r.OpenAPISchema("OrganizationListResponse", openapi.Object([]string{"organizations"},
		map[string]*openapi.Schema{
			"organizations": {Type: "array", Items: openapi.Ref("Organization")},
			"nextCursor":    openapi.String(),
		}))
	r.OpenAPISchema("Membership", openapi.Object(
		[]string{"id", "orgId", "userId", "role", "status", "joinedAt"},
		map[string]*openapi.Schema{
			"id":       openapi.String(),
			"orgId":    openapi.String(),
			"userId":   openapi.String(),
			"role":     openapi.String(),
			"status":   openapi.String(),
			"joinedAt": {Type: "string", Format: "date-time"},
		}))
	r.OpenAPISchema("MembershipResponse", openapi.Object([]string{"membership"},
		map[string]*openapi.Schema{"membership": openapi.Ref("Membership")}))
}

// guard requires a signed-in principal.
func (p *Plugin) guard(fn func(http.ResponseWriter, *http.Request, *plugin.Principal)) http.Handler {
	gate := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal := p.principals.Current(r.Context())
		if principal == nil {
			p.writeErr(w, r, apierr.ErrUnauthorized)
			return
		}
		fn(w, r, principal)
	})
	return p.protect(gate)
}

// pageOf returns the page size and the cursor of a list request.
func pageOf(r *http.Request) (int, string) {
	limit := 0
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if value, err := strconv.Atoi(raw); err == nil {
			limit = value
		}
	}
	if limit > maxPageSize {
		limit = maxPageSize
	}
	return limit, r.URL.Query().Get("cursor")
}

// handleList serves GET /organizations. It returns the organizations of the
// caller.
func (p *Plugin) handleList(w http.ResponseWriter, r *http.Request, principal *plugin.Principal) {
	limit, cursor := pageOf(r)
	orgs, next, err := p.List(r.Context(), principal.User.ID, limit, cursor)
	if err != nil {
		p.writeErr(w, r, err)
		return
	}
	out := make([]organizationDTO, 0, len(orgs))
	for i := range orgs {
		out = append(out, p.toOrganizationDTO(&orgs[i]))
	}
	p.svc.HTTP().WriteJSON(w, http.StatusOK, organizationListResponse{Organizations: out, NextCursor: next})
}

// handleCreate serves POST /organizations.
func (p *Plugin) handleCreate(w http.ResponseWriter, r *http.Request, principal *plugin.Principal) {
	var req createRequest
	if err := p.svc.HTTP().DecodeJSON(r, &req); err != nil {
		p.writeErr(w, r, err)
		return
	}
	org, err := p.Create(r.Context(), principal.User, CreateInput{
		Name: req.Name, Slug: req.Slug, Extra: p.inputFields(req.Extra),
	})
	if err != nil {
		p.writeErr(w, r, err)
		return
	}
	p.svc.HTTP().WriteJSON(w, http.StatusCreated, organizationResponse{Organization: p.toOrganizationDTO(org)})
}

// handleGet serves GET /organizations/{id}.
func (p *Plugin) handleGet(w http.ResponseWriter, r *http.Request, principal *plugin.Principal) {
	id := r.PathValue("id")
	if _, _, err := p.authorize(r.Context(), id, principal.User.ID, PermissionOrgRead); err != nil {
		p.writeErr(w, r, err)
		return
	}
	org, err := p.Get(r.Context(), id)
	if err != nil {
		p.writeErr(w, r, err)
		return
	}
	p.svc.HTTP().WriteJSON(w, http.StatusOK, organizationResponse{Organization: p.toOrganizationDTO(org)})
}

// handleUpdate serves PATCH /organizations/{id}.
func (p *Plugin) handleUpdate(w http.ResponseWriter, r *http.Request, principal *plugin.Principal) {
	id := r.PathValue("id")
	var req updateRequest
	if err := p.svc.HTTP().DecodeJSON(r, &req); err != nil {
		p.writeErr(w, r, err)
		return
	}
	if _, _, err := p.authorize(r.Context(), id, principal.User.ID, PermissionOrgUpdate); err != nil {
		p.writeErr(w, r, err)
		return
	}
	org, err := p.Update(r.Context(), principal.User, id, UpdateInput{
		Name: req.Name, Slug: req.Slug, Extra: p.inputFields(req.Extra),
	})
	if err != nil {
		p.writeErr(w, r, err)
		return
	}
	p.svc.HTTP().WriteJSON(w, http.StatusOK, organizationResponse{Organization: p.toOrganizationDTO(org)})
}

// handleDelete serves DELETE /organizations/{id}.
func (p *Plugin) handleDelete(w http.ResponseWriter, r *http.Request, principal *plugin.Principal) {
	id := r.PathValue("id")
	if _, _, err := p.authorize(r.Context(), id, principal.User.ID, PermissionOrgDelete); err != nil {
		p.writeErr(w, r, err)
		return
	}
	if err := p.Delete(r.Context(), principal.User, id); err != nil {
		p.writeErr(w, r, err)
		return
	}
	p.svc.HTTP().WriteJSON(w, http.StatusOK, map[string]bool{"success": true})
}

// inputFields keeps the host-owned fields that an HTTP route can write. A
// field that the host does not mark as input never reaches the store.
func (p *Plugin) inputFields(in map[string]any) map[string]any {
	if len(in) == 0 {
		return nil
	}
	out := map[string]any{}
	for _, f := range p.schemaOptions.OrgFields {
		if !f.Input {
			continue
		}
		if value, ok := in[f.Name]; ok {
			out[f.Name] = value
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
