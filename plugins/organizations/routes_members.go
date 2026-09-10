package organizations

import (
	"net/http"
	"time"

	"github.com/alternayte/auth-all/openapi"
	"github.com/alternayte/auth-all/plugin"
	"github.com/alternayte/auth-all/store"
)

// membershipDTO is the public shape of one membership.
type membershipDTO struct {
	ID       string    `json:"id"`
	OrgID    string    `json:"orgId"`
	UserID   string    `json:"userId"`
	Role     string    `json:"role"`
	Status   string    `json:"status"`
	JoinedAt time.Time `json:"joinedAt"`
}

// membershipResponse carries one membership.
type membershipResponse struct {
	Membership membershipDTO `json:"membership"`
}

// memberListResponse carries one page of members.
type memberListResponse struct {
	Members    []membershipDTO `json:"members"`
	NextCursor string          `json:"nextCursor"`
}

// memberUpdateRequest is the body of the member update route. A nil field
// keeps the stored value.
type memberUpdateRequest struct {
	Role   *string `json:"role"`
	Status *string `json:"status"`
}

// toMembershipDTO returns the public shape of one membership.
func toMembershipDTO(m *store.Membership) membershipDTO {
	return membershipDTO{
		ID: m.ID, OrgID: m.OrgID, UserID: m.UserID,
		Role: m.Role, Status: m.Status, JoinedAt: m.JoinedAt,
	}
}

// registerMemberRoutes mounts the membership routes.
func (p *Plugin) registerMemberRoutes(r *plugin.Registry) {
	tag := []string{"organizations"}
	r.Route(plugin.Route{
		Method: http.MethodGet, Path: "/organizations/{id}/members", Handler: p.guard(p.handleListMembers),
		Operation: orgOperation("listOrganizationMembers", "List the members of one organization", tag, nil,
			openapi.Ref("MemberListResponse"), "listMembers", "404"),
	})
	r.Route(plugin.Route{
		Method: http.MethodPatch, Path: "/organizations/{id}/members/{userId}", Handler: p.guard(p.handleUpdateMember),
		Operation: memberOperation("updateOrganizationMember", "Change the role or the status of one member", tag,
			openapi.JSONBody(openapi.Object(nil, map[string]*openapi.Schema{
				"role":   openapi.String(),
				"status": openapi.String(),
			})),
			openapi.Ref("MembershipResponse"), "setMember", "400", "404", "409"),
	})
	r.Route(plugin.Route{
		Method: http.MethodDelete, Path: "/organizations/{id}/members/{userId}", Handler: p.guard(p.handleRemoveMember),
		Operation: memberOperation("removeOrganizationMember", "Remove one member", tag, nil,
			openapi.Ref("SuccessResponse"), "removeMember", "404", "409"),
	})
}

// memberOperation builds one operation that names an organization and a member
// in the path.
func memberOperation(id, summary string, tag []string, body *openapi.RequestBody,
	okSchema *openapi.Schema, method string, codes ...string) *openapi.Operation {
	parameters := []openapi.Parameter{
		{Name: "id", In: "path", Required: true, Schema: openapi.String()},
		{Name: "userId", In: "path", Required: true, Schema: openapi.String()},
	}
	return withParameters(id, summary, tag, body, okSchema, method, parameters, codes...)
}

// handleListMembers serves GET /organizations/{id}/members.
func (p *Plugin) handleListMembers(w http.ResponseWriter, r *http.Request, principal *plugin.Principal) {
	orgID := r.PathValue("id")
	if _, _, err := p.authorize(r.Context(), orgID, principal.User.ID, PermissionMemberRead); err != nil {
		p.writeErr(w, r, err)
		return
	}
	limit, cursor := pageOf(r)
	filter := store.MemberFilter{Limit: limit, Cursor: cursor}
	if role := r.URL.Query().Get("role"); role != "" {
		filter.Role = &role
	}
	if status := r.URL.Query().Get("status"); status != "" {
		filter.Status = &status
	}
	page, err := p.ListMembers(r.Context(), orgID, filter)
	if err != nil {
		p.writeErr(w, r, err)
		return
	}
	out := make([]membershipDTO, 0, len(page.Members))
	for i := range page.Members {
		out = append(out, toMembershipDTO(&page.Members[i]))
	}
	p.svc.HTTP().WriteJSON(w, http.StatusOK, memberListResponse{Members: out, NextCursor: page.NextCursor})
}

// handleUpdateMember serves PATCH /organizations/{id}/members/{userId}.
func (p *Plugin) handleUpdateMember(w http.ResponseWriter, r *http.Request, principal *plugin.Principal) {
	orgID := r.PathValue("id")
	userID := r.PathValue("userId")
	var req memberUpdateRequest
	if err := p.svc.HTTP().DecodeJSON(r, &req); err != nil {
		p.writeErr(w, r, err)
		return
	}
	var m *store.Membership
	var err error
	if req.Role != nil {
		if m, err = p.SetRole(r.Context(), principal.User, orgID, userID, *req.Role); err != nil {
			p.writeErr(w, r, err)
			return
		}
	}
	if req.Status != nil {
		if m, err = p.SetStatus(r.Context(), principal.User, orgID, userID, *req.Status); err != nil {
			p.writeErr(w, r, err)
			return
		}
	}
	if m == nil {
		// The request changed nothing, so the route returns the stored row.
		if _, _, err := p.authorize(r.Context(), orgID, principal.User.ID, PermissionMemberRead); err != nil {
			p.writeErr(w, r, err)
			return
		}
		if m, err = p.members.MembershipOf(r.Context(), orgID, userID); err != nil {
			p.writeErr(w, r, notAMember(err))
			return
		}
	}
	p.svc.HTTP().WriteJSON(w, http.StatusOK, membershipResponse{Membership: toMembershipDTO(m)})
}

// handleRemoveMember serves DELETE /organizations/{id}/members/{userId}.
func (p *Plugin) handleRemoveMember(w http.ResponseWriter, r *http.Request, principal *plugin.Principal) {
	orgID := r.PathValue("id")
	userID := r.PathValue("userId")
	if err := p.Remove(r.Context(), principal.User, orgID, userID); err != nil {
		p.writeErr(w, r, err)
		return
	}
	p.svc.HTTP().WriteJSON(w, http.StatusOK, map[string]bool{"success": true})
}
