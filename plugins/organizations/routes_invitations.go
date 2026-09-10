package organizations

import (
	"net/http"
	"time"

	"github.com/alternayte/auth-all/openapi"
	"github.com/alternayte/auth-all/plugin"
	"github.com/alternayte/auth-all/store"
)

// invitationDTO is the public shape of one invitation. It never carries the
// token and never the digest.
type invitationDTO struct {
	ID        string    `json:"id"`
	OrgID     string    `json:"orgId"`
	Email     string    `json:"email"`
	Role      string    `json:"role"`
	Status    string    `json:"status"`
	ExpiresAt time.Time `json:"expiresAt"`
	CreatedAt time.Time `json:"createdAt"`
}

// inviteResponse carries the plaintext token one time.
type inviteResponse struct {
	Invitation invitationDTO `json:"invitation"`
	// Token appears one time, in this response. The store keeps the digest.
	Token string `json:"token"`
}

// invitationListResponse carries one page of invitations.
type invitationListResponse struct {
	Invitations []invitationDTO `json:"invitations"`
	NextCursor  string          `json:"nextCursor"`
}

// inviteRequest is the body of the invite route.
type inviteRequest struct {
	Email string `json:"email"`
	Role  string `json:"role"`
}

// acceptRequest is the body of the accept route.
type acceptRequest struct {
	Token string `json:"token"`
}

// toInvitationDTO returns the public shape of one invitation.
func toInvitationDTO(i *store.Invitation) invitationDTO {
	return invitationDTO{
		ID: i.ID, OrgID: i.OrgID, Email: i.EmailNormalized, Role: i.Role,
		Status: i.Status, ExpiresAt: i.ExpiresAt, CreatedAt: i.CreatedAt,
	}
}

// registerInvitationRoutes mounts the invitation routes.
func (p *Plugin) registerInvitationRoutes(r *plugin.Registry) {
	tag := []string{"organizations"}
	r.Route(plugin.Route{
		Method: http.MethodGet, Path: "/organizations/{id}/invitations", Handler: p.guard(p.handleListInvitations),
		Operation: orgOperation("listOrganizationInvitations", "List the invitations of one organization", tag, nil,
			openapi.Ref("InvitationListResponse"), "listInvitations", "404"),
	})
	r.Route(plugin.Route{
		Method: http.MethodPost, Path: "/organizations/{id}/invitations", Handler: p.guard(p.handleInvite),
		Operation: orgOperation("createOrganizationInvitation", "Invite an address into one organization", tag,
			openapi.JSONBody(openapi.Object([]string{"email"}, map[string]*openapi.Schema{
				"email": openapi.String(),
				"role":  openapi.String(),
			})),
			openapi.Ref("InvitationCreateResponse"), "invite", "400", "404", "409"),
	})
	r.Route(plugin.Route{
		Method: http.MethodPost, Path: "/organizations/{id}/invitations/{invitationId}/revoke",
		Handler: p.guard(p.handleRevokeInvitation),
		Operation: invitationOperation("revokeOrganizationInvitation", "Revoke one pending invitation", tag, nil,
			openapi.Ref("SuccessResponse"), "revokeInvitation", "400", "404"),
	})
	r.Route(plugin.Route{
		Method: http.MethodPost, Path: "/organizations/invitations/accept", Handler: p.guard(p.handleAccept),
		Operation: operation("acceptOrganizationInvitation", "Accept one invitation", tag,
			openapi.JSONBody(openapi.Object([]string{"token"}, map[string]*openapi.Schema{
				"token": openapi.String(),
			})),
			openapi.Ref("MembershipResponse"), "acceptInvitation", "400", "409"),
	})
}

// invitationOperation builds one operation that names an organization and an
// invitation in the path.
func invitationOperation(id, summary string, tag []string, body *openapi.RequestBody,
	okSchema *openapi.Schema, method string, codes ...string) *openapi.Operation {
	parameters := []openapi.Parameter{
		{Name: "id", In: "path", Required: true, Schema: openapi.String()},
		{Name: "invitationId", In: "path", Required: true, Schema: openapi.String()},
	}
	return withParameters(id, summary, tag, body, okSchema, method, parameters, codes...)
}

// registerInvitationSchemas adds the component schemas of the invitation
// responses.
func registerInvitationSchemas(r *plugin.Registry) {
	r.OpenAPISchema("Invitation", openapi.Object(
		[]string{"id", "orgId", "email", "role", "status", "expiresAt", "createdAt"},
		map[string]*openapi.Schema{
			"id":        openapi.String(),
			"orgId":     openapi.String(),
			"email":     openapi.String(),
			"role":      openapi.String(),
			"status":    openapi.String(),
			"expiresAt": {Type: "string", Format: "date-time"},
			"createdAt": {Type: "string", Format: "date-time"},
		}))
	r.OpenAPISchema("InvitationCreateResponse", openapi.Object([]string{"invitation", "token"},
		map[string]*openapi.Schema{
			"invitation": openapi.Ref("Invitation"),
			// The token appears one time, in this response.
			"token": openapi.String(),
		}))
	r.OpenAPISchema("InvitationListResponse", openapi.Object([]string{"invitations"},
		map[string]*openapi.Schema{
			"invitations": {Type: "array", Items: openapi.Ref("Invitation")},
			"nextCursor":  openapi.String(),
		}))
}

// handleInvite serves POST /organizations/{id}/invitations.
func (p *Plugin) handleInvite(w http.ResponseWriter, r *http.Request, principal *plugin.Principal) {
	var req inviteRequest
	if err := p.svc.HTTP().DecodeJSON(r, &req); err != nil {
		p.writeErr(w, r, err)
		return
	}
	invitation, token, err := p.Invite(r.Context(), principal.User, InviteInput{
		OrgID: r.PathValue("id"), Email: req.Email, Role: req.Role,
	})
	if err != nil {
		p.writeErr(w, r, err)
		return
	}
	p.svc.HTTP().WriteJSON(w, http.StatusCreated, inviteResponse{
		Invitation: toInvitationDTO(invitation), Token: token,
	})
}

// handleListInvitations serves GET /organizations/{id}/invitations.
func (p *Plugin) handleListInvitations(w http.ResponseWriter, r *http.Request, principal *plugin.Principal) {
	orgID := r.PathValue("id")
	if _, _, err := p.authorize(r.Context(), orgID, principal.User.ID, PermissionMemberRead); err != nil {
		p.writeErr(w, r, err)
		return
	}
	limit, cursor := pageOf(r)
	filter := store.InvitationFilter{Limit: limit, Cursor: cursor}
	if status := r.URL.Query().Get("status"); status != "" {
		filter.Status = &status
	}
	page, err := p.ListInvitations(r.Context(), orgID, filter)
	if err != nil {
		p.writeErr(w, r, err)
		return
	}
	out := make([]invitationDTO, 0, len(page.Invitations))
	for i := range page.Invitations {
		out = append(out, toInvitationDTO(&page.Invitations[i]))
	}
	p.svc.HTTP().WriteJSON(w, http.StatusOK, invitationListResponse{
		Invitations: out, NextCursor: page.NextCursor,
	})
}

// handleRevokeInvitation serves the revoke route.
func (p *Plugin) handleRevokeInvitation(w http.ResponseWriter, r *http.Request, principal *plugin.Principal) {
	err := p.RevokeInvitation(r.Context(), principal.User, r.PathValue("id"), r.PathValue("invitationId"))
	if err != nil {
		p.writeErr(w, r, err)
		return
	}
	p.svc.HTTP().WriteJSON(w, http.StatusOK, map[string]bool{"success": true})
}

// handleAccept serves POST /organizations/invitations/accept.
func (p *Plugin) handleAccept(w http.ResponseWriter, r *http.Request, principal *plugin.Principal) {
	var req acceptRequest
	if err := p.svc.HTTP().DecodeJSON(r, &req); err != nil {
		p.writeErr(w, r, err)
		return
	}
	member, err := p.AcceptInvitation(r.Context(), principal.User, req.Token)
	if err != nil {
		p.writeErr(w, r, err)
		return
	}
	p.svc.HTTP().WriteJSON(w, http.StatusOK, membershipResponse{Membership: toMembershipDTO(member)})
}
