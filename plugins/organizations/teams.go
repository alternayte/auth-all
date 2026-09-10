package organizations

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/alternayte/auth-all/apierr"
	"github.com/alternayte/auth-all/events"
	"github.com/alternayte/auth-all/openapi"
	"github.com/alternayte/auth-all/plugin"
	"github.com/alternayte/auth-all/store"
)

// CreateTeam declares one team of one organization.
//
// A team name is unique inside the organization. A team can carry a role, and
// the effective permission set of a member is the union of the organization
// role and of every team role.
func (p *Plugin) CreateTeam(ctx context.Context, actor *store.User, orgID, name, role string) (*store.Team, error) {
	name = strings.TrimSpace(name)
	if name == "" || len([]rune(name)) > 100 {
		return nil, apierr.ErrInvalidRequest.WithMessage("The team name must hold 1 to 100 characters.")
	}
	if role != "" {
		granted, known, err := p.knownRole(ctx, p.store, orgID, role)
		if err != nil {
			return nil, err
		}
		if !known {
			return nil, apierr.ErrRoleUnknown
		}
		if actor != nil {
			_, held, err := p.authorize(ctx, orgID, actor.ID, PermissionTeamWrite)
			if err != nil {
				return nil, err
			}
			// A team role never grants a permission that the creator lacks.
			if !held.CoversSet(granted) {
				return nil, apierr.ErrRoleNotAllowed
			}
		}
	} else if actor != nil {
		if _, _, err := p.authorize(ctx, orgID, actor.ID, PermissionTeamWrite); err != nil {
			return nil, err
		}
	}

	teams, err := teamStore(p.store)
	if err != nil {
		return nil, err
	}
	if _, err := p.orgs.OrganizationByID(ctx, orgID); err != nil {
		return nil, notFound(err)
	}
	team := &store.Team{ID: uuid.NewString(), OrgID: orgID, Name: name, Role: role, CreatedAt: p.now()}
	if err := teams.CreateTeam(ctx, team); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return nil, apierr.ErrInvalidRequest.WithMessage("The organization already holds a team of that name.")
		}
		return nil, err
	}
	p.emit(ctx, events.TeamCreated, actorID(actor), orgID, map[string]any{
		"teamId": team.ID, "team": team.Name, "role": team.Role,
	})
	return team, nil
}

// DeleteTeam removes one team and its team memberships. The organization
// memberships stay.
func (p *Plugin) DeleteTeam(ctx context.Context, actor *store.User, orgID, teamID string) error {
	teams, err := p.teamOf(ctx, orgID, teamID)
	if err != nil {
		return err
	}
	if actor != nil {
		if _, _, err := p.authorize(ctx, orgID, actor.ID, PermissionTeamWrite); err != nil {
			return err
		}
	}
	store, err := teamStore(p.store)
	if err != nil {
		return err
	}
	if err := store.DeleteTeam(ctx, teams.ID); err != nil {
		return notFound(err)
	}
	p.emit(ctx, events.TeamDeleted, actorID(actor), orgID, map[string]any{"teamId": teamID})
	return nil
}

// AddTeamMember puts one member of the organization in one team.
//
// A user without a membership of the organization never joins a team.
func (p *Plugin) AddTeamMember(ctx context.Context, actor *store.User, orgID, teamID, userID string) error {
	team, err := p.teamOf(ctx, orgID, teamID)
	if err != nil {
		return err
	}
	if actor != nil {
		if _, _, err := p.authorize(ctx, orgID, actor.ID, PermissionTeamWrite); err != nil {
			return err
		}
	}
	// The person must already hold a membership of the organization.
	if _, err := p.membershipOf(ctx, orgID, userID); err != nil {
		return err
	}
	teams, err := teamStore(p.store)
	if err != nil {
		return err
	}
	if err := teams.AddTeamMember(ctx, team.ID, userID); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return apierr.ErrAlreadyMember
		}
		return err
	}
	p.emit(ctx, events.TeamMemberAdded, actorID(actor), orgID, map[string]any{
		"teamId": team.ID, "memberId": userID,
	})
	return nil
}

// RemoveTeamMember takes one member out of one team. The organization
// membership stays.
func (p *Plugin) RemoveTeamMember(ctx context.Context, actor *store.User, orgID, teamID, userID string) error {
	team, err := p.teamOf(ctx, orgID, teamID)
	if err != nil {
		return err
	}
	if actor != nil {
		if _, _, err := p.authorize(ctx, orgID, actor.ID, PermissionTeamWrite); err != nil {
			return err
		}
	}
	teams, err := teamStore(p.store)
	if err != nil {
		return err
	}
	if err := teams.RemoveTeamMember(ctx, team.ID, userID); err != nil {
		return notFound(err)
	}
	p.emit(ctx, events.TeamMemberRemoved, actorID(actor), orgID, map[string]any{
		"teamId": team.ID, "memberId": userID,
	})
	return nil
}

// ListTeams returns the teams of one organization.
func (p *Plugin) ListTeams(ctx context.Context, orgID string) ([]store.Team, error) {
	teams, err := teamStore(p.store)
	if err != nil {
		return nil, err
	}
	return teams.ListTeams(ctx, orgID)
}

// teamOf returns one team of one organization.
func (p *Plugin) teamOf(ctx context.Context, orgID, teamID string) (*store.Team, error) {
	teams, err := teamStore(p.store)
	if err != nil {
		return nil, err
	}
	team, err := teams.TeamByID(ctx, teamID)
	if err != nil {
		return nil, notFound(err)
	}
	if team.OrgID != orgID {
		return nil, apierr.ErrNotFound
	}
	return team, nil
}

// teamStore returns the team store of one store value.
func teamStore(s store.Store) (store.TeamStore, error) {
	teams, ok := s.(store.TeamStore)
	if !ok {
		return nil, errors.New("authall/organizations: the configured store holds no team")
	}
	return teams, nil
}

// teamDTO is the public shape of one team.
type teamDTO struct {
	ID        string    `json:"id"`
	OrgID     string    `json:"orgId"`
	Name      string    `json:"name"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"createdAt"`
}

// teamResponse carries one team.
type teamResponse struct {
	Team teamDTO `json:"team"`
}

// teamListResponse carries the teams of one organization.
type teamListResponse struct {
	Teams []teamDTO `json:"teams"`
}

// createTeamRequest is the body of the create team route.
type createTeamRequest struct {
	Name string `json:"name"`
	Role string `json:"role"`
}

// teamMemberRequest is the body of the team member route.
type teamMemberRequest struct {
	UserID string `json:"userId"`
}

// toTeamDTO returns the public shape of one team.
func toTeamDTO(t *store.Team) teamDTO {
	return teamDTO{ID: t.ID, OrgID: t.OrgID, Name: t.Name, Role: t.Role, CreatedAt: t.CreatedAt}
}

// registerTeamRoutes mounts the team routes.
func (p *Plugin) registerTeamRoutes(r *plugin.Registry) {
	tag := []string{"organizations"}
	r.Route(plugin.Route{
		Method: http.MethodGet, Path: "/organizations/{id}/teams", Handler: p.guard(p.handleListTeams),
		Operation: orgOperation("listOrganizationTeams", "List the teams of one organization", tag, nil,
			openapi.Ref("TeamListResponse"), "listTeams", "404"),
	})
	r.Route(plugin.Route{
		Method: http.MethodPost, Path: "/organizations/{id}/teams", Handler: p.guard(p.handleCreateTeam),
		Operation: orgOperation("createOrganizationTeam", "Create one team", tag,
			openapi.JSONBody(openapi.Object([]string{"name"}, map[string]*openapi.Schema{
				"name": openapi.String(),
				"role": openapi.String(),
			})),
			openapi.Ref("TeamResponse"), "createTeam", "400", "404"),
	})
	r.Route(plugin.Route{
		Method: http.MethodDelete, Path: "/organizations/{id}/teams/{teamId}", Handler: p.guard(p.handleDeleteTeam),
		Operation: teamOperation("deleteOrganizationTeam", "Remove one team", tag, nil,
			openapi.Ref("SuccessResponse"), "deleteTeam", "404"),
	})
	r.Route(plugin.Route{
		Method: http.MethodPost, Path: "/organizations/{id}/teams/{teamId}/members",
		Handler: p.guard(p.handleAddTeamMember),
		Operation: teamOperation("addOrganizationTeamMember", "Put one member in one team", tag,
			openapi.JSONBody(openapi.Object([]string{"userId"}, map[string]*openapi.Schema{
				"userId": openapi.String(),
			})),
			openapi.Ref("SuccessResponse"), "addTeamMember", "400", "404", "409"),
	})
	r.Route(plugin.Route{
		Method: http.MethodDelete, Path: "/organizations/{id}/teams/{teamId}/members/{userId}",
		Handler: p.guard(p.handleRemoveTeamMember),
		Operation: teamMemberOperation("removeOrganizationTeamMember", "Take one member out of one team", tag, nil,
			openapi.Ref("SuccessResponse"), "removeTeamMember", "404"),
	})
}

// teamOperation builds one operation that names an organization and a team in
// the path.
func teamOperation(id, summary string, tag []string, body *openapi.RequestBody,
	okSchema *openapi.Schema, method string, codes ...string) *openapi.Operation {
	parameters := []openapi.Parameter{
		{Name: "id", In: "path", Required: true, Schema: openapi.String()},
		{Name: "teamId", In: "path", Required: true, Schema: openapi.String()},
	}
	return withParameters(id, summary, tag, body, okSchema, method, parameters, codes...)
}

// teamMemberOperation builds one operation that names an organization, a team,
// and a member in the path.
func teamMemberOperation(id, summary string, tag []string, body *openapi.RequestBody,
	okSchema *openapi.Schema, method string, codes ...string) *openapi.Operation {
	parameters := []openapi.Parameter{
		{Name: "id", In: "path", Required: true, Schema: openapi.String()},
		{Name: "teamId", In: "path", Required: true, Schema: openapi.String()},
		{Name: "userId", In: "path", Required: true, Schema: openapi.String()},
	}
	return withParameters(id, summary, tag, body, okSchema, method, parameters, codes...)
}

// registerTeamSchemas adds the component schemas of the team responses.
func registerTeamSchemas(r *plugin.Registry) {
	r.OpenAPISchema("Team", openapi.Object(
		[]string{"id", "orgId", "name", "createdAt"},
		map[string]*openapi.Schema{
			"id":        openapi.String(),
			"orgId":     openapi.String(),
			"name":      openapi.String(),
			"role":      openapi.String(),
			"createdAt": {Type: "string", Format: "date-time"},
		}))
	r.OpenAPISchema("TeamResponse", openapi.Object([]string{"team"},
		map[string]*openapi.Schema{"team": openapi.Ref("Team")}))
	r.OpenAPISchema("TeamListResponse", openapi.Object([]string{"teams"},
		map[string]*openapi.Schema{"teams": {Type: "array", Items: openapi.Ref("Team")}}))
}

// handleCreateTeam serves POST /organizations/{id}/teams.
func (p *Plugin) handleCreateTeam(w http.ResponseWriter, r *http.Request, principal *plugin.Principal) {
	var req createTeamRequest
	if err := p.svc.HTTP().DecodeJSON(r, &req); err != nil {
		p.writeErr(w, r, err)
		return
	}
	team, err := p.CreateTeam(r.Context(), principal.User, r.PathValue("id"), req.Name, req.Role)
	if err != nil {
		p.writeErr(w, r, err)
		return
	}
	p.svc.HTTP().WriteJSON(w, http.StatusCreated, teamResponse{Team: toTeamDTO(team)})
}

// handleListTeams serves GET /organizations/{id}/teams.
func (p *Plugin) handleListTeams(w http.ResponseWriter, r *http.Request, principal *plugin.Principal) {
	orgID := r.PathValue("id")
	if _, _, err := p.authorize(r.Context(), orgID, principal.User.ID, PermissionMemberRead); err != nil {
		p.writeErr(w, r, err)
		return
	}
	teams, err := p.ListTeams(r.Context(), orgID)
	if err != nil {
		p.writeErr(w, r, err)
		return
	}
	out := make([]teamDTO, 0, len(teams))
	for i := range teams {
		out = append(out, toTeamDTO(&teams[i]))
	}
	p.svc.HTTP().WriteJSON(w, http.StatusOK, teamListResponse{Teams: out})
}

// handleDeleteTeam serves DELETE /organizations/{id}/teams/{teamId}.
func (p *Plugin) handleDeleteTeam(w http.ResponseWriter, r *http.Request, principal *plugin.Principal) {
	if err := p.DeleteTeam(r.Context(), principal.User, r.PathValue("id"), r.PathValue("teamId")); err != nil {
		p.writeErr(w, r, err)
		return
	}
	p.svc.HTTP().WriteJSON(w, http.StatusOK, map[string]bool{"success": true})
}

// handleAddTeamMember serves POST /organizations/{id}/teams/{teamId}/members.
func (p *Plugin) handleAddTeamMember(w http.ResponseWriter, r *http.Request, principal *plugin.Principal) {
	var req teamMemberRequest
	if err := p.svc.HTTP().DecodeJSON(r, &req); err != nil {
		p.writeErr(w, r, err)
		return
	}
	err := p.AddTeamMember(r.Context(), principal.User, r.PathValue("id"), r.PathValue("teamId"), req.UserID)
	if err != nil {
		p.writeErr(w, r, err)
		return
	}
	p.svc.HTTP().WriteJSON(w, http.StatusOK, map[string]bool{"success": true})
}

// handleRemoveTeamMember serves the team member removal route.
func (p *Plugin) handleRemoveTeamMember(w http.ResponseWriter, r *http.Request, principal *plugin.Principal) {
	err := p.RemoveTeamMember(r.Context(), principal.User,
		r.PathValue("id"), r.PathValue("teamId"), r.PathValue("userId"))
	if err != nil {
		p.writeErr(w, r, err)
		return
	}
	p.svc.HTTP().WriteJSON(w, http.StatusOK, map[string]bool{"success": true})
}
