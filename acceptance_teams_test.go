package authall_test

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/alternayte/auth-all/apierr"
	"github.com/alternayte/auth-all/internal/testsupport"
	"github.com/alternayte/auth-all/store"
)

// teamBody is the decoded body of one team response.
type teamBody struct {
	Team struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		Role string `json:"role"`
	} `json:"team"`
}

// TestSCNTEAM001ThePermissionsAreTheUnion proves SCN-TEAM-001, REQ-TEAM-001,
// REQ-TEAM-002, REQ-TEAM-005, and REQ-PRM-011.
func TestSCNTEAM001ThePermissionsAreTheUnion(t *testing.T) {
	h, orgs := activeHarness(t)
	orgID, _ := newOrganization(t, h, "owner@example.com", "acme")
	activate(t, h, orgID)
	// The member holds the organization role "viewer", which allows a read
	// only.
	member := addMember(t, h, orgID, "bob@example.com", "viewer")

	// The team carries the role "admin", which allows a write.
	created := h.Do(http.MethodPost, "/organizations/"+orgID+"/teams",
		map[string]any{"name": "platform", "role": "admin"})
	if created.Status != http.StatusCreated {
		t.Fatalf("the team got status %d: %s", created.Status, string(created.Body))
	}
	var team teamBody
	created.Decode(t, &team)
	if team.Team.Name != "platform" || team.Team.Role != "admin" {
		t.Fatalf("the team = %+v", team.Team)
	}

	// A team name is unique inside the organization.
	duplicate := h.Do(http.MethodPost, "/organizations/"+orgID+"/teams",
		map[string]any{"name": "platform", "role": "admin"})
	if duplicate.Status != http.StatusBadRequest {
		t.Fatalf("a duplicate team got status %d, want 400", duplicate.Status)
	}

	// Before the member joins the team the write route refuses.
	signInAs(t, h, "bob@example.com")
	activate(t, h, orgID)
	if resp := hostRequest(t, h, "project:write"); resp.Status != http.StatusForbidden {
		t.Fatalf("the viewer write got status %d, want 403", resp.Status)
	}

	// The member joins the team.
	signInAs(t, h, "owner@example.com")
	activate(t, h, orgID)
	joined := h.Do(http.MethodPost, "/organizations/"+orgID+"/teams/"+team.Team.ID+"/members",
		map[string]any{"userId": member})
	if joined.Status != http.StatusOK {
		t.Fatalf("the team member got status %d: %s", joined.Status, string(joined.Body))
	}

	// The permission set is now the union of the organization role and of the
	// team role.
	signInAs(t, h, "bob@example.com")
	activate(t, h, orgID)
	if resp := hostRequest(t, h, "project:read"); resp.Status != http.StatusOK {
		t.Fatalf("the organization role read got status %d", resp.Status)
	}
	if resp := hostRequest(t, h, "project:write"); resp.Status != http.StatusOK {
		t.Fatalf("the team role write got status %d: %s", resp.Status, string(resp.Body))
	}
	if resp := hostRequest(t, h, "billing:read"); resp.Status != http.StatusOK {
		t.Fatalf("the team role billing read got status %d", resp.Status)
	}
	ctx := hostContext(t, h)
	if !orgs.Can(ctx, "project:write") || !orgs.Can(ctx, "project:read") {
		t.Fatal("Can does not hold the union of the roles")
	}
	if orgs.Can(ctx, "organization:delete") {
		t.Fatal("the union holds a permission of no role")
	}

	// The removal from the team takes the team permissions away, and the
	// organization membership stays.
	signInAs(t, h, "owner@example.com")
	activate(t, h, orgID)
	left := h.Do(http.MethodDelete,
		"/organizations/"+orgID+"/teams/"+team.Team.ID+"/members/"+member, nil)
	if left.Status != http.StatusOK {
		t.Fatalf("the team removal got status %d: %s", left.Status, string(left.Body))
	}
	signInAs(t, h, "bob@example.com")
	activate(t, h, orgID)
	if resp := hostRequest(t, h, "project:write"); resp.Status != http.StatusForbidden {
		t.Fatalf("the former team member still writes: status %d", resp.Status)
	}
	if resp := hostRequest(t, h, "project:read"); resp.Status != http.StatusOK {
		t.Fatalf("the organization membership is gone: status %d", resp.Status)
	}
}

// TestSCNTEAM002ATeamNeedsAnOrganizationMembership proves SCN-TEAM-002 and
// REQ-TEAM-003.
func TestSCNTEAM002ATeamNeedsAnOrganizationMembership(t *testing.T) {
	h, _ := activeHarness(t)
	orgID, _ := newOrganization(t, h, "owner@example.com", "acme")
	activate(t, h, orgID)
	created := h.Do(http.MethodPost, "/organizations/"+orgID+"/teams",
		map[string]any{"name": "platform", "role": "admin"})
	var team teamBody
	created.Decode(t, &team)

	// A person with no membership of the organization never joins the team.
	jar := h.SaveCookies()
	h.ClearCookies()
	_, stranger := h.SignUp("mallory@example.com", testPassword)
	h.RestoreCookies(jar)

	resp := h.Do(http.MethodPost, "/organizations/"+orgID+"/teams/"+team.Team.ID+"/members",
		map[string]any{"userId": stranger.User.ID})
	if resp.Status != http.StatusForbidden {
		t.Fatalf("status %d, want 403: %s", resp.Status, string(resp.Body))
	}
	if code := resp.ErrorCode(t); code != string(apierr.CodeNotAMember) {
		t.Fatalf("the code = %s, want %s", code, apierr.CodeNotAMember)
	}

	// A team of another organization is never reachable through this one.
	other := createOrganization(t, h, "Second", "second")
	wrong := h.Do(http.MethodDelete, "/organizations/"+other+"/teams/"+team.Team.ID, nil)
	if wrong.Status != http.StatusNotFound {
		t.Fatalf("a team of another organization got status %d, want 404", wrong.Status)
	}
}

// TestSCNTEAM003TheTeamDeletionKeepsTheMemberships proves SCN-TEAM-003 and
// REQ-TEAM-004. The scenario runs on both engines.
func TestSCNTEAM003TheTeamDeletionKeepsTheMemberships(t *testing.T) {
	engines := map[string]func(t *testing.T) store.Store{
		"SQLite":     testsupport.NewSQLite,
		"PostgreSQL": testsupport.NewPostgres,
	}
	for name, newStore := range engines {
		t.Run(name, func(t *testing.T) {
			s := newStore(t)
			h, _ := orgHarnessWithStore(t, s)
			orgID, owner := newOrganization(t, h, "owner@example.com", "acme")
			member := addMember(t, h, orgID, "bob@example.com", "member")
			activate(t, h, orgID)

			created := h.Do(http.MethodPost, "/organizations/"+orgID+"/teams",
				map[string]any{"name": "platform", "role": "admin"})
			if created.Status != http.StatusCreated {
				t.Fatalf("the team got status %d: %s", created.Status, string(created.Body))
			}
			var team teamBody
			created.Decode(t, &team)
			for _, id := range []string{owner, member} {
				joined := h.Do(http.MethodPost,
					"/organizations/"+orgID+"/teams/"+team.Team.ID+"/members", map[string]any{"userId": id})
				if joined.Status != http.StatusOK {
					t.Fatalf("the team member got status %d: %s", joined.Status, string(joined.Body))
				}
			}

			teams := s.(store.TeamStore)
			if members, err := teams.ListTeamMembers(context.Background(), team.Team.ID); err != nil || len(members) != 2 {
				t.Fatalf("the team holds %v, %v", members, err)
			}

			// The deletion removes the team and its team memberships.
			removed := h.Do(http.MethodDelete, "/organizations/"+orgID+"/teams/"+team.Team.ID, nil)
			if removed.Status != http.StatusOK {
				t.Fatalf("the deletion got status %d: %s", removed.Status, string(removed.Body))
			}
			if _, err := teams.TeamByID(context.Background(), team.Team.ID); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("the team survived: %v", err)
			}
			if members, err := teams.ListTeamMembers(context.Background(), team.Team.ID); err != nil || len(members) != 0 {
				t.Fatalf("a team membership survived: %v, %v", members, err)
			}

			// The organization memberships stay.
			for _, id := range []string{owner, member} {
				if got := membershipOf(t, s, orgID, id); got.Status != store.MembershipActive {
					t.Fatalf("the organization membership of %s changed: %+v", id, got)
				}
			}
		})
	}
}
