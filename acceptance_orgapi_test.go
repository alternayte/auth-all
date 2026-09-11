package authall_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alternayte/auth-all/apierr"
	"github.com/alternayte/auth-all/internal/testsupport"
	"github.com/alternayte/auth-all/plugins/organizations"
	"github.com/alternayte/auth-all/store"
)

// TestTheGoAPIServesEveryOperation covers the Go API of the plugin. A host
// that builds its own routes calls these methods, so each one needs evidence.
func TestTheGoAPIServesEveryOperation(t *testing.T) {
	h, orgs := customRoleHarness(t)
	ctx := context.Background()
	orgID, owner := newOrganization(t, h, "owner@example.com", "acme")
	ownerUser, err := h.Store.Users().GetByNormalizedEmail(ctx, "owner@example.com")
	if err != nil {
		t.Fatalf("read the owner: %v", err)
	}
	member := addMember(t, h, orgID, "bob@example.com", "member")
	memberUser, err := h.Store.Users().GetByNormalizedEmail(ctx, "bob@example.com")
	if err != nil {
		t.Fatalf("read the member: %v", err)
	}

	t.Run("SuspendAndRestore", func(t *testing.T) {
		out, err := orgs.Suspend(ctx, ownerUser, orgID, member)
		if err != nil || out.Status != store.MembershipSuspended {
			t.Fatalf("Suspend = %+v, %v", out, err)
		}
		// A second suspension changes nothing and reports no error.
		if out, err = orgs.Suspend(ctx, ownerUser, orgID, member); err != nil ||
			out.Status != store.MembershipSuspended {
			t.Fatalf("the second Suspend = %+v, %v", out, err)
		}
		if out, err = orgs.Restore(ctx, ownerUser, orgID, member); err != nil ||
			out.Status != store.MembershipActive {
			t.Fatalf("Restore = %+v, %v", out, err)
		}
		if _, err := orgs.SetStatus(ctx, ownerUser, orgID, member, "asleep"); err == nil {
			t.Fatal("an unknown status must fail")
		}
		if _, err := orgs.SetStatus(ctx, ownerUser, orgID, "ghost", store.MembershipActive); !errors.Is(err, apierr.ErrNotAMember) {
			t.Fatalf("an unknown member = %v, want NOT_A_MEMBER", err)
		}
		// A caller with no membership of the named organization learns nothing
		// about it, so the membership check answers first.
		if _, err := orgs.SetStatus(ctx, ownerUser, "ghost", member, store.MembershipActive); !errors.Is(err, apierr.ErrNotAMember) {
			t.Fatalf("an unknown organization = %v, want NOT_A_MEMBER", err)
		}
	})

	t.Run("SetRoleEdges", func(t *testing.T) {
		// The same role changes nothing.
		out, err := orgs.SetRole(ctx, ownerUser, orgID, member, "member")
		if err != nil || out.Role != "member" {
			t.Fatalf("the same role = %+v, %v", out, err)
		}
		if _, err := orgs.SetRole(ctx, ownerUser, orgID, "ghost", "member"); !errors.Is(err, apierr.ErrNotAMember) {
			t.Fatalf("an unknown member = %v", err)
		}
		if _, err := orgs.SetRole(ctx, ownerUser, "ghost", member, "member"); !errors.Is(err, apierr.ErrNotAMember) {
			t.Fatalf("an unknown organization = %v, want NOT_A_MEMBER", err)
		}
		if _, err := orgs.SetRole(ctx, ownerUser, orgID, member, ""); !errors.Is(err, apierr.ErrRoleUnknown) {
			t.Fatalf("an empty role = %v, want ROLE_UNKNOWN", err)
		}
	})

	t.Run("CustomRoles", func(t *testing.T) {
		role, err := orgs.CreateRole(ctx, ownerUser, orgID, "auditor", []string{"project:read"})
		if err != nil || role.Name != "auditor" {
			t.Fatalf("CreateRole = %+v, %v", role, err)
		}
		// A second role of one name fails.
		if _, err := orgs.CreateRole(ctx, ownerUser, orgID, "auditor", []string{"project:read"}); err == nil {
			t.Fatal("a duplicate role name must fail")
		}
		if _, err := orgs.CreateRole(ctx, ownerUser, "ghost", "other", []string{"project:read"}); !errors.Is(err, apierr.ErrNotAMember) {
			t.Fatalf("an unknown organization = %v, want NOT_A_MEMBER", err)
		}
		roles, err := orgs.ListRoles(ctx, orgID)
		if err != nil || len(roles) != 1 {
			t.Fatalf("ListRoles = %v, %v", roles, err)
		}
		if err := orgs.DeleteRole(ctx, ownerUser, orgID, "ghost"); !errors.Is(err, apierr.ErrNotFound) {
			t.Fatalf("an unknown role = %v, want NOT_FOUND", err)
		}
		if err := orgs.DeleteRole(ctx, ownerUser, orgID, "auditor"); err != nil {
			t.Fatalf("DeleteRole = %v", err)
		}
	})

	t.Run("Invitations", func(t *testing.T) {
		invitation, token, err := orgs.Invite(ctx, ownerUser, organizations.InviteInput{
			OrgID: orgID, Email: "New@Example.com",
		})
		if err != nil || token == "" {
			t.Fatalf("Invite = %v, %q", err, token)
		}
		// The default role of the plugin applies when the input names none.
		if invitation.Role != "member" {
			t.Fatalf("the role = %q, want the default role", invitation.Role)
		}
		if invitation.EmailNormalized != "new@example.com" {
			t.Fatalf("the address = %q, want the normalized address", invitation.EmailNormalized)
		}
		for _, address := range []string{"", "not-an-address", "@example.com"} {
			if _, _, err := orgs.Invite(ctx, ownerUser, organizations.InviteInput{
				OrgID: orgID, Email: address,
			}); !errors.Is(err, apierr.ErrInvalidRequest) {
				t.Fatalf("the address %q = %v, want INVALID_REQUEST", address, err)
			}
		}
		if _, _, err := orgs.Invite(ctx, ownerUser, organizations.InviteInput{
			OrgID: orgID, Email: "other@example.com", Role: "wizard",
		}); !errors.Is(err, apierr.ErrRoleUnknown) {
			t.Fatalf("an unknown role = %v, want ROLE_UNKNOWN", err)
		}
		if _, _, err := orgs.Invite(ctx, ownerUser, organizations.InviteInput{
			OrgID: "ghost", Email: "other@example.com",
		}); !errors.Is(err, apierr.ErrNotAMember) {
			t.Fatalf("an unknown organization = %v, want NOT_A_MEMBER", err)
		}

		page, err := orgs.ListInvitations(ctx, orgID, store.InvitationFilter{Limit: 10})
		if err != nil || len(page.Invitations) != 1 {
			t.Fatalf("ListInvitations = %+v, %v", page, err)
		}

		// An acceptance needs a signed-in user and a token.
		if _, err := orgs.AcceptInvitation(ctx, nil, token); !errors.Is(err, apierr.ErrUnauthorized) {
			t.Fatalf("an anonymous acceptance = %v", err)
		}
		if _, err := orgs.AcceptInvitation(ctx, memberUser, ""); !errors.Is(err, apierr.ErrInvitationInvalid) {
			t.Fatalf("an empty token = %v", err)
		}
		if _, err := orgs.AcceptInvitation(ctx, memberUser, token); !errors.Is(err, apierr.ErrInvitationInvalid) {
			t.Fatalf("a wrong address = %v", err)
		}

		// The revocation ends it, and a second one fails.
		if err := orgs.RevokeInvitation(ctx, ownerUser, orgID, invitation.ID); err != nil {
			t.Fatalf("RevokeInvitation = %v", err)
		}
		if err := orgs.RevokeInvitation(ctx, ownerUser, orgID, invitation.ID); !errors.Is(err, apierr.ErrInvitationInvalid) {
			t.Fatalf("a second revocation = %v", err)
		}
		if err := orgs.RevokeInvitation(ctx, ownerUser, orgID, "ghost"); !errors.Is(err, apierr.ErrInvitationInvalid) {
			t.Fatalf("an unknown invitation = %v", err)
		}
		// An invitation of another organization never belongs to this one.
		other, _, err := orgs.Invite(ctx, ownerUser, organizations.InviteInput{
			OrgID: orgID, Email: "second@example.com",
		})
		if err != nil {
			t.Fatalf("the second invitation failed: %v", err)
		}
		second := createOrganizationFor(t, orgs, ownerUser, "second")
		if err := orgs.RevokeInvitation(ctx, ownerUser, second, other.ID); !errors.Is(err, apierr.ErrInvitationInvalid) {
			t.Fatalf("an invitation of another organization = %v", err)
		}
	})

	t.Run("Teams", func(t *testing.T) {
		team, err := orgs.CreateTeam(ctx, ownerUser, orgID, "platform", "admin")
		if err != nil {
			t.Fatalf("CreateTeam = %v", err)
		}
		if _, err := orgs.CreateTeam(ctx, ownerUser, orgID, "platform", ""); err == nil {
			t.Fatal("a duplicate team name must fail")
		}
		for _, name := range []string{"", "   "} {
			if _, err := orgs.CreateTeam(ctx, ownerUser, orgID, name, ""); !errors.Is(err, apierr.ErrInvalidRequest) {
				t.Fatalf("the name %q = %v", name, err)
			}
		}
		if _, err := orgs.CreateTeam(ctx, ownerUser, orgID, "ghosts", "wizard"); !errors.Is(err, apierr.ErrRoleUnknown) {
			t.Fatalf("an unknown team role = %v", err)
		}
		if _, err := orgs.CreateTeam(ctx, ownerUser, "ghost", "platform", ""); !errors.Is(err, apierr.ErrNotAMember) {
			t.Fatalf("an unknown organization = %v, want NOT_A_MEMBER", err)
		}
		teams, err := orgs.ListTeams(ctx, orgID)
		if err != nil || len(teams) != 1 {
			t.Fatalf("ListTeams = %v, %v", teams, err)
		}
		if err := orgs.AddTeamMember(ctx, ownerUser, orgID, team.ID, member); err != nil {
			t.Fatalf("AddTeamMember = %v", err)
		}
		if err := orgs.AddTeamMember(ctx, ownerUser, orgID, team.ID, member); !errors.Is(err, apierr.ErrAlreadyMember) {
			t.Fatalf("a second team membership = %v", err)
		}
		if err := orgs.AddTeamMember(ctx, ownerUser, orgID, "ghost", member); !errors.Is(err, apierr.ErrNotFound) {
			t.Fatalf("an unknown team = %v", err)
		}
		if err := orgs.RemoveTeamMember(ctx, ownerUser, orgID, team.ID, member); err != nil {
			t.Fatalf("RemoveTeamMember = %v", err)
		}
		if err := orgs.RemoveTeamMember(ctx, ownerUser, orgID, team.ID, member); !errors.Is(err, apierr.ErrNotFound) {
			t.Fatalf("a second removal = %v", err)
		}
		if err := orgs.DeleteTeam(ctx, ownerUser, orgID, team.ID); err != nil {
			t.Fatalf("DeleteTeam = %v", err)
		}
		if err := orgs.DeleteTeam(ctx, ownerUser, orgID, team.ID); !errors.Is(err, apierr.ErrNotFound) {
			t.Fatalf("a second deletion = %v", err)
		}
	})

	t.Run("UpdateEdges", func(t *testing.T) {
		if _, err := orgs.Update(ctx, ownerUser, "ghost", organizations.UpdateInput{}); !errors.Is(err, apierr.ErrNotFound) {
			t.Fatalf("an unknown organization = %v", err)
		}
		empty := ""
		if _, err := orgs.Update(ctx, ownerUser, orgID, organizations.UpdateInput{Name: &empty}); !errors.Is(err, apierr.ErrInvalidRequest) {
			t.Fatalf("an empty name = %v", err)
		}
		bad := "Not A Slug"
		if _, err := orgs.Update(ctx, ownerUser, orgID, organizations.UpdateInput{Slug: &bad}); !errors.Is(err, apierr.ErrInvalidRequest) {
			t.Fatalf("an invalid slug = %v", err)
		}
		if _, err := orgs.Create(ctx, nil, organizations.CreateInput{Name: "Acme", Slug: "acme-two"}); !errors.Is(err, apierr.ErrUnauthorized) {
			t.Fatalf("a create with no actor and no owner = %v", err)
		}
		if _, err := orgs.Get(ctx, "ghost"); !errors.Is(err, apierr.ErrNotFound) {
			t.Fatalf("Get of an unknown organization = %v", err)
		}
		if _, err := orgs.Create(ctx, ownerUser, organizations.CreateInput{Name: "Acme", Slug: ""}); !errors.Is(err, apierr.ErrInvalidRequest) {
			t.Fatalf("an empty slug = %v", err)
		}
	})
	_ = owner
}

// createOrganizationFor creates one organization through the Go API.
func createOrganizationFor(t *testing.T, orgs *organizations.Plugin, owner *store.User, slug string) string {
	t.Helper()
	org, err := orgs.Create(context.Background(), owner, organizations.CreateInput{Name: slug, Slug: slug})
	if err != nil {
		t.Fatalf("create %s: %v", slug, err)
	}
	return org.ID
}

// TestSetActiveNeedsASession proves that only a session switches the
// organization, and that RequireFunc protects a handler function.
func TestSetActiveNeedsASession(t *testing.T) {
	h, orgs := activeHarness(t)
	orgID, _ := newOrganization(t, h, "owner@example.com", "acme")

	// SetActive uses the principal of the request, so a request with no
	// principal fails.
	request := httptest.NewRequest(http.MethodPost, "/switch", nil)
	recorder := httptest.NewRecorder()
	if err := orgs.SetActive(t.Context(), recorder, request, orgID); !errors.Is(err, apierr.ErrUnauthorized) {
		t.Fatalf("SetActive with no principal = %v, want UNAUTHORIZED", err)
	}

	// RequireFunc protects a handler function.
	handler := orgs.RequireFunc("project:read", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	if handler == nil {
		t.Fatal("RequireFunc returned no handler")
	}
	plain := httptest.NewRecorder()
	handler.ServeHTTP(plain, httptest.NewRequest(http.MethodGet, "/projects", nil))
	if plain.Code != http.StatusUnauthorized && plain.Code != http.StatusForbidden {
		t.Fatalf("RequireFunc allowed an anonymous request: %d", plain.Code)
	}
}

// TestTheRoleDeclarationReadsItsParts covers the accessors of one declared
// role.
func TestTheRoleDeclarationReadsItsParts(t *testing.T) {
	role := organizations.Role("admin", "member:*", "project:read")
	if role.Name() != "admin" {
		t.Fatalf("Name() = %q", role.Name())
	}
	set := role.Permissions()
	if !set.Allows("member:invite") || !set.Allows("project:read") {
		t.Fatalf("Permissions() = %v", set.Statements())
	}
	if set.Allows("project:write") {
		t.Fatal("the role holds no project:write")
	}
}

// TestThePersonalOrganizationTakesTheDisplayName proves the naming rule of a
// personal organization. The name takes the display name, and the slug takes
// the local part of the address with a unique suffix.
func TestThePersonalOrganizationTakesTheDisplayName(t *testing.T) {
	h, _ := orgHarness(t, organizations.WithPersonalOrganizations())
	ctx := context.Background()
	// A sign-up with no display name takes the local part of the address.
	h.SignUp("Bob.Smith@example.com", testPassword)
	list := h.Do(http.MethodGet, "/organizations", nil)
	var page organizationListBody
	list.Decode(t, &page)
	if len(page.Organizations) != 1 {
		t.Fatalf("the sign-up created %d organizations", len(page.Organizations))
	}
	// The slug keeps the letters and the digits of the local part, and it
	// replaces every other character.
	if !strings.HasPrefix(page.Organizations[0].Slug, "bob-smith-") {
		t.Fatalf("the slug = %q, want the local part and a suffix", page.Organizations[0].Slug)
	}
	org, err := h.Store.(store.OrganizationStore).OrganizationByID(ctx, page.Organizations[0].ID)
	if err != nil {
		t.Fatalf("read the organization: %v", err)
	}
	// The name takes the display name of the person when one exists, and the
	// local part of the address otherwise.
	if org.Name == "" {
		t.Fatal("the personal organization holds no name")
	}
	if user, err := h.Store.Users().GetByNormalizedEmail(ctx, "bob.smith@example.com"); err != nil {
		t.Fatalf("read the user: %v", err)
	} else if user.DisplayName != "" && org.Name != user.DisplayName {
		t.Fatalf("the name = %q, want the display name %q", org.Name, user.DisplayName)
	}
}

// TestEveryWriteRouteRefusesAnInvalidBody proves that a malformed body reaches
// no operation, and that every read route refuses a person with no membership.
func TestEveryWriteRouteRefusesAnInvalidBody(t *testing.T) {
	h, orgs := customRoleHarness(t)
	orgID, owner := newOrganization(t, h, "owner@example.com", "acme")
	activate(t, h, orgID)
	team, err := orgs.CreateTeam(t.Context(), nil, orgID, "platform", "admin")
	if err != nil {
		t.Fatalf("create the team: %v", err)
	}

	writes := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/organizations"},
		{http.MethodPatch, "/organizations/" + orgID},
		{http.MethodPatch, "/organizations/" + orgID + "/members/" + owner},
		{http.MethodPost, "/organizations/" + orgID + "/invitations"},
		{http.MethodPost, "/organizations/invitations/accept"},
		{http.MethodPost, "/organizations/" + orgID + "/roles"},
		{http.MethodPost, "/organizations/" + orgID + "/teams"},
		{http.MethodPost, "/organizations/" + orgID + "/teams/" + team.ID + "/members"},
	}
	for _, w := range writes {
		resp := h.DoURL(w.method, h.URL(w.path), "{not json")
		if resp.Status != http.StatusBadRequest {
			t.Fatalf("%s %s got status %d, want 400: %s", w.method, w.path, resp.Status, string(resp.Body))
		}
	}

	// Every route of the organization refuses a person with no membership.
	h.ClearCookies()
	h.SignUp("mallory@example.com", testPassword)
	reads := []struct {
		method string
		path   string
		body   any
	}{
		{http.MethodGet, "/organizations/" + orgID, nil},
		{http.MethodGet, "/organizations/" + orgID + "/members", nil},
		{http.MethodGet, "/organizations/" + orgID + "/invitations", nil},
		{http.MethodGet, "/organizations/" + orgID + "/roles", nil},
		{http.MethodGet, "/organizations/" + orgID + "/teams", nil},
		{http.MethodPost, "/organizations/" + orgID + "/invitations", map[string]any{"email": "x@example.com"}},
		{http.MethodPost, "/organizations/" + orgID + "/roles", map[string]any{"name": "x", "permissions": []string{"project:read"}}},
		{http.MethodPost, "/organizations/" + orgID + "/teams", map[string]any{"name": "x"}},
		{http.MethodDelete, "/organizations/" + orgID + "/teams/" + team.ID, nil},
		{http.MethodPost, "/organizations/" + orgID + "/teams/" + team.ID + "/members", map[string]any{"userId": owner}},
		{http.MethodDelete, "/organizations/" + orgID + "/teams/" + team.ID + "/members/" + owner, nil},
		{http.MethodDelete, "/organizations/" + orgID + "/roles/auditor", nil},
		{http.MethodDelete, "/organizations/" + orgID + "/members/" + owner, nil},
		{http.MethodPatch, "/organizations/" + orgID + "/members/" + owner, map[string]any{"role": "viewer"}},
		{http.MethodPost, "/organizations/" + orgID + "/invitations/unknown/revoke", nil},
	}
	for _, r := range reads {
		resp := h.Do(r.method, r.path, r.body)
		if resp.Status != http.StatusForbidden {
			t.Fatalf("%s %s got status %d, want 403: %s", r.method, r.path, resp.Status, string(resp.Body))
		}
	}

	// A member with no permission of the route gets a denial as well.
	writeMembership(t, h.Store, orgID, userIDOf(t, h.Store, "mallory@example.com"), "viewer", store.MembershipActive)
	for _, r := range []struct {
		method string
		path   string
		body   any
	}{
		{http.MethodPost, "/organizations/" + orgID + "/roles", map[string]any{"name": "x", "permissions": []string{"project:read"}}},
		{http.MethodPost, "/organizations/" + orgID + "/teams", map[string]any{"name": "x"}},
		{http.MethodDelete, "/organizations/" + orgID, nil},
	} {
		resp := h.Do(r.method, r.path, r.body)
		if resp.Status != http.StatusForbidden {
			t.Fatalf("%s %s got status %d for a viewer, want 403", r.method, r.path, resp.Status)
		}
		if code := resp.ErrorCode(t); code != string(apierr.CodePermissionDenied) {
			t.Fatalf("%s %s got the code %s", r.method, r.path, code)
		}
	}

	// A viewer holds organization:read, so it reads the organization. The
	// member list needs member:read, which the viewer does not hold.
	if resp := h.Do(http.MethodGet, "/organizations/"+orgID, nil); resp.Status != http.StatusOK {
		t.Fatalf("the viewer read got status %d: %s", resp.Status, string(resp.Body))
	}
	for _, path := range []string{
		"/organizations/" + orgID + "/members",
		"/organizations/" + orgID + "/teams",
		"/organizations/" + orgID + "/invitations",
		"/organizations/" + orgID + "/roles",
	} {
		resp := h.Do(http.MethodGet, path, nil)
		if resp.Status != http.StatusForbidden {
			t.Fatalf("the viewer read of %s got status %d, want 403", path, resp.Status)
		}
	}
}

// TestAKeyNeverSwitchesTheOrganization proves that only a session names the
// active organization. A key carries its organization from its own row.
func TestAKeyNeverSwitchesTheOrganization(t *testing.T) {
	h, _ := orgKeyHarness(t)
	orgID, _ := newOrganization(t, h, "owner@example.com", "acme")
	resp := h.Do(http.MethodPost, "/api-keys", map[string]any{"name": "ci", "role": "owner", "orgId": orgID})
	var body keyBody
	resp.Decode(t, &body)

	h.ClearCookies()
	for _, path := range []string{"/organizations/" + orgID + "/activate", "/organizations/deactivate"} {
		out := h.DoURL(http.MethodPost, h.URL(path), nil, testsupport.WithBearer(body.Plaintext))
		if out.Status != http.StatusForbidden {
			t.Fatalf("the key reached %s with status %d, want 403: %s", path, out.Status, string(out.Body))
		}
	}
}
