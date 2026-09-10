package authall_test

import (
	"net/http"
	"testing"

	"github.com/alternayte/auth-all/apierr"
	"github.com/alternayte/auth-all/plugins/organizations"
	"github.com/alternayte/auth-all/store"
)

// TestSCNPRM003TheWriteRouteNeedsTheWritePermission proves SCN-PRM-003,
// REQ-PRM-005, and REQ-PRM-006.
func TestSCNPRM003TheWriteRouteNeedsTheWritePermission(t *testing.T) {
	h, _ := activeHarness(t)
	orgID, _ := newOrganization(t, h, "owner@example.com", "acme")
	addMember(t, h, orgID, "viewer@example.com", "viewer")
	addMember(t, h, orgID, "admin@example.com", "admin")

	// A viewer reads and never writes.
	signInAs(t, h, "viewer@example.com")
	activate(t, h, orgID)
	if resp := hostRequest(t, h, "project:read"); resp.Status != http.StatusOK {
		t.Fatalf("the viewer read got status %d: %s", resp.Status, string(resp.Body))
	}
	denied := hostRequest(t, h, "project:write")
	if denied.Status != http.StatusForbidden {
		t.Fatalf("the viewer write got status %d, want 403", denied.Status)
	}
	if code := denied.ErrorCode(t); code != string(apierr.CodePermissionDenied) {
		t.Fatalf("the code = %s, want %s", code, apierr.CodePermissionDenied)
	}

	// An admin writes.
	signInAs(t, h, "admin@example.com")
	activate(t, h, orgID)
	if resp := hostRequest(t, h, "project:write"); resp.Status != http.StatusOK {
		t.Fatalf("the admin write got status %d: %s", resp.Status, string(resp.Body))
	}

	// A request with no principal gets 401 and never 403.
	h.ClearCookies()
	anonymous := hostRequest(t, h, "project:read")
	if anonymous.Status != http.StatusUnauthorized {
		t.Fatalf("an anonymous request got status %d, want 401", anonymous.Status)
	}
}

// TestSCNPRM004AnUnknownPermissionIsDenied proves SCN-PRM-004 and
// REQ-PRM-003. The check is default deny.
func TestSCNPRM004AnUnknownPermissionIsDenied(t *testing.T) {
	h, orgs := activeHarness(t)
	orgID, owner := newOrganization(t, h, "owner@example.com", "acme")
	// The owner holds every permission, so the organization role is not the
	// reason for a denial here.
	activate(t, h, orgID)

	// A statement that the grammar refuses is denied, even for an owner.
	for _, statement := range []string{"unknown", "project read", "", "project:read:extra", "*:*:*"} {
		if orgs.Can(hostContext(t, h), statement) {
			t.Fatalf("the statement %q was allowed", statement)
		}
	}

	// A member whose role holds no permission is denied.
	blank := addMember(t, h, orgID, "blank@example.com", "")
	setMembershipRole(t, h.Store, orgID, blank, "")
	signInAs(t, h, "blank@example.com")
	activate(t, h, orgID)
	for _, statement := range []string{"project:read", "project:write", "billing:read"} {
		resp := hostRequest(t, h, statement)
		if resp.Status != http.StatusForbidden {
			t.Fatalf("the member with no role reached %s with status %d", statement, resp.Status)
		}
		if code := resp.ErrorCode(t); code != string(apierr.CodePermissionDenied) {
			t.Fatalf("the code = %s, want %s", code, apierr.CodePermissionDenied)
		}
	}

	// A role that the configuration does not declare holds no permission.
	setMembershipRole(t, h.Store, orgID, blank, "wizard")
	if resp := hostRequest(t, h, "project:read"); resp.Status != http.StatusForbidden {
		t.Fatalf("an undeclared role reached a route with status %d", resp.Status)
	}
	_ = owner
}

// TestSCNPRM005NoActiveOrganizationRefuses proves SCN-PRM-005 and REQ-PRM-007.
func TestSCNPRM005NoActiveOrganizationRefuses(t *testing.T) {
	h, _ := activeHarness(t)
	newOrganization(t, h, "owner@example.com", "acme")

	// The owner holds every permission, and the session names no organization
	// until the switch runs.
	resp := hostRequest(t, h, "project:read")
	if resp.Status != http.StatusForbidden {
		t.Fatalf("status %d, want 403: %s", resp.Status, string(resp.Body))
	}
	if code := resp.ErrorCode(t); code != string(apierr.CodeNoActiveOrganization) {
		t.Fatalf("the code = %s, want %s", code, apierr.CodeNoActiveOrganization)
	}

	// The switch back to no organization refuses again.
	orgID := userOrganization(t, h)
	activate(t, h, orgID)
	if got := hostRequest(t, h, "project:read"); got.Status != http.StatusOK {
		t.Fatalf("the active organization got status %d", got.Status)
	}
	clear := h.Do(http.MethodPost, "/organizations/deactivate", nil)
	if clear.Status != http.StatusOK {
		t.Fatalf("the deactivation got status %d: %s", clear.Status, string(clear.Body))
	}
	after := hostRequest(t, h, "project:read")
	if after.Status != http.StatusForbidden {
		t.Fatalf("status %d after the deactivation, want 403", after.Status)
	}
	if code := after.ErrorCode(t); code != string(apierr.CodeNoActiveOrganization) {
		t.Fatalf("the code = %s, want %s", code, apierr.CodeNoActiveOrganization)
	}
}

// TestSCNPRM008CanAnswersEveryPair proves SCN-PRM-008 and REQ-PRM-004. Every
// pair of a role and a statement gets the answer of the declaration.
func TestSCNPRM008CanAnswersEveryPair(t *testing.T) {
	h, orgs := activeHarness(t)
	orgID, _ := newOrganization(t, h, "owner@example.com", "acme")

	// The expected answer of each role for each statement.
	statements := []string{"project:read", "project:write", "billing:read", "member:invite", "organization:delete"}
	want := map[string]map[string]bool{
		"owner": {"project:read": true, "project:write": true, "billing:read": true,
			"member:invite": true, "organization:delete": true},
		"admin": {"project:read": true, "project:write": true, "billing:read": true,
			"member:invite": true, "organization:delete": false},
		"member": {"project:read": true, "project:write": true, "billing:read": false,
			"member:invite": false, "organization:delete": false},
		"viewer": {"project:read": true, "project:write": false, "billing:read": false,
			"member:invite": false, "organization:delete": false},
	}

	member := addMember(t, h, orgID, "bob@example.com", "viewer")
	signInAs(t, h, "bob@example.com")
	activate(t, h, orgID)
	for role, answers := range want {
		setMembershipRole(t, h.Store, orgID, member, role)
		ctx := hostContext(t, h)
		for _, statement := range statements {
			if got := orgs.Can(ctx, statement); got != answers[statement] {
				t.Fatalf("the role %q with %q = %v, want %v", role, statement, got, answers[statement])
			}
		}
	}

	// A context with no organization answers false for every statement.
	for _, statement := range statements {
		if orgs.Can(t.Context(), statement) {
			t.Fatalf("a context with no organization allowed %q", statement)
		}
	}
	// From reports no active organization for the same context.
	if _, ok := organizations.From(t.Context()); ok {
		t.Fatal("From returned an active organization for an empty context")
	}
}

// TestSCNPRM008ASuspendedMemberAnswersFalse proves REQ-PRM-012 for Can.
func TestSCNPRM008ASuspendedMemberAnswersFalse(t *testing.T) {
	h, orgs := activeHarness(t)
	orgID, _ := newOrganization(t, h, "owner@example.com", "acme")
	member := addMember(t, h, orgID, "bob@example.com", "admin")
	signInAs(t, h, "bob@example.com")
	activate(t, h, orgID)
	if !orgs.Can(hostContext(t, h), "project:read") {
		t.Fatal("the active member holds project:read")
	}
	setMembershipStatus(t, h.Store, orgID, member, store.MembershipSuspended)
	if orgs.Can(hostContext(t, h), "project:read") {
		t.Fatal("a suspended member holds no permission")
	}
}
