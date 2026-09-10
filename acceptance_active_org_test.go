package authall_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/alternayte/auth-all/apierr"
	"github.com/alternayte/auth-all/internal/testsupport"
	"github.com/alternayte/auth-all/plugins/organizations"
	"github.com/alternayte/auth-all/store"
)

// activeHarness returns an organization harness with one host route for each
// permission of the test roles.
func activeHarness(t *testing.T) (*testsupport.Harness, *organizations.Plugin) {
	t.Helper()
	h, orgs := orgHarness(t)
	for _, statement := range []string{"project:read", "project:write", "billing:read"} {
		want := statement
		h.Handle("/host/"+want, orgs.Require(want, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			active, ok := organizations.From(r.Context())
			if !ok {
				t.Error("the handler got no active organization")
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			if active.Organization == nil || active.Membership == nil {
				t.Errorf("the active organization is incomplete: %+v", active)
			}
			w.Header().Set("X-Org", active.Organization.Slug)
			w.Header().Set("X-Role", active.Membership.Role)
			w.WriteHeader(http.StatusOK)
		})))
	}
	return h, orgs
}

// hostRequest calls one host route with the session of the harness.
func hostRequest(t *testing.T, h *testsupport.Harness, statement string, opts ...testsupport.RequestOption) *testsupport.Response {
	t.Helper()
	return h.DoURL(http.MethodGet, h.BaseURL+"/host/"+statement, nil, opts...)
}

// TestSCNCTX001TheSwitchChangesThePermissions proves SCN-CTX-001,
// REQ-CTX-001, REQ-CTX-002, and REQ-CTX-005.
func TestSCNCTX001TheSwitchChangesThePermissions(t *testing.T) {
	h, _ := activeHarness(t)
	_, out := h.SignUp("alice@example.com", testPassword)

	// The person owns one organization and views another.
	ownerOrg := createOrganization(t, h, "Owner Org", "owner-org")
	viewerOrg := createOrganization(t, h, "Viewer Org", "viewer-org")
	setMembershipRole(t, h.Store, viewerOrg, out.User.ID, "viewer")

	// With no active organization every organization route refuses.
	if resp := hostRequest(t, h, "project:read"); resp.Status != http.StatusForbidden {
		t.Fatalf("with no active organization the status is %d, want 403", resp.Status)
	}

	activate(t, h, ownerOrg)
	read := hostRequest(t, h, "project:read")
	if read.Status != http.StatusOK {
		t.Fatalf("the owner read got status %d: %s", read.Status, string(read.Body))
	}
	if got := read.Header.Get("X-Org"); got != "owner-org" {
		t.Fatalf("the active organization = %q, want owner-org", got)
	}
	if got := read.Header.Get("X-Role"); got != "owner" {
		t.Fatalf("the role = %q, want owner", got)
	}
	if resp := hostRequest(t, h, "billing:read"); resp.Status != http.StatusOK {
		t.Fatalf("the owner billing read got status %d", resp.Status)
	}

	// The switch changes the permissions with the organization.
	activate(t, h, viewerOrg)
	if resp := hostRequest(t, h, "project:read"); resp.Status != http.StatusOK {
		t.Fatalf("the viewer read got status %d: %s", resp.Status, string(resp.Body))
	}
	write := hostRequest(t, h, "project:write")
	if write.Status != http.StatusForbidden {
		t.Fatalf("the viewer write got status %d, want 403", write.Status)
	}
	if code := write.ErrorCode(t); code != string(apierr.CodePermissionDenied) {
		t.Fatalf("the viewer write code = %s, want %s", code, apierr.CodePermissionDenied)
	}
	if resp := hostRequest(t, h, "billing:read"); resp.Status != http.StatusForbidden {
		t.Fatalf("the viewer billing read got status %d, want 403", resp.Status)
	}
}

// TestSCNCTX002ASwitchNeedsAMembership proves SCN-CTX-002 and REQ-CTX-001.
func TestSCNCTX002ASwitchNeedsAMembership(t *testing.T) {
	h, _ := activeHarness(t)
	h.SignUp("alice@example.com", testPassword)
	own := createOrganization(t, h, "Own", "own")

	h.ClearCookies()
	h.SignUp("mallory@example.com", testPassword)
	resp := h.Do(http.MethodPost, "/organizations/"+own+"/activate", nil)
	if resp.Status != http.StatusForbidden {
		t.Fatalf("status %d, want 403: %s", resp.Status, string(resp.Body))
	}
	if code := resp.ErrorCode(t); code != string(apierr.CodeNotAMember) {
		t.Fatalf("the code = %s, want %s", code, apierr.CodeNotAMember)
	}
	if resp := hostRequest(t, h, "project:read"); resp.Status != http.StatusForbidden {
		t.Fatalf("the stranger reached a route with status %d", resp.Status)
	}

	// An unknown organization fails as well.
	unknown := h.Do(http.MethodPost, "/organizations/does-not-exist/activate", nil)
	if unknown.Status != http.StatusNotFound {
		t.Fatalf("an unknown organization got status %d, want 404", unknown.Status)
	}

	// A suspended membership never becomes active.
	signInAs(t, h, "alice@example.com")
	setMembershipStatus(t, h.Store, own, userIDOf(t, h.Store, "alice@example.com"), store.MembershipSuspended)
	suspended := h.Do(http.MethodPost, "/organizations/"+own+"/activate", nil)
	if suspended.Status != http.StatusForbidden {
		t.Fatalf("a suspended member got status %d, want 403", suspended.Status)
	}
}

// TestSCNCTX005ARequestValueNeverSetsTheOrganization proves SCN-CTX-005,
// REQ-CTX-006, and SI-04.
func TestSCNCTX005ARequestValueNeverSetsTheOrganization(t *testing.T) {
	h, _ := activeHarness(t)
	_, out := h.SignUp("alice@example.com", testPassword)
	viewer := createOrganization(t, h, "Viewer Org", "viewer-org")
	setMembershipRole(t, h.Store, viewer, out.User.ID, "viewer")
	owner := createOrganization(t, h, "Owner Org", "owner-org")
	activate(t, h, viewer)

	// A header and a query parameter that name the owner organization change
	// nothing. The viewer role still decides.
	headers := []testsupport.RequestOption{
		testsupport.WithHeader("X-Organization", owner),
		testsupport.WithHeader("X-Org-Id", owner),
		testsupport.WithHeader("Organization", "owner-org"),
	}
	for _, opt := range headers {
		resp := hostRequest(t, h, "project:write", opt)
		if resp.Status != http.StatusForbidden {
			t.Fatalf("a header changed the organization: status %d", resp.Status)
		}
	}
	query := h.DoURL(http.MethodGet, h.BaseURL+"/host/project:write?orgId="+owner+"&organization=owner-org", nil)
	if query.Status != http.StatusForbidden {
		t.Fatalf("a query parameter changed the organization: status %d", query.Status)
	}
	// The session still names the viewer organization.
	read := hostRequest(t, h, "project:read")
	if read.Status != http.StatusOK || read.Header.Get("X-Org") != "viewer-org" {
		t.Fatalf("the active organization changed: %d %q", read.Status, read.Header.Get("X-Org"))
	}
}

// TestSCNCTX004ARemovalTakesEffectOnEveryInstance proves SCN-CTX-004,
// REQ-CTX-004, REQ-MEM-005, and SI-05. Two instances share one database.
func TestSCNCTX004ARemovalTakesEffectOnEveryInstance(t *testing.T) {
	s := testsupport.NewSQLite(t)
	instanceA, orgsA := orgHarnessWithStore(t, s)
	instanceB, orgsB := orgHarnessWithStore(t, s)
	for _, pair := range []struct {
		h *testsupport.Harness
		p *organizations.Plugin
	}{{instanceA, orgsA}, {instanceB, orgsB}} {
		pair.h.Handle("/host/project:read", pair.p.Require("project:read",
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })))
	}

	// The owner of instance A creates the organization and adds one member.
	orgID, _ := newOrganization(t, instanceA, "owner@example.com", "acme")
	_, member := instanceB.SignUp("bob@example.com", testPassword)
	writeMembership(t, s, orgID, member.User.ID, "member", store.MembershipActive)

	// The member works on instance B.
	resp := instanceB.Do(http.MethodPost, "/organizations/"+orgID+"/activate", nil)
	if resp.Status != http.StatusOK {
		t.Fatalf("the switch on instance B got status %d: %s", resp.Status, string(resp.Body))
	}
	if got := hostRequest(t, instanceB, "project:read"); got.Status != http.StatusOK {
		t.Fatalf("the member on instance B got status %d", got.Status)
	}

	// Instance A removes the member.
	if err := orgsA.Remove(context.Background(), nil, orgID, member.User.ID); err != nil {
		t.Fatalf("remove the member: %v", err)
	}

	// The next request of instance B refuses, and the active organization of
	// the session is gone.
	after := hostRequest(t, instanceB, "project:read")
	if after.Status != http.StatusForbidden {
		t.Fatalf("the removed member got status %d, want 403: %s", after.Status, string(after.Body))
	}
	if code := after.ErrorCode(t); code != string(apierr.CodeNoActiveOrganization) {
		t.Fatalf("the code = %s, want %s", code, apierr.CodeNoActiveOrganization)
	}
}

// TestSCNMEM004TheRemovalEndsTheActiveOrganization proves SCN-MEM-004 and
// REQ-MEM-005 through the HTTP routes.
func TestSCNMEM004TheRemovalEndsTheActiveOrganization(t *testing.T) {
	h, _ := activeHarness(t)
	orgID, _ := newOrganization(t, h, "owner@example.com", "acme")
	member := addMember(t, h, orgID, "bob@example.com", "member")

	signInAs(t, h, "bob@example.com")
	activate(t, h, orgID)
	if got := hostRequest(t, h, "project:read"); got.Status != http.StatusOK {
		t.Fatalf("the member got status %d", got.Status)
	}

	signInAs(t, h, "owner@example.com")
	remove := h.Do(http.MethodDelete, "/organizations/"+orgID+"/members/"+member, nil)
	if remove.Status != http.StatusOK {
		t.Fatalf("the removal got status %d: %s", remove.Status, string(remove.Body))
	}

	signInAs(t, h, "bob@example.com")
	after := hostRequest(t, h, "project:read")
	if after.Status != http.StatusForbidden {
		t.Fatalf("the removed member got status %d, want 403: %s", after.Status, string(after.Body))
	}
	if code := after.ErrorCode(t); code != string(apierr.CodeNoActiveOrganization) {
		t.Fatalf("the code = %s, want %s", code, apierr.CodeNoActiveOrganization)
	}
}

// TestSCNCTX003TheCredentialReadCostsOneRoundTrip proves SCN-CTX-003,
// REQ-CTX-003, and NFR-01. One statement returns the session, the user, the
// organization, and the membership.
func TestSCNCTX003TheCredentialReadCostsOneRoundTrip(t *testing.T) {
	s := testsupport.NewSQLite(t)
	reader, ok := s.(store.SessionOrgReader)
	if !ok {
		t.Fatal("the store cannot read a membership with a session")
	}
	h, _ := orgHarnessWithStore(t, s)
	_, out := h.SignUp("alice@example.com", testPassword)
	orgID := createOrganization(t, h, "Acme", "acme")
	activate(t, h, orgID)

	cookie := h.SessionCookie()
	if cookie == nil {
		t.Fatal("the sign-up set no session cookie")
	}
	sess, user, org, member, err := reader.SessionWithUserAndMembership(
		context.Background(), sha256Hex(cookie.Value))
	if err != nil {
		t.Fatalf("the joined read failed: %v", err)
	}
	if sess == nil || user == nil || org == nil || member == nil {
		t.Fatalf("the joined read returned %v %v %v %v", sess, user, org, member)
	}
	if user.ID != out.User.ID || org.ID != orgID || member.Role != "owner" {
		t.Fatalf("the joined read = %+v %+v %+v", user, org, member)
	}

	// A session with no active organization returns the same row shape.
	h.ClearCookies()
	h.SignUp("bob@example.com", testPassword)
	second := h.SessionCookie()
	sess, user, org, member, err = reader.SessionWithUserAndMembership(
		context.Background(), sha256Hex(second.Value))
	if err != nil {
		t.Fatalf("the joined read of a plain session failed: %v", err)
	}
	if sess == nil || user == nil {
		t.Fatal("the joined read lost the session")
	}
	if org != nil || member != nil {
		t.Fatalf("a session with no organization returned %+v %+v", org, member)
	}
}

// createOrganization creates one organization through the HTTP route.
func createOrganization(t *testing.T, h *testsupport.Harness, name, slug string) string {
	t.Helper()
	resp := h.Do(http.MethodPost, "/organizations", map[string]any{"name": name, "slug": slug})
	if resp.Status != http.StatusCreated {
		t.Fatalf("create %s: %d %s", slug, resp.Status, string(resp.Body))
	}
	var body organizationBody
	resp.Decode(t, &body)
	return body.Organization.ID
}

// activate switches the active organization of the session.
func activate(t *testing.T, h *testsupport.Harness, orgID string) {
	t.Helper()
	resp := h.Do(http.MethodPost, "/organizations/"+orgID+"/activate", nil)
	if resp.Status != http.StatusOK {
		t.Fatalf("activate %s: %d %s", orgID, resp.Status, string(resp.Body))
	}
}

// setMembershipRole writes the role of one membership in the store.
func setMembershipRole(t *testing.T, s store.Store, orgID, userID, role string) {
	t.Helper()
	members := s.(store.MembershipStore)
	m, err := members.MembershipOf(context.Background(), orgID, userID)
	if err != nil {
		t.Fatalf("read the membership: %v", err)
	}
	m.Role = role
	if err := members.UpdateMembership(context.Background(), m); err != nil {
		t.Fatalf("update the membership: %v", err)
	}
}

// setMembershipStatus writes the status of one membership in the store.
func setMembershipStatus(t *testing.T, s store.Store, orgID, userID, status string) {
	t.Helper()
	members := s.(store.MembershipStore)
	m, err := members.MembershipOf(context.Background(), orgID, userID)
	if err != nil {
		t.Fatalf("read the membership: %v", err)
	}
	m.Status = status
	if err := members.UpdateMembership(context.Background(), m); err != nil {
		t.Fatalf("update the membership: %v", err)
	}
}

// userIDOf returns the identifier of one address.
func userIDOf(t *testing.T, s store.Store, address string) string {
	t.Helper()
	user, err := s.Users().GetByNormalizedEmail(context.Background(), address)
	if err != nil {
		t.Fatalf("read the user %s: %v", address, err)
	}
	return user.ID
}
