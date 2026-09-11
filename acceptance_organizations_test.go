package authall_test

import (
	"context"
	"net/http"
	"testing"

	authall "github.com/alternayte/auth-all"
	"github.com/alternayte/auth-all/apierr"
	"github.com/alternayte/auth-all/hook"
	"github.com/alternayte/auth-all/internal/testsupport"
	"github.com/alternayte/auth-all/plugins/organizations"
	"github.com/alternayte/auth-all/schema"
	"github.com/alternayte/auth-all/store"
)

// testRoles are the built-in roles of the organization tests. They follow the
// example of the design document.
func testRoles() organizations.Option {
	return organizations.Roles(
		organizations.Role("owner", "*"),
		organizations.Role("admin", "member:*", "role:*", "organization:read", "organization:update", "project:*", "billing:read"),
		organizations.Role("member", "organization:read", "project:read", "project:write"),
		organizations.Role("viewer", "organization:read", "project:read"),
	)
}

// orgHarness returns a harness with the organizations plugin.
func orgHarness(t *testing.T, opts ...organizations.Option) (*testsupport.Harness, *organizations.Plugin) {
	t.Helper()
	all := append([]organizations.Option{testRoles(),
		organizations.DefaultRole("member"), organizations.OwnerRole("owner")}, opts...)
	orgs := organizations.New(all...)
	h := emailPasswordHarness(t,
		authall.WithPlugins(orgs),
		authall.WithOrganizationFields(schema.UserField{
			Name: "billing_email", Type: schema.TypeText, Nullable: true, Input: true, Returned: true,
		}),
	)
	return h, orgs
}

// orgHarnessWithStore returns an organization harness over a supplied store.
func orgHarnessWithStore(t *testing.T, s store.Store, opts ...organizations.Option) (*testsupport.Harness, *organizations.Plugin) {
	t.Helper()
	all := append([]organizations.Option{testRoles(),
		organizations.DefaultRole("member"), organizations.OwnerRole("owner")}, opts...)
	orgs := organizations.New(all...)
	h := testsupport.NewHarnessWithStore(t, s, authall.WithEmailPassword(), authall.WithPlugins(orgs))
	return h, orgs
}

// organizationBody is the decoded body of one organization response.
type organizationBody struct {
	Organization struct {
		ID        string         `json:"id"`
		Name      string         `json:"name"`
		Slug      string         `json:"slug"`
		Extra     map[string]any `json:"extra"`
		CreatedAt string         `json:"createdAt"`
	} `json:"organization"`
}

// organizationListBody is the decoded body of one organization list.
type organizationListBody struct {
	Organizations []struct {
		ID   string `json:"id"`
		Slug string `json:"slug"`
	} `json:"organizations"`
	NextCursor string `json:"nextCursor"`
}

// membershipOf reads one membership straight from the store.
func membershipOf(t *testing.T, s store.Store, orgID, userID string) *store.Membership {
	t.Helper()
	members, ok := s.(store.MembershipStore)
	if !ok {
		t.Fatal("the store holds no membership")
	}
	m, err := members.MembershipOf(context.Background(), orgID, userID)
	if err != nil {
		t.Fatalf("read the membership: %v", err)
	}
	return m
}

// TestSCNORG001TheCreatorHoldsTheOwnerRole proves SCN-ORG-001, REQ-ORG-001,
// and REQ-ORG-003.
func TestSCNORG001TheCreatorHoldsTheOwnerRole(t *testing.T) {
	h, _ := orgHarness(t)
	_, out := h.SignUp("alice@example.com", testPassword)

	resp := h.Do(http.MethodPost, "/organizations", map[string]any{"name": "Acme", "slug": "acme"})
	if resp.Status != http.StatusCreated {
		t.Fatalf("status %d: %s", resp.Status, string(resp.Body))
	}
	var body organizationBody
	resp.Decode(t, &body)
	if body.Organization.Name != "Acme" || body.Organization.Slug != "acme" {
		t.Fatalf("the response = %+v", body.Organization)
	}
	if body.Organization.ID == "" || body.Organization.CreatedAt == "" {
		t.Fatalf("the response holds no identity: %+v", body.Organization)
	}

	m := membershipOf(t, h.Store, body.Organization.ID, out.User.ID)
	if m.Role != "owner" {
		t.Fatalf("the creator holds the role %q, want owner", m.Role)
	}
	if m.Status != store.MembershipActive {
		t.Fatalf("the membership status = %q, want active", m.Status)
	}

	// The organization appears in the list of the creator.
	list := h.Do(http.MethodGet, "/organizations", nil)
	if list.Status != http.StatusOK {
		t.Fatalf("list status %d: %s", list.Status, string(list.Body))
	}
	var page organizationListBody
	list.Decode(t, &page)
	if len(page.Organizations) != 1 || page.Organizations[0].ID != body.Organization.ID {
		t.Fatalf("the list = %+v", page.Organizations)
	}
}

// TestSCNORG001AnAnonymousRequestIsRefused proves that the create route needs
// a signed-in person.
func TestSCNORG001AnAnonymousRequestIsRefused(t *testing.T) {
	h, _ := orgHarness(t)
	resp := h.Do(http.MethodPost, "/organizations", map[string]any{"name": "Acme", "slug": "acme"})
	if resp.Status != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401: %s", resp.Status, string(resp.Body))
	}
}

// TestSCNORG002TheSlugRulesHold proves SCN-ORG-002 and REQ-ORG-002.
func TestSCNORG002TheSlugRulesHold(t *testing.T) {
	h, _ := orgHarness(t)
	h.SignUp("alice@example.com", testPassword)

	invalid := []string{"", "Acme", "-acme", "acme_group", "acme group", "acme/group", "ACME",
		"a234567890123456789012345678901234567890123456789012345678901234"}
	for _, slug := range invalid {
		resp := h.Do(http.MethodPost, "/organizations", map[string]any{"name": "Acme", "slug": slug})
		if resp.Status != http.StatusBadRequest {
			t.Fatalf("the slug %q got status %d, want 400: %s", slug, resp.Status, string(resp.Body))
		}
		if code := resp.ErrorCode(t); code != string(apierr.CodeInvalidRequest) {
			t.Fatalf("the slug %q got the code %s", slug, code)
		}
	}

	valid := []string{"acme", "a", "acme-group", "0acme", "a23456789012345678901234567890123456789012345678901234567890123"}
	for _, slug := range valid {
		resp := h.Do(http.MethodPost, "/organizations", map[string]any{"name": "Acme", "slug": slug})
		if resp.Status != http.StatusCreated {
			t.Fatalf("the slug %q got status %d: %s", slug, resp.Status, string(resp.Body))
		}
	}

	// A duplicate slug fails with its own code.
	resp := h.Do(http.MethodPost, "/organizations", map[string]any{"name": "Acme Two", "slug": "acme"})
	if resp.Status != http.StatusConflict {
		t.Fatalf("a duplicate slug got status %d, want 409: %s", resp.Status, string(resp.Body))
	}
	if code := resp.ErrorCode(t); code != string(apierr.CodeSlugTaken) {
		t.Fatalf("a duplicate slug got the code %s, want %s", code, apierr.CodeSlugTaken)
	}
}

// TestSCNORG002TheNameRulesHold proves the name rule of REQ-ORG-001.
func TestSCNORG002TheNameRulesHold(t *testing.T) {
	h, _ := orgHarness(t)
	h.SignUp("alice@example.com", testPassword)

	long := make([]byte, 201)
	for i := range long {
		long[i] = 'a'
	}
	for _, name := range []string{"", "   ", string(long)} {
		resp := h.Do(http.MethodPost, "/organizations", map[string]any{"name": name, "slug": "acme"})
		if resp.Status != http.StatusBadRequest {
			t.Fatalf("the name of %d characters got status %d", len(name), resp.Status)
		}
	}
}

// TestSCNORG006TheUpdateWritesEveryField proves SCN-ORG-006 and REQ-ORG-004.
func TestSCNORG006TheUpdateWritesEveryField(t *testing.T) {
	h, _ := orgHarness(t)
	h.SignUp("alice@example.com", testPassword)

	resp := h.Do(http.MethodPost, "/organizations", map[string]any{
		"name": "Acme", "slug": "acme", "extra": map[string]any{"billing_email": "pay@acme.example"},
	})
	if resp.Status != http.StatusCreated {
		t.Fatalf("create status %d: %s", resp.Status, string(resp.Body))
	}
	var created organizationBody
	resp.Decode(t, &created)
	if got := created.Organization.Extra["billing_email"]; got != "pay@acme.example" {
		t.Fatalf("the host field = %v, want the written address", got)
	}

	updated := h.Do(http.MethodPatch, "/organizations/"+created.Organization.ID, map[string]any{
		"name": "Acme Group", "slug": "acme-group",
		"extra": map[string]any{"billing_email": "billing@acme.example"},
	})
	if updated.Status != http.StatusOK {
		t.Fatalf("update status %d: %s", updated.Status, string(updated.Body))
	}
	var body organizationBody
	updated.Decode(t, &body)
	if body.Organization.Name != "Acme Group" || body.Organization.Slug != "acme-group" {
		t.Fatalf("the update = %+v", body.Organization)
	}
	if got := body.Organization.Extra["billing_email"]; got != "billing@acme.example" {
		t.Fatalf("the host field = %v, want the new address", got)
	}

	// The read route returns the same organization.
	read := h.Do(http.MethodGet, "/organizations/"+created.Organization.ID, nil)
	if read.Status != http.StatusOK {
		t.Fatalf("read status %d: %s", read.Status, string(read.Body))
	}
	var out organizationBody
	read.Decode(t, &out)
	if out.Organization.Slug != "acme-group" {
		t.Fatalf("the read = %+v", out.Organization)
	}
}

// TestSCNORG006AStrangerCannotReachTheOrganization proves that every
// organization route is default deny for a person with no membership.
func TestSCNORG006AStrangerCannotReachTheOrganization(t *testing.T) {
	h, _ := orgHarness(t)
	h.SignUp("alice@example.com", testPassword)
	resp := h.Do(http.MethodPost, "/organizations", map[string]any{"name": "Acme", "slug": "acme"})
	var created organizationBody
	resp.Decode(t, &created)

	h.ClearCookies()
	h.SignUp("mallory@example.com", testPassword)
	for _, tc := range []struct {
		method string
		body   any
	}{
		{http.MethodGet, nil},
		{http.MethodPatch, map[string]any{"name": "Taken"}},
		{http.MethodDelete, nil},
	} {
		out := h.Do(tc.method, "/organizations/"+created.Organization.ID, tc.body)
		if out.Status != http.StatusForbidden {
			t.Fatalf("%s got status %d, want 403: %s", tc.method, out.Status, string(out.Body))
		}
		if code := out.ErrorCode(t); code != string(apierr.CodeNotAMember) {
			t.Fatalf("%s got the code %s, want %s", tc.method, code, apierr.CodeNotAMember)
		}
	}
}

// TestSCNORG003TheDeletionRunsTheBeforeHook proves the hook half of
// SCN-ORG-003 and REQ-ORG-006. The hook receives the transactional store, and
// it can reject the deletion.
func TestSCNORG003TheDeletionRunsTheBeforeHook(t *testing.T) {
	orgs := organizations.New(testRoles(), organizations.DefaultRole("member"), organizations.OwnerRole("owner"))
	reject := true
	var sawTx bool
	h := emailPasswordHarness(t, authall.WithPlugins(orgs))
	h.Auth.Hooks().OnBeforeOrganizationDelete(func(ctx context.Context, ev *hook.OrganizationEvent) error {
		sawTx = ev.Tx != nil
		if reject {
			return apierr.ErrForbidden.WithMessage("The organization holds open invoices.")
		}
		return nil
	})
	h.SignUp("alice@example.com", testPassword)
	resp := h.Do(http.MethodPost, "/organizations", map[string]any{"name": "Acme", "slug": "acme"})
	var created organizationBody
	resp.Decode(t, &created)

	refused := h.Do(http.MethodDelete, "/organizations/"+created.Organization.ID, nil)
	if refused.Status != http.StatusForbidden {
		t.Fatalf("the rejected deletion got status %d: %s", refused.Status, string(refused.Body))
	}
	if !sawTx {
		t.Fatal("the Before hook got no transactional store")
	}
	if _, err := orgs.Get(context.Background(), created.Organization.ID); err != nil {
		t.Fatalf("the rejected deletion removed the organization: %v", err)
	}

	reject = false
	accepted := h.Do(http.MethodDelete, "/organizations/"+created.Organization.ID, nil)
	if accepted.Status != http.StatusOK {
		t.Fatalf("the deletion got status %d: %s", accepted.Status, string(accepted.Body))
	}
	if _, err := orgs.Get(context.Background(), created.Organization.ID); err == nil {
		t.Fatal("the organization survived the deletion")
	}
}

// TestSCNORG005ThePersonalOrganizationIsAnOption proves SCN-ORG-005 and
// REQ-ORG-008.
func TestSCNORG005ThePersonalOrganizationIsAnOption(t *testing.T) {
	// With the option off a sign-up creates no organization.
	off, _ := orgHarness(t)
	_, first := off.SignUp("alice@example.com", testPassword)
	list := off.Do(http.MethodGet, "/organizations", nil)
	if list.Status != http.StatusOK {
		t.Fatalf("the list got status %d: %s", list.Status, string(list.Body))
	}
	var page organizationListBody
	list.Decode(t, &page)
	if len(page.Organizations) != 0 {
		t.Fatalf("the sign-up created %d organizations, want none", len(page.Organizations))
	}
	_ = first

	// With the option on a sign-up creates one organization, and the person
	// owns it.
	on, _ := orgHarness(t, organizations.WithPersonalOrganizations())
	_, second := on.SignUp("bob@example.com", testPassword)
	list = on.Do(http.MethodGet, "/organizations", nil)
	if list.Status != http.StatusOK {
		t.Fatalf("the list got status %d: %s", list.Status, string(list.Body))
	}
	list.Decode(t, &page)
	if len(page.Organizations) != 1 {
		t.Fatalf("the sign-up created %d organizations, want one", len(page.Organizations))
	}
	m := membershipOf(t, on.Store, page.Organizations[0].ID, second.User.ID)
	if m.Role != "owner" {
		t.Fatalf("the person holds the role %q, want owner", m.Role)
	}

	// A second person gets an organization of its own, and the slugs differ.
	on.ClearCookies()
	on.SignUp("bob@other.example.com", testPassword)
	list = on.Do(http.MethodGet, "/organizations", nil)
	var other organizationListBody
	list.Decode(t, &other)
	if len(other.Organizations) != 1 {
		t.Fatalf("the second person holds %d organizations, want one", len(other.Organizations))
	}
	if other.Organizations[0].Slug == page.Organizations[0].Slug {
		t.Fatalf("two people share the slug %q", other.Organizations[0].Slug)
	}
}
