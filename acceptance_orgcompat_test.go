package authall_test

import (
	"net/http"
	"testing"

	authall "github.com/alternayte/auth-all"
	"github.com/alternayte/auth-all/apierr"
	"github.com/alternayte/auth-all/internal/testsupport"
	"github.com/alternayte/auth-all/plugins/admin"
	"github.com/alternayte/auth-all/plugins/organizations"
	"github.com/alternayte/auth-all/plugins/roles"
)

// compatHarness returns a harness with the global role hierarchy of v0.3.0,
// the admin plugin, and the organizations plugin.
func compatHarness(t *testing.T) (*testsupport.Harness, *organizations.Plugin) {
	t.Helper()
	orgs := organizations.New(testRoles(), organizations.DefaultRole("member"),
		organizations.OwnerRole("owner"))
	hierarchy := roles.New(roles.Hierarchy("viewer", "operator", "admin"), roles.Default("viewer"))
	adm := admin.New(admin.Organizations(orgs))
	h := testsupport.NewHarness(t, authall.WithEmailPassword(),
		authall.WithPlugins(hierarchy, orgs, adm))
	// A global role route of v0.3.0, with no organization.
	h.Handle("/host/global", hierarchy.Require("operator",
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if got := roles.From(r.Context()); got == "" {
				t.Error("the handler got no effective role")
			}
			w.WriteHeader(http.StatusOK)
		})))
	h.Handle("/host/project:read", orgs.Require("project:read",
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })))
	return h, orgs
}

// TestSCNINT002TheGlobalRoleKeepsItsBehavior proves SCN-INT-002 and
// REQ-INT-004. With no active organization the global role still decides.
func TestSCNINT002TheGlobalRoleKeepsItsBehavior(t *testing.T) {
	h, _ := compatHarness(t)
	h.SignUp("alice@example.com", testPassword)

	// The default global role is too low for the route.
	if resp := h.DoURL(http.MethodGet, h.BaseURL+"/host/global", nil); resp.Status != http.StatusForbidden {
		t.Fatalf("the viewer got status %d, want 403", resp.Status)
	}

	// The global role decides, and the organizations plugin changes nothing.
	setRole(t, h.Store, "alice@example.com", "operator")
	signInAs(t, h, "alice@example.com")
	if resp := h.DoURL(http.MethodGet, h.BaseURL+"/host/global", nil); resp.Status != http.StatusOK {
		t.Fatalf("the operator got status %d: %s", resp.Status, string(resp.Body))
	}

	// The same person holds no organization permission, because the session
	// names no organization.
	denied := h.DoURL(http.MethodGet, h.BaseURL+"/host/project:read", nil)
	if denied.Status != http.StatusForbidden {
		t.Fatalf("an organization route got status %d, want 403", denied.Status)
	}
	if code := denied.ErrorCode(t); code != string(apierr.CodeNoActiveOrganization) {
		t.Fatalf("the code = %s, want %s", code, apierr.CodeNoActiveOrganization)
	}

	// An active organization does not change the global role route.
	orgID := createOrganization(t, h, "Acme", "acme")
	activate(t, h, orgID)
	if resp := h.DoURL(http.MethodGet, h.BaseURL+"/host/global", nil); resp.Status != http.StatusOK {
		t.Fatalf("the global route with an active organization got status %d", resp.Status)
	}
	if resp := h.DoURL(http.MethodGet, h.BaseURL+"/host/project:read", nil); resp.Status != http.StatusOK {
		t.Fatalf("the organization route got status %d", resp.Status)
	}
}

// TestSCNINT003AnApplicationAdministratorManagesEveryOrganization proves
// SCN-INT-003 and REQ-INT-005.
func TestSCNINT003AnApplicationAdministratorManagesEveryOrganization(t *testing.T) {
	h, orgs := compatHarness(t)

	// Two people own one organization each.
	h.SignUp("alice@example.com", testPassword)
	first := createOrganization(t, h, "First", "first")
	h.ClearCookies()
	h.SignUp("bob@example.com", testPassword)
	second := createOrganization(t, h, "Second", "second")

	// A person who is no administrator reaches no administrative route.
	refused := h.Do(http.MethodGet, "/admin/organizations", nil)
	if refused.Status != http.StatusForbidden {
		t.Fatalf("a member got status %d, want 403: %s", refused.Status, string(refused.Body))
	}

	// The administrator of the application lists every organization.
	h.ClearCookies()
	h.SignUp("root@example.com", testPassword)
	setRole(t, h.Store, "root@example.com", "admin")
	signInAs(t, h, "root@example.com")

	list := h.Do(http.MethodGet, "/admin/organizations?limit=100", nil)
	if list.Status != http.StatusOK {
		t.Fatalf("the administrative list got status %d: %s", list.Status, string(list.Body))
	}
	var page organizationListBody
	list.Decode(t, &page)
	seen := map[string]bool{}
	for _, o := range page.Organizations {
		seen[o.ID] = true
	}
	if !seen[first] || !seen[second] {
		t.Fatalf("the administrative list misses an organization: %+v", page.Organizations)
	}

	// The administrator deletes an organization of another person.
	remove := h.Do(http.MethodDelete, "/admin/organizations/"+second, nil)
	if remove.Status != http.StatusOK {
		t.Fatalf("the administrative deletion got status %d: %s", remove.Status, string(remove.Body))
	}
	if _, err := orgs.Get(t.Context(), second); err == nil {
		t.Fatal("the organization survived the administrative deletion")
	}
	if _, err := orgs.Get(t.Context(), first); err != nil {
		t.Fatalf("the administrative deletion removed another organization: %v", err)
	}

	// An unknown organization gives 404.
	unknown := h.Do(http.MethodDelete, "/admin/organizations/does-not-exist", nil)
	if unknown.Status != http.StatusNotFound {
		t.Fatalf("an unknown organization got status %d, want 404", unknown.Status)
	}
}

// TestSCNINT003TheAdministrativeRoutesStayOff proves HC-02. An application
// that wires no organizations plugin gets no administrative organization
// route.
func TestSCNINT003TheAdministrativeRoutesStayOff(t *testing.T) {
	hierarchy := roles.New(roles.Hierarchy("viewer", "admin"), roles.Default("viewer"))
	h := testsupport.NewHarness(t, authall.WithEmailPassword(),
		authall.WithPlugins(hierarchy, admin.New()))
	h.SignUp("root@example.com", testPassword)
	setRole(t, h.Store, "root@example.com", "admin")
	signInAs(t, h, "root@example.com")
	resp := h.Do(http.MethodGet, "/admin/organizations", nil)
	if resp.Status != http.StatusNotFound {
		t.Fatalf("status %d, want 404: %s", resp.Status, string(resp.Body))
	}
}
