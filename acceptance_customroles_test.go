package authall_test

import (
	"net/http"
	"testing"

	authall "github.com/alternayte/auth-all"
	"github.com/alternayte/auth-all/apierr"
	"github.com/alternayte/auth-all/internal/testsupport"
	"github.com/alternayte/auth-all/plugins/organizations"
)

// customRoleHarness returns a harness that allows custom roles.
func customRoleHarness(t *testing.T) (*testsupport.Harness, *organizations.Plugin) {
	t.Helper()
	orgs := organizations.New(testRoles(), organizations.DefaultRole("member"),
		organizations.OwnerRole("owner"), organizations.AllowCustomRoles(true))
	h := testsupport.NewHarness(t, authall.WithEmailPassword(), authall.WithPlugins(orgs))
	h.Handle("/host/capture", h.Auth.LoadSession(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			captured.Store(h, r.Context())
			w.WriteHeader(http.StatusOK)
		})))
	for _, statement := range []string{"project:read", "project:write", "billing:read"} {
		h.Handle("/host/"+statement, orgs.Require(statement,
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })))
	}
	return h, orgs
}

// TestSCNPRM007ACustomRoleNeverEscalates proves SCN-PRM-007, REQ-PRM-009,
// REQ-PRM-010, and SI-02.
func TestSCNPRM007ACustomRoleNeverEscalates(t *testing.T) {
	h, _ := customRoleHarness(t)
	orgID, _ := newOrganization(t, h, "owner@example.com", "acme")
	addMember(t, h, orgID, "admin@example.com", "admin")

	signInAs(t, h, "admin@example.com")
	activate(t, h, orgID)

	// An admin declares a role inside the permissions of the admin.
	created := h.Do(http.MethodPost, "/organizations/"+orgID+"/roles", map[string]any{
		"name": "auditor", "permissions": []string{"project:read", "billing:read"},
	})
	if created.Status != http.StatusCreated {
		t.Fatalf("the custom role got status %d: %s", created.Status, string(created.Body))
	}

	// A role with a permission the admin lacks fails.
	for _, statements := range [][]string{{"*"}, {"billing:*"}, {"organization:delete"}, {"project:read", "*"}} {
		refused := h.Do(http.MethodPost, "/organizations/"+orgID+"/roles", map[string]any{
			"name": "escalated", "permissions": statements,
		})
		if refused.Status != http.StatusForbidden {
			t.Fatalf("the statements %v got status %d, want 403: %s", statements, refused.Status, string(refused.Body))
		}
		if code := refused.ErrorCode(t); code != string(apierr.CodeRoleNotAllowed) {
			t.Fatalf("the statements %v got the code %s, want %s", statements, code, apierr.CodeRoleNotAllowed)
		}
	}

	// A name that shadows a built-in role fails.
	for _, name := range []string{"owner", "admin", "member", "viewer"} {
		shadow := h.Do(http.MethodPost, "/organizations/"+orgID+"/roles", map[string]any{
			"name": name, "permissions": []string{"project:read"},
		})
		if shadow.Status != http.StatusBadRequest {
			t.Fatalf("the name %q got status %d, want 400: %s", name, shadow.Status, string(shadow.Body))
		}
	}

	// An invalid statement and an invalid name fail.
	for _, body := range []map[string]any{
		{"name": "bad", "permissions": []string{"project read"}},
		{"name": "bad", "permissions": []string{}},
		{"name": "Bad Name", "permissions": []string{"project:read"}},
	} {
		resp := h.Do(http.MethodPost, "/organizations/"+orgID+"/roles", body)
		if resp.Status != http.StatusBadRequest {
			t.Fatalf("the body %v got status %d, want 400: %s", body, resp.Status, string(resp.Body))
		}
	}
}

// TestSCNPRM007ACustomRoleCarriesItsPermissions proves that a member of a
// custom role holds exactly the statements of that role.
func TestSCNPRM007ACustomRoleCarriesItsPermissions(t *testing.T) {
	h, orgs := customRoleHarness(t)
	orgID, _ := newOrganization(t, h, "owner@example.com", "acme")
	activate(t, h, orgID)
	created := h.Do(http.MethodPost, "/organizations/"+orgID+"/roles", map[string]any{
		"name": "auditor", "permissions": []string{"project:read", "billing:read"},
	})
	if created.Status != http.StatusCreated {
		t.Fatalf("the custom role got status %d: %s", created.Status, string(created.Body))
	}

	// The list route returns the role.
	list := h.Do(http.MethodGet, "/organizations/"+orgID+"/roles", nil)
	var page struct {
		Roles []struct {
			Name        string   `json:"name"`
			Permissions []string `json:"permissions"`
		} `json:"roles"`
	}
	list.Decode(t, &page)
	if len(page.Roles) != 1 || page.Roles[0].Name != "auditor" {
		t.Fatalf("the role list = %+v", page.Roles)
	}
	if len(page.Roles[0].Permissions) != 2 {
		t.Fatalf("the role holds %v", page.Roles[0].Permissions)
	}

	// A member takes the custom role, and the check reads its statements.
	member := addMember(t, h, orgID, "bob@example.com", "viewer")
	set := h.Do(http.MethodPatch, "/organizations/"+orgID+"/members/"+member,
		map[string]any{"role": "auditor"})
	if set.Status != http.StatusOK {
		t.Fatalf("the role change got status %d: %s", set.Status, string(set.Body))
	}

	signInAs(t, h, "bob@example.com")
	activate(t, h, orgID)
	if resp := h.DoURL(http.MethodGet, h.BaseURL+"/host/project:read", nil); resp.Status != http.StatusOK {
		t.Fatalf("the custom role read got status %d: %s", resp.Status, string(resp.Body))
	}
	if resp := h.DoURL(http.MethodGet, h.BaseURL+"/host/billing:read", nil); resp.Status != http.StatusOK {
		t.Fatalf("the custom role billing read got status %d", resp.Status)
	}
	write := h.DoURL(http.MethodGet, h.BaseURL+"/host/project:write", nil)
	if write.Status != http.StatusForbidden {
		t.Fatalf("the custom role write got status %d, want 403", write.Status)
	}
	ctx := hostContext(t, h)
	if !orgs.Can(ctx, "billing:read") || orgs.Can(ctx, "project:write") {
		t.Fatal("Can does not follow the custom role")
	}

	// The deletion removes the role.
	signInAs(t, h, "owner@example.com")
	activate(t, h, orgID)
	remove := h.Do(http.MethodDelete, "/organizations/"+orgID+"/roles/auditor", nil)
	if remove.Status != http.StatusOK {
		t.Fatalf("the deletion got status %d: %s", remove.Status, string(remove.Body))
	}
	// The member of a role that is gone holds no permission, which is default
	// deny.
	signInAs(t, h, "bob@example.com")
	if resp := h.DoURL(http.MethodGet, h.BaseURL+"/host/project:read", nil); resp.Status != http.StatusForbidden {
		t.Fatalf("a removed role still allows a read: status %d", resp.Status)
	}
}

// TestSCNPRM007CustomRolesAreOffByDefault proves HC-02 for the custom roles.
func TestSCNPRM007CustomRolesAreOffByDefault(t *testing.T) {
	h, _ := activeHarness(t)
	orgID, _ := newOrganization(t, h, "owner@example.com", "acme")
	activate(t, h, orgID)
	resp := h.Do(http.MethodPost, "/organizations/"+orgID+"/roles", map[string]any{
		"name": "auditor", "permissions": []string{"project:read"},
	})
	if resp.Status != http.StatusForbidden {
		t.Fatalf("status %d, want 403: %s", resp.Status, string(resp.Body))
	}
}
