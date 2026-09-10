package authall_test

import (
	"context"
	"net/http"
	"testing"

	authall "github.com/alternayte/auth-all"
	"github.com/alternayte/auth-all/internal/testsupport"
	"github.com/alternayte/auth-all/plugins/apikeys"
	"github.com/alternayte/auth-all/plugins/organizations"
	"github.com/alternayte/auth-all/plugins/roles"
)

// orgKeyHarness returns a harness with the roles plugin, the organizations
// plugin, and the API keys plugin.
func orgKeyHarness(t *testing.T) (*testsupport.Harness, *organizations.Plugin) {
	t.Helper()
	orgs := organizations.New(testRoles(), organizations.DefaultRole("member"),
		organizations.OwnerRole("owner"))
	hierarchy := roles.New(roles.Hierarchy("viewer", "admin"), roles.Default("viewer"))
	keys := apikeys.New(apikeys.Organizations(orgs))
	h := testsupport.NewHarness(t, authall.WithEmailPassword(),
		authall.WithPlugins(hierarchy, orgs, keys))
	for _, statement := range []string{"project:read", "project:write"} {
		h.Handle("/host/"+statement, orgs.Require(statement,
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })))
	}
	return h, orgs
}

// keyBody is the decoded body of one key response.
type keyBody struct {
	Key struct {
		ID    string  `json:"id"`
		Role  string  `json:"role"`
		OrgID *string `json:"orgId"`
	} `json:"key"`
	Plaintext string `json:"plaintext"`
}

// TestSCNINT001AnOrganizationKeyFollowsItsOwner proves SCN-INT-001,
// REQ-INT-001, REQ-INT-002, REQ-INT-003, and SI-08.
func TestSCNINT001AnOrganizationKeyFollowsItsOwner(t *testing.T) {
	h, _ := orgKeyHarness(t)
	orgID, _ := newOrganization(t, h, "owner@example.com", "acme")
	member := addMember(t, h, orgID, "bob@example.com", "admin")

	// The member creates a key of that organization.
	signInAs(t, h, "bob@example.com")
	resp := h.Do(http.MethodPost, "/api-keys", map[string]any{
		"name": "ci", "role": "admin", "orgId": orgID,
	})
	if resp.Status != http.StatusCreated {
		t.Fatalf("the key got status %d: %s", resp.Status, string(resp.Body))
	}
	var body keyBody
	resp.Decode(t, &body)
	if body.Key.OrgID == nil || *body.Key.OrgID != orgID {
		t.Fatalf("the key names the organization %v", body.Key.OrgID)
	}

	// The key reaches a route of that organization with no switch.
	h.ClearCookies()
	read := h.DoURL(http.MethodGet, h.BaseURL+"/host/project:read", nil,
		testsupport.WithBearer(body.Plaintext))
	if read.Status != http.StatusOK {
		t.Fatalf("the key read got status %d: %s", read.Status, string(read.Body))
	}
	write := h.DoURL(http.MethodGet, h.BaseURL+"/host/project:write", nil,
		testsupport.WithBearer(body.Plaintext))
	if write.Status != http.StatusOK {
		t.Fatalf("the key write got status %d: %s", write.Status, string(write.Body))
	}

	// A demotion of the owner narrows the key at once. The intersection keeps
	// the live permissions of the member only.
	setMembershipRole(t, h.Store, orgID, member, "viewer")
	afterRead := h.DoURL(http.MethodGet, h.BaseURL+"/host/project:read", nil,
		testsupport.WithBearer(body.Plaintext))
	if afterRead.Status != http.StatusOK {
		t.Fatalf("the demoted key read got status %d", afterRead.Status)
	}
	afterWrite := h.DoURL(http.MethodGet, h.BaseURL+"/host/project:write", nil,
		testsupport.WithBearer(body.Plaintext))
	if afterWrite.Status != http.StatusForbidden {
		t.Fatalf("the demoted key still writes: status %d", afterWrite.Status)
	}

	// After the owner leaves the organization the key gets 401.
	members := h.Store.(interface {
		DeleteMembership(ctx context.Context, orgID, userID string) error
	})
	if err := members.DeleteMembership(context.Background(), orgID, member); err != nil {
		t.Fatalf("remove the member: %v", err)
	}
	gone := h.DoURL(http.MethodGet, h.BaseURL+"/host/project:read", nil,
		testsupport.WithBearer(body.Plaintext))
	if gone.Status != http.StatusUnauthorized {
		t.Fatalf("the key of a former member got status %d, want 401: %s", gone.Status, string(gone.Body))
	}
}

// TestSCNINT001AKeyNeedsAMembership proves that a key never names an
// organization of another person.
func TestSCNINT001AKeyNeedsAMembership(t *testing.T) {
	h, _ := orgKeyHarness(t)
	orgID, _ := newOrganization(t, h, "owner@example.com", "acme")

	h.ClearCookies()
	h.SignUp("mallory@example.com", testPassword)
	resp := h.Do(http.MethodPost, "/api-keys", map[string]any{
		"name": "steal", "role": "admin", "orgId": orgID,
	})
	if resp.Status != http.StatusForbidden {
		t.Fatalf("status %d, want 403: %s", resp.Status, string(resp.Body))
	}

	// A key of an unknown role of the organization fails.
	signInAs(t, h, "owner@example.com")
	unknown := h.Do(http.MethodPost, "/api-keys", map[string]any{
		"name": "ci", "role": "wizard", "orgId": orgID,
	})
	if unknown.Status != http.StatusBadRequest {
		t.Fatalf("an unknown role got status %d, want 400: %s", unknown.Status, string(unknown.Body))
	}
}

// TestSCNINT001APlainKeyKeepsItsBehavior proves HC-01 for the API keys. A key
// with no organization behaves as it does in v0.3.0.
func TestSCNINT001APlainKeyKeepsItsBehavior(t *testing.T) {
	h, _ := orgKeyHarness(t)
	h.SignUp("alice@example.com", testPassword)
	resp := h.Do(http.MethodPost, "/api-keys", map[string]any{"name": "plain"})
	if resp.Status != http.StatusCreated {
		t.Fatalf("the plain key got status %d: %s", resp.Status, string(resp.Body))
	}
	var body keyBody
	resp.Decode(t, &body)
	if body.Key.OrgID != nil {
		t.Fatalf("the plain key names the organization %v", *body.Key.OrgID)
	}
	// The key authenticates, and it reaches no organization route.
	h.ClearCookies()
	session := h.DoURL(http.MethodGet, h.URL("/session"), nil, testsupport.WithBearer(body.Plaintext))
	if session.Status != http.StatusOK {
		t.Fatalf("the plain key session got status %d: %s", session.Status, string(session.Body))
	}
	denied := h.DoURL(http.MethodGet, h.BaseURL+"/host/project:read", nil,
		testsupport.WithBearer(body.Plaintext))
	if denied.Status != http.StatusForbidden {
		t.Fatalf("the plain key reached an organization route: status %d", denied.Status)
	}
}

// TestSCNORG003TheDeletionRemovesTheOrganizationKeys proves the key half of
// SCN-ORG-003, REQ-ORG-005, and SI-10. The API keys plugin removes its rows in
// the transaction of the deletion.
func TestSCNORG003TheDeletionRemovesTheOrganizationKeys(t *testing.T) {
	h, orgs := orgKeyHarness(t)
	orgID, _ := newOrganization(t, h, "owner@example.com", "acme")

	// One key of the organization and one key of the whole application.
	orgKey := h.Do(http.MethodPost, "/api-keys", map[string]any{
		"name": "ci", "role": "owner", "orgId": orgID,
	})
	if orgKey.Status != http.StatusCreated {
		t.Fatalf("the organization key got status %d: %s", orgKey.Status, string(orgKey.Body))
	}
	var scoped keyBody
	orgKey.Decode(t, &scoped)
	plain := h.Do(http.MethodPost, "/api-keys", map[string]any{"name": "plain"})
	var global keyBody
	plain.Decode(t, &global)

	if err := orgs.Delete(context.Background(), nil, orgID); err != nil {
		t.Fatalf("delete the organization: %v", err)
	}

	// The organization key is gone, so it authenticates nothing.
	h.ClearCookies()
	gone := h.DoURL(http.MethodGet, h.BaseURL+"/host/project:read", nil,
		testsupport.WithBearer(scoped.Plaintext))
	if gone.Status != http.StatusUnauthorized {
		t.Fatalf("the organization key got status %d, want 401: %s", gone.Status, string(gone.Body))
	}
	// The key of the whole application stays. It authenticates, and it holds
	// no organization, so the organization route answers 403 and not 401.
	kept := h.DoURL(http.MethodGet, h.BaseURL+"/host/project:read", nil,
		testsupport.WithBearer(global.Plaintext))
	if kept.Status != http.StatusForbidden {
		t.Fatalf("the plain key got status %d, want 403: %s", kept.Status, string(kept.Body))
	}
}
