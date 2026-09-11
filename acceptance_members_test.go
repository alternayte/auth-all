package authall_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/alternayte/auth-all/apierr"
	"github.com/alternayte/auth-all/internal/testsupport"
	"github.com/alternayte/auth-all/store"
)

// membershipBody is the decoded body of one membership response.
type membershipBody struct {
	Membership struct {
		UserID string `json:"userId"`
		Role   string `json:"role"`
		Status string `json:"status"`
	} `json:"membership"`
}

// memberListBody is the decoded body of one member list.
type memberListBody struct {
	Members []struct {
		UserID string `json:"userId"`
		Role   string `json:"role"`
		Status string `json:"status"`
	} `json:"members"`
	NextCursor string `json:"nextCursor"`
}

// newOrganization signs up one owner and returns the organization identifier
// and the owner.
func newOrganization(t *testing.T, h *testsupport.Harness, address, slug string) (string, string) {
	t.Helper()
	_, out := h.SignUp(address, testPassword)
	resp := h.Do(http.MethodPost, "/organizations", map[string]any{"name": slug, "slug": slug})
	if resp.Status != http.StatusCreated {
		t.Fatalf("create the organization: %d %s", resp.Status, string(resp.Body))
	}
	var body organizationBody
	resp.Decode(t, &body)
	return body.Organization.ID, out.User.ID
}

// addMember signs up one person and writes the membership in the store.
func addMember(t *testing.T, h *testsupport.Harness, orgID, address, role string) string {
	t.Helper()
	jar := h.SaveCookies()
	h.ClearCookies()
	_, out := h.SignUp(address, testPassword)
	h.RestoreCookies(jar)
	writeMembership(t, h.Store, orgID, out.User.ID, role, store.MembershipActive)
	return out.User.ID
}

// writeMembership puts one membership straight in the store.
func writeMembership(t *testing.T, s store.Store, orgID, userID, role, status string) {
	t.Helper()
	members, ok := s.(store.MembershipStore)
	if !ok {
		t.Fatal("the store holds no membership")
	}
	m := &store.Membership{
		ID: orgID + ":" + userID, OrgID: orgID, UserID: userID,
		Role: role, Status: status, JoinedAt: time.Now().UTC(),
	}
	if err := members.CreateMembership(context.Background(), m); err != nil {
		t.Fatalf("write the membership: %v", err)
	}
}

// signInAs replaces the session of the client.
func signInAs(t *testing.T, h *testsupport.Harness, address string) {
	t.Helper()
	h.ClearCookies()
	if resp, _ := h.SignIn(address, testPassword); resp.Status != http.StatusOK {
		t.Fatalf("sign in as %s: %d %s", address, resp.Status, string(resp.Body))
	}
}

// TestSCNMEM003TheRoleChangeAcceptsOnlyAKnownRole proves SCN-MEM-003,
// REQ-MEM-003, and REQ-MEM-004.
func TestSCNMEM003TheRoleChangeAcceptsOnlyAKnownRole(t *testing.T) {
	h, _ := orgHarness(t)
	orgID, _ := newOrganization(t, h, "owner@example.com", "acme")
	member := addMember(t, h, orgID, "bob@example.com", "viewer")

	resp := h.Do(http.MethodPatch, "/organizations/"+orgID+"/members/"+member,
		map[string]any{"role": "member"})
	if resp.Status != http.StatusOK {
		t.Fatalf("status %d: %s", resp.Status, string(resp.Body))
	}
	var body membershipBody
	resp.Decode(t, &body)
	if body.Membership.Role != "member" {
		t.Fatalf("the role = %q, want member", body.Membership.Role)
	}
	if got := membershipOf(t, h.Store, orgID, member); got.Role != "member" {
		t.Fatalf("the stored role = %q, want member", got.Role)
	}

	unknown := h.Do(http.MethodPatch, "/organizations/"+orgID+"/members/"+member,
		map[string]any{"role": "wizard"})
	if unknown.Status != http.StatusBadRequest {
		t.Fatalf("an unknown role got status %d: %s", unknown.Status, string(unknown.Body))
	}
	if code := unknown.ErrorCode(t); code != string(apierr.CodeRoleUnknown) {
		t.Fatalf("an unknown role got the code %s, want %s", code, apierr.CodeRoleUnknown)
	}
}

// TestSCNMEM005TheLastOwnerKeepsTheRole proves SCN-MEM-005 and REQ-MEM-006.
func TestSCNMEM005TheLastOwnerKeepsTheRole(t *testing.T) {
	h, _ := orgHarness(t)
	orgID, owner := newOrganization(t, h, "owner@example.com", "acme")

	demote := h.Do(http.MethodPatch, "/organizations/"+orgID+"/members/"+owner,
		map[string]any{"role": "admin"})
	if demote.Status != http.StatusConflict {
		t.Fatalf("the demotion got status %d: %s", demote.Status, string(demote.Body))
	}
	if code := demote.ErrorCode(t); code != string(apierr.CodeLastOwner) {
		t.Fatalf("the demotion got the code %s, want %s", code, apierr.CodeLastOwner)
	}

	remove := h.Do(http.MethodDelete, "/organizations/"+orgID+"/members/"+owner, nil)
	if remove.Status != http.StatusConflict {
		t.Fatalf("the removal got status %d: %s", remove.Status, string(remove.Body))
	}
	suspend := h.Do(http.MethodPatch, "/organizations/"+orgID+"/members/"+owner,
		map[string]any{"status": "suspended"})
	if suspend.Status != http.StatusConflict {
		t.Fatalf("the suspension got status %d: %s", suspend.Status, string(suspend.Body))
	}
	if got := membershipOf(t, h.Store, orgID, owner); got.Role != "owner" {
		t.Fatalf("the owner lost the role: %+v", got)
	}

	// A second owner makes the change legal.
	second := addMember(t, h, orgID, "second@example.com", "owner")
	if got := membershipOf(t, h.Store, orgID, second); got.Role != "owner" {
		t.Fatalf("the second owner is absent: %+v", got)
	}
	again := h.Do(http.MethodPatch, "/organizations/"+orgID+"/members/"+owner,
		map[string]any{"role": "admin"})
	if again.Status != http.StatusOK {
		t.Fatalf("the demotion with two owners got status %d: %s", again.Status, string(again.Body))
	}
}

// TestSCNMEM007AnAdminCannotGrantTheOwnerRole proves SCN-MEM-007 and
// REQ-MEM-008. A member never grants a permission that the member does not
// hold.
func TestSCNMEM007AnAdminCannotGrantTheOwnerRole(t *testing.T) {
	h, _ := orgHarness(t)
	orgID, _ := newOrganization(t, h, "owner@example.com", "acme")
	addMember(t, h, orgID, "admin@example.com", "admin")
	target := addMember(t, h, orgID, "bob@example.com", "viewer")

	signInAs(t, h, "admin@example.com")
	resp := h.Do(http.MethodPatch, "/organizations/"+orgID+"/members/"+target,
		map[string]any{"role": "owner"})
	if resp.Status != http.StatusForbidden {
		t.Fatalf("status %d, want 403: %s", resp.Status, string(resp.Body))
	}
	if code := resp.ErrorCode(t); code != string(apierr.CodeRoleNotAllowed) {
		t.Fatalf("the code = %s, want %s", code, apierr.CodeRoleNotAllowed)
	}
	if got := membershipOf(t, h.Store, orgID, target); got.Role != "viewer" {
		t.Fatalf("the role changed to %q", got.Role)
	}

	// The admin grants a role that the admin holds.
	allowed := h.Do(http.MethodPatch, "/organizations/"+orgID+"/members/"+target,
		map[string]any{"role": "member"})
	if allowed.Status != http.StatusOK {
		t.Fatalf("a weaker role got status %d: %s", allowed.Status, string(allowed.Body))
	}

	// The owner grants the owner role, because the owner holds every
	// permission.
	signInAs(t, h, "owner@example.com")
	promote := h.Do(http.MethodPatch, "/organizations/"+orgID+"/members/"+target,
		map[string]any{"role": "owner"})
	if promote.Status != http.StatusOK {
		t.Fatalf("the owner promotion got status %d: %s", promote.Status, string(promote.Body))
	}
}

// TestSCNMEM008SuspendStopsEveryPermission proves SCN-MEM-008, REQ-MEM-009,
// and REQ-PRM-012.
func TestSCNMEM008SuspendStopsEveryPermission(t *testing.T) {
	h, _ := orgHarness(t)
	orgID, _ := newOrganization(t, h, "owner@example.com", "acme")
	member := addMember(t, h, orgID, "bob@example.com", "admin")

	// The member reads the organization while the membership is active.
	signInAs(t, h, "bob@example.com")
	if resp := h.Do(http.MethodGet, "/organizations/"+orgID, nil); resp.Status != http.StatusOK {
		t.Fatalf("the active member got status %d: %s", resp.Status, string(resp.Body))
	}

	signInAs(t, h, "owner@example.com")
	suspend := h.Do(http.MethodPatch, "/organizations/"+orgID+"/members/"+member,
		map[string]any{"status": "suspended"})
	if suspend.Status != http.StatusOK {
		t.Fatalf("the suspension got status %d: %s", suspend.Status, string(suspend.Body))
	}
	if got := membershipOf(t, h.Store, orgID, member); got.Status != store.MembershipSuspended {
		t.Fatalf("the status = %q, want suspended", got.Status)
	}

	// A suspended membership holds no permission, and the row stays.
	signInAs(t, h, "bob@example.com")
	denied := h.Do(http.MethodGet, "/organizations/"+orgID, nil)
	if denied.Status != http.StatusForbidden {
		t.Fatalf("the suspended member got status %d, want 403: %s", denied.Status, string(denied.Body))
	}
	if code := denied.ErrorCode(t); code != string(apierr.CodePermissionDenied) {
		t.Fatalf("the code = %s, want %s", code, apierr.CodePermissionDenied)
	}

	// The restore gives the permissions back.
	signInAs(t, h, "owner@example.com")
	restore := h.Do(http.MethodPatch, "/organizations/"+orgID+"/members/"+member,
		map[string]any{"status": "active"})
	if restore.Status != http.StatusOK {
		t.Fatalf("the restore got status %d: %s", restore.Status, string(restore.Body))
	}
	signInAs(t, h, "bob@example.com")
	if resp := h.Do(http.MethodGet, "/organizations/"+orgID, nil); resp.Status != http.StatusOK {
		t.Fatalf("the restored member got status %d: %s", resp.Status, string(resp.Body))
	}
}

// TestSCNMEM009ThePagesCoverEveryMember proves SCN-MEM-009 and REQ-MEM-010 at
// the HTTP layer. The contract suite proves the same rule on both engines.
func TestSCNMEM009ThePagesCoverEveryMember(t *testing.T) {
	h, _ := orgHarness(t)
	orgID, owner := newOrganization(t, h, "owner@example.com", "acme")

	const extra = 40
	want := map[string]string{owner: "owner"}
	for i := range extra {
		role := "viewer"
		status := store.MembershipActive
		if i%2 == 0 {
			role = "member"
		}
		if i%5 == 0 {
			status = store.MembershipSuspended
		}
		user := testsupport.NewUser(fmt.Sprintf("member%02d@example.com", i))
		if err := h.Store.Users().Create(context.Background(), user); err != nil {
			t.Fatalf("create the user %d: %v", i, err)
		}
		writeMembership(t, h.Store, orgID, user.ID, role, status)
		want[user.ID] = role
	}

	seen := map[string]bool{}
	cursor := ""
	for {
		target := fmt.Sprintf("/organizations/%s/members?limit=7", orgID)
		if cursor != "" {
			target += "&cursor=" + cursor
		}
		resp := h.Do(http.MethodGet, target, nil)
		if resp.Status != http.StatusOK {
			t.Fatalf("list status %d: %s", resp.Status, string(resp.Body))
		}
		var page memberListBody
		resp.Decode(t, &page)
		for _, m := range page.Members {
			if seen[m.UserID] {
				t.Fatalf("the member %s repeats", m.UserID)
			}
			seen[m.UserID] = true
		}
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}
	if len(seen) != len(want) {
		t.Fatalf("the pages hold %d members, want %d", len(seen), len(want))
	}

	// The role filter and the status filter keep their rows.
	resp := h.Do(http.MethodGet, "/organizations/"+orgID+"/members?role=viewer&limit=200", nil)
	var viewers memberListBody
	resp.Decode(t, &viewers)
	if len(viewers.Members) == 0 {
		t.Fatal("the role filter returned no member")
	}
	for _, m := range viewers.Members {
		if m.Role != "viewer" {
			t.Fatalf("the role filter returned the role %q", m.Role)
		}
	}
	resp = h.Do(http.MethodGet, "/organizations/"+orgID+"/members?status=suspended&limit=200", nil)
	var suspended memberListBody
	resp.Decode(t, &suspended)
	if len(suspended.Members) == 0 {
		t.Fatal("the status filter returned no member")
	}
	for _, m := range suspended.Members {
		if m.Status != store.MembershipSuspended {
			t.Fatalf("the status filter returned the status %q", m.Status)
		}
	}
}

// TestSCNMEM006TheOwnerGuardHoldsUnderConcurrency proves SCN-MEM-006 and
// REQ-MEM-007. Two owners demote each other in parallel, and one owner always
// stays.
func TestSCNMEM006TheOwnerGuardHoldsUnderConcurrency(t *testing.T) {
	s := testsupport.NewPostgres(t)
	h, plugin := orgHarnessWithStore(t, s)
	orgID, first := newOrganization(t, h, "first@example.com", "acme")
	second := addMember(t, h, orgID, "second@example.com", "owner")

	const rounds = 100
	for round := range rounds {
		if round > 0 {
			// Restore two owners before every round.
			for _, id := range []string{first, second} {
				m := membershipOf(t, h.Store, orgID, id)
				if m.Role == "owner" {
					continue
				}
				if _, err := plugin.SetRole(context.Background(), nil, orgID, id, "owner"); err != nil {
					t.Fatalf("restore the owner: %v", err)
				}
			}
		}
		var wg sync.WaitGroup
		var mu sync.Mutex
		refused := 0
		wg.Add(2)
		for _, id := range []string{first, second} {
			go func(target string) {
				defer wg.Done()
				// One of the two demotions must fail with LAST_OWNER.
				_, err := plugin.SetRole(context.Background(), nil, orgID, target, "admin")
				mu.Lock()
				defer mu.Unlock()
				if errors.Is(err, apierr.ErrLastOwner) {
					refused++
				}
			}(id)
		}
		wg.Wait()

		owners := 0
		for _, id := range []string{first, second} {
			if membershipOf(t, h.Store, orgID, id).Role == "owner" {
				owners++
			}
		}
		if owners != 1 {
			t.Fatalf("round %d left %d owners, want exactly one", round, owners)
		}
		if refused != 1 {
			t.Fatalf("round %d refused %d demotions, want exactly one", round, refused)
		}
	}
}
