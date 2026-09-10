package authall_test

import (
	"context"
	"errors"
	"net/http"
	"testing"

	authall "github.com/alternayte/auth-all"
	"github.com/alternayte/auth-all/events"
	"github.com/alternayte/auth-all/internal/testsupport"
	"github.com/alternayte/auth-all/plugins/organizations"
)

// recordingChecker records the questions of the plugin and answers them.
type recordingChecker struct {
	queries []organizations.Query
	allow   bool
	err     error
}

func (c *recordingChecker) Allowed(_ context.Context, q organizations.Query) (bool, error) {
	c.queries = append(c.queries, q)
	if c.err != nil {
		return true, c.err
	}
	return c.allow, nil
}

// TestSCNINT004TheObjectCheckerIsOptional proves SCN-INT-004, REQ-INT-006,
// REQ-INT-007, and REQ-INT-008.
func TestSCNINT004TheObjectCheckerIsOptional(t *testing.T) {
	// With no checker CanObject reports an error.
	h, plain := activeHarness(t)
	orgID, _ := newOrganization(t, h, "owner@example.com", "acme")
	activate(t, h, orgID)
	allowed, err := plain.CanObject(hostContext(t, h), "document:read", "document:abc123")
	if err == nil {
		t.Fatal("CanObject must report an error with no checker")
	}
	if !errors.Is(err, organizations.ErrNoObjectChecker) {
		t.Fatalf("the error = %v, want ErrNoObjectChecker", err)
	}
	if allowed {
		t.Fatal("CanObject must deny with no checker")
	}

	// With a checker the plugin passes the subject, the organization, the
	// role, and the permissions.
	checker := &recordingChecker{allow: true}
	orgs := organizations.New(testRoles(), organizations.DefaultRole("member"),
		organizations.OwnerRole("owner"), organizations.WithObjectChecker(checker))
	second := testsupport.NewHarness(t, authall.WithEmailPassword(), authall.WithPlugins(orgs))
	second.Handle("/host/capture", second.Auth.LoadSession(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			captured.Store(second, r.Context())
			w.WriteHeader(http.StatusOK)
		})))
	otherOrg, owner := newOrganization(t, second, "owner@example.com", "acme")
	activate(t, second, otherOrg)

	ctx := hostContext(t, second)
	allowed, err = orgs.CanObject(ctx, "document:read", "document:abc123")
	if err != nil || !allowed {
		t.Fatalf("CanObject = %v, %v, want true", allowed, err)
	}
	if len(checker.queries) != 1 {
		t.Fatalf("the checker got %d questions, want 1", len(checker.queries))
	}
	q := checker.queries[0]
	if q.SubjectID != owner {
		t.Fatalf("the subject = %q, want the owner", q.SubjectID)
	}
	if q.OrgID != otherOrg {
		t.Fatalf("the organization = %q, want %q", q.OrgID, otherOrg)
	}
	if q.Role != "owner" {
		t.Fatalf("the role = %q, want owner", q.Role)
	}
	if q.Action != "document:read" || q.Object != "document:abc123" {
		t.Fatalf("the question = %+v", q)
	}
	if len(q.Permissions) == 0 || q.Permissions[0] != "*" {
		t.Fatalf("the permissions = %v, want the owner set", q.Permissions)
	}

	// A denial of the checker denies the request.
	checker.allow = false
	if allowed, err := orgs.CanObject(ctx, "document:read", "document:abc123"); allowed || err != nil {
		t.Fatalf("a denial = %v, %v, want false and no error", allowed, err)
	}

	// An error of the checker denies the request, even when the checker
	// answers true.
	checker.err = errors.New("the policy service is unreachable")
	allowed, err = orgs.CanObject(ctx, "document:read", "document:abc123")
	if allowed {
		t.Fatal("an error of the checker must deny the request")
	}
	if err == nil {
		t.Fatal("an error of the checker must reach the caller")
	}

	// A context with no active organization denies and asks nothing.
	checker.err = nil
	before := len(checker.queries)
	if allowed, err := orgs.CanObject(t.Context(), "document:read", "document:abc123"); allowed || err != nil {
		t.Fatalf("a context with no organization = %v, %v", allowed, err)
	}
	if len(checker.queries) != before {
		t.Fatal("the plugin asked the checker with no active organization")
	}
}

// TestSCNINT005EveryChangeEmitsAnEvent proves SCN-INT-005 and REQ-INT-009.
// Every membership change and every organization change emits an event with
// the actor and the organization.
func TestSCNINT005EveryChangeEmitsAnEvent(t *testing.T) {
	var seen []events.Event
	orgs := organizations.New(testRoles(), organizations.DefaultRole("member"),
		organizations.OwnerRole("owner"), organizations.AllowCustomRoles(true))
	h := testsupport.NewHarness(t, authall.WithEmailPassword(), authall.WithPlugins(orgs),
		authall.WithEventHandler(events.HandlerFunc(func(_ context.Context, e events.Event) {
			seen = append(seen, e)
		})))

	orgID, owner := newOrganization(t, h, "owner@example.com", "acme")
	activate(t, h, orgID)
	member := addMember(t, h, orgID, "bob@example.com", "viewer")

	// One change of each kind.
	steps := []struct {
		name   string
		method string
		path   string
		body   any
		want   events.Name
	}{
		{"the update", http.MethodPatch, "/organizations/" + orgID,
			map[string]any{"name": "Acme Group"}, events.OrganizationUpdated},
		{"the role change", http.MethodPatch, "/organizations/" + orgID + "/members/" + member,
			map[string]any{"role": "member"}, events.MemberRoleChanged},
		{"the suspension", http.MethodPatch, "/organizations/" + orgID + "/members/" + member,
			map[string]any{"status": "suspended"}, events.MemberSuspended},
		{"the restore", http.MethodPatch, "/organizations/" + orgID + "/members/" + member,
			map[string]any{"status": "active"}, events.MemberRestored},
		{"the custom role", http.MethodPost, "/organizations/" + orgID + "/roles",
			map[string]any{"name": "auditor", "permissions": []string{"project:read"}}, events.CustomRoleCreated},
		{"the invitation", http.MethodPost, "/organizations/" + orgID + "/invitations",
			map[string]any{"email": "new@example.com", "role": "member"}, events.InvitationCreated},
		{"the removal", http.MethodDelete, "/organizations/" + orgID + "/members/" + member,
			nil, events.MemberRemoved},
		{"the deletion", http.MethodDelete, "/organizations/" + orgID, nil, events.OrganizationDeleted},
	}
	for _, step := range steps {
		seen = nil
		resp := h.Do(step.method, step.path, step.body)
		if resp.Status != http.StatusOK && resp.Status != http.StatusCreated {
			t.Fatalf("%s got status %d: %s", step.name, resp.Status, string(resp.Body))
		}
		var event *events.Event
		for i := range seen {
			if seen[i].Name == step.want {
				event = &seen[i]
			}
		}
		if event == nil {
			t.Fatalf("%s emitted no %s event", step.name, step.want)
		}
		if got := event.Fields["orgId"]; got != orgID {
			t.Fatalf("%s named the organization %v, want %s", step.name, got, orgID)
		}
		if event.UserID != owner {
			t.Fatalf("%s named the actor %q, want the owner", step.name, event.UserID)
		}
	}

	// The create event of the organization names the actor and the
	// organization as well.
	seen = nil
	other := createOrganization(t, h, "Second", "second")
	var created *events.Event
	for i := range seen {
		if seen[i].Name == events.OrganizationCreated {
			created = &seen[i]
		}
	}
	if created == nil {
		t.Fatal("the creation emitted no event")
	}
	if created.Fields["orgId"] != other || created.UserID != owner {
		t.Fatalf("the creation event = %+v", created)
	}
	// The first membership of the creator emits its own event.
	var added *events.Event
	for i := range seen {
		if seen[i].Name == events.MemberAdded {
			added = &seen[i]
		}
	}
	if added == nil || added.Fields["memberId"] != owner {
		t.Fatalf("the first membership emitted no event: %+v", added)
	}
}
