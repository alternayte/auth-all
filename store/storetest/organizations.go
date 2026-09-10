package storetest

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/alternayte/auth-all/schema"
	"github.com/alternayte/auth-all/store"
)

// runOrganizationTests executes the organization part of the contract suite.
// The organization tables belong to the organizations plugin, so the suite
// applies them before the first test.
func runOrganizationTests(t *testing.T, newStore Factory, o schema.Options) {
	t.Helper()
	tests := []struct {
		name string
		fn   func(t *testing.T, s store.Store)
	}{
		{"OrganizationCreateAndRead", testOrganizationCreateAndRead},
		{"OrganizationSlugIsUnique", testOrganizationSlugUnique},
		{"OrganizationUpdate", testOrganizationUpdate},
		{"SCNORG003TheDeletionLeavesNoRowBehind", testOrganizationDeleteCascade},
		{"SCNORG004ThePagesCoverEveryOrganization", testOrganizationPages},
		{"SCNMEM001OneUserHoldsThreeMemberships", testMembershipInManyOrganizations},
		{"SCNMEM002ASecondMembershipInOneOrganizationFails", testMembershipIsUniquePerOrganization},
		{"Invitations", testInvitations},
		{"SCNINV005TenParallelAcceptancesSpendOneInvitation", testConcurrentInvitationConsume},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newStore(t)
			migrateOrganizations(t, s, o)
			tc.fn(t, s)
		})
	}
}

// migrateOrganizations applies the organization tables to a migrated store.
func migrateOrganizations(t *testing.T, s store.Store, o schema.Options) {
	t.Helper()
	sc, err := schema.NewCoreWithOptions(o)
	if err != nil {
		t.Fatalf("schema: %v", err)
	}
	for _, table := range schema.OrganizationTables(sc.Options()) {
		if err := sc.Add(table); err != nil {
			t.Fatalf("add the organization table: %v", err)
		}
	}
	units, err := schema.OrganizationUnits("organizations", sc.Options())
	if err != nil {
		t.Fatalf("organization units: %v", err)
	}
	for _, unit := range units {
		if err := sc.AddUnit(unit); err != nil {
			t.Fatalf("add the organization unit: %v", err)
		}
	}
	if _, err := s.Migrator().Apply(ctx(t), sc); err != nil {
		t.Fatalf("migrate the organization tables: %v", err)
	}
}

// orgStore returns the organization store of the adapter.
func orgStore(t *testing.T, s store.Store) store.OrganizationStore {
	t.Helper()
	orgs, ok := s.(store.OrganizationStore)
	if !ok {
		t.Fatal("the adapter holds no organization store")
	}
	return orgs
}

// memberStore returns the membership store of the adapter.
func memberStore(t *testing.T, s store.Store) store.MembershipStore {
	t.Helper()
	members, ok := s.(store.MembershipStore)
	if !ok {
		t.Fatal("the adapter holds no membership store")
	}
	return members
}

// uniqueSlug returns a slug that no other test run holds. One adapter test
// shares a database between the subtests, so a fixed slug would collide.
func uniqueSlug(parts ...string) string {
	out := "s" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	for _, part := range parts {
		out += "-" + part
	}
	return out
}

// NewOrganization returns a valid organization value for tests.
func NewOrganization(name, slug string) *store.Organization {
	n := now()
	return &store.Organization{ID: uuid.NewString(), Name: name, Slug: slug, CreatedAt: n, UpdatedAt: n}
}

// newMembership returns a valid membership value for tests.
func newMembership(orgID, userID, role string) *store.Membership {
	return &store.Membership{
		ID: uuid.NewString(), OrgID: orgID, UserID: userID,
		Role: role, Status: store.MembershipActive, JoinedAt: now(),
	}
}

func testOrganizationCreateAndRead(t *testing.T, s store.Store) {
	orgs := orgStore(t, s)
	o := NewOrganization("Acme", uniqueSlug("acme"))
	if err := orgs.CreateOrganization(ctx(t), o); err != nil {
		t.Fatalf("create: %v", err)
	}
	read, err := orgs.OrganizationByID(ctx(t), o.ID)
	if err != nil {
		t.Fatalf("read by id: %v", err)
	}
	if read.Name != "Acme" || read.Slug != o.Slug {
		t.Fatalf("read = %+v", read)
	}
	if !read.CreatedAt.Equal(o.CreatedAt) {
		t.Fatalf("created at = %v, want %v", read.CreatedAt, o.CreatedAt)
	}
	bySlug, err := orgs.OrganizationBySlug(ctx(t), o.Slug)
	if err != nil || bySlug.ID != o.ID {
		t.Fatalf("read by slug = %v, %v", bySlug, err)
	}
	if _, err := orgs.OrganizationByID(ctx(t), uuid.NewString()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("an unknown organization = %v, want ErrNotFound", err)
	}
	if _, err := orgs.OrganizationBySlug(ctx(t), "ghost"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("an unknown slug = %v, want ErrNotFound", err)
	}
}

func testOrganizationSlugUnique(t *testing.T, s store.Store) {
	orgs := orgStore(t, s)
	o := NewOrganization("Acme", uniqueSlug("acme"))
	if err := orgs.CreateOrganization(ctx(t), o); err != nil {
		t.Fatalf("create: %v", err)
	}
	err := orgs.CreateOrganization(ctx(t), NewOrganization("Acme Two", o.Slug))
	if !errors.Is(err, store.ErrConflict) {
		t.Fatalf("a duplicate slug = %v, want ErrConflict", err)
	}
}

func testOrganizationUpdate(t *testing.T, s store.Store) {
	orgs := orgStore(t, s)
	o := NewOrganization("Acme", uniqueSlug("acme"))
	if err := orgs.CreateOrganization(ctx(t), o); err != nil {
		t.Fatalf("create: %v", err)
	}
	other := NewOrganization("Other", uniqueSlug("other"))
	if err := orgs.CreateOrganization(ctx(t), other); err != nil {
		t.Fatalf("create the second organization: %v", err)
	}

	o.Name = "Acme Group"
	o.Slug = uniqueSlug("acme-group")
	o.UpdatedAt = now().Add(time.Second)
	if err := orgs.UpdateOrganization(ctx(t), o); err != nil {
		t.Fatalf("update: %v", err)
	}
	read, err := orgs.OrganizationByID(ctx(t), o.ID)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if read.Name != "Acme Group" || read.Slug != o.Slug {
		t.Fatalf("read = %+v", read)
	}

	o.Slug = other.Slug
	if err := orgs.UpdateOrganization(ctx(t), o); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("a taken slug = %v, want ErrConflict", err)
	}
	absent := NewOrganization("Ghost", uniqueSlug("ghost"))
	if err := orgs.UpdateOrganization(ctx(t), absent); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("an absent organization = %v, want ErrNotFound", err)
	}
}

// testOrganizationDeleteCascade proves SCN-ORG-003 at the storage layer. The
// deletion removes the organization, every membership, every invitation, every
// custom role, and every team in one transaction.
func testOrganizationDeleteCascade(t *testing.T, s store.Store) {
	orgs := orgStore(t, s)
	members := memberStore(t, s)
	o := NewOrganization("Acme", uniqueSlug("acme"))
	if err := orgs.CreateOrganization(ctx(t), o); err != nil {
		t.Fatalf("create: %v", err)
	}
	keep := NewOrganization("Keep", uniqueSlug("keep"))
	if err := orgs.CreateOrganization(ctx(t), keep); err != nil {
		t.Fatalf("create the second organization: %v", err)
	}
	user := mustCreateUser(t, s, uniqueSlug()+"@example.com")
	other := mustCreateUser(t, s, uniqueSlug()+"@example.com")
	if err := members.CreateMembership(ctx(t), newMembership(o.ID, user.ID, "owner")); err != nil {
		t.Fatalf("create the membership: %v", err)
	}
	if err := members.CreateMembership(ctx(t), newMembership(keep.ID, other.ID, "owner")); err != nil {
		t.Fatalf("create the second membership: %v", err)
	}

	// The organization holds one invitation, one custom role, one team, one
	// team membership, and one organization-scoped key.
	invitations := invitationStore(t, s)
	invitationHash := uniqueSlug("hash")
	if err := invitations.CreateInvitation(ctx(t),
		newInvitation(o.ID, "new@example.com", "member", invitationHash, now().Add(time.Hour))); err != nil {
		t.Fatalf("create the invitation: %v", err)
	}
	roles, ok := s.(store.CustomRoleStore)
	if !ok {
		t.Fatal("the adapter holds no custom role store")
	}
	if err := roles.CreateCustomRole(ctx(t), &store.CustomRole{
		ID: uuid.NewString(), OrgID: o.ID, Name: "auditor",
		Permissions: "project:read", CreatedAt: now(),
	}); err != nil {
		t.Fatalf("create the custom role: %v", err)
	}
	teams, ok := s.(store.TeamStore)
	if !ok {
		t.Fatal("the adapter holds no team store")
	}
	team := &store.Team{ID: uuid.NewString(), OrgID: o.ID, Name: "platform", Role: "admin", CreatedAt: now()}
	if err := teams.CreateTeam(ctx(t), team); err != nil {
		t.Fatalf("create the team: %v", err)
	}
	if err := teams.AddTeamMember(ctx(t), team.ID, user.ID); err != nil {
		t.Fatalf("create the team membership: %v", err)
	}

	err := s.Transaction(ctx(t), func(tx store.Store) error {
		return orgStore(t, tx).DeleteOrganization(ctx(t), o.ID)
	})
	if err != nil {
		t.Fatalf("delete: %v", err)
	}

	if _, err := orgs.OrganizationByID(ctx(t), o.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the organization survived: %v", err)
	}
	if _, err := members.MembershipOf(ctx(t), o.ID, user.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a membership survived: %v", err)
	}
	// The rows of another organization stay.
	if _, err := members.MembershipOf(ctx(t), keep.ID, other.ID); err != nil {
		t.Fatalf("the membership of another organization is gone: %v", err)
	}
	// No invitation, custom role, team, or team membership survives the
	// deletion. The API keys plugin removes its own rows in the same
	// transaction, which the HTTP scenario proves.
	if _, err := invitations.InvitationByTokenHash(ctx(t), invitationHash); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("an invitation survived: %v", err)
	}
	if _, err := roles.CustomRoleByName(ctx(t), o.ID, "auditor"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a custom role survived: %v", err)
	}
	if _, err := teams.TeamByID(ctx(t), team.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a team survived: %v", err)
	}
	if held, err := teams.ListTeamMembers(ctx(t), team.ID); err != nil || len(held) != 0 {
		t.Fatalf("a team membership survived: %v, %v", held, err)
	}
	// The user stays, because a person outlives one organization.
	if _, err := s.Users().GetByID(ctx(t), user.ID); err != nil {
		t.Fatalf("the user is gone: %v", err)
	}
	if err := orgs.DeleteOrganization(ctx(t), o.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a second deletion = %v, want ErrNotFound", err)
	}
}

// testOrganizationPages proves SCN-ORG-004. The pages of 300 organizations
// cover every row, and no row repeats.
func testOrganizationPages(t *testing.T, s store.Store) {
	const total = 300
	orgs := orgStore(t, s)
	members := memberStore(t, s)
	user := mustCreateUser(t, s, uniqueSlug()+"@example.com")
	stranger := mustCreateUser(t, s, uniqueSlug()+"@example.com")

	base := uniqueSlug("org")
	want := make(map[string]bool, total)
	for i := range total {
		o := NewOrganization(fmt.Sprintf("Org %03d", i), fmt.Sprintf("%s-%03d", base, i))
		if err := orgs.CreateOrganization(ctx(t), o); err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
		if err := members.CreateMembership(ctx(t), newMembership(o.ID, user.ID, "member")); err != nil {
			t.Fatalf("create the membership %d: %v", i, err)
		}
		want[o.ID] = true
	}
	// One organization of another person must stay out of the list.
	hidden := NewOrganization("Hidden", uniqueSlug("hidden"))
	if err := orgs.CreateOrganization(ctx(t), hidden); err != nil {
		t.Fatalf("create the hidden organization: %v", err)
	}
	if err := members.CreateMembership(ctx(t), newMembership(hidden.ID, stranger.ID, "owner")); err != nil {
		t.Fatalf("create the hidden membership: %v", err)
	}

	seen := map[string]bool{}
	cursor := ""
	pages := 0
	for {
		page, next, err := orgs.ListOrganizations(ctx(t), store.OrganizationFilter{
			UserID: user.ID, Limit: 40, Cursor: cursor,
		})
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		pages++
		for _, o := range page {
			if seen[o.ID] {
				t.Fatalf("the organization %s repeats", o.Slug)
			}
			if !want[o.ID] {
				t.Fatalf("the organization %s belongs to another user", o.Slug)
			}
			seen[o.ID] = true
		}
		if next == "" {
			break
		}
		cursor = next
		if pages > total {
			t.Fatal("the pages do not end")
		}
	}
	if len(seen) != total {
		t.Fatalf("the pages hold %d organizations, want %d", len(seen), total)
	}
	if _, _, err := orgs.ListOrganizations(ctx(t), store.OrganizationFilter{Cursor: "not-a-cursor!"}); err == nil {
		t.Fatal("an invalid cursor must fail")
	}
}

// testMembershipInManyOrganizations proves SCN-MEM-001. One user holds a
// membership in three organizations with three roles.
func testMembershipInManyOrganizations(t *testing.T, s store.Store) {
	orgs := orgStore(t, s)
	members := memberStore(t, s)
	user := mustCreateUser(t, s, uniqueSlug()+"@example.com")

	base := uniqueSlug("org")
	roles := []string{"owner", "admin", "viewer"}
	ids := make([]string, 0, len(roles))
	for i, role := range roles {
		o := NewOrganization(fmt.Sprintf("Org %d", i), fmt.Sprintf("%s-%d", base, i))
		if err := orgs.CreateOrganization(ctx(t), o); err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
		if err := members.CreateMembership(ctx(t), newMembership(o.ID, user.ID, role)); err != nil {
			t.Fatalf("create the membership %d: %v", i, err)
		}
		ids = append(ids, o.ID)
	}

	held, err := members.MembershipsOfUser(ctx(t), user.ID)
	if err != nil {
		t.Fatalf("memberships of the user: %v", err)
	}
	if len(held) != len(roles) {
		t.Fatalf("the user holds %d memberships, want %d", len(held), len(roles))
	}
	for i, id := range ids {
		m, err := members.MembershipOf(ctx(t), id, user.ID)
		if err != nil {
			t.Fatalf("membership %d: %v", i, err)
		}
		if m.Role != roles[i] {
			t.Fatalf("the role of organization %d = %q, want %q", i, m.Role, roles[i])
		}
		if m.Status != store.MembershipActive {
			t.Fatalf("the status = %q, want %q", m.Status, store.MembershipActive)
		}
	}
	if _, err := members.MembershipOf(ctx(t), ids[0], uuid.NewString()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("an unknown membership = %v, want ErrNotFound", err)
	}
}

// testMembershipIsUniquePerOrganization proves SCN-MEM-002. One user holds at
// most one membership in one organization.
func testMembershipIsUniquePerOrganization(t *testing.T, s store.Store) {
	orgs := orgStore(t, s)
	members := memberStore(t, s)
	o := NewOrganization("Acme", uniqueSlug("acme"))
	if err := orgs.CreateOrganization(ctx(t), o); err != nil {
		t.Fatalf("create: %v", err)
	}
	user := mustCreateUser(t, s, uniqueSlug()+"@example.com")
	if err := members.CreateMembership(ctx(t), newMembership(o.ID, user.ID, "member")); err != nil {
		t.Fatalf("create the membership: %v", err)
	}
	err := members.CreateMembership(ctx(t), newMembership(o.ID, user.ID, "owner"))
	if !errors.Is(err, store.ErrConflict) {
		t.Fatalf("a second membership = %v, want ErrConflict", err)
	}
}

// invitationStore returns the invitation store of the adapter.
func invitationStore(t *testing.T, s store.Store) store.InvitationStore {
	t.Helper()
	invitations, ok := s.(store.InvitationStore)
	if !ok {
		t.Fatal("the adapter holds no invitation store")
	}
	return invitations
}

// newInvitation returns a valid invitation value for tests.
func newInvitation(orgID, address, role, tokenHash string, expires time.Time) *store.Invitation {
	return &store.Invitation{
		ID: uuid.NewString(), OrgID: orgID, EmailNormalized: address, Role: role,
		InvitedBy: uuid.NewString(), TokenHash: tokenHash,
		Status: store.InvitationPending, ExpiresAt: expires, CreatedAt: now(),
	}
}

func testInvitations(t *testing.T, s store.Store) {
	orgs := orgStore(t, s)
	invitations := invitationStore(t, s)
	o := NewOrganization("Acme", uniqueSlug("acme"))
	if err := orgs.CreateOrganization(ctx(t), o); err != nil {
		t.Fatalf("create: %v", err)
	}
	hash := uniqueSlug("hash")
	i := newInvitation(o.ID, "new@example.com", "member", hash, now().Add(time.Hour))
	if err := invitations.CreateInvitation(ctx(t), i); err != nil {
		t.Fatalf("create the invitation: %v", err)
	}
	if err := invitations.CreateInvitation(ctx(t),
		newInvitation(o.ID, "other@example.com", "member", hash, now().Add(time.Hour))); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("a duplicate digest = %v, want ErrConflict", err)
	}
	read, err := invitations.InvitationByTokenHash(ctx(t), hash)
	if err != nil || read.ID != i.ID {
		t.Fatalf("read by digest = %v, %v", read, err)
	}
	if byID, err := invitations.InvitationByID(ctx(t), i.ID); err != nil || byID.TokenHash != hash {
		t.Fatalf("read by id = %v, %v", byID, err)
	}
	if _, err := invitations.InvitationByTokenHash(ctx(t), "absent"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("an unknown digest = %v, want ErrNotFound", err)
	}

	// The count holds the pending and unexpired invitations only.
	count, err := invitations.CountPendingInvitations(ctx(t), o.ID, now())
	if err != nil || count != 1 {
		t.Fatalf("the pending count = %d, %v, want 1", count, err)
	}
	expired := newInvitation(o.ID, "old@example.com", "member", uniqueSlug("old"), now().Add(-time.Hour))
	if err := invitations.CreateInvitation(ctx(t), expired); err != nil {
		t.Fatalf("create the expired invitation: %v", err)
	}
	if count, err = invitations.CountPendingInvitations(ctx(t), o.ID, now()); err != nil || count != 1 {
		t.Fatalf("the pending count with an expired row = %d, %v, want 1", count, err)
	}
	// An expired invitation is never consumed.
	if _, err := invitations.ConsumeInvitation(ctx(t), expired.TokenHash, now()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("an expired consume = %v, want ErrNotFound", err)
	}

	// The list pages the invitations of one organization.
	page, next, err := invitations.ListInvitations(ctx(t), store.InvitationFilter{OrgID: o.ID, Limit: 10})
	if err != nil || len(page) != 2 || next != "" {
		t.Fatalf("the list = %d rows, %q, %v", len(page), next, err)
	}
	pending := store.InvitationPending
	filtered, _, err := invitations.ListInvitations(ctx(t),
		store.InvitationFilter{OrgID: o.ID, Status: &pending, Limit: 10})
	if err != nil || len(filtered) != 2 {
		t.Fatalf("the status filter = %d rows, %v", len(filtered), err)
	}

	// The revocation stops the invitation, and a second one fails.
	if err := invitations.SetInvitationStatus(ctx(t), i.ID, store.InvitationPending, store.InvitationRevoked); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if err := invitations.SetInvitationStatus(ctx(t), i.ID,
		store.InvitationPending, store.InvitationRevoked); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a second revocation = %v, want ErrNotFound", err)
	}
	if _, err := invitations.ConsumeInvitation(ctx(t), hash, now()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a revoked consume = %v, want ErrNotFound", err)
	}
}

// testConcurrentInvitationConsume proves SCN-INV-005 and REQ-INV-008. Ten
// parallel acceptances of one invitation spend it one time.
func testConcurrentInvitationConsume(t *testing.T, s store.Store) {
	const attempts = 10
	orgs := orgStore(t, s)
	invitations := invitationStore(t, s)
	o := NewOrganization("Acme", uniqueSlug("acme"))
	if err := orgs.CreateOrganization(ctx(t), o); err != nil {
		t.Fatalf("create: %v", err)
	}
	hash := uniqueSlug("hash")
	if err := invitations.CreateInvitation(ctx(t),
		newInvitation(o.ID, "new@example.com", "member", hash, now().Add(time.Hour))); err != nil {
		t.Fatalf("create the invitation: %v", err)
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	accepted := 0
	wg.Add(attempts)
	for range attempts {
		go func() {
			defer wg.Done()
			out, err := invitations.ConsumeInvitation(ctx(t), hash, now())
			mu.Lock()
			defer mu.Unlock()
			if err == nil && out != nil {
				accepted++
			}
		}()
	}
	wg.Wait()
	if accepted != 1 {
		t.Fatalf("%d of %d acceptances passed, want exactly one", accepted, attempts)
	}
	final, err := invitations.InvitationByTokenHash(ctx(t), hash)
	if err != nil {
		t.Fatalf("read the invitation: %v", err)
	}
	if final.Status != store.InvitationAccepted {
		t.Fatalf("the status = %q, want accepted", final.Status)
	}
}
