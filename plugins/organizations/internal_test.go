package organizations

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/alternayte/auth-all/apierr"
	"github.com/alternayte/auth-all/store"
)

// bareStore satisfies store.Store and implements no optional interface. A
// store of an older adapter looks like this, and every capability must then
// report a clear error.
type bareStore struct{ store.Store }

// TestABareStoreReportsAClearError proves that every capability names the
// missing part of the storage boundary.
func TestABareStoreReportsAClearError(t *testing.T) {
	t.Parallel()

	bare := bareStore{}
	if _, _, err := orgStores(bare); err == nil || !strings.Contains(err.Error(), "organization") {
		t.Fatalf("orgStores = %v, want an error that names the organization", err)
	}
	if _, err := invitationStore(bare); err == nil || !strings.Contains(err.Error(), "invitation") {
		t.Fatalf("invitationStore = %v", err)
	}
	if _, err := customRoleStore(bare); err == nil || !strings.Contains(err.Error(), "custom role") {
		t.Fatalf("customRoleStore = %v", err)
	}
	if _, err := teamStore(bare); err == nil || !strings.Contains(err.Error(), "team") {
		t.Fatalf("teamStore = %v", err)
	}
	// A store with no active organization needs no change on a removal.
	p := &Plugin{}
	if err := p.clearActiveOrganization(context.Background(), bare, "org", "user"); err != nil {
		t.Fatalf("clearActiveOrganization = %v, want no error", err)
	}
}

// TestTheErrorMappingKeepsTheCode proves that a storage error becomes the
// public code, and that every other error passes through.
func TestTheErrorMappingKeepsTheCode(t *testing.T) {
	t.Parallel()

	other := errors.New("the database is unreachable")
	tests := []struct {
		name string
		fn   func(error) error
		want error
	}{
		{"a taken slug", slugError, apierr.ErrSlugTaken},
		{"an absent row", notFound, apierr.ErrNotFound},
		{"an absent membership", notAMember, apierr.ErrNotAMember},
		{"an invalid invitation", invitationInvalid, apierr.ErrInvitationInvalid},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			source := store.ErrNotFound
			if tc.want == apierr.ErrSlugTaken {
				source = store.ErrConflict
			}
			if got := tc.fn(source); !errors.Is(got, tc.want) {
				t.Fatalf("the mapping = %v, want %v", got, tc.want)
			}
			// An error of another kind never becomes a public code.
			if got := tc.fn(other); !errors.Is(got, other) {
				t.Fatalf("another error = %v, want it unchanged", got)
			}
		})
	}
}

// TestTheClockFallsBackToTheWallClock proves that a plugin with no configured
// clock still writes a timestamp.
func TestTheClockFallsBackToTheWallClock(t *testing.T) {
	t.Parallel()

	p := &Plugin{}
	before := time.Now().UTC().Add(-time.Second)
	got := p.now()
	if got.Before(before) {
		t.Fatalf("now() = %v, want the wall clock", got)
	}
	fixed := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	p.clock = func() time.Time { return fixed }
	if !p.now().Equal(fixed) {
		t.Fatalf("now() = %v, want the configured clock", p.now())
	}
	// An emitter that is absent drops the event and never panics.
	p.emit(context.Background(), "auth.test", "user", "org", nil)
}

// TestASuspendedMembershipHoldsNoPermission proves REQ-PRM-012 at the smallest
// level, and it proves that an absent membership holds nothing.
func TestASuspendedMembershipHoldsNoPermission(t *testing.T) {
	t.Parallel()

	p := New(Roles(Role("admin", "project:*")))
	if err := p.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	bare := bareStore{}
	set, err := p.permissionsOfMembership(context.Background(), bare, nil)
	if err != nil || !set.Empty() {
		t.Fatalf("an absent membership = %v, %v", set.Statements(), err)
	}
	suspended := &store.Membership{OrgID: "org", Role: "admin", Status: store.MembershipSuspended}
	if set, err = p.permissionsOfMembership(context.Background(), bare, suspended); err != nil || !set.Empty() {
		t.Fatalf("a suspended membership = %v, %v", set.Statements(), err)
	}
	active := &store.Membership{OrgID: "org", Role: "admin", Status: store.MembershipActive}
	if set, err = p.permissionsOfMembership(context.Background(), bare, active); err != nil {
		t.Fatalf("an active membership = %v", err)
	}
	if !set.Allows("project:read") {
		t.Fatalf("an active membership holds %v", set.Statements())
	}

	// The union of a team role reaches the set.
	active.TeamRoles = "admin"
	active.Role = "viewer"
	if set, err = p.permissionsOfMembership(context.Background(), bare, active); err != nil {
		t.Fatalf("a team role = %v", err)
	}
	if !set.Allows("project:read") {
		t.Fatalf("the team role holds %v", set.Statements())
	}
	// A stored statement that the grammar refuses widens nothing.
	active.TeamRoles = ""
	active.Permissions = "project read"
	if set, err = p.permissionsOfMembership(context.Background(), bare, active); err != nil {
		t.Fatalf("an invalid stored statement = %v", err)
	}
	if !set.Empty() {
		t.Fatalf("an invalid stored statement widened the set to %v", set.Statements())
	}
}

// TestThePersonalNameFallsBackToTheAddress proves the naming rule with no
// display name.
func TestThePersonalNameFallsBackToTheAddress(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		user *store.User
		want string
	}{
		{"the display name", &store.User{DisplayName: "Bob Smith", EmailNormalized: "bob@example.com"}, "Bob Smith"},
		{"the local part", &store.User{EmailNormalized: "bob@example.com"}, "bob"},
		{"no address", &store.User{}, "Personal"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := personalName(tc.user); got != tc.want {
				t.Fatalf("personalName = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestThePersonalSlugFollowsTheSlugRule proves that every generated slug
// matches the accepted form.
func TestThePersonalSlugFollowsTheSlugRule(t *testing.T) {
	t.Parallel()

	users := []*store.User{
		{ID: "11111111-2222-3333-4444-555555555555", EmailNormalized: "bob.smith@example.com"},
		{ID: "11111111-2222-3333-4444-555555555556", EmailNormalized: "UPPER@example.com"},
		{ID: "11111111-2222-3333-4444-555555555557", EmailNormalized: "+@example.com"},
		{ID: "11111111-2222-3333-4444-555555555558", EmailNormalized: "@example.com"},
		{ID: "11111111-2222-3333-4444-555555555559", EmailNormalized: strings.Repeat("a", 90) + "@example.com"},
	}
	seen := map[string]bool{}
	for _, user := range users {
		slug := personalSlug(user)
		if !slugPattern.MatchString(slug) {
			t.Fatalf("the slug %q does not match the slug rule", slug)
		}
		if seen[slug] {
			t.Fatalf("the slug %q repeats", slug)
		}
		seen[slug] = true
	}
}

// TestAnUnknownRoleHoldsNothing proves that a role of no declaration and of no
// custom row holds no permission.
func TestAnUnknownRoleHoldsNothing(t *testing.T) {
	t.Parallel()

	p := New(Roles(Role("admin", "project:*")))
	if err := p.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	set, known, err := p.knownRole(context.Background(), bareStore{}, "org", "")
	if err != nil || known || !set.Empty() {
		t.Fatalf("an empty role = %v, %v, %v", set.Statements(), known, err)
	}
	// A store with no custom role table answers that the role is unknown.
	if set, known, err = p.knownRole(context.Background(), bareStore{}, "org", "wizard"); err != nil || known {
		t.Fatalf("an unknown role = %v, %v, %v", set.Statements(), known, err)
	}
	if set, known, err = p.knownRole(context.Background(), bareStore{}, "org", "admin"); err != nil || !known {
		t.Fatalf("a declared role = %v, %v, %v", set.Statements(), known, err)
	}
	if !set.Allows("project:read") {
		t.Fatalf("the declared role holds %v", set.Statements())
	}
}

// TestTheInvitationTokenIsRandomAndHashed proves the token rule with no HTTP
// server.
func TestTheInvitationTokenIsRandomAndHashed(t *testing.T) {
	t.Parallel()

	seen := map[string]bool{}
	for range 100 {
		token, err := newInvitationToken()
		if err != nil {
			t.Fatalf("newInvitationToken = %v", err)
		}
		if seen[token] {
			t.Fatalf("the token %q repeats", token)
		}
		seen[token] = true
		sum := digest(token)
		if len(sum) != 64 {
			t.Fatalf("the digest holds %d characters, want 64", len(sum))
		}
		if sum == token {
			t.Fatal("the digest equals the token")
		}
	}
}

// TestTheMemberLimitCountsNothingWhenItIsOff proves that a plugin with no
// limit needs no count.
func TestTheMemberLimitCountsNothingWhenItIsOff(t *testing.T) {
	t.Parallel()

	p := &Plugin{}
	if err := p.guardMemberLimit(context.Background(), bareStore{}, "org", time.Now()); err != nil {
		t.Fatalf("guardMemberLimit with no limit = %v", err)
	}
	// With a limit the guard needs the stores, so a bare store reports the
	// missing capability instead of passing the check.
	p.maxMembers = 3
	if err := p.guardMemberLimit(context.Background(), bareStore{}, "org", time.Now()); err == nil {
		t.Fatal("guardMemberLimit with a limit and no store must fail")
	}
}
