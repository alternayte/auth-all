package store

import (
	"context"
	"time"
)

// The interfaces in this file are optional. A store that does not implement
// one keeps the v0.3.0 behavior, and the organizations plugin reports a clear
// error at construction.

// Organization is one tenant of the application.
type Organization struct {
	ID   string
	Name string
	// Slug is the unique, lowercase name of the organization in a URL.
	Slug      string
	CreatedAt time.Time
	UpdatedAt time.Time
	// Extra holds the host-owned columns of the organizations table.
	Extra *ExtraFields
}

// Membership joins one person and one organization.
type Membership struct {
	ID     string
	OrgID  string
	UserID string
	// Role is a built-in role or a custom role of this organization.
	Role string
	// Status is MembershipActive or MembershipSuspended.
	Status   string
	JoinedAt time.Time
}

// The status values of one membership. A suspended membership keeps the row,
// and it holds no permission.
const (
	MembershipActive    = "active"
	MembershipSuspended = "suspended"
)

// OrganizationFilter selects and pages a list of organizations.
type OrganizationFilter struct {
	// UserID keeps the organizations of one member. An empty value returns
	// every organization, which the administrative list needs.
	UserID string
	// Limit is the number of returned organizations.
	Limit int
	// Cursor continues an earlier page. An empty value starts at the first
	// organization.
	Cursor string
}

// MemberFilter selects and pages the members of one organization.
type MemberFilter struct {
	OrgID string
	// Role keeps the members of one role. A nil value keeps every role.
	Role *string
	// Status keeps the members of one status. A nil value keeps every status.
	Status *string
	Limit  int
	Cursor string
}

// OrganizationStore holds the organizations of the organizations plugin.
type OrganizationStore interface {
	// CreateOrganization inserts one organization. It returns ErrConflict when
	// the slug belongs to another organization.
	CreateOrganization(ctx context.Context, o *Organization) error
	// OrganizationByID returns one organization. It returns ErrNotFound when
	// no organization matches.
	OrganizationByID(ctx context.Context, id string) (*Organization, error)
	// OrganizationBySlug returns one organization by its slug.
	OrganizationBySlug(ctx context.Context, slug string) (*Organization, error)
	// UpdateOrganization writes the name, the slug, the update time, and the
	// host-owned fields. It returns ErrConflict when the slug belongs to
	// another organization, and ErrNotFound when the organization is absent.
	UpdateOrganization(ctx context.Context, o *Organization) error
	// DeleteOrganization removes one organization and every row that belongs
	// to it. The caller runs it inside a write transaction.
	DeleteOrganization(ctx context.Context, id string) error
	// ListOrganizations returns one page and the cursor of the next page. An
	// empty cursor means that no page follows. The order is stable, so no
	// organization repeats and no organization is lost.
	ListOrganizations(ctx context.Context, f OrganizationFilter) (orgs []Organization, next string, err error)
}

// MembershipStore holds the memberships of the organizations plugin.
type MembershipStore interface {
	// CreateMembership inserts one membership. It returns ErrConflict when the
	// user already holds a membership of that organization.
	CreateMembership(ctx context.Context, m *Membership) error
	// MembershipOf returns the membership of one user in one organization. It
	// returns ErrNotFound when no membership exists.
	MembershipOf(ctx context.Context, orgID, userID string) (*Membership, error)
	// UpdateMembership writes the role and the status of one membership.
	UpdateMembership(ctx context.Context, m *Membership) error
	// DeleteMembership removes one membership. It returns ErrNotFound when no
	// membership exists.
	DeleteMembership(ctx context.Context, orgID, userID string) error
	// ListMembers returns one page of the members of one organization, and the
	// cursor of the next page.
	ListMembers(ctx context.Context, f MemberFilter) (members []Membership, next string, err error)
	// MembershipsOfUser returns every membership of one user.
	MembershipsOfUser(ctx context.Context, userID string) ([]Membership, error)
	// LockActiveMembersWithRole returns the identifiers of the active members
	// of one role in one organization, and it locks the rows until the
	// transaction ends.
	//
	// The caller must run it inside a write transaction. The lock makes the
	// owner guard safe under concurrent requests.
	LockActiveMembersWithRole(ctx context.Context, orgID, role string) ([]string, error)
	// CountMembers returns the number of active members of one organization.
	CountMembers(ctx context.Context, orgID string) (int, error)
}
