package organizations

import (
	"context"
	"errors"
	"strings"

	"github.com/alternayte/auth-all/apierr"
	"github.com/alternayte/auth-all/plugins/organizations/permission"
	"github.com/alternayte/auth-all/store"
)

// The permission statements that the built-in routes of Auth-All ask for. An
// application declares them in its roles. The example roles of the guide give
// "member:*" to an administrator and "*" to an owner.
const (
	PermissionOrgRead     = "organization:read"
	PermissionOrgUpdate   = "organization:update"
	PermissionOrgDelete   = "organization:delete"
	PermissionMemberRead  = "member:read"
	PermissionMemberWrite = "member:write"
	PermissionMemberAdd   = "member:invite"
	PermissionRoleWrite   = "role:write"
	PermissionTeamWrite   = "team:write"
)

// permissionsOfMembership returns the effective permission set of one
// membership.
//
// The set is the union of the organization role and of every team role. A
// suspended membership holds no permission, which is default deny.
func (p *Plugin) permissionsOfMembership(ctx context.Context, s store.Store, m *store.Membership) (permission.Set, error) {
	if m == nil || m.Status != store.MembershipActive {
		return permission.Set{}, nil
	}
	set, _, err := p.knownRole(ctx, s, m.OrgID, m.Role)
	if err != nil {
		return permission.Set{}, err
	}
	if m.Permissions != "" {
		// The credential read resolved the extra statements of the membership.
		extra, err := permission.NewSet(strings.Fields(m.Permissions)...)
		if err == nil {
			set = set.Union(extra)
		}
	}
	return set, nil
}

// membershipOf returns the membership of one user in one organization.
func (p *Plugin) membershipOf(ctx context.Context, orgID, userID string) (*store.Membership, error) {
	m, err := p.members.MembershipOf(ctx, orgID, userID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, apierr.ErrNotAMember
		}
		return nil, err
	}
	return m, nil
}

// authorize reports an error when the user does not hold the statement in the
// organization. A user with no active membership gets NOT_A_MEMBER, and a
// member without the permission gets PERMISSION_DENIED.
func (p *Plugin) authorize(ctx context.Context, orgID, userID, statement string) (*store.Membership, permission.Set, error) {
	m, err := p.membershipOf(ctx, orgID, userID)
	if err != nil {
		return nil, permission.Set{}, err
	}
	set, err := p.permissionsOfMembership(ctx, p.store, m)
	if err != nil {
		return nil, permission.Set{}, err
	}
	if !set.Allows(statement) {
		return nil, permission.Set{}, apierr.ErrPermissionDenied
	}
	return m, set, nil
}
