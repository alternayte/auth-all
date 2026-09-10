package organizations

import (
	"context"
	"errors"

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
	set, err := p.roleSet(ctx, s, m.OrgID, m.Role)
	if err != nil {
		return permission.Set{}, err
	}
	return set, nil
}

// roleSet returns the permission set of one role name of one organization. A
// built-in role wins over a custom role of the same name, because a custom
// role never shadows a built-in name.
func (p *Plugin) roleSet(ctx context.Context, s store.Store, orgID, role string) (permission.Set, error) {
	if set, ok := p.PermissionsOf(role); ok {
		return set, nil
	}
	// A role that the application does not declare holds no permission until
	// the custom roles of the organization answer for it.
	return permission.Set{}, nil
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
