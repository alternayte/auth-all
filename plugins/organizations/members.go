package organizations

import (
	"context"
	"errors"
	"time"

	"github.com/alternayte/auth-all/apierr"
	"github.com/alternayte/auth-all/events"
	"github.com/alternayte/auth-all/hook"
	"github.com/alternayte/auth-all/plugins/organizations/permission"
	"github.com/alternayte/auth-all/store"
)

// MemberPage is one page of the member list.
type MemberPage struct {
	Members []store.Membership
	// NextCursor continues the list. An empty value means that no page
	// follows.
	NextCursor string
}

// ListMembers returns one page of the members of one organization.
func (p *Plugin) ListMembers(ctx context.Context, orgID string, f store.MemberFilter) (MemberPage, error) {
	f.OrgID = orgID
	members, next, err := p.members.ListMembers(ctx, f)
	if err != nil {
		return MemberPage{}, err
	}
	return MemberPage{Members: members, NextCursor: next}, nil
}

// SetRole changes the role of one member.
//
// The role must be a built-in role or a custom role of that organization. The
// caller never grants a role that holds a permission the caller lacks, and the
// change never removes the last owner.
func (p *Plugin) SetRole(ctx context.Context, actor *store.User, orgID, userID, role string) (*store.Membership, error) {
	granted, known, err := p.knownRole(ctx, p.store, orgID, role)
	if err != nil {
		return nil, err
	}
	if !known {
		return nil, apierr.ErrRoleUnknown
	}
	if actor != nil {
		// HC-04. A member never grants a permission that the member does not
		// hold.
		_, held, err := p.authorize(ctx, orgID, actor.ID, PermissionMemberWrite)
		if err != nil {
			return nil, err
		}
		if !held.CoversSet(granted) {
			return nil, apierr.ErrRoleNotAllowed
		}
	}

	var out *store.Membership
	var from string
	err = p.store.Transaction(ctx, func(tx store.Store) error {
		orgs, members, err := orgStores(tx)
		if err != nil {
			return err
		}
		org, err := orgs.OrganizationByID(ctx, orgID)
		if err != nil {
			return notFound(err)
		}
		m, err := members.MembershipOf(ctx, orgID, userID)
		if err != nil {
			return notAMember(err)
		}
		from = m.Role
		if from == role {
			out = m
			return nil
		}
		if err := p.guardOwner(ctx, members, orgID, m, role, m.Status); err != nil {
			return err
		}
		m.Role = role
		ev := &hook.MembershipEvent{Org: org, Membership: m, From: from, Actor: actor, Tx: tx}
		if err := p.hooks.RunBeforeMembershipChange(ctx, ev); err != nil {
			return err
		}
		if err := members.UpdateMembership(ctx, m); err != nil {
			return notAMember(err)
		}
		out = m
		return nil
	})
	if err != nil {
		return nil, err
	}
	if from != out.Role {
		p.hooks.RunAfterMembershipChange(ctx, &hook.MembershipEvent{Membership: out, From: from, Actor: actor})
		p.emit(ctx, events.MemberRoleChanged, actorID(actor), orgID, map[string]any{
			"memberId": userID, "from": from, "to": out.Role,
		})
	}
	return out, nil
}

// SetStatus suspends or restores one member.
//
// A suspended membership keeps the row, and it holds no permission. The change
// never suspends the last owner.
func (p *Plugin) SetStatus(ctx context.Context, actor *store.User, orgID, userID, status string) (*store.Membership, error) {
	if status != store.MembershipActive && status != store.MembershipSuspended {
		return nil, apierr.ErrInvalidRequest.WithMessage("The status must be active or suspended.")
	}
	if actor != nil {
		if _, _, err := p.authorize(ctx, orgID, actor.ID, PermissionMemberWrite); err != nil {
			return nil, err
		}
	}

	var out *store.Membership
	var changed bool
	err := p.store.Transaction(ctx, func(tx store.Store) error {
		orgs, members, err := orgStores(tx)
		if err != nil {
			return err
		}
		org, err := orgs.OrganizationByID(ctx, orgID)
		if err != nil {
			return notFound(err)
		}
		m, err := members.MembershipOf(ctx, orgID, userID)
		if err != nil {
			return notAMember(err)
		}
		if m.Status == status {
			out = m
			return nil
		}
		if err := p.guardOwner(ctx, members, orgID, m, m.Role, status); err != nil {
			return err
		}
		m.Status = status
		ev := &hook.MembershipEvent{Org: org, Membership: m, Actor: actor, Tx: tx}
		if err := p.hooks.RunBeforeMembershipChange(ctx, ev); err != nil {
			return err
		}
		if err := members.UpdateMembership(ctx, m); err != nil {
			return notAMember(err)
		}
		out = m
		changed = true
		return nil
	})
	if err != nil {
		return nil, err
	}
	if changed {
		p.hooks.RunAfterMembershipChange(ctx, &hook.MembershipEvent{Membership: out, Actor: actor})
		name := events.MemberRestored
		if status == store.MembershipSuspended {
			name = events.MemberSuspended
		}
		p.emit(ctx, name, actorID(actor), orgID, map[string]any{"memberId": userID})
	}
	return out, nil
}

// Suspend stops every permission of one member and keeps the row.
func (p *Plugin) Suspend(ctx context.Context, actor *store.User, orgID, userID string) (*store.Membership, error) {
	return p.SetStatus(ctx, actor, orgID, userID, store.MembershipSuspended)
}

// Restore gives a suspended member the permissions of its role again.
func (p *Plugin) Restore(ctx context.Context, actor *store.User, orgID, userID string) (*store.Membership, error) {
	return p.SetStatus(ctx, actor, orgID, userID, store.MembershipActive)
}

// Remove deletes one membership.
//
// The removal ends the active organization of every session of that member in
// that organization, so the next request of every instance refuses.
func (p *Plugin) Remove(ctx context.Context, actor *store.User, orgID, userID string) error {
	if actor != nil && actor.ID != userID {
		if _, _, err := p.authorize(ctx, orgID, actor.ID, PermissionMemberWrite); err != nil {
			return err
		}
	}

	var removed *store.Membership
	err := p.store.Transaction(ctx, func(tx store.Store) error {
		orgs, members, err := orgStores(tx)
		if err != nil {
			return err
		}
		org, err := orgs.OrganizationByID(ctx, orgID)
		if err != nil {
			return notFound(err)
		}
		m, err := members.MembershipOf(ctx, orgID, userID)
		if err != nil {
			return notAMember(err)
		}
		// A removal takes the role away, so the owner guard runs with an empty
		// role and an inactive status.
		if err := p.guardOwner(ctx, members, orgID, m, "", store.MembershipSuspended); err != nil {
			return err
		}
		ev := &hook.MembershipEvent{Org: org, Membership: m, Actor: actor, Tx: tx}
		if err := p.hooks.RunBeforeMembershipChange(ctx, ev); err != nil {
			return err
		}
		if err := members.DeleteMembership(ctx, orgID, userID); err != nil {
			return notAMember(err)
		}
		if err := p.clearActiveOrganization(ctx, tx, orgID, userID); err != nil {
			return err
		}
		removed = m
		return nil
	})
	if err != nil {
		return err
	}
	p.hooks.RunAfterMembershipChange(ctx, &hook.MembershipEvent{Membership: removed, Actor: actor})
	p.emit(ctx, events.MemberRemoved, actorID(actor), orgID, map[string]any{
		"memberId": userID, "role": removed.Role,
	})
	return nil
}

// guardOwner refuses a change that removes the last active owner.
//
// The lock holds the owner rows of the organization until the transaction
// ends, so two parallel changes never both pass.
func (p *Plugin) guardOwner(ctx context.Context, members store.MembershipStore,
	orgID string, m *store.Membership, nextRole, nextStatus string) error {
	if m.Role != p.ownerRole || m.Status != store.MembershipActive {
		return nil
	}
	if nextRole == p.ownerRole && nextStatus == store.MembershipActive {
		return nil
	}
	owners, err := members.LockActiveMembersWithRole(ctx, orgID, p.ownerRole)
	if err != nil {
		return err
	}
	remaining := 0
	for _, id := range owners {
		if id != m.UserID {
			remaining++
		}
	}
	if remaining == 0 {
		return apierr.ErrLastOwner
	}
	return nil
}

// knownRole returns the permission set of a role of one organization. The
// second result reports whether the organization holds the role.
func (p *Plugin) knownRole(ctx context.Context, s store.Store, orgID, role string) (permission.Set, bool, error) {
	if role == "" {
		return permission.Set{}, false, nil
	}
	if set, ok := p.PermissionsOf(role); ok {
		return set, true, nil
	}
	return permission.Set{}, false, nil
}

// notAMember maps an absent membership to the public error.
func notAMember(err error) error {
	if errors.Is(err, store.ErrNotFound) {
		return apierr.ErrNotAMember
	}
	return err
}

// clearActiveOrganization ends the active organization of every session of one
// user in one organization. The session column arrives with the active
// organization, so a store without it needs no change.
func (p *Plugin) clearActiveOrganization(ctx context.Context, tx store.Store, orgID, userID string) error {
	sessions, ok := tx.(store.ActiveOrganizationStore)
	if !ok {
		return nil
	}
	return sessions.ClearActiveOrganization(ctx, orgID, userID)
}

// guardMemberLimit refuses a change that passes the member limit.
//
// The count holds the active members and the pending invitations, and it runs
// inside the write transaction. A batch of invitations therefore cannot pass
// the limit together.
func (p *Plugin) guardMemberLimit(ctx context.Context, tx store.Store, orgID string, now time.Time) error {
	if p.maxMembers <= 0 {
		return nil
	}
	_, members, err := orgStores(tx)
	if err != nil {
		return err
	}
	count, err := members.CountMembers(ctx, orgID)
	if err != nil {
		return err
	}
	invitations, err := invitationStore(tx)
	if err != nil {
		return err
	}
	pending, err := invitations.CountPendingInvitations(ctx, orgID, now)
	if err != nil {
		return err
	}
	if count+pending >= p.maxMembers {
		return apierr.ErrMemberLimit
	}
	return nil
}
