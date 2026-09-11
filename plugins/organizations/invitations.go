package organizations

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/alternayte/auth-all/apierr"
	"github.com/alternayte/auth-all/email"
	"github.com/alternayte/auth-all/events"
	"github.com/alternayte/auth-all/hook"
	"github.com/alternayte/auth-all/store"
)

// DefaultInvitationTTL is the lifetime of one invitation. The option
// InvitationTTL changes it.
const DefaultInvitationTTL = 7 * 24 * time.Hour

// invitationTokenBytes is the number of random bytes of one invitation token.
// 32 bytes carry 256 bits, which needs no slow hash.
const invitationTokenBytes = 32

// InviteInput names one invitation.
type InviteInput struct {
	OrgID string
	Email string
	Role  string
}

// Invite creates one pending invitation and returns the plaintext token.
//
// The plaintext appears one time, in the return value. The store keeps the
// SHA-256 digest only. Auth-All sends no message. It emits the intent, and the
// application sends the invitation.
func (p *Plugin) Invite(ctx context.Context, actor *store.User, in InviteInput) (*store.Invitation, string, error) {
	address := email.Normalize(in.Email)
	if address == "" || !email.Valid(address) {
		return nil, "", apierr.ErrInvalidRequest.WithMessage("The email address is invalid.")
	}
	role := in.Role
	if role == "" {
		role = p.defaultRole
	}
	granted, known, err := p.knownRole(ctx, p.store, in.OrgID, role)
	if err != nil {
		return nil, "", err
	}
	if !known {
		return nil, "", apierr.ErrRoleUnknown
	}
	if actor != nil {
		_, held, err := p.authorize(ctx, in.OrgID, actor.ID, PermissionMemberAdd)
		if err != nil {
			return nil, "", err
		}
		// An invitation never names a role above the role of the inviter.
		if !held.CoversSet(granted) {
			return nil, "", apierr.ErrRoleNotAllowed
		}
	}

	token, err := newInvitationToken()
	if err != nil {
		return nil, "", apierr.ErrInternal.WithCause(err)
	}
	now := p.now()
	invitation := &store.Invitation{
		ID: uuid.NewString(), OrgID: in.OrgID, EmailNormalized: address, Role: role,
		InvitedBy: actorID(actor), TokenHash: digest(token), Status: store.InvitationPending,
		ExpiresAt: now.Add(p.invitationTTL()), CreatedAt: now,
	}

	err = p.store.Transaction(ctx, func(tx store.Store) error {
		orgs, members, err := orgStores(tx)
		if err != nil {
			return err
		}
		invitations, err := invitationStore(tx)
		if err != nil {
			return err
		}
		if _, err := orgs.OrganizationByID(ctx, in.OrgID); err != nil {
			return notFound(err)
		}
		// An address that already holds a membership needs no invitation.
		user, err := tx.Users().GetByNormalizedEmail(ctx, address)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		if user != nil {
			if _, err := members.MembershipOf(ctx, in.OrgID, user.ID); err == nil {
				return apierr.ErrAlreadyMember
			} else if !errors.Is(err, store.ErrNotFound) {
				return err
			}
		}
		if err := p.guardMemberLimit(ctx, tx, in.OrgID, now); err != nil {
			return err
		}
		return invitations.CreateInvitation(ctx, invitation)
	})
	if err != nil {
		return nil, "", err
	}

	// The event carries the address and the link data. It never carries the
	// token digest, and Auth-All sends no message.
	p.emit(ctx, events.InvitationCreated, actorID(actor), in.OrgID, map[string]any{
		"invitationId": invitation.ID,
		"email":        invitation.EmailNormalized,
		"role":         invitation.Role,
		"expiresAt":    invitation.ExpiresAt,
	})
	return invitation, token, nil
}

// AcceptInvitation turns one invitation into a membership.
//
// The signed-in user must hold the normalized address of the invitation. An
// unknown, used, revoked, or expired invitation gives one message for all four
// cases, so a holder learns nothing about the token.
func (p *Plugin) AcceptInvitation(ctx context.Context, user *store.User, token string) (*store.Membership, error) {
	if user == nil {
		return nil, apierr.ErrUnauthorized
	}
	if token == "" {
		return nil, apierr.ErrInvitationInvalid
	}
	hash := digest(token)

	var member *store.Membership
	var orgID string
	err := p.store.Transaction(ctx, func(tx store.Store) error {
		_, members, err := orgStores(tx)
		if err != nil {
			return err
		}
		invitations, err := invitationStore(tx)
		if err != nil {
			return err
		}
		// The read binds the invitation to one address before the consume, so
		// a wrong address never spends the invitation.
		pending, err := invitations.InvitationByTokenHash(ctx, hash)
		if err != nil {
			return invitationInvalid(err)
		}
		if pending.EmailNormalized != user.EmailNormalized {
			return apierr.ErrInvitationInvalid
		}
		// The consume runs before the membership check, so a spent, a revoked,
		// and an expired invitation all give one message. A membership that
		// arrived another way fails after it, with its own code.
		// One conditional update spends the invitation, so ten parallel
		// acceptances create one membership.
		accepted, err := invitations.ConsumeInvitation(ctx, hash, p.now())
		if err != nil {
			return invitationInvalid(err)
		}
		member = &store.Membership{
			ID: uuid.NewString(), OrgID: accepted.OrgID, UserID: user.ID,
			Role: accepted.Role, Status: store.MembershipActive, JoinedAt: p.now(),
		}
		orgID = accepted.OrgID
		if err := members.CreateMembership(ctx, member); err != nil {
			if errors.Is(err, store.ErrConflict) {
				return apierr.ErrAlreadyMember
			}
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	p.hooks.RunAfterMembershipChange(ctx, &hook.MembershipEvent{Membership: member})
	p.emit(ctx, events.InvitationAccepted, user.ID, orgID, map[string]any{
		"memberId": user.ID, "role": member.Role,
	})
	p.emit(ctx, events.MemberAdded, user.ID, orgID, map[string]any{
		"memberId": user.ID, "role": member.Role,
	})
	return member, nil
}

// RevokeInvitation ends one pending invitation.
func (p *Plugin) RevokeInvitation(ctx context.Context, actor *store.User, orgID, invitationID string) error {
	if actor != nil {
		if _, _, err := p.authorize(ctx, orgID, actor.ID, PermissionMemberAdd); err != nil {
			return err
		}
	}
	invitations, err := invitationStore(p.store)
	if err != nil {
		return err
	}
	invitation, err := invitations.InvitationByID(ctx, invitationID)
	if err != nil {
		return invitationInvalid(err)
	}
	if invitation.OrgID != orgID {
		return apierr.ErrInvitationInvalid
	}
	if err := invitations.SetInvitationStatus(ctx, invitationID,
		store.InvitationPending, store.InvitationRevoked); err != nil {
		return invitationInvalid(err)
	}
	p.emit(ctx, events.InvitationRevoked, actorID(actor), orgID, map[string]any{
		"invitationId": invitationID,
	})
	return nil
}

// InvitationPage is one page of the invitation list.
type InvitationPage struct {
	Invitations []store.Invitation
	NextCursor  string
}

// ListInvitations returns one page of the invitations of one organization.
func (p *Plugin) ListInvitations(ctx context.Context, orgID string, f store.InvitationFilter) (InvitationPage, error) {
	invitations, err := invitationStore(p.store)
	if err != nil {
		return InvitationPage{}, err
	}
	f.OrgID = orgID
	out, next, err := invitations.ListInvitations(ctx, f)
	if err != nil {
		return InvitationPage{}, err
	}
	return InvitationPage{Invitations: out, NextCursor: next}, nil
}

// invitationTTL returns the configured lifetime of one invitation.
func (p *Plugin) invitationTTL() time.Duration {
	if p.invitationLifetime <= 0 {
		return DefaultInvitationTTL
	}
	return p.invitationLifetime
}

// invitationStore returns the invitation store of one store value.
func invitationStore(s store.Store) (store.InvitationStore, error) {
	invitations, ok := s.(store.InvitationStore)
	if !ok {
		return nil, errors.New("authall/organizations: the configured store holds no invitation")
	}
	return invitations, nil
}

// invitationInvalid maps every failed lookup to one public error, so an
// unknown, a used, a revoked, and an expired invitation look equal.
func invitationInvalid(err error) error {
	if errors.Is(err, store.ErrNotFound) {
		return apierr.ErrInvitationInvalid
	}
	return err
}

// newInvitationToken returns one URL-safe token of 32 random bytes.
func newInvitationToken() (string, error) {
	raw := make([]byte, invitationTokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// digest returns the SHA-256 hex digest of one token.
func digest(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
