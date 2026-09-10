package organizations

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/alternayte/auth-all/apierr"
	"github.com/alternayte/auth-all/events"
	"github.com/alternayte/auth-all/hook"
	"github.com/alternayte/auth-all/store"
)

// maxNameLength is the highest accepted length of an organization name.
const maxNameLength = 200

// slugPattern is the accepted form of a slug.
var slugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// CreateInput names one new organization.
type CreateInput struct {
	Name string
	Slug string
	// OwnerID is the first member. An empty value uses the caller.
	OwnerID string
	// Extra holds the host-owned fields of the organization.
	Extra map[string]any
}

// UpdateInput names the changed fields of one organization. A nil field keeps
// the stored value.
type UpdateInput struct {
	Name *string
	Slug *string
	// Extra holds the host-owned fields that the change writes.
	Extra map[string]any
}

// Create returns a new organization, and it makes the owner the first member.
//
// The creator becomes a member with the configured owner role, so an
// organization never starts without an owner.
func (p *Plugin) Create(ctx context.Context, actor *store.User, in CreateInput) (*store.Organization, error) {
	name := strings.TrimSpace(in.Name)
	if name == "" || len(name) > maxNameLength {
		return nil, apierr.ErrInvalidRequest.WithMessage("The name must hold 1 to 200 characters.")
	}
	slug := strings.TrimSpace(in.Slug)
	if slug == "" {
		return nil, apierr.ErrInvalidRequest.WithMessage("The slug is required.")
	}
	if !slugPattern.MatchString(slug) {
		return nil, apierr.ErrInvalidRequest.WithMessage("The slug must match ^[a-z0-9][a-z0-9-]{0,62}$.")
	}
	ownerID := in.OwnerID
	if ownerID == "" {
		if actor == nil {
			return nil, apierr.ErrUnauthorized
		}
		ownerID = actor.ID
	}

	now := p.now()
	org := &store.Organization{
		ID: uuid.NewString(), Name: name, Slug: slug,
		CreatedAt: now, UpdatedAt: now, Extra: store.NewExtraFields(in.Extra),
	}
	member := &store.Membership{
		ID: uuid.NewString(), OrgID: org.ID, UserID: ownerID,
		Role: p.ownerRole, Status: store.MembershipActive, JoinedAt: now,
	}

	err := p.store.Transaction(ctx, func(tx store.Store) error {
		orgs, members, err := orgStores(tx)
		if err != nil {
			return err
		}
		ev := &hook.OrganizationEvent{Org: org, Actor: actor, Tx: tx}
		if err := p.hooks.RunBeforeOrganizationCreate(ctx, ev); err != nil {
			return err
		}
		if err := orgs.CreateOrganization(ctx, org); err != nil {
			return slugError(err)
		}
		return members.CreateMembership(ctx, member)
	})
	if err != nil {
		return nil, err
	}
	p.hooks.RunAfterOrganizationCreate(ctx, &hook.OrganizationEvent{Org: org, Actor: actor})
	p.hooks.RunAfterMembershipChange(ctx, &hook.MembershipEvent{Org: org, Membership: member, Actor: actor})
	p.emit(ctx, events.OrganizationCreated, actorID(actor), org.ID, map[string]any{
		"slug": org.Slug, "name": org.Name,
	})
	p.emit(ctx, events.MemberAdded, actorID(actor), org.ID, map[string]any{
		"memberId": member.UserID, "role": member.Role,
	})
	return org, nil
}

// Update writes the name, the slug, and the host-owned fields.
func (p *Plugin) Update(ctx context.Context, actor *store.User, orgID string, in UpdateInput) (*store.Organization, error) {
	if in.Name != nil {
		name := strings.TrimSpace(*in.Name)
		if name == "" || len(name) > maxNameLength {
			return nil, apierr.ErrInvalidRequest.WithMessage("The name must hold 1 to 200 characters.")
		}
		in.Name = &name
	}
	if in.Slug != nil {
		slug := strings.TrimSpace(*in.Slug)
		if !slugPattern.MatchString(slug) {
			return nil, apierr.ErrInvalidRequest.WithMessage("The slug must match ^[a-z0-9][a-z0-9-]{0,62}$.")
		}
		in.Slug = &slug
	}

	var out *store.Organization
	err := p.store.Transaction(ctx, func(tx store.Store) error {
		orgs, _, err := orgStores(tx)
		if err != nil {
			return err
		}
		org, err := orgs.OrganizationByID(ctx, orgID)
		if err != nil {
			return notFound(err)
		}
		if in.Name != nil {
			org.Name = *in.Name
		}
		if in.Slug != nil {
			org.Slug = *in.Slug
		}
		for name, value := range in.Extra {
			if org.Extra == nil {
				org.Extra = store.NewExtraFields(nil)
			}
			org.Extra.Set(name, value)
		}
		org.UpdatedAt = p.now()
		ev := &hook.OrganizationEvent{Org: org, Actor: actor, Tx: tx}
		if err := p.hooks.RunBeforeOrganizationUpdate(ctx, ev); err != nil {
			return err
		}
		if err := orgs.UpdateOrganization(ctx, org); err != nil {
			return slugError(err)
		}
		out = org
		return nil
	})
	if err != nil {
		return nil, err
	}
	p.hooks.RunAfterOrganizationUpdate(ctx, &hook.OrganizationEvent{Org: out, Actor: actor})
	p.emit(ctx, events.OrganizationUpdated, actorID(actor), out.ID, map[string]any{
		"slug": out.Slug, "name": out.Name,
	})
	return out, nil
}

// Delete removes one organization and every row that belongs to it.
//
// The Before hook receives the transactional store, so the application removes
// its own rows of the organization in the same transaction.
func (p *Plugin) Delete(ctx context.Context, actor *store.User, orgID string) error {
	var deleted *store.Organization
	err := p.store.Transaction(ctx, func(tx store.Store) error {
		orgs, _, err := orgStores(tx)
		if err != nil {
			return err
		}
		org, err := orgs.OrganizationByID(ctx, orgID)
		if err != nil {
			return notFound(err)
		}
		ev := &hook.OrganizationEvent{Org: org, Actor: actor, Tx: tx}
		if err := p.hooks.RunBeforeOrganizationDelete(ctx, ev); err != nil {
			return err
		}
		if err := orgs.DeleteOrganization(ctx, orgID); err != nil {
			return notFound(err)
		}
		deleted = org
		return nil
	})
	if err != nil {
		return err
	}
	p.hooks.RunAfterOrganizationDelete(ctx, &hook.OrganizationEvent{Org: deleted, Actor: actor})
	p.emit(ctx, events.OrganizationDeleted, actorID(actor), deleted.ID, map[string]any{
		"slug": deleted.Slug,
	})
	return nil
}

// List returns one page of the organizations of one user.
func (p *Plugin) List(ctx context.Context, userID string, limit int, cursor string) ([]store.Organization, string, error) {
	return p.orgs.ListOrganizations(ctx, store.OrganizationFilter{UserID: userID, Limit: limit, Cursor: cursor})
}

// Get returns one organization.
func (p *Plugin) Get(ctx context.Context, orgID string) (*store.Organization, error) {
	org, err := p.orgs.OrganizationByID(ctx, orgID)
	if err != nil {
		return nil, notFound(err)
	}
	return org, nil
}

// orgStores returns the organization store and the membership store of one
// transactional store.
func orgStores(tx store.Store) (store.OrganizationStore, store.MembershipStore, error) {
	orgs, ok := tx.(store.OrganizationStore)
	if !ok {
		return nil, nil, errors.New("authall/organizations: the configured store holds no organization")
	}
	members, ok := tx.(store.MembershipStore)
	if !ok {
		return nil, nil, errors.New("authall/organizations: the configured store holds no membership")
	}
	return orgs, members, nil
}

// slugError maps a uniqueness failure to the public slug error.
func slugError(err error) error {
	if errors.Is(err, store.ErrConflict) {
		return apierr.ErrSlugTaken
	}
	return err
}

// notFound maps an absent row to the public not found error.
func notFound(err error) error {
	if errors.Is(err, store.ErrNotFound) {
		return apierr.ErrNotFound
	}
	return err
}

// actorID returns the identifier of the acting person, or an empty string.
func actorID(actor *store.User) string {
	if actor == nil {
		return ""
	}
	return actor.ID
}

// emit writes one audit event with the organization identifier.
func (p *Plugin) emit(ctx context.Context, name events.Name, userID, orgID string, fields map[string]any) {
	if p.events == nil {
		return
	}
	if fields == nil {
		fields = map[string]any{}
	}
	fields["orgId"] = orgID
	p.events.Emit(ctx, name, userID, fields)
}

// now returns the configured clock of the instance.
func (p *Plugin) now() time.Time {
	if p.clock == nil {
		return time.Now().UTC()
	}
	return p.clock()
}
