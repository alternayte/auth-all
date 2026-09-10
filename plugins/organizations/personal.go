package organizations

import (
	"context"
	"strings"

	"github.com/alternayte/auth-all/hook"
	"github.com/alternayte/auth-all/store"
)

// WithPersonalOrganizations creates one organization for each new person.
//
// The option is off by default, because many applications need none, and an
// automatic row surprises them.
func WithPersonalOrganizations() Option {
	return func(p *Plugin) { p.personal = true }
}

// PersonalOrganizationName returns the name of the personal organization of
// one user. The default is the display name, or the local part of the address.
func personalName(u *store.User) string {
	if u.DisplayName != "" {
		return u.DisplayName
	}
	local, _, _ := strings.Cut(u.EmailNormalized, "@")
	if local == "" {
		return "Personal"
	}
	return local
}

// personalSlug returns a slug of the address that follows the slug rule. The
// identifier of the user keeps it unique.
func personalSlug(u *store.User) string {
	local, _, _ := strings.Cut(u.EmailNormalized, "@")
	var b strings.Builder
	for _, r := range local {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + ('a' - 'A'))
		default:
			b.WriteByte('-')
		}
	}
	slug := strings.Trim(b.String(), "-")
	if slug == "" {
		slug = "user"
	}
	// The whole identifier is the suffix, so two people never share a slug.
	// The name part gives way, because the slug holds 63 characters at most.
	suffix := strings.ReplaceAll(u.ID, "-", "")
	room := 63 - len(suffix) - 1
	if room < 1 {
		// An identifier that fills the slug alone leaves no name part.
		return suffix[:63]
	}
	if len(slug) > room {
		slug = strings.Trim(slug[:room], "-")
	}
	if slug == "" {
		slug = "user"
	}
	return slug + "-" + suffix
}

// registerPersonalOrganization creates one organization for each new person.
// The hook runs in the transaction of the creation, so a failure leaves no
// user without the organization.
func (p *Plugin) registerPersonalOrganization(hooks *hook.Hooks) {
	if !p.personal {
		return
	}
	hooks.OnAfterUserInsert(func(ctx context.Context, ev *hook.UserCreate) error {
		orgs, members, err := orgStores(ev.Tx)
		if err != nil {
			return err
		}
		now := p.now()
		org := &store.Organization{
			ID: newID(), Name: personalName(ev.User), Slug: personalSlug(ev.User),
			CreatedAt: now, UpdatedAt: now,
		}
		if err := orgs.CreateOrganization(ctx, org); err != nil {
			return err
		}
		return members.CreateMembership(ctx, &store.Membership{
			ID: newID(), OrgID: org.ID, UserID: ev.User.ID,
			Role: p.ownerRole, Status: store.MembershipActive, JoinedAt: now,
		})
	})
}
