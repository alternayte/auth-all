package organizations

import (
	"context"

	"github.com/alternayte/auth-all/plugin"
	"github.com/alternayte/auth-all/store"
)

// WithPermissions returns a context that carries an active organization whose
// role holds the given statements. A test of this package uses it to reach the
// check with no HTTP server.
func WithPermissions(ctx context.Context, statements ...string) context.Context {
	return plugin.WithOrganization(ctx, plugin.OrganizationContext{
		Organization: &store.Organization{ID: "org"},
		Membership:   &store.Membership{OrgID: "org", Status: store.MembershipActive},
		Permissions:  statements,
	})
}

// Validate runs the declaration guards of the plugin.
func (p *Plugin) Validate() error { return p.validate() }

// DefaultRoleName returns the resolved default role.
func (p *Plugin) DefaultRoleName() string { return p.defaultRole }

// OwnerRoleName returns the resolved owner role.
func (p *Plugin) OwnerRoleName() string { return p.ownerRole }
