package organizations

import (
	"context"

	"github.com/alternayte/auth-all/plugins/organizations/permission"
)

// WithPermissions returns a context that carries an active organization with
// the given permission set. A test of this package uses it to reach the check
// with no HTTP server.
func WithPermissions(ctx context.Context, set permission.Set) context.Context {
	return withActive(ctx, active{permissions: set})
}

// Validate runs the declaration guards of the plugin.
func (p *Plugin) Validate() error { return p.validate() }

// DefaultRoleName returns the resolved default role.
func (p *Plugin) DefaultRoleName() string { return p.defaultRole }

// OwnerRoleName returns the resolved owner role.
func (p *Plugin) OwnerRoleName() string { return p.ownerRole }
