package organizations

import (
	"context"
	"errors"

	"github.com/alternayte/auth-all/plugin"
)

// ObjectChecker answers a question about one object.
//
// Auth-All resolves the person, the organization, and the role, and it passes
// them to the checker. An application that needs a relationship graph wires
// this to Ory Keto, SpiceDB, or OpenFGA. Auth-All holds the identity that
// those services lack.
//
// Auth-All answers a role question and a permission question. It answers no
// per-object question of its own.
type ObjectChecker interface {
	// Allowed reports whether the subject can run the action on the object. An
	// error denies the request.
	Allowed(ctx context.Context, q Query) (bool, error)
}

// Query is one per-object question.
type Query struct {
	// SubjectID is the person of the request.
	SubjectID string
	// OrgID is the active organization.
	OrgID string
	// Role is the role of the membership.
	Role string
	// Permissions holds the effective statements of the member.
	Permissions []string
	// Action is the asked permission, for example "document:read".
	Action string
	// Object names the object, for example "document:abc123".
	Object string
}

// ErrNoObjectChecker reports that the application configured no checker.
var ErrNoObjectChecker = errors.New("authall/organizations: no object checker is configured. Use organizations.WithObjectChecker")

// WithObjectChecker sends a per-object question to an external policy service.
// The option is off by default, so CanObject reports an error until the
// application wires a checker.
func WithObjectChecker(c ObjectChecker) Option {
	return func(p *Plugin) { p.objects = c }
}

// CanObject asks the external policy service about one object.
//
// It reports an error when no checker is configured, and it denies when the
// checker fails. Every other outcome is the answer of the checker.
func (p *Plugin) CanObject(ctx context.Context, action, object string) (bool, error) {
	if p.objects == nil {
		return false, ErrNoObjectChecker
	}
	value, ok := plugin.OrganizationFrom(ctx)
	if !ok {
		// No active organization means no subject for the question, which is
		// default deny.
		return false, nil
	}
	set, _ := p.activePermissions(ctx)
	allowed, err := p.objects.Allowed(ctx, Query{
		SubjectID:   value.Membership.UserID,
		OrgID:       value.Organization.ID,
		Role:        value.Membership.Role,
		Permissions: set.Statements(),
		Action:      action,
		Object:      object,
	})
	if err != nil {
		// An error of the checker denies the request.
		return false, err
	}
	return allowed, nil
}
