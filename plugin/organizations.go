package plugin

import (
	"context"

	"github.com/alternayte/auth-all/store"
)

// OrganizationContext carries the active organization of one request. The core
// puts it in the request context after it resolves the credential, so a plugin
// and a host handler read it with no store access.
type OrganizationContext struct {
	// Organization is the active organization of the session.
	Organization *store.Organization
	// Membership is the membership of that organization.
	Membership *store.Membership
	// Permissions holds the extra statements that the credential read
	// resolved, for a custom role and for every team role of the member.
	Permissions []string
}

// organizationContextKey is the private context key of the active
// organization.
type organizationContextKey struct{}

// WithOrganization returns a context that carries the active organization.
func WithOrganization(ctx context.Context, value OrganizationContext) context.Context {
	return context.WithValue(ctx, organizationContextKey{}, value)
}

// OrganizationFrom returns the active organization of the context. The second
// result is false when no organization is active, which is default deny.
func OrganizationFrom(ctx context.Context) (OrganizationContext, bool) {
	value, ok := ctx.Value(organizationContextKey{}).(OrganizationContext)
	if !ok || value.Organization == nil || value.Membership == nil {
		return OrganizationContext{}, false
	}
	return value, true
}
