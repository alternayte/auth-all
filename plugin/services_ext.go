package plugin

import (
	"context"
	"net/http"
)

// The interfaces in this file are optional. A plugin asks the Services value
// for one with a type assertion. A new method on Services would break every
// third-party implementation, so every later capability arrives here.
//
//	svc, ok := reg.Services().(plugin.RoleServices)
//	if !ok {
//	    return errors.New("this Auth-All version has no role service")
//	}

// RoleService reads the configured role hierarchy.
type RoleService interface {
	// Names returns the roles from the lowest to the highest.
	Names() []string
	// Default returns the role of a user whose role is empty.
	Default() string
	// Rank returns the position of a role. A role that the configuration does
	// not name ranks below every role, so its rank is negative.
	Rank(role string) int
	// AtLeast reports whether role ranks equal to or above min.
	AtLeast(role, min string) bool
}

// RoleServices exposes the role service.
type RoleServices interface {
	Roles() RoleService
}

// RoleConfigurator installs a role hierarchy in the core. The roles plugin
// calls it during registration.
type RoleConfigurator interface {
	// SetRoles installs the ordered hierarchy and the default role.
	SetRoles(names []string, defaultRole string) error
}

// PrincipalService reads the principal of one request.
type PrincipalService interface {
	// Current returns the principal of the request context. It returns nil
	// when no middleware authenticated the request.
	Current(ctx context.Context) *Principal
}

// PrincipalServices exposes the principal service.
type PrincipalServices interface {
	Principals() PrincipalService
}

// ProtectService wraps a handler with the Auth-All authentication middleware.
// The wrapped handler runs the origin check of the host routes.
type ProtectService interface {
	// Protect refuses a request with no principal, and it refuses an unsafe
	// cross-site request that a cookie authenticated.
	Protect(next http.Handler) http.Handler
}
