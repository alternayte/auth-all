package authall

import (
	"context"
	"fmt"
	"net/http"

	"github.com/alternayte/auth-all/plugin"
)

// roleService reads the configured hierarchy. The roles plugin installs it.
type roleService struct{ auth *Auth }

// Names implements plugin.RoleService.
func (s *roleService) Names() []string {
	return append([]string(nil), s.auth.roleHierarchy...)
}

// Default implements plugin.RoleService.
func (s *roleService) Default() string { return s.auth.defaultRole }

// Rank implements plugin.RoleService. A role that the configuration does not
// name ranks below every role, so an unknown role gets -1. Default deny.
func (s *roleService) Rank(role string) int {
	if role == "" {
		role = s.auth.defaultRole
	}
	for i, name := range s.auth.roleHierarchy {
		if name == role {
			return i
		}
	}
	return -1
}

// AtLeast implements plugin.RoleService.
func (s *roleService) AtLeast(role, min string) bool {
	minRank := s.Rank(min)
	if minRank < 0 {
		// An unknown minimum can never pass. Default deny.
		return false
	}
	return s.Rank(role) >= minRank
}

// Roles implements plugin.RoleServices.
func (s *services) Roles() plugin.RoleService { return &roleService{auth: s.auth} }

// SetRoles implements plugin.RoleConfigurator.
func (s *services) SetRoles(names []string, defaultRole string) error {
	if len(names) == 0 {
		return fmt.Errorf("authall: the role hierarchy is empty")
	}
	seen := map[string]bool{}
	for _, name := range names {
		if name == "" {
			return fmt.Errorf("authall: a role name is empty")
		}
		if seen[name] {
			return fmt.Errorf("authall: the role %q is listed twice", name)
		}
		seen[name] = true
	}
	if !seen[defaultRole] {
		return fmt.Errorf("authall: the default role %q is not in the hierarchy", defaultRole)
	}
	if s.auth.roleHierarchy != nil {
		return fmt.Errorf("authall: a role hierarchy is already installed")
	}
	s.auth.roleHierarchy = append([]string(nil), names...)
	s.auth.defaultRole = defaultRole
	return nil
}

// Principals implements plugin.PrincipalServices.
func (s *services) Principals() plugin.PrincipalService { return &principalService{auth: s.auth} }

// principalService reads the principal of one request.
type principalService struct{ auth *Auth }

// Current implements plugin.PrincipalService.
func (s *principalService) Current(ctx context.Context) *plugin.Principal {
	p := PrincipalFrom(ctx)
	if p == nil {
		return nil
	}
	return &plugin.Principal{
		User:    p.User,
		Session: p.Session,
		APIKey:  p.APIKey,
		Role:    p.Role,
		Method:  p.Method,
	}
}

// Protect implements plugin.ProtectService.
func (s *services) Protect(next http.Handler) http.Handler { return s.auth.RequireAuth(next) }
