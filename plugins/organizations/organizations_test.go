package organizations_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alternayte/auth-all/apierr"
	"github.com/alternayte/auth-all/plugins/organizations"
)

// declared returns a plugin with the roles of the design document.
func declared() *organizations.Plugin {
	return organizations.New(
		organizations.Roles(
			organizations.Role("owner", "*"),
			organizations.Role("admin", "member:*", "project:*", "billing:read"),
			organizations.Role("member", "project:read", "project:write"),
			organizations.Role("viewer", "project:read"),
		),
		organizations.DefaultRole("member"),
		organizations.OwnerRole("owner"),
	)
}

// TestSCNPRM006RequirePanicsForAnUnheldPermission proves SCN-PRM-006 and
// REQ-PRM-008. A route that no declared role can reach fails at construction.
func TestSCNPRM006RequirePanicsForAnUnheldPermission(t *testing.T) {
	t.Parallel()

	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	tests := []struct {
		name      string
		statement string
		want      string
	}{
		{"no role holds it", "nobody:holds", "no declared role holds"},
		{"an invalid statement", "nobody holds", "is invalid"},
		{"a wildcard above every role", "billing:*", "no declared role holds"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			defer func() {
				recovered := recover()
				if recovered == nil {
					t.Fatalf("Require(%q) must panic", tc.statement)
				}
				message, ok := recovered.(string)
				if !ok || !strings.Contains(message, tc.want) {
					t.Fatalf("the panic must name the fault, got %v", recovered)
				}
			}()
			// The owner role holds "*", so a declaration without it proves the
			// guard. The plugin below declares no owner.
			narrow := organizations.New(organizations.Roles(
				organizations.Role("admin", "member:*", "project:*", "billing:read"),
				organizations.Role("viewer", "project:read"),
			))
			narrow.Require(tc.statement, next)
		})
	}
}

// TestSCNPRM006RequireAcceptsADeclaredPermission proves that the guard passes
// a statement that a declared role holds.
func TestSCNPRM006RequireAcceptsADeclaredPermission(t *testing.T) {
	t.Parallel()

	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	for _, statement := range []string{"project:write", "project:*", "billing:read", "*", "member:invite"} {
		if handler := declared().Require(statement, next); handler == nil {
			t.Fatalf("Require(%q) must return a handler", statement)
		}
	}
}

// TestRequireIsDefaultDeny proves HC-08 and REQ-PRM-007. A request with no
// active organization never reaches the handler.
func TestRequireIsDefaultDeny(t *testing.T) {
	t.Parallel()

	reached := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached = true })
	plugin := declared()
	if err := plugin.Validate(); err != nil {
		t.Fatalf("Validate() = %v", err)
	}
	handler := plugin.Require("project:write", next)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/projects", nil))
	if reached {
		t.Fatal("the handler must not run without an active organization")
	}
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusForbidden)
	}
	if !strings.Contains(recorder.Body.String(), string(apierr.CodeNoActiveOrganization)) {
		t.Fatalf("body = %q, want %s", recorder.Body.String(), apierr.CodeNoActiveOrganization)
	}
}

// TestRequireRefusesAMemberWithoutThePermission proves REQ-PRM-005 and the
// PERMISSION_DENIED code of REQ-PRM-006 at the handler level.
func TestRequireRefusesAMemberWithoutThePermission(t *testing.T) {
	t.Parallel()

	reached := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached = true })
	handler := declared().Require("project:write", next)

	request := httptest.NewRequest(http.MethodPost, "/projects", nil)
	viewer := organizations.WithPermissions(request.Context(), "project:read")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request.WithContext(viewer))
	if reached {
		t.Fatal("a viewer must not reach the write handler")
	}
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusForbidden)
	}
	if !strings.Contains(recorder.Body.String(), string(apierr.CodePermissionDenied)) {
		t.Fatalf("body = %q, want %s", recorder.Body.String(), apierr.CodePermissionDenied)
	}

	request = httptest.NewRequest(http.MethodPost, "/projects", nil)
	admin := organizations.WithPermissions(request.Context(), "project:*")
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request.WithContext(admin))
	if !reached {
		t.Fatal("an admin must reach the write handler")
	}
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
}

// TestCanIsDefaultDeny proves REQ-PRM-004 and REQ-PRM-003 for the handler API.
func TestCanIsDefaultDeny(t *testing.T) {
	t.Parallel()

	plugin := declared()
	if plugin.Can(context.Background(), "project:read") {
		t.Fatal("a context with no organization holds no permission")
	}
	ctx := organizations.WithPermissions(context.Background(), "project:read")
	if !plugin.Can(ctx, "project:read") {
		t.Fatal("Can must report the held permission")
	}
	for _, ask := range []string{"project:write", "unknown:action", "project read", ""} {
		if plugin.Can(ctx, ask) {
			t.Fatalf("Can(%q) must be false", ask)
		}
	}
}

// TestTheDeclarationGuards proves the construction rules of the roles.
func TestTheDeclarationGuards(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		plugin *organizations.Plugin
		want   string
	}{
		{"no role", organizations.New(), "at least one role"},
		{
			"a duplicate role",
			organizations.New(organizations.Roles(
				organizations.Role("admin", "*"),
				organizations.Role("admin", "project:read"),
			)),
			"declared twice",
		},
		{
			"an unknown default role",
			organizations.New(organizations.Roles(organizations.Role("admin", "*")), organizations.DefaultRole("ghost")),
			"default role",
		},
		{
			"an unknown owner role",
			organizations.New(organizations.Roles(organizations.Role("admin", "*")), organizations.OwnerRole("ghost")),
			"owner role",
		},
		{
			"a negative limit",
			organizations.New(organizations.Roles(organizations.Role("admin", "*")), organizations.MaxMembers(-1)),
			"negative",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.plugin.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate() = %v, want an error that names %q", err, tc.want)
			}
		})
	}
}

// TestTheDeclarationDefaults proves the resolved default role and owner role.
func TestTheDeclarationDefaults(t *testing.T) {
	t.Parallel()

	plugin := organizations.New(organizations.Roles(
		organizations.Role("owner", "*"),
		organizations.Role("viewer", "project:read"),
	))
	if err := plugin.Validate(); err != nil {
		t.Fatalf("Validate() = %v", err)
	}
	if got := plugin.OwnerRoleName(); got != "owner" {
		t.Fatalf("the owner role = %q, want the first declared role", got)
	}
	if got := plugin.DefaultRoleName(); got != "viewer" {
		t.Fatalf("the default role = %q, want the last declared role", got)
	}
	if got := plugin.ID(); got != organizations.ID {
		t.Fatalf("ID() = %q", got)
	}
	names := plugin.RoleNames()
	if len(names) != 2 || names[0] != "owner" || names[1] != "viewer" {
		t.Fatalf("RoleNames() = %v", names)
	}
	set, ok := plugin.PermissionsOf("viewer")
	if !ok || !set.Allows("project:read") {
		t.Fatalf("PermissionsOf(viewer) = %v, %v", set.Statements(), ok)
	}
	if _, ok := plugin.PermissionsOf("ghost"); ok {
		t.Fatal("PermissionsOf must refuse an undeclared role")
	}
}

// TestRoleNeedsAName proves that an empty role name fails at construction.
func TestRoleNeedsAName(t *testing.T) {
	t.Parallel()

	defer func() {
		if recover() == nil {
			t.Fatal("Role must panic without a name")
		}
	}()
	organizations.Role("", "*")
}
