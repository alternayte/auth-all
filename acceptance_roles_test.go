package authall_test

import (
	"context"
	"net/http"
	"testing"

	authall "github.com/alternayte/auth-all"
	"github.com/alternayte/auth-all/apierr"
	"github.com/alternayte/auth-all/internal/testsupport"
	"github.com/alternayte/auth-all/plugins/roles"
	"github.com/alternayte/auth-all/store"
)

// testHierarchy is the role hierarchy of the role tests.
var testHierarchy = []string{"viewer", "operator", "editor", "admin"}

// rolesHarness returns a harness with the roles plugin and one route for each
// configured role.
func rolesHarness(t *testing.T) (*testsupport.Harness, *roles.Plugin) {
	t.Helper()
	r := roles.New(roles.Hierarchy(testHierarchy...), roles.Default("viewer"))
	h := emailPasswordHarness(t, authall.WithPlugins(r))
	for _, name := range testHierarchy {
		min := name
		h.Handle("/host/"+min, r.Require(min, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if got := roles.From(req.Context()); got == "" {
				t.Error("the handler got no effective role")
			}
			w.WriteHeader(http.StatusOK)
		})))
	}
	return h, r
}

// setRole writes the role of a user directly in the store.
func setRole(t *testing.T, s store.Store, address, role string) {
	t.Helper()
	ctx := context.Background()
	user, err := s.Users().GetByNormalizedEmail(ctx, address)
	if err != nil {
		t.Fatalf("read user: %v", err)
	}
	user.Role = role
	if err := s.Users().Update(ctx, user); err != nil {
		t.Fatalf("update user: %v", err)
	}
}

// TestSCNROLE001AnInvalidHierarchyFailsConstruction proves REQ-ROLE-001 and
// REQ-ROLE-002.
func TestSCNROLE001AnInvalidHierarchyFailsConstruction(t *testing.T) {
	s := testsupport.NewSQLite(t)
	bad := []*roles.Plugin{
		roles.New(),
		roles.New(roles.Hierarchy("viewer", "admin", "viewer")),
		roles.New(roles.Hierarchy("viewer", "admin"), roles.Default("root")),
		roles.New(roles.Hierarchy("viewer", "")),
	}
	for i, p := range bad {
		if _, err := authall.New(authall.WithStore(s), authall.WithPlugins(p)); err == nil {
			t.Fatalf("the hierarchy of case %d was accepted", i)
		}
	}
	if _, err := authall.New(authall.WithStore(s),
		authall.WithPlugins(roles.New(roles.Hierarchy(testHierarchy...), roles.Default("viewer")))); err != nil {
		t.Fatalf("a valid hierarchy failed: %v", err)
	}
}

// TestSCNROLE002ANewUserGetsTheDefaultRole proves REQ-ROLE-003 and
// REQ-ROLE-009.
func TestSCNROLE002ANewUserGetsTheDefaultRole(t *testing.T) {
	h, _ := rolesHarness(t)
	h.SignUp("viewer@example.com", testPassword)
	var body struct {
		User struct {
			Role string `json:"role"`
		} `json:"user"`
	}
	resp := h.Do(http.MethodGet, "/session", nil)
	if resp.Status != http.StatusOK {
		t.Fatalf("status %d: %s", resp.Status, string(resp.Body))
	}
	resp.Decode(t, &body)
	if body.User.Role != "viewer" {
		t.Fatalf("the session role is %q, want viewer", body.User.Role)
	}
}

// TestSCNROLE003ALowerRoleIsRefused proves REQ-ROLE-004 and REQ-ROLE-005.
func TestSCNROLE003ALowerRoleIsRefused(t *testing.T) {
	h, _ := rolesHarness(t)
	const address = "editor@example.com"
	h.SignUp(address, testPassword)

	// The user starts as a viewer, so the operator route refuses.
	resp := h.DoURL(http.MethodGet, h.BaseURL+"/host/operator", nil)
	if resp.Status != http.StatusForbidden {
		t.Fatalf("status %d: %s", resp.Status, string(resp.Body))
	}
	if code := errorCode(t, resp); code != string(apierr.CodeInsufficientRole) {
		t.Fatalf("the code is %q", code)
	}

	// An editor passes the operator route, because editor ranks above it.
	setRole(t, h.Store, address, "editor")
	resp = h.DoURL(http.MethodGet, h.BaseURL+"/host/operator", nil)
	if resp.Status != http.StatusOK {
		t.Fatalf("the editor got %d: %s", resp.Status, string(resp.Body))
	}
	// The same editor cannot reach the admin route.
	resp = h.DoURL(http.MethodGet, h.BaseURL+"/host/admin", nil)
	if resp.Status != http.StatusForbidden {
		t.Fatalf("the editor reached the admin route with %d", resp.Status)
	}
}

// TestSCNROLE004AnAnonymousRequestIsRefused proves REQ-ROLE-005.
func TestSCNROLE004AnAnonymousRequestIsRefused(t *testing.T) {
	h, _ := rolesHarness(t)
	resp := h.DoURL(http.MethodGet, h.BaseURL+"/host/operator", nil)
	if resp.Status != http.StatusUnauthorized {
		t.Fatalf("status %d: %s", resp.Status, string(resp.Body))
	}
	if code := errorCode(t, resp); code != string(apierr.CodeUnauthorized) {
		t.Fatalf("the code is %q", code)
	}
}

// TestSCNROLE005AnUnknownRoleRanksBelowEveryRole proves REQ-ROLE-006.
func TestSCNROLE005AnUnknownRoleRanksBelowEveryRole(t *testing.T) {
	h, _ := rolesHarness(t)
	const address = "ghost@example.com"
	h.SignUp(address, testPassword)
	setRole(t, h.Store, address, "ghost")
	for _, name := range testHierarchy {
		resp := h.DoURL(http.MethodGet, h.BaseURL+"/host/"+name, nil)
		if resp.Status != http.StatusForbidden {
			t.Fatalf("the route %s returned %d for the role ghost", name, resp.Status)
		}
	}
}

// TestSCNROLE006TheRoleHelpersAnswerEveryPair proves REQ-ROLE-007 and
// REQ-ROLE-008.
func TestSCNROLE006TheRoleHelpersAnswerEveryPair(t *testing.T) {
	h, r := rolesHarness(t)

	// An unknown minimum panics at construction, because such a route can
	// never pass.
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("Require accepted an unknown minimum role")
			}
		}()
		r.Require("root", http.NotFoundHandler())
	}()

	// AtLeast answers every pair of the hierarchy.
	var got [][]bool
	h.Handle("/host/pairs", r.Require("viewer", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		row := make([]bool, len(testHierarchy))
		for i, min := range testHierarchy {
			row[i] = roles.AtLeast(req.Context(), min)
		}
		got = append(got, row)
		w.WriteHeader(http.StatusOK)
	})))

	const address = "pairs@example.com"
	h.SignUp(address, testPassword)
	for _, role := range testHierarchy {
		setRole(t, h.Store, address, role)
		if resp := h.DoURL(http.MethodGet, h.BaseURL+"/host/pairs", nil); resp.Status != http.StatusOK {
			t.Fatalf("the role %s got %d", role, resp.Status)
		}
	}
	if len(got) != len(testHierarchy) {
		t.Fatalf("%d rows, want %d", len(got), len(testHierarchy))
	}
	for i := range testHierarchy {
		for j := range testHierarchy {
			want := i >= j
			if got[i][j] != want {
				t.Fatalf("AtLeast(%s, %s) = %v, want %v",
					testHierarchy[i], testHierarchy[j], got[i][j], want)
			}
		}
	}
	// A context with no role check answers false. Default deny.
	if roles.AtLeast(context.Background(), "viewer") {
		t.Fatal("AtLeast passed a context with no role")
	}
	if roles.From(context.Background()) != "" {
		t.Fatal("From returned a role for a context with no role")
	}
}
