package authall_test

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	authall "github.com/alternayte/auth-all"
	"github.com/alternayte/auth-all/apierr"
	"github.com/alternayte/auth-all/internal/testsupport"
	"github.com/alternayte/auth-all/plugins/admin"
	"github.com/alternayte/auth-all/plugins/roles"
	"github.com/alternayte/auth-all/ratelimit"
	"github.com/alternayte/auth-all/store"
)

// adminUser is the public shape of a user in an administrative response.
type adminUser struct {
	ID                 string  `json:"id"`
	Email              string  `json:"email"`
	Role               string  `json:"role"`
	DisabledAt         *string `json:"disabledAt"`
	MustChangePassword bool    `json:"mustChangePassword"`
}

// adminHarness returns a harness with the roles plugin, the admin plugin, one
// signed-in administrator, and one protected host route.
func adminHarness(t *testing.T) (*testsupport.Harness, *admin.Plugin) {
	t.Helper()
	r := roles.New(roles.Hierarchy(testHierarchy...), roles.Default("viewer"))
	adm := admin.New(admin.AdminRole("admin"))
	h := emailPasswordHarness(t, authall.WithPlugins(r, adm))
	h.Handle("/host/protected", h.Auth.RequireAuth(http.HandlerFunc(
		func(w http.ResponseWriter, req *http.Request) { w.WriteHeader(http.StatusNoContent) })))
	return h, adm
}

// signInAsAdmin creates one administrator and signs in as that user.
func signInAsAdmin(t *testing.T, h *testsupport.Harness) string {
	t.Helper()
	const address = "root@example.com"
	h.SignUp(address, testPassword)
	setRole(t, h.Store, address, "admin")
	user, err := h.Store.Users().GetByNormalizedEmail(context.Background(), address)
	if err != nil {
		t.Fatalf("read admin: %v", err)
	}
	return user.ID
}

// TestSCNADM001AViewerCannotListTheUsers proves REQ-ADM-001.
func TestSCNADM001AViewerCannotListTheUsers(t *testing.T) {
	h, _ := adminHarness(t)
	h.SignUp("viewer-list@example.com", testPassword)
	resp := h.Do(http.MethodGet, "/admin/users", nil)
	if resp.Status != http.StatusForbidden {
		t.Fatalf("status %d: %s", resp.Status, string(resp.Body))
	}
	if code := errorCode(t, resp); code != string(apierr.CodeInsufficientRole) {
		t.Fatalf("the code is %q", code)
	}
	// An anonymous request gets 401.
	h.ClearCookies()
	resp = h.Do(http.MethodGet, "/admin/users", nil)
	if resp.Status != http.StatusUnauthorized {
		t.Fatalf("the anonymous request got %d", resp.Status)
	}
}

// TestSCNADM003AnAdminCreatesAUserWithATemporaryPassword proves REQ-ADM-003 to
// REQ-ADM-006.
func TestSCNADM003AnAdminCreatesAUserWithATemporaryPassword(t *testing.T) {
	h, _ := adminHarness(t)
	signInAsAdmin(t, h)

	resp := h.Do(http.MethodPost, "/admin/users", map[string]any{
		"email": "new.person@example.com", "role": "operator",
	})
	if resp.Status != http.StatusCreated {
		t.Fatalf("status %d: %s", resp.Status, string(resp.Body))
	}
	var created struct {
		User              adminUser `json:"user"`
		TemporaryPassword string    `json:"temporaryPassword"`
	}
	resp.Decode(t, &created)
	if len(created.TemporaryPassword) != 20 {
		t.Fatalf("the temporary password has %d characters", len(created.TemporaryPassword))
	}
	if created.User.Role != "operator" || !created.User.MustChangePassword {
		t.Fatalf("unexpected user: %+v", created.User)
	}

	// The new user signs in and reaches no protected route.
	h.ClearCookies()
	resp, _ = h.SignIn("new.person@example.com", created.TemporaryPassword)
	if resp.Status != http.StatusOK {
		t.Fatalf("the sign-in returned %d: %s", resp.Status, string(resp.Body))
	}
	out := h.DoURL(http.MethodGet, h.BaseURL+"/host/protected", nil)
	if out.Status != http.StatusForbidden {
		t.Fatalf("the protected route returned %d", out.Status)
	}
	if code := errorCode(t, out); code != string(apierr.CodePasswordChangeRequired) {
		t.Fatalf("the code is %q", code)
	}
	// The session route and the sign-out route stay open.
	if got := h.Do(http.MethodGet, "/session", nil); got.Status != http.StatusOK {
		t.Fatalf("the session route returned %d", got.Status)
	}
}

// TestSCNADM004ThePasswordChangeClearsTheFlag proves REQ-ADM-007.
func TestSCNADM004ThePasswordChangeClearsTheFlag(t *testing.T) {
	h, _ := adminHarness(t)
	signInAsAdmin(t, h)
	resp := h.Do(http.MethodPost, "/admin/users", map[string]any{"email": "change@example.com"})
	var created struct {
		TemporaryPassword string `json:"temporaryPassword"`
	}
	resp.Decode(t, &created)

	h.ClearCookies()
	h.SignIn("change@example.com", created.TemporaryPassword)
	const fresh = "a-brand-new-password"
	got := h.Do(http.MethodPost, "/password/change", map[string]any{
		"currentPassword": created.TemporaryPassword, "newPassword": fresh,
	})
	if got.Status != http.StatusOK {
		t.Fatalf("the change returned %d: %s", got.Status, string(got.Body))
	}
	h.ClearCookies()
	h.SignIn("change@example.com", fresh)
	out := h.DoURL(http.MethodGet, h.BaseURL+"/host/protected", nil)
	if out.Status != http.StatusNoContent {
		t.Fatalf("the protected route returned %d: %s", out.Status, string(out.Body))
	}
}

// TestSCNADM005AnUnknownRoleIsRefused proves REQ-ADM-008.
func TestSCNADM005AnUnknownRoleIsRefused(t *testing.T) {
	h, _ := adminHarness(t)
	signInAsAdmin(t, h)
	target := createUser(t, h, "role-target@example.com")
	resp := h.Do(http.MethodPost, "/admin/users/"+target+"/role", map[string]any{"role": "ghost"})
	if resp.Status != http.StatusBadRequest {
		t.Fatalf("status %d: %s", resp.Status, string(resp.Body))
	}
	if code := errorCode(t, resp); code != string(apierr.CodeRoleUnknown) {
		t.Fatalf("the code is %q", code)
	}
	resp = h.Do(http.MethodPost, "/admin/users/"+target+"/role", map[string]any{"role": "editor"})
	if resp.Status != http.StatusOK {
		t.Fatalf("the known role returned %d: %s", resp.Status, string(resp.Body))
	}
	var body struct {
		User adminUser `json:"user"`
	}
	resp.Decode(t, &body)
	if body.User.Role != "editor" {
		t.Fatalf("the role is %q", body.User.Role)
	}
}

// createUser creates one user through the administrative route and returns the
// identifier.
func createUser(t *testing.T, h *testsupport.Harness, address string) string {
	t.Helper()
	resp := h.Do(http.MethodPost, "/admin/users", map[string]any{"email": address})
	if resp.Status != http.StatusCreated {
		t.Fatalf("create %s: %d %s", address, resp.Status, string(resp.Body))
	}
	var created struct {
		User adminUser `json:"user"`
	}
	resp.Decode(t, &created)
	return created.User.ID
}

// TestSCNADM006DisableEndsEverySession proves REQ-ADM-009 and REQ-ADM-011.
func TestSCNADM006DisableEndsEverySession(t *testing.T) {
	h, _ := adminHarness(t)
	signInAsAdmin(t, h)
	const address = "disabled@example.com"
	target := createUser(t, h, address)
	// The user takes a real password, so the sign-in test is meaningful.
	resetPassword(t, h, target, testPassword)

	adminCookies := h.SaveCookies()
	h.ClearCookies()
	h.SignIn(address, testPassword)
	userCookies := h.SaveCookies()

	h.RestoreCookies(adminCookies)
	resp := h.Do(http.MethodPost, "/admin/users/"+target+"/disable", nil)
	if resp.Status != http.StatusOK {
		t.Fatalf("disable returned %d: %s", resp.Status, string(resp.Body))
	}

	// The session of the user is gone.
	h.RestoreCookies(userCookies)
	out := h.DoURL(http.MethodGet, h.BaseURL+"/host/protected", nil)
	if out.Status != http.StatusUnauthorized {
		t.Fatalf("the session of the disabled user returned %d", out.Status)
	}

	// A correct password reports the disabled account. A wrong password
	// reports invalid credentials, so the response tells nothing to a caller
	// without the password.
	h.ClearCookies()
	resp, _ = h.SignIn(address, testPassword)
	if resp.Status != http.StatusForbidden {
		t.Fatalf("the sign-in returned %d: %s", resp.Status, string(resp.Body))
	}
	if code := errorCode(t, resp); code != string(apierr.CodeUserDisabled) {
		t.Fatalf("the code is %q", code)
	}
	resp, _ = h.SignIn(address, "another-wrong-password")
	if code := errorCode(t, resp); code != string(apierr.CodeInvalidCredentials) {
		t.Fatalf("the wrong password gave %q", code)
	}
}

// resetPassword sets a known password for one user through the administrative
// route.
func resetPassword(t *testing.T, h *testsupport.Harness, id, password string) {
	t.Helper()
	resp := h.Do(http.MethodPost, "/admin/users/"+id+"/password", map[string]any{
		"password": password, "temporary": false,
	})
	if resp.Status != http.StatusOK {
		t.Fatalf("reset: %d %s", resp.Status, string(resp.Body))
	}
}

// TestSCNADM007EnableRestoresTheSignIn proves REQ-ADM-010.
func TestSCNADM007EnableRestoresTheSignIn(t *testing.T) {
	h, _ := adminHarness(t)
	signInAsAdmin(t, h)
	const address = "enabled@example.com"
	target := createUser(t, h, address)
	resetPassword(t, h, target, testPassword)
	if resp := h.Do(http.MethodPost, "/admin/users/"+target+"/disable", nil); resp.Status != http.StatusOK {
		t.Fatalf("disable: %d", resp.Status)
	}
	if resp := h.Do(http.MethodPost, "/admin/users/"+target+"/enable", nil); resp.Status != http.StatusOK {
		t.Fatalf("enable: %d", resp.Status)
	}
	h.ClearCookies()
	resp, _ := h.SignIn(address, testPassword)
	if resp.Status != http.StatusOK {
		t.Fatalf("the sign-in returned %d: %s", resp.Status, string(resp.Body))
	}
}

// TestSCNADM008AResetEndsEverySession proves REQ-ADM-012 and REQ-SES-004.
func TestSCNADM008AResetEndsEverySession(t *testing.T) {
	h, _ := adminHarness(t)
	signInAsAdmin(t, h)
	const address = "reset@example.com"
	target := createUser(t, h, address)
	resetPassword(t, h, target, testPassword)

	adminCookies := h.SaveCookies()
	h.ClearCookies()
	h.SignIn(address, testPassword)
	userCookies := h.SaveCookies()

	h.RestoreCookies(adminCookies)
	resp := h.Do(http.MethodPost, "/admin/users/"+target+"/password", nil)
	if resp.Status != http.StatusOK {
		t.Fatalf("reset returned %d: %s", resp.Status, string(resp.Body))
	}
	var body struct {
		TemporaryPassword string `json:"temporaryPassword"`
	}
	resp.Decode(t, &body)
	if len(body.TemporaryPassword) != 20 {
		t.Fatalf("the temporary password has %d characters", len(body.TemporaryPassword))
	}

	h.RestoreCookies(userCookies)
	out := h.Do(http.MethodGet, "/sessions", nil)
	if out.Status != http.StatusUnauthorized {
		t.Fatalf("the old session returned %d", out.Status)
	}
	sessions, err := h.Store.Sessions().ListByUser(context.Background(), target)
	if err != nil {
		t.Fatalf("list sessions: %v", err)
	}
	if len(sessions) != 0 {
		t.Fatalf("%d sessions remain", len(sessions))
	}
}

// TestSCNADM009TheLastAdminKeepsTheRole proves REQ-ADM-013.
func TestSCNADM009TheLastAdminKeepsTheRole(t *testing.T) {
	h, _ := adminHarness(t)
	id := signInAsAdmin(t, h)

	resp := h.Do(http.MethodPost, "/admin/users/"+id+"/role", map[string]any{"role": "viewer"})
	if resp.Status != http.StatusConflict {
		t.Fatalf("the demotion returned %d: %s", resp.Status, string(resp.Body))
	}
	if code := errorCode(t, resp); code != string(apierr.CodeLastAdmin) {
		t.Fatalf("the code is %q", code)
	}

	// A second administrator makes the demotion possible.
	other := createUser(t, h, "second-admin@example.com")
	if got := h.Do(http.MethodPost, "/admin/users/"+other+"/role",
		map[string]any{"role": "admin"}); got.Status != http.StatusOK {
		t.Fatalf("promote: %d %s", got.Status, string(got.Body))
	}
	if got := h.Do(http.MethodPost, "/admin/users/"+id+"/role",
		map[string]any{"role": "viewer"}); got.Status != http.StatusOK {
		t.Fatalf("the demotion returned %d: %s", got.Status, string(got.Body))
	}
}

// TestSCNADM009TheLastAdminStaysEnabled proves REQ-ADM-013 for the disable
// route.
func TestSCNADM009TheLastAdminStaysEnabled(t *testing.T) {
	h, _ := adminHarness(t)
	signInAsAdmin(t, h)
	// A second administrator disables the first one, and then no other
	// administrator remains.
	other := createUser(t, h, "other-admin@example.com")
	resetPassword(t, h, other, testPassword)
	if got := h.Do(http.MethodPost, "/admin/users/"+other+"/role",
		map[string]any{"role": "admin"}); got.Status != http.StatusOK {
		t.Fatalf("promote: %d", got.Status)
	}
	firstID := userID(t, h, "root@example.com")

	// The second administrator signs in and disables the first one.
	h.ClearCookies()
	h.SignIn("other-admin@example.com", testPassword)
	if got := h.Do(http.MethodPost, "/admin/users/"+firstID+"/disable", nil); got.Status != http.StatusOK {
		t.Fatalf("the disable returned %d: %s", got.Status, string(got.Body))
	}

	// Only one administrator remains, so the demotion of that account fails.
	otherID := userID(t, h, "other-admin@example.com")
	resp := h.Do(http.MethodPost, "/admin/users/"+otherID+"/role", map[string]any{"role": "viewer"})
	if resp.Status != http.StatusConflict {
		t.Fatalf("the demotion returned %d: %s", resp.Status, string(resp.Body))
	}
	if code := errorCode(t, resp); code != string(apierr.CodeLastAdmin) {
		t.Fatalf("the code is %q", code)
	}
	// The first administrator comes back.
	if got := h.Do(http.MethodPost, "/admin/users/"+firstID+"/enable", nil); got.Status != http.StatusOK {
		t.Fatalf("enable: %d %s", got.Status, string(got.Body))
	}
}

// userID returns the identifier of one address.
func userID(t *testing.T, h *testsupport.Harness, address string) string {
	t.Helper()
	user, err := h.Store.Users().GetByNormalizedEmail(context.Background(), address)
	if err != nil {
		t.Fatalf("read %s: %v", address, err)
	}
	return user.ID
}

// TestSCNADM011AnAdminCannotDisableTheOwnAccount proves REQ-ADM-015.
func TestSCNADM011AnAdminCannotDisableTheOwnAccount(t *testing.T) {
	h, _ := adminHarness(t)
	id := signInAsAdmin(t, h)
	// A second administrator exists, so the last-admin guard does not answer
	// first.
	other := createUser(t, h, "spare-admin@example.com")
	if got := h.Do(http.MethodPost, "/admin/users/"+other+"/role",
		map[string]any{"role": "admin"}); got.Status != http.StatusOK {
		t.Fatalf("promote: %d", got.Status)
	}
	resp := h.Do(http.MethodPost, "/admin/users/"+id+"/disable", nil)
	if resp.Status != http.StatusForbidden {
		t.Fatalf("status %d: %s", resp.Status, string(resp.Body))
	}
	if code := errorCode(t, resp); code != string(apierr.CodeForbidden) {
		t.Fatalf("the code is %q", code)
	}
}

// TestSCNADM012ACrossSitePostIsRefused proves REQ-ADM-016.
func TestSCNADM012ACrossSitePostIsRefused(t *testing.T) {
	h, _ := adminHarness(t)
	signInAsAdmin(t, h)
	target := createUser(t, h, "csrf-target@example.com")
	resp := h.Do(http.MethodPost, "/admin/users/"+target+"/disable", nil, crossSite)
	if resp.Status != http.StatusForbidden {
		t.Fatalf("status %d: %s", resp.Status, string(resp.Body))
	}
	if code := errorCode(t, resp); code != string(apierr.CodeOriginNotAllowed) {
		t.Fatalf("the code is %q", code)
	}
}

// TestSCNADM002ThePagesCoverEveryUser proves REQ-ADM-002. It runs on
// PostgreSQL and on SQLite.
func TestSCNADM002ThePagesCoverEveryUser(t *testing.T) {
	for _, c := range []struct {
		name  string
		build func(*testing.T) store.Store
	}{
		{"sqlite", testsupport.NewSQLite},
		{"postgres", testsupport.NewPostgres},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := c.build(t)
			admins, ok := s.(store.UserAdminStore)
			if !ok {
				t.Fatal("the store lists no users")
			}
			ctx := context.Background()
			const total = 450
			for i := range total {
				user := testsupport.NewUser(fmt.Sprintf("user%04d@example.com", i))
				if i%3 == 0 {
					user.Role = "operator"
				}
				if i%5 == 0 {
					now := user.CreatedAt
					user.DisabledAt = &now
				}
				if err := s.Users().Create(ctx, user); err != nil {
					t.Fatalf("create %d: %v", i, err)
				}
			}
			seen := map[string]bool{}
			cursor := ""
			pages := 0
			for {
				users, next, err := admins.ListUsers(ctx, store.UserListFilter{Limit: 200, Cursor: cursor})
				if err != nil {
					t.Fatalf("list: %v", err)
				}
				for _, u := range users {
					if seen[u.ID] {
						t.Fatalf("the user %s repeats", u.Email)
					}
					seen[u.ID] = true
				}
				pages++
				if next == "" {
					break
				}
				cursor = next
				if pages > 10 {
					t.Fatal("the list does not end")
				}
			}
			if len(seen) != total {
				t.Fatalf("the pages covered %d users, want %d", len(seen), total)
			}

			// Each filter selects the expected users.
			role := "operator"
			byRole, _, err := admins.ListUsers(ctx, store.UserListFilter{Role: &role, Limit: 200})
			if err != nil {
				t.Fatalf("filter role: %v", err)
			}
			for _, u := range byRole {
				if u.Role != role {
					t.Fatalf("the role filter returned %q", u.Role)
				}
			}
			disabled := true
			byState, _, err := admins.ListUsers(ctx, store.UserListFilter{Disabled: &disabled, Limit: 200})
			if err != nil {
				t.Fatalf("filter disabled: %v", err)
			}
			for _, u := range byState {
				if u.DisabledAt == nil {
					t.Fatal("the disabled filter returned an enabled user")
				}
			}
			byPrefix, _, err := admins.ListUsers(ctx, store.UserListFilter{EmailPrefix: "user000", Limit: 200})
			if err != nil {
				t.Fatalf("filter prefix: %v", err)
			}
			if len(byPrefix) != 10 {
				t.Fatalf("the prefix filter returned %d users, want 10", len(byPrefix))
			}
		})
	}
}

// TestSCNADM010TheGuardHoldsUnderConcurrency proves REQ-ADM-014. Two parallel
// demotions of the last two administrators leave at least one administrator.
func TestSCNADM010TheGuardHoldsUnderConcurrency(t *testing.T) {
	for _, c := range []struct {
		name  string
		build func(*testing.T) store.Store
	}{
		{"sqlite", testsupport.NewSQLite},
		{"postgres", testsupport.NewPostgres},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := c.build(t)
			adm := admin.New(admin.AdminRole("admin"))
			auth, err := authall.New(
				authall.WithStore(s),
				authall.WithBaseURL("https://app.example.com"),
				authall.WithEmailPassword(),
				authall.WithRateLimiter(ratelimit.NewMemory(1000, time.Minute)),
				authall.WithPlugins(roles.New(roles.Hierarchy(testHierarchy...), roles.Default("viewer")), adm),
			)
			if err != nil {
				t.Fatalf("new: %v", err)
			}
			if _, err := auth.Migrate(context.Background()); err != nil {
				t.Fatalf("migrate: %v", err)
			}
			ctx := context.Background()
			const rounds = 100
			for round := range rounds {
				first := newAdmin(t, s, fmt.Sprintf("a%03d@example.com", round))
				second := newAdmin(t, s, fmt.Sprintf("b%03d@example.com", round))
				var wg sync.WaitGroup
				for _, id := range []string{first, second} {
					wg.Add(1)
					go func() {
						defer wg.Done()
						_, _ = adm.SetRole(ctx, id, "viewer")
					}()
				}
				wg.Wait()
				left := 0
				for _, id := range []string{first, second} {
					user, err := s.Users().GetByID(ctx, id)
					if err != nil {
						t.Fatalf("read user: %v", err)
					}
					if user.Role == "admin" {
						left++
					}
				}
				if left == 0 {
					t.Fatalf("round %d removed every administrator", round)
				}
				// The round ends with no administrator of this pair, so the
				// next round starts clean.
				for _, id := range []string{first, second} {
					if err := s.Users().Delete(ctx, id); err != nil {
						t.Fatalf("delete user: %v", err)
					}
				}
			}
		})
	}
}

// newAdmin inserts one enabled administrator and returns the identifier.
func newAdmin(t *testing.T, s store.Store, address string) string {
	t.Helper()
	user := testsupport.NewUser(address)
	user.Role = "admin"
	if err := s.Users().Create(context.Background(), user); err != nil {
		t.Fatalf("create %s: %v", address, err)
	}
	return user.ID
}
