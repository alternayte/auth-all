package authall_test

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	authall "github.com/alternayte/auth-all"
	"github.com/alternayte/auth-all/apierr"
	"github.com/alternayte/auth-all/events"
	"github.com/alternayte/auth-all/internal/testsupport"
	"github.com/alternayte/auth-all/plugins/admin"
	"github.com/alternayte/auth-all/plugins/roles"
	"github.com/alternayte/auth-all/ratelimit"
	"github.com/alternayte/auth-all/store"
)

// recorder collects the events of one instance.
type recorder struct {
	mu     sync.Mutex
	events []events.Event
}

// HandleEvent implements events.Handler.
func (r *recorder) HandleEvent(_ context.Context, e events.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

// All returns a copy of the collected events.
func (r *recorder) All() []events.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]events.Event(nil), r.events...)
}

// operatorInstance returns an Auth-All instance with the roles plugin and the
// admin plugin over one store.
func operatorInstance(t *testing.T, s store.Store, opts ...authall.Option) (*authall.Auth, *admin.Plugin) {
	t.Helper()
	adm := admin.New(admin.AdminRole("admin"))
	base := []authall.Option{
		authall.WithStore(s),
		authall.WithBaseURL("https://app.example.com"),
		authall.WithEmailPassword(),
		authall.WithRateLimiter(ratelimit.NewMemory(1000, time.Minute)),
		authall.WithPlugins(roles.New(roles.Hierarchy(testHierarchy...), roles.Default("viewer")), adm),
	}
	auth, err := authall.New(append(base, opts...)...)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if _, err := auth.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return auth, adm
}

// opsStores names the databases of every operator scenario.
var opsStores = []struct {
	name  string
	build func(*testing.T) store.Store
}{
	{"sqlite", testsupport.NewSQLite},
	{"postgres", testsupport.NewPostgres},
}

// TestSCNOPS001BootstrapCreatesOneAdmin proves REQ-OPS-001 and REQ-OPS-002.
func TestSCNOPS001BootstrapCreatesOneAdmin(t *testing.T) {
	for _, c := range opsStores {
		t.Run(c.name, func(t *testing.T) {
			s := c.build(t)
			_, adm := operatorInstance(t, s)
			ctx := context.Background()
			created, err := adm.Bootstrap(ctx, admin.Credentials{
				Email: "root@example.com", Password: testPassword,
			})
			if err != nil || !created {
				t.Fatalf("the first bootstrap returned %v %v", created, err)
			}
			first := userOf(t, s, "root@example.com")
			if first.Role != "admin" {
				t.Fatalf("the role is %q", first.Role)
			}

			// A second call changes nothing.
			again, err := adm.Bootstrap(ctx, admin.Credentials{
				Email: "other@example.com", Password: testPassword,
			})
			if err != nil {
				t.Fatalf("the second bootstrap failed: %v", err)
			}
			if again {
				t.Fatal("the second bootstrap created a user")
			}
			users, _, err := s.(store.UserAdminStore).ListUsers(ctx, store.UserListFilter{Limit: 10})
			if err != nil {
				t.Fatalf("list: %v", err)
			}
			if len(users) != 1 {
				t.Fatalf("%d users exist, want 1", len(users))
			}
			second := userOf(t, s, "root@example.com")
			if !second.UpdatedAt.Equal(first.UpdatedAt) {
				t.Fatal("the second bootstrap changed the user")
			}
		})
	}
}

// userOf returns one user by address.
func userOf(t *testing.T, s store.Store, address string) *store.User {
	t.Helper()
	user, err := s.Users().GetByNormalizedEmail(context.Background(), address)
	if err != nil {
		t.Fatalf("read %s: %v", address, err)
	}
	return user
}

// TestSCNOPS002ParallelBootstrapCreatesOneUser proves REQ-OPS-003.
func TestSCNOPS002ParallelBootstrapCreatesOneUser(t *testing.T) {
	for _, c := range opsStores {
		t.Run(c.name, func(t *testing.T) {
			s := c.build(t)
			ctx := context.Background()
			// Ten instances share one database, as ten replicas do.
			plugins := make([]*admin.Plugin, 10)
			for i := range plugins {
				_, plugins[i] = operatorInstance(t, s)
			}
			var wg sync.WaitGroup
			results := make([]bool, len(plugins))
			for i, adm := range plugins {
				wg.Add(1)
				go func() {
					defer wg.Done()
					created, err := adm.Bootstrap(ctx, admin.Credentials{
						Email: "root@example.com", Password: testPassword,
					})
					if err != nil {
						return
					}
					results[i] = created
				}()
			}
			wg.Wait()
			users, _, err := s.(store.UserAdminStore).ListUsers(ctx, store.UserListFilter{Limit: 20})
			if err != nil {
				t.Fatalf("list: %v", err)
			}
			if len(users) != 1 {
				t.Fatalf("%d users exist, want 1", len(users))
			}
			winners := 0
			for _, created := range results {
				if created {
					winners++
				}
			}
			if winners != 1 {
				t.Fatalf("%d calls reported a creation, want 1", winners)
			}
		})
	}
}

// TestSCNOPS003AWeakPasswordFailsTheBootstrap proves REQ-OPS-004.
func TestSCNOPS003AWeakPasswordFailsTheBootstrap(t *testing.T) {
	s := testsupport.NewSQLite(t)
	_, adm := operatorInstance(t, s)
	created, err := adm.Bootstrap(context.Background(), admin.Credentials{
		Email: "root@example.com", Password: "short",
	})
	if created {
		t.Fatal("a weak password created an administrator")
	}
	if !errors.Is(err, apierr.ErrWeakPassword) {
		t.Fatalf("the error is %v", err)
	}
	users, _, listErr := s.(store.UserAdminStore).ListUsers(context.Background(), store.UserListFilter{Limit: 10})
	if listErr != nil {
		t.Fatalf("list: %v", listErr)
	}
	if len(users) != 0 {
		t.Fatalf("%d users exist, want 0", len(users))
	}
}

// TestSCNOPS004TheBootstrapUserKeepsThePassword proves REQ-OPS-005.
func TestSCNOPS004TheBootstrapUserKeepsThePassword(t *testing.T) {
	for _, c := range opsStores {
		t.Run(c.name, func(t *testing.T) {
			s := c.build(t)
			_, adm := operatorInstance(t, s)
			if _, err := adm.Bootstrap(context.Background(), admin.Credentials{
				Email: "root@example.com", Password: testPassword,
			}); err != nil {
				t.Fatalf("bootstrap: %v", err)
			}
			if userOf(t, s, "root@example.com").MustChangePassword {
				t.Fatal("the bootstrap user must change the password")
			}

			// A host that asks for it gets the flag.
			other := c.build(t)
			_, adm2 := operatorInstance(t, other)
			if _, err := adm2.Bootstrap(context.Background(), admin.Credentials{
				Email: "root@example.com", Password: testPassword, TemporaryPassword: true,
			}); err != nil {
				t.Fatalf("bootstrap: %v", err)
			}
			if !userOf(t, other, "root@example.com").MustChangePassword {
				t.Fatal("the requested flag is absent")
			}
		})
	}
}

// TestSCNOPS005TheOperatorMethodsEmitSystemEvents proves REQ-OPS-006 and
// REQ-OPS-007.
func TestSCNOPS005TheOperatorMethodsEmitSystemEvents(t *testing.T) {
	for _, c := range opsStores {
		t.Run(c.name, func(t *testing.T) {
			s := c.build(t)
			rec := &recorder{}
			_, adm := operatorInstance(t, s, authall.WithEventHandler(rec))
			ctx := context.Background()

			user, password, err := adm.CreateUser(ctx, admin.CreateUserInput{
				Email: "operator@example.com", Role: "operator", TemporaryPassword: true,
			})
			if err != nil {
				t.Fatalf("create: %v", err)
			}
			if len(password) != 20 {
				t.Fatalf("the password has %d characters", len(password))
			}
			if !user.MustChangePassword || user.Role != "operator" {
				t.Fatalf("unexpected user: %+v", user)
			}
			if _, err := adm.ResetPassword(ctx, user.ID, admin.ResetOptions{Temporary: true}); err != nil {
				t.Fatalf("reset: %v", err)
			}

			names := map[events.Name]events.Event{}
			for _, e := range rec.All() {
				names[e.Name] = e
			}
			for _, name := range []events.Name{events.UserCreated, events.PasswordResetByAdmin} {
				got, ok := names[name]
				if !ok {
					t.Fatalf("the event %s is absent", name)
				}
				if got.Actor != events.ActorSystem {
					t.Fatalf("the actor of %s is %q, want %s", name, got.Actor, events.ActorSystem)
				}
				if got.Target != user.ID {
					t.Fatalf("the target of %s is %q", name, got.Target)
				}
				if got.Time.IsZero() {
					t.Fatalf("the event %s has no time", name)
				}
			}
		})
	}
}

// TestSCNSES001RevokeOtherSessionsKeepsTheCurrentOne proves REQ-SES-001 and
// REQ-SES-003.
func TestSCNSES001RevokeOtherSessionsKeepsTheCurrentOne(t *testing.T) {
	for _, c := range opsStores {
		t.Run(c.name, func(t *testing.T) {
			s := c.build(t)
			auth, _ := operatorInstance(t, s)
			ctx := context.Background()
			user := testsupport.NewUser("sessions@example.com")
			if err := s.Users().Create(ctx, user); err != nil {
				t.Fatalf("create user: %v", err)
			}
			ids := make([]string, 3)
			for i := range ids {
				ids[i] = newSession(t, s, user.ID)
			}
			removed, err := auth.RevokeOtherSessions(ctx, ids[0])
			if err != nil {
				t.Fatalf("revoke: %v", err)
			}
			if removed != 2 {
				t.Fatalf("the revoke removed %d sessions, want 2", removed)
			}
			left, err := s.Sessions().ListByUser(ctx, user.ID)
			if err != nil {
				t.Fatalf("list: %v", err)
			}
			if len(left) != 1 || left[0].ID != ids[0] {
				t.Fatalf("the remaining sessions are %+v", left)
			}
			// A second call removes nothing.
			removed, err = auth.RevokeOtherSessions(ctx, ids[0])
			if err != nil || removed != 0 {
				t.Fatalf("the second call returned %d %v", removed, err)
			}
		})
	}
}

// newSession inserts one session of a user and returns the identifier.
func newSession(t *testing.T, s store.Store, userID string) string {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Millisecond)
	sess := &store.Session{
		ID:         testsupport.NewUser("x@example.com").ID,
		UserID:     userID,
		TokenHash:  sha256Hex(userID + now.String() + testsupport.NewUser("y@example.com").ID),
		CreatedAt:  now,
		ExpiresAt:  now.Add(time.Hour),
		LastSeenAt: now,
	}
	if err := s.Sessions().Create(context.Background(), sess); err != nil {
		t.Fatalf("create session: %v", err)
	}
	return sess.ID
}

// TestSCNSES002TheRevokeAllRouteKeepsTheV1Contract proves REQ-SES-002.
func TestSCNSES002TheRevokeAllRouteKeepsTheV1Contract(t *testing.T) {
	h := emailPasswordHarness(t)
	const address = "revoke-all@example.com"
	h.SignUp(address, testPassword)
	first := h.SaveCookies()
	h.ClearCookies()
	h.SignIn(address, testPassword)

	// The default keeps the current session.
	resp := h.Do(http.MethodPost, "/sessions/revoke-all", nil)
	if resp.Status != http.StatusOK {
		t.Fatalf("status %d: %s", resp.Status, string(resp.Body))
	}
	if got := h.Do(http.MethodGet, "/sessions", nil); got.Status != http.StatusOK {
		t.Fatalf("the current session ended: %d", got.Status)
	}
	h.RestoreCookies(first)
	if got := h.Do(http.MethodGet, "/sessions", nil); got.Status != http.StatusUnauthorized {
		t.Fatalf("the other session survived: %d", got.Status)
	}
}
