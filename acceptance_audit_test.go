package authall_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	authall "github.com/alternayte/auth-all"
	"github.com/alternayte/auth-all/events"
	"github.com/alternayte/auth-all/hook"
	"github.com/alternayte/auth-all/internal/testsupport"
	"github.com/alternayte/auth-all/plugins/admin"
	"github.com/alternayte/auth-all/plugins/apikeys"
	"github.com/alternayte/auth-all/plugins/roles"
)

// auditHarness returns a harness with every plugin and one event recorder.
func auditHarness(t *testing.T, opts ...authall.Option) (*testsupport.Harness, *recorder) {
	t.Helper()
	rec := &recorder{}
	r := roles.New(roles.Hierarchy(testHierarchy...), roles.Default("viewer"))
	all := append([]authall.Option{
		authall.WithPlugins(r, admin.New(), apikeys.New()),
		authall.WithEventHandler(rec),
	}, opts...)
	h := emailPasswordHarness(t, all...)
	h.Handle("/host/any", h.Auth.RequireAuth(http.HandlerFunc(
		func(w http.ResponseWriter, req *http.Request) { w.WriteHeader(http.StatusNoContent) })))
	return h, rec
}

// runEveryAuditedOperation runs one operation of each audited name and returns
// the secrets of the run.
func runEveryAuditedOperation(t *testing.T, h *testsupport.Harness) []string {
	t.Helper()
	const adminAddress = "audit-admin@example.com"
	const targetAddress = "audit-target@example.com"
	const targetPassword = "a-known-target-password"

	h.SignUp(adminAddress, testPassword)
	setRole(t, h.Store, adminAddress, "admin")

	// A sign-in failure and a sign-in success.
	adminCookies := h.SaveCookies()
	h.ClearCookies()
	h.SignIn(adminAddress, "a-wrong-password-value")
	h.SignIn(adminAddress, testPassword)
	h.RestoreCookies(adminCookies)

	// The administrator creates a user, changes the role, disables it, enables
	// it, and resets the password.
	target := createUser(t, h, targetAddress)
	if got := h.Do(http.MethodPost, "/admin/users/"+target+"/role",
		map[string]any{"role": "operator"}); got.Status != http.StatusOK {
		t.Fatalf("role: %d %s", got.Status, string(got.Body))
	}
	if got := h.Do(http.MethodPost, "/admin/users/"+target+"/disable", nil); got.Status != http.StatusOK {
		t.Fatalf("disable: %d", got.Status)
	}
	if got := h.Do(http.MethodPost, "/admin/users/"+target+"/enable", nil); got.Status != http.StatusOK {
		t.Fatalf("enable: %d", got.Status)
	}
	if got := h.Do(http.MethodPost, "/admin/users/"+target+"/password",
		map[string]any{"password": targetPassword, "temporary": false}); got.Status != http.StatusOK {
		t.Fatalf("password: %d", got.Status)
	}

	// The administrator creates and revokes one key.
	_, plaintext, key := createKey(t, h, map[string]any{"name": "audit"})
	if got := h.Do(http.MethodPost, "/api-keys/"+key.ID+"/revoke", nil); got.Status != http.StatusOK {
		t.Fatalf("revoke: %d %s", got.Status, string(got.Body))
	}

	// A sign-out ends the run.
	if got := h.Do(http.MethodPost, "/sign-out", nil); got.Status != http.StatusOK {
		t.Fatalf("sign-out: %d", got.Status)
	}
	return []string{testPassword, targetPassword, plaintext, "a-wrong-password-value"}
}

// TestSCNAUD001EveryOperationEmitsOneEvent proves REQ-AUD-001 and REQ-AUD-002.
func TestSCNAUD001EveryOperationEmitsOneEvent(t *testing.T) {
	h, rec := auditHarness(t)
	runEveryAuditedOperation(t, h)

	wanted := []events.Name{
		events.SignIn, events.SignInFailed, events.SignOut,
		events.UserCreated, events.UserUpdated, events.UserDisabled, events.UserEnabled,
		events.PasswordResetByAdmin, events.RoleChanged,
		events.APIKeyCreated, events.APIKeyRevoked,
	}
	seen := map[events.Name][]events.Event{}
	for _, e := range rec.All() {
		seen[e.Name] = append(seen[e.Name], e)
	}
	for _, name := range wanted {
		list, ok := seen[name]
		if !ok {
			t.Fatalf("the event %s is absent", name)
		}
		for _, e := range list {
			if e.Time.IsZero() {
				t.Fatalf("the event %s has no time", name)
			}
			if e.Actor == "" {
				t.Fatalf("the event %s has no actor", name)
			}
			if e.IP == "" {
				t.Fatalf("the event %s has no client address", name)
			}
			if name == events.SignInFailed {
				// A failed sign-in has no session, so it names no method.
				continue
			}
			if e.Target == "" {
				t.Fatalf("the event %s has no target", name)
			}
		}
	}
	// A request that a session authenticated names the method.
	for _, e := range seen[events.RoleChanged] {
		if e.Method != authall.MethodSession {
			t.Fatalf("the role change names the method %q", e.Method)
		}
	}
}

// TestSCNAUD002NoEventCarriesASecret proves REQ-AUD-003 and REQ-AUD-004.
func TestSCNAUD002NoEventCarriesASecret(t *testing.T) {
	h, rec := auditHarness(t)
	secrets := runEveryAuditedOperation(t, h)

	for _, e := range rec.All() {
		text := fmt.Sprintf("%s|%s|%s|%s|%v", e.Actor, e.Target, e.IP, e.Method, e.Fields)
		for _, secret := range secrets {
			if secret == "" {
				continue
			}
			if strings.Contains(text, secret) {
				t.Fatalf("the event %s carries a secret: %s", e.Name, text)
			}
		}
		if strings.Contains(text, "$argon2") {
			t.Fatalf("the event %s carries a password hash", e.Name)
		}
		if strings.Contains(text, "audit-admin@example.com") {
			t.Fatalf("the event %s carries an email address", e.Name)
		}
	}

	// A failed sign-in names the digest of the address and a reason.
	found := false
	for _, e := range rec.All() {
		if e.Name != events.SignInFailed {
			continue
		}
		found = true
		digest, _ := e.Fields["email_digest"].(string)
		if len(digest) != 64 {
			t.Fatalf("the digest is %q", digest)
		}
		if digest != sha256Hex("audit-admin@example.com") {
			t.Fatalf("the digest does not match the normalized address")
		}
		if reason, _ := e.Fields["reason"].(string); reason == "" {
			t.Fatal("the failed sign-in names no reason")
		}
	}
	if !found {
		t.Fatal("no failed sign-in was recorded")
	}
}

// failingHandler returns an error for every event.
type failingHandler struct{ seen int }

// HandleEvent implements events.Handler.
func (f *failingHandler) HandleEvent(context.Context, events.Event) { f.seen++ }

// TestSCNAUD003AHandlerErrorChangesNoResponse proves REQ-AUD-005 and
// REQ-AUD-006.
func TestSCNAUD003AHandlerErrorChangesNoResponse(t *testing.T) {
	failing := &failingHandler{}
	h, _ := auditHarness(t, authall.WithEventHandler(failing))
	const address = "hook-admin@example.com"
	h.SignUp(address, testPassword)
	setRole(t, h.Store, address, "admin")
	target := createUser(t, h, "hook-target@example.com")
	if failing.seen == 0 {
		t.Fatal("the handler saw no event")
	}

	// A Before hook of the role change receives the transactional store and
	// can reject the change.
	var sawTx bool
	h.Auth.Hooks().OnBeforeRoleChange(func(_ context.Context, ev *hook.RoleChange) error {
		sawTx = ev.Tx != nil
		return errors.New("the hook refuses the change")
	})
	resp := h.Do(http.MethodPost, "/admin/users/"+target+"/role", map[string]any{"role": "operator"})
	if resp.Status != http.StatusInternalServerError {
		t.Fatalf("the refused change returned %d: %s", resp.Status, string(resp.Body))
	}
	if !sawTx {
		t.Fatal("the Before hook got no transactional store")
	}
	user, err := h.Store.Users().GetByID(context.Background(), target)
	if err != nil {
		t.Fatalf("read user: %v", err)
	}
	if user.Role == "operator" {
		t.Fatal("the refused change was committed")
	}
}
