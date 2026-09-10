package authall_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	authall "github.com/alternayte/auth-all"
	"github.com/alternayte/auth-all/internal/testsupport"
	"github.com/alternayte/auth-all/schema"
	"github.com/alternayte/auth-all/store"
)

// fieldsHarness returns a harness with two host-owned user fields.
func fieldsHarness(t *testing.T, fields ...schema.UserField) *testsupport.Harness {
	t.Helper()
	s := testsupport.NewSQLiteWithOptions(t, schema.Options{UserFields: fields})
	return testsupport.NewHarnessWithStore(t, s,
		authall.WithEmailPassword(),
		authall.WithUserFields(fields...),
	)
}

// TestSCNSCH006TheInputAndOutputRulesHold proves REQ-SCH-007 and REQ-SCH-008.
func TestSCNSCH006TheInputAndOutputRulesHold(t *testing.T) {
	h := fieldsHarness(t,
		// The host writes the team itself, so no route can set it.
		schema.UserField{Name: "team", Type: schema.TypeText, Nullable: true, Returned: true},
		// The nickname comes from the sign-up form and stays private.
		schema.UserField{Name: "nickname", Type: schema.TypeText, Nullable: true, Input: true},
	)
	resp := h.Do(http.MethodPost, "/sign-up/email", map[string]any{
		"email": "fields@example.com", "password": testPassword, "name": "Test User",
		"team": "platform", "nickname": "tester",
	})
	if resp.Status != http.StatusCreated {
		t.Fatalf("status %d: %s", resp.Status, string(resp.Body))
	}

	// The route ignored the field with Input false.
	user, err := h.Store.Users().GetByNormalizedEmail(context.Background(), "fields@example.com")
	if err != nil {
		t.Fatalf("read user: %v", err)
	}
	team, err := authall.Field[string](user, "team")
	if err != nil {
		t.Fatalf("read team: %v", err)
	}
	if team != "" {
		t.Fatalf("the sign-up wrote the team %q", team)
	}
	nickname, err := authall.Field[string](user, "nickname")
	if err != nil {
		t.Fatalf("read nickname: %v", err)
	}
	if nickname != "tester" {
		t.Fatalf("the nickname is %q", nickname)
	}

	// The host writes the team, and the session response returns it.
	user.Extra["team"] = "platform"
	if err := h.Store.Users().Update(context.Background(), user); err != nil {
		t.Fatalf("update user: %v", err)
	}
	got := h.Do(http.MethodGet, "/session", nil)
	if got.Status != http.StatusOK {
		t.Fatalf("session: %d", got.Status)
	}
	body := string(got.Body)
	if !strings.Contains(body, `"team":"platform"`) {
		t.Fatalf("the session response has no team: %s", body)
	}
	if strings.Contains(body, "nickname") {
		t.Fatalf("the session response carries the field with Returned false: %s", body)
	}
}

// TestSCNSCH007ATypeMismatchReportsAnError proves REQ-SCH-009.
func TestSCNSCH007ATypeMismatchReportsAnError(t *testing.T) {
	h := fieldsHarness(t,
		schema.UserField{Name: "team", Type: schema.TypeText, Nullable: true, Input: true, Returned: true},
		schema.UserField{Name: "seats", Type: schema.TypeInt, Nullable: true, Input: true},
	)
	resp := h.Do(http.MethodPost, "/sign-up/email", map[string]any{
		"email": "typed@example.com", "password": testPassword,
		"team": "platform", "seats": 7,
	})
	if resp.Status != http.StatusCreated {
		t.Fatalf("status %d: %s", resp.Status, string(resp.Body))
	}
	user, err := h.Store.Users().GetByNormalizedEmail(context.Background(), "typed@example.com")
	if err != nil {
		t.Fatalf("read user: %v", err)
	}
	if _, err := authall.Field[int64](user, "team"); err == nil {
		t.Fatal("a text field answered an integer request")
	}
	seats, err := authall.Field[int64](user, "seats")
	if err != nil {
		t.Fatalf("read seats: %v", err)
	}
	if seats != 7 {
		t.Fatalf("the seats value is %d", seats)
	}
	if _, err := authall.Field[string](user, "absent"); err == nil {
		t.Fatal("an undeclared field answered a request")
	}
}

// TestTheUserFieldColumnsJoinTheSchema checks that a declared field becomes a
// column of the users table.
func TestTheUserFieldColumnsJoinTheSchema(t *testing.T) {
	h := fieldsHarness(t, schema.UserField{Name: "team", Type: schema.TypeText, Nullable: true})
	inspector, ok := h.Store.(store.CatalogInspector)
	if !ok {
		t.Fatal("the store cannot read the catalog")
	}
	columns, exists, err := inspector.TableColumns(context.Background(), h.Auth.Schema().Names().Users)
	if err != nil || !exists {
		t.Fatalf("the users table is absent: %v", err)
	}
	found := false
	for _, c := range columns {
		if c == "team" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the column team is absent: %v", columns)
	}
	if len(h.Auth.UserFields()) != 1 {
		t.Fatalf("the instance declares %d fields", len(h.Auth.UserFields()))
	}
}
