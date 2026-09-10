package permission_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/alternayte/auth-all/plugins/organizations/permission"
)

// TestSCNPRM001TheWildcardCoversItsSegment proves SCN-PRM-001. The statement
// "project:read" matches "project:read", "project:*", and "*". It does not
// match "billing:*", and the set does not answer "project:read:extra".
func TestSCNPRM001TheWildcardCoversItsSegment(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		grants  []string
		ask     string
		allowed bool
	}{
		{"the exact statement", []string{"project:read"}, "project:read", true},
		{"the action wildcard", []string{"project:*"}, "project:read", true},
		{"every permission", []string{"*"}, "project:read", true},
		{"the resource wildcard", []string{"*:read"}, "project:read", true},
		{"another resource", []string{"billing:*"}, "project:read", false},
		{"a third segment", []string{"project:read"}, "project:read:extra", false},
		{"another action", []string{"project:read"}, "project:write", false},
		{"an empty set", nil, "project:read", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			set := permission.MustNewSet(tc.grants...)
			if got := set.Allows(tc.ask); got != tc.allowed {
				t.Fatalf("Allows(%q) with %v = %v, want %v", tc.ask, tc.grants, got, tc.allowed)
			}
		})
	}
}

// TestSCNPRM001AWildcardNeedsAWildcardGrant proves the second half of the
// match rule. A concrete grant never covers the whole reach of a wildcard, so
// a member with "project:read" cannot grant "project:*".
func TestSCNPRM001AWildcardNeedsAWildcardGrant(t *testing.T) {
	t.Parallel()

	narrow := permission.MustNewSet("project:read")
	if narrow.Covers(permission.MustParse("project:*")) {
		t.Fatal("a set of project:read must not cover project:*")
	}
	if narrow.Covers(permission.MustParse("*")) {
		t.Fatal("a set of project:read must not cover *")
	}
	wide := permission.MustNewSet("project:*")
	if !wide.Covers(permission.MustParse("project:*")) {
		t.Fatal("a set of project:* must cover project:*")
	}
	if wide.Covers(permission.MustParse("*")) {
		t.Fatal("a set of project:* must not cover *")
	}
	if !permission.MustNewSet("*").Covers(permission.MustParse("*")) {
		t.Fatal("a set of * must cover *")
	}
}

// TestSCNPRM002TheGrammarRefusesAPattern proves SCN-PRM-002 and REQ-PRM-013. A
// statement with a space, a slash, or a regular expression character fails the
// construction, so no evaluation ever reads a pattern.
func TestSCNPRM002TheGrammarRefusesAPattern(t *testing.T) {
	t.Parallel()

	invalid := []string{
		"project read",
		"project:re ad",
		"project/read",
		"project:.*",
		"^project:read$",
		"project:[a-z]+",
		"project:(read|write)",
		"project:read?",
		"project:read+",
		"project:read\\d",
		"Project:Read",
		"project",
		"project:read:extra",
		"project:",
		":read",
		"",
		"pro*ject:read",
		"project:**",
	}
	for _, raw := range invalid {
		if _, err := permission.Parse(raw); !errors.Is(err, permission.ErrInvalid) {
			t.Fatalf("Parse(%q) = %v, want ErrInvalid", raw, err)
		}
		if permission.MustNewSet().Allows(raw) {
			t.Fatalf("Allows(%q) must be false", raw)
		}
	}

	valid := []string{"*", "project:*", "*:read", "project:read", "a_b.c-d:read"}
	for _, raw := range valid {
		stmt, err := permission.Parse(raw)
		if err != nil {
			t.Fatalf("Parse(%q) = %v, want no error", raw, err)
		}
		if stmt.String() != raw {
			t.Fatalf("Parse(%q).String() = %q", raw, stmt.String())
		}
	}
}

// TestSCNPRM002AnInvalidStatementFailsTheSet proves that a set refuses an
// invalid statement at construction, and that MustNewSet panics.
func TestSCNPRM002AnInvalidStatementFailsTheSet(t *testing.T) {
	t.Parallel()

	if _, err := permission.NewSet("project:read", "project read"); !errors.Is(err, permission.ErrInvalid) {
		t.Fatalf("NewSet with an invalid statement = %v, want ErrInvalid", err)
	}
	defer func() {
		recovered := recover()
		if recovered == nil {
			t.Fatal("MustNewSet must panic on an invalid statement")
		}
		if !strings.Contains(recovered.(string), "invalid") {
			t.Fatalf("the panic must name the fault: %v", recovered)
		}
	}()
	permission.MustNewSet("project read")
}

// TestSCNPRM002MustParsePanics proves the constant helper.
func TestSCNPRM002MustParsePanics(t *testing.T) {
	t.Parallel()

	defer func() {
		if recover() == nil {
			t.Fatal("MustParse must panic on an invalid statement")
		}
	}()
	permission.MustParse("project read")
}

// TestTheUnionHoldsEveryStatement proves the union that a team role needs.
func TestTheUnionHoldsEveryStatement(t *testing.T) {
	t.Parallel()

	org := permission.MustNewSet("project:read")
	team := permission.MustNewSet("billing:read", "project:read")
	union := org.Union(team)
	for _, ask := range []string{"project:read", "billing:read"} {
		if !union.Allows(ask) {
			t.Fatalf("the union must allow %q", ask)
		}
	}
	if union.Allows("project:write") {
		t.Fatal("the union must hold no other statement")
	}
	want := []string{"billing:read", "project:read"}
	got := union.Statements()
	if len(got) != len(want) {
		t.Fatalf("Statements() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Statements() = %v, want %v", got, want)
		}
	}
	if union.Empty() {
		t.Fatal("the union holds statements")
	}
	if !permission.MustNewSet().Empty() {
		t.Fatal("the empty set is empty")
	}
}

// TestCoversSetGuardsAGrant proves the guard that a role change needs. A
// member never grants a set that the member does not hold.
func TestCoversSetGuardsAGrant(t *testing.T) {
	t.Parallel()

	admin := permission.MustNewSet("member:*", "project:*", "billing:read")
	if !admin.CoversSet(permission.MustNewSet("project:read", "billing:read")) {
		t.Fatal("an admin covers a weaker set")
	}
	if admin.CoversSet(permission.MustNewSet("*")) {
		t.Fatal("an admin must not cover every permission")
	}
	if admin.CoversSet(permission.MustNewSet("billing:*")) {
		t.Fatal("an admin with billing:read must not cover billing:*")
	}
	if !permission.MustNewSet("*").CoversSet(admin) {
		t.Fatal("an owner covers every set")
	}
	if !admin.CoversSet(permission.MustNewSet()) {
		t.Fatal("every set covers the empty set")
	}
}
