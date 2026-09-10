package authall_test

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/alternayte/auth-all/plugins/organizations"
	"github.com/alternayte/auth-all/plugins/organizations/permission"
	"github.com/alternayte/auth-all/schema"
)

// TestNFR001TheOrganizationResolutionUsesOneRoundTrip proves NFR-01 and
// REQ-CTX-003 with a counting store. One statement returns the session, the
// user, the organization, the membership, and the resolved statements.
func TestNFR001TheOrganizationResolutionUsesOneRoundTrip(t *testing.T) {
	s := countingStore(t, schema.DefaultOptions())
	h, orgs := orgHarnessWithStore(t, s)
	h.Handle("/host/probe", orgs.Require("project:read", http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })))
	orgID, _ := newOrganization(t, h, "owner@example.com", "acme")
	activate(t, h, orgID)

	// The first protected request can write the last seen time of the session,
	// so the touch is the one extra write.
	statements.Store(0)
	if got := h.DoURL(http.MethodGet, h.BaseURL+"/host/probe", nil); got.Status != http.StatusOK {
		t.Fatalf("the probe returned %d", got.Status)
	}
	if first := statements.Load(); first > 2 {
		t.Fatalf("the resolution used %d statements, want one read and at most one touch", first)
	}

	// A second request inside the touch interval reads only. The permission
	// check adds no statement, which is NFR-02.
	statements.Store(0)
	if got := h.DoURL(http.MethodGet, h.BaseURL+"/host/probe", nil); got.Status != http.StatusOK {
		t.Fatalf("the probe returned %d", got.Status)
	}
	if second := statements.Load(); second != 1 {
		t.Fatalf("the second resolution used %d statements, want 1", second)
	}
}

// TestNFR002APermissionCheckNeedsNoStoreAccess proves NFR-02. The check reads
// the request context only, so it works when the database answers nothing.
func TestNFR002APermissionCheckNeedsNoStoreAccess(t *testing.T) {
	s := countingStore(t, schema.DefaultOptions())
	h, orgs := orgHarnessWithStore(t, s)
	orgID, _ := newOrganization(t, h, "owner@example.com", "acme")
	h.Handle("/host/capture", h.Auth.LoadSession(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			captured.Store(h, r.Context())
			w.WriteHeader(http.StatusOK)
		})))
	activate(t, h, orgID)
	ctx := hostContext(t, h)

	// Every check after the credential read costs no statement.
	statements.Store(0)
	for range 1000 {
		if !orgs.Can(ctx, "project:read") {
			t.Fatal("the owner holds project:read")
		}
		// The owner holds every permission, so the denied case uses a
		// statement that the grammar refuses.
		if orgs.Can(ctx, "unknown action") {
			t.Fatal("a statement that the grammar refuses is denied")
		}
	}
	if used := statements.Load(); used != 0 {
		t.Fatalf("the checks used %d statements, want 0", used)
	}
	// The check runs no network call either. It reads one map of the context.
	if _, ok := organizations.From(ctx); !ok {
		t.Fatal("the context holds no active organization")
	}
}

// TestNFR003APermissionCheckStaysBelowTwoMicroseconds proves NFR-03. The set
// holds 100 statements, and one check costs at most 2 microseconds.
func TestNFR003APermissionCheckStaysBelowTwoMicroseconds(t *testing.T) {
	set := benchmarkSet()
	const rounds = 200000
	asks := []string{"resource25:read", "resource49:write", "absent:action", "resource00:delete"}

	start := time.Now()
	allowed := 0
	for i := range rounds {
		if set.Allows(asks[i%len(asks)]) {
			allowed++
		}
	}
	each := time.Since(start) / rounds
	if allowed == 0 {
		t.Fatal("the set allowed nothing, so the measurement is wrong")
	}
	if each > 2*time.Microsecond {
		t.Fatalf("one check costs %v, want at most 2 microseconds", each)
	}
	t.Logf("one check of a set of %d statements costs %v", len(set.Statements()), each)
}

// benchmarkSet returns a set of 100 statements.
func benchmarkSet() permission.Set {
	statements := make([]string, 0, 100)
	for i := range 50 {
		statements = append(statements,
			fmt.Sprintf("resource%02d:read", i), fmt.Sprintf("resource%02d:write", i))
	}
	return permission.MustNewSet(statements...)
}

// BenchmarkPermissionCheck measures one check of a set of 100 statements.
// NFR-03 asks for at most 2 microseconds.
func BenchmarkPermissionCheck(b *testing.B) {
	set := benchmarkSet()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; b.Loop(); i++ {
		if !set.Allows("resource25:read") {
			b.Fatal("the set holds the statement")
		}
	}
}

// BenchmarkPermissionCheckMiss measures one denied check of the same set.
func BenchmarkPermissionCheckMiss(b *testing.B) {
	set := benchmarkSet()
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if set.Allows("absent:action") {
			b.Fatal("the set holds no such statement")
		}
	}
}

// TestSI09TheEvaluationReadsNoPattern proves SI-09. The grammar refuses every
// regular expression character, so an evaluation never reads a pattern of a
// request.
func TestSI09TheEvaluationReadsNoPattern(t *testing.T) {
	// A set that a role declares holds concrete statements only.
	set := permission.MustNewSet("project:*", "billing:read")
	patterns := []string{
		".*", "project:.*", "^project:read$", "project:[a-z]+", "project:(read|write)",
		"project:read|billing:read", "project:read\\d", "project:rea?d", "project:read+",
		"project:*extra", "**", "project:**",
	}
	for _, pattern := range patterns {
		if set.Allows(pattern) {
			t.Fatalf("the pattern %q was allowed", pattern)
		}
		if _, err := permission.Parse(pattern); err == nil {
			t.Fatalf("the pattern %q passed the grammar", pattern)
		}
	}
	// A wildcard matches one whole segment and never a part of one.
	if set.Allows("projectx:read") {
		t.Fatal("a wildcard matched a part of a segment")
	}
	// The dot is a literal character of a segment, and never a pattern. A set
	// of "pro.ect:read" therefore matches that name only.
	literal := permission.MustNewSet("pro.ect:read")
	if !literal.Allows("pro.ect:read") {
		t.Fatal("the literal statement does not match itself")
	}
	for _, ask := range []string{"project:read", "proXect:read", "pro-ect:read"} {
		if literal.Allows(ask) {
			t.Fatalf("the dot matched %q, so it behaved as a pattern", ask)
		}
	}
}
