package storelimit_test

import (
	"context"
	"database/sql"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alternayte/auth-all/internal/testsupport"
	"github.com/alternayte/auth-all/ratelimit"
	"github.com/alternayte/auth-all/ratelimit/storelimit"
	"github.com/alternayte/auth-all/schema"
	"github.com/alternayte/auth-all/store"
)

// signInRules are the default rules of the sign-in flow.
var signInRules = ratelimit.DefaultSignInRules()

// newLimiter returns a limiter over a store that already holds the counter
// table.
func newLimiter(t *testing.T, s store.Store, rules []ratelimit.Rule, opts ...storelimit.Option) *storelimit.Limiter {
	t.Helper()
	l, err := storelimit.New(s, rules, opts...)
	if err != nil {
		t.Fatalf("new limiter: %v", err)
	}
	return l
}

// newStore returns a SQLite store whose schema holds the counter table.
func newStore(t *testing.T) store.Store {
	t.Helper()
	s := testsupport.NewSQLite(t)
	addCounterTable(t, s)
	return s
}

// addCounterTable applies the counter table of the limiter.
func addCounterTable(t *testing.T, s store.Store) {
	t.Helper()
	sc, err := schema.NewCore()
	if err != nil {
		t.Fatalf("schema: %v", err)
	}
	if err := sc.Add(storelimit.Table(schema.DefaultOptions())); err != nil {
		t.Fatalf("add table: %v", err)
	}
	units, err := storelimit.Units(schema.DefaultOptions())
	if err != nil {
		t.Fatalf("units: %v", err)
	}
	for _, u := range units {
		if err := sc.AddUnit(u); err != nil {
			t.Fatalf("add unit: %v", err)
		}
	}
	testsupport.MigrateSchema(t, s, sc)
}

// TestSCNRL002ARuleSetRefusesWhenEitherRuleIsOver proves REQ-RL-002 and
// REQ-RL-004.
func TestSCNRL002ARuleSetRefusesWhenEitherRuleIsOver(t *testing.T) {
	s := newStore(t)
	rules := []ratelimit.Rule{
		{Operation: ratelimit.OpSignIn, Scope: ratelimit.ScopeEmail, Limit: 2, Window: time.Minute},
		{Operation: ratelimit.OpSignIn, Scope: ratelimit.ScopeIP, Limit: 5, Window: time.Minute},
	}
	l := newLimiter(t, s, rules)
	ctx := context.Background()

	// The email rule is the lower one, so it refuses first.
	key := ratelimit.Key{Operation: ratelimit.OpSignIn, Email: "a@example.com", IP: "10.0.0.1"}
	for i := range 2 {
		d, err := l.Decide(ctx, key)
		if err != nil || !d.Allowed {
			t.Fatalf("attempt %d was refused: %v %+v", i+1, err, d)
		}
	}
	d, err := l.Decide(ctx, key)
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if d.Allowed {
		t.Fatal("the third attempt for one email was allowed")
	}
	if d.RetryAfter <= 0 || d.RetryAfter > time.Minute {
		t.Fatalf("the retry time is %s", d.RetryAfter)
	}

	// The IP rule refuses on its own, with another email each time.
	l2 := newLimiter(t, newStore(t), []ratelimit.Rule{
		{Operation: ratelimit.OpSignIn, Scope: ratelimit.ScopeIP, Limit: 2, Window: time.Minute},
	})
	for i := range 2 {
		d, err := l2.Decide(ctx, ratelimit.Key{Operation: ratelimit.OpSignIn, IP: "10.0.0.9"})
		if err != nil || !d.Allowed {
			t.Fatalf("attempt %d was refused: %v %+v", i+1, err, d)
		}
	}
	d, err = l2.Decide(ctx, ratelimit.Key{Operation: ratelimit.OpSignIn, IP: "10.0.0.9"})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if d.Allowed {
		t.Fatal("the third attempt from one address was allowed")
	}

	// A rule of another operation counts nothing here.
	d, err = l.Decide(ctx, ratelimit.Key{Operation: ratelimit.OpSignUp, Email: "a@example.com"})
	if err != nil || !d.Allowed {
		t.Fatalf("another operation was refused: %v %+v", err, d)
	}
}

// TestSCNRL004TheAddressKeyCountsPerBlock proves REQ-RL-007.
func TestSCNRL004TheAddressKeyCountsPerBlock(t *testing.T) {
	first := storelimit.IPKey("2001:db8:1:2::1")
	second := storelimit.IPKey("2001:db8:1:2:ffff:ffff:ffff:ffff")
	if first != second {
		t.Fatalf("two addresses of one /64 give %q and %q", first, second)
	}
	other := storelimit.IPKey("2001:db8:1:3::1")
	if other == first {
		t.Fatal("two addresses of two blocks share one key")
	}
	if got := storelimit.IPKey("::ffff:10.0.0.1"); got != "10.0.0.1" {
		t.Fatalf("the mapped address gives %q", got)
	}
	if got := storelimit.IPKey("10.0.0.1"); got != "10.0.0.1" {
		t.Fatalf("the IPv4 address gives %q", got)
	}
	if storelimit.IPKey("") != "" {
		t.Fatal("an empty address gives a key")
	}
}

// TestSCNRL005TheTableHoldsNoAddress proves REQ-RL-008 and SI-10.
func TestSCNRL005TheTableHoldsNoAddress(t *testing.T) {
	s := newStore(t)
	l := newLimiter(t, s, signInRules)
	const address = "secret.person@example.com"
	if _, err := l.Decide(context.Background(), ratelimit.Key{
		Operation: ratelimit.OpSignIn, Email: address, IP: "10.0.0.1",
	}); err != nil {
		t.Fatalf("decide: %v", err)
	}
	for _, key := range counterKeys(t, s) {
		if strings.Contains(key, address) || strings.Contains(key, "example.com") {
			t.Fatalf("the counter key holds the address: %s", key)
		}
	}
	// The digest of the normalized address identifies the counter.
	want := storelimit.Subject(ratelimit.ScopeEmail, ratelimit.Key{Email: "  SECRET.Person@Example.com "})
	found := false
	for _, key := range counterKeys(t, s) {
		if strings.HasSuffix(key, want) {
			found = true
		}
	}
	if !found {
		t.Fatal("no counter carries the digest of the normalized address")
	}
}

// counterKeys returns every key of the counter table.
func counterKeys(t *testing.T, s store.Store) []string {
	t.Helper()
	return readKeys(t, s)
}

// readKeys reads the key column of the counter table through the database
// handle of the store.
func readKeys(t *testing.T, s store.Store) []string {
	t.Helper()
	handle, ok := s.(interface{ DB() *sql.DB })
	if !ok {
		t.Fatal("the store exposes no database handle")
	}
	rows, err := handle.DB().QueryContext(context.Background(),
		"SELECT key FROM "+schema.DefaultNames().RateLimits)
	if err != nil {
		t.Fatalf("read counters: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out = append(out, key)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	return out
}

// TestSCNRL007CleanupRemovesOnlyEndedWindows proves REQ-RL-010.
func TestSCNRL007CleanupRemovesOnlyEndedWindows(t *testing.T) {
	s := newStore(t)
	now := time.Now().UTC()
	clock := now
	l := newLimiter(t, s, []ratelimit.Rule{
		{Operation: ratelimit.OpSignIn, Scope: ratelimit.ScopeIP, Limit: 5, Window: time.Minute},
	}, storelimit.WithClock(func() time.Time { return clock }))
	ctx := context.Background()
	if _, err := l.Decide(ctx, ratelimit.Key{Operation: ratelimit.OpSignIn, IP: "10.0.0.1"}); err != nil {
		t.Fatalf("decide: %v", err)
	}
	clock = now.Add(2 * time.Minute)
	if _, err := l.Decide(ctx, ratelimit.Key{Operation: ratelimit.OpSignIn, IP: "10.0.0.2"}); err != nil {
		t.Fatalf("decide: %v", err)
	}
	removed, err := l.Cleanup(ctx, clock.Add(-time.Minute))
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if removed != 1 {
		t.Fatalf("cleanup removed %d counters, want 1", removed)
	}
	if got := len(readKeys(t, s)); got != 1 {
		t.Fatalf("%d counters remain, want 1", got)
	}
}

// TestSCNRL003ParallelAttemptsAllowExactlyTheLimit proves REQ-RL-006. It runs
// on PostgreSQL and on SQLite.
func TestSCNRL003ParallelAttemptsAllowExactlyTheLimit(t *testing.T) {
	for _, c := range []struct {
		name  string
		build func(*testing.T) store.Store
	}{
		{"sqlite", newStore},
		{"postgres", func(t *testing.T) store.Store {
			s := testsupport.NewPostgres(t)
			addCounterTable(t, s)
			return s
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := c.build(t)
			const limit = 5
			const attempts = 50
			l := newLimiter(t, s, []ratelimit.Rule{
				{Operation: ratelimit.OpSignIn, Scope: ratelimit.ScopeIP, Limit: limit, Window: time.Hour},
			})
			var mu sync.Mutex
			allowed := 0
			var wg sync.WaitGroup
			for range attempts {
				wg.Add(1)
				go func() {
					defer wg.Done()
					d, err := l.Decide(context.Background(), ratelimit.Key{
						Operation: ratelimit.OpSignIn, IP: "10.1.2.3",
					})
					if err != nil {
						return
					}
					if d.Allowed {
						mu.Lock()
						allowed++
						mu.Unlock()
					}
				}()
			}
			wg.Wait()
			if allowed != limit {
				t.Fatalf("%d attempts were allowed, want %d", allowed, limit)
			}
		})
	}
}

// TestTheLimiterRefusesAnUnusableRule checks the construction guard.
func TestTheLimiterRefusesAnUnusableRule(t *testing.T) {
	s := newStore(t)
	bad := [][]ratelimit.Rule{
		{},
		{{Scope: ratelimit.ScopeIP, Limit: 1, Window: time.Minute}},
		{{Operation: ratelimit.OpSignIn, Scope: "user", Limit: 1, Window: time.Minute}},
		{{Operation: ratelimit.OpSignIn, Scope: ratelimit.ScopeIP, Limit: 0, Window: time.Minute}},
		{{Operation: ratelimit.OpSignIn, Scope: ratelimit.ScopeIP, Limit: 1}},
	}
	for _, rules := range bad {
		if _, err := storelimit.New(s, rules); err == nil {
			t.Fatalf("the rules %+v were accepted", rules)
		}
	}
}
