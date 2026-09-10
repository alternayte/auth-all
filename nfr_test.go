package authall_test

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	authall "github.com/alternayte/auth-all"
	"github.com/alternayte/auth-all/internal/testsupport"
	"github.com/alternayte/auth-all/plugins/apikeys"
	"github.com/alternayte/auth-all/ratelimit"
	"github.com/alternayte/auth-all/ratelimit/storelimit"
	"github.com/alternayte/auth-all/schema"
	"github.com/alternayte/auth-all/store"
	"github.com/alternayte/auth-all/store/sqlite"
)

// statements counts every statement that reaches the database.
var statements atomic.Int64

// countingDriver wraps the SQLite driver and counts the statements.
type countingDriver struct{ inner driver.Driver }

// Open implements driver.Driver.
func (d countingDriver) Open(name string) (driver.Conn, error) {
	conn, err := d.inner.Open(name)
	if err != nil {
		return nil, err
	}
	return countingConn{inner: conn}, nil
}

// countingConn counts the statements of one connection.
type countingConn struct{ inner driver.Conn }

// Prepare implements driver.Conn.
func (c countingConn) Prepare(query string) (driver.Stmt, error) { return c.inner.Prepare(query) }

// Close implements driver.Conn.
func (c countingConn) Close() error { return c.inner.Close() }

// Begin implements driver.Conn. The interface still names it, so the wrapper
// forwards the call.
func (c countingConn) Begin() (driver.Tx, error) {
	return c.BeginTx(context.Background(), driver.TxOptions{})
}

// BeginTx implements driver.ConnBeginTx. The SQLite driver implements it, so
// the wrapper needs no deprecated call.
func (c countingConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	beginner, ok := c.inner.(driver.ConnBeginTx)
	if !ok {
		return nil, driver.ErrSkip
	}
	return beginner.BeginTx(ctx, opts)
}

// QueryContext implements driver.QueryerContext.
func (c countingConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	queryer, ok := c.inner.(driver.QueryerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	statements.Add(1)
	return queryer.QueryContext(ctx, query, args)
}

// ExecContext implements driver.ExecerContext.
func (c countingConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	execer, ok := c.inner.(driver.ExecerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	statements.Add(1)
	return execer.ExecContext(ctx, query, args)
}

// countingStore returns a migrated SQLite store that counts its statements.
func countingStore(t *testing.T, opts schema.Options) store.Store {
	t.Helper()
	probe, err := sqlite.Open("file:" + filepath.Join(t.TempDir(), "probe.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	inner := probe.Driver()
	_ = probe.Close()
	name := "authall-counting-" + t.Name()
	sql.Register(name, countingDriver{inner: inner})

	db, err := sql.Open(name, "file:"+filepath.Join(t.TempDir(), "counted.db"))
	if err != nil {
		t.Fatalf("open counted: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s := sqlite.New(db)
	if c, ok := s.(store.SchemaConfigurable); ok {
		if err := c.UseSchema(opts); err != nil {
			t.Fatalf("use schema: %v", err)
		}
	}
	sc, err := schema.NewCoreWithOptions(opts)
	if err != nil {
		t.Fatalf("schema: %v", err)
	}
	if err := sc.Add(storelimit.Table(opts)); err != nil {
		t.Fatalf("add table: %v", err)
	}
	units, err := storelimit.Units(opts)
	if err != nil {
		t.Fatalf("units: %v", err)
	}
	for _, u := range units {
		if err := sc.AddUnit(u); err != nil {
			t.Fatalf("add unit: %v", err)
		}
	}
	testsupport.MigrateSchema(t, s, sc)
	return s
}

// TestNFR001CredentialResolutionUsesOneRoundTrip proves NFR-01.
func TestNFR001CredentialResolutionUsesOneRoundTrip(t *testing.T) {
	s := countingStore(t, schema.DefaultOptions())
	h := testsupport.NewHarnessWithStore(t, s, authall.WithEmailPassword())
	h.Handle("/host/probe", h.Auth.RequireAuth(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })))
	h.SignUp("round@example.com", testPassword)

	// The first protected request writes the last seen time of the session, so
	// the touch is the one extra write.
	statements.Store(0)
	if got := h.DoURL(http.MethodGet, h.BaseURL+"/host/probe", nil); got.Status != http.StatusOK {
		t.Fatalf("the probe returned %d", got.Status)
	}
	first := statements.Load()
	if first > 2 {
		t.Fatalf("the resolution used %d statements, want one read and at most one touch", first)
	}

	// A second request inside the touch interval reads only.
	statements.Store(0)
	if got := h.DoURL(http.MethodGet, h.BaseURL+"/host/probe", nil); got.Status != http.StatusOK {
		t.Fatalf("the probe returned %d", got.Status)
	}
	if second := statements.Load(); second != 1 {
		t.Fatalf("the second resolution used %d statements, want 1", second)
	}
}

// TestNFR003ARateLimitCheckUsesOneRoundTripForEachRule proves NFR-03.
func TestNFR003ARateLimitCheckUsesOneRoundTripForEachRule(t *testing.T) {
	s := countingStore(t, schema.DefaultOptions())
	rules := ratelimit.DefaultSignInRules()
	limiter, err := storelimit.New(s, rules)
	if err != nil {
		t.Fatalf("limiter: %v", err)
	}
	statements.Store(0)
	if _, err := limiter.Decide(context.Background(), ratelimit.Key{
		Operation: ratelimit.OpSignIn, Email: "counted@example.com", IP: "10.0.0.1",
	}); err != nil {
		t.Fatalf("decide: %v", err)
	}
	if got := statements.Load(); got != int64(len(rules)) {
		t.Fatalf("the check used %d statements, want %d", got, len(rules))
	}
}

// TestNFR004TheModuleGraphKeepsTheV1Dependencies proves NFR-04.
func TestNFR004TheModuleGraphKeepsTheV1Dependencies(t *testing.T) {
	raw, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	// The v1 release requires exactly these four modules. A new direct
	// requirement reaches every application, so the list is part of the
	// contract.
	want := []string{
		"github.com/google/uuid",
		"github.com/jackc/pgx/v5",
		"golang.org/x/crypto",
		"modernc.org/sqlite",
	}
	direct := directRequires(string(raw))
	if len(direct) != len(want) {
		t.Fatalf("the module requires %v, want %v", direct, want)
	}
	for i, name := range want {
		if direct[i] != name {
			t.Fatalf("the module requires %v, want %v", direct, want)
		}
	}
}

// directRequires returns the direct requirements of a go.mod file.
func directRequires(content string) []string {
	var out []string
	inBlock := false
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "require (":
			inBlock = true
			continue
		case inBlock && line == ")":
			inBlock = false
			continue
		}
		if !inBlock || line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		if strings.Contains(line, "// indirect") {
			continue
		}
		out = append(out, strings.Fields(line)[0])
	}
	return out
}

// TestNFR007EveryNewPluginHasAGuide proves NFR-07.
func TestNFR007EveryNewPluginHasAGuide(t *testing.T) {
	for _, name := range []string{
		"roles.md", "api-keys.md", "admin.md", "bootstrap.md",
		"rate-limits.md", "host-migrations.md", "huma.md",
	} {
		info, err := os.Stat(filepath.Join("docs", "guides", name))
		if err != nil {
			t.Fatalf("the guide %s is absent: %v", name, err)
		}
		if info.Size() < 500 {
			t.Fatalf("the guide %s holds %d bytes", name, info.Size())
		}
	}
	raw, err := os.ReadFile(filepath.Join("docs", "guides", "security-model.md"))
	if err != nil {
		t.Fatalf("read the security guide: %v", err)
	}
	text := string(raw)
	for i := 1; i <= 13; i++ {
		id := "SI-" + pad(i)
		if !strings.Contains(text, id) {
			t.Fatalf("the security guide does not state %s", id)
		}
	}
	if !strings.Contains(text, "consistency bound") {
		t.Fatal("the security guide does not describe the consistency bound")
	}
}

// pad returns the two-digit form of one number.
func pad(value int) string {
	if value < 10 {
		return "0" + string(rune('0'+value))
	}
	return string(rune('0'+value/10)) + string(rune('0'+value%10))
}

// TestNFR002ResolutionStaysBelowTheLatencyBound proves NFR-02.
//
// The run uses a scaled volume by default. AUTHALL_BENCH_FULL=1 runs the full
// volume of the requirement: 1 million sessions and 100 000 keys.
func TestNFR002ResolutionStaysBelowTheLatencyBound(t *testing.T) {
	if testing.Short() {
		t.Skip("the latency measurement needs a full run")
	}
	if os.Getenv("AUTHALL_LATENCY") != "1" {
		// The measurement needs a database that no other test uses at the same
		// time. The verification command runs it in its own step.
		t.Skip("AUTHALL_LATENCY is not 1. Run: just test-latency")
	}
	if testing.CoverMode() != "" {
		// The coverage instrumentation adds time to every statement, so the
		// measurement would report the instrumentation and not the store.
		t.Skip("the latency measurement needs a run without coverage")
	}
	sessions, keys := 20000, 2000
	if os.Getenv("AUTHALL_BENCH_FULL") == "1" {
		sessions, keys = 1000000, 100000
	}
	// The key table belongs to the plugin, so the benchmark schema holds it.
	s := testsupport.NewPostgres(t)
	sc, err := schema.NewCore()
	if err != nil {
		t.Fatalf("schema: %v", err)
	}
	if err := sc.Add(apikeys.Table(schema.DefaultOptions())); err != nil {
		t.Fatalf("add table: %v", err)
	}
	testsupport.MigrateSchema(t, s, sc)
	p99, baseline := measureResolution(t, s, sessions, keys)
	// The requirement bounds the overhead of the resolution. The baseline is
	// one empty round trip on the same connection pool, so the difference
	// holds the Auth-All work and no transport time.
	overhead := p99 - baseline
	if overhead > 2*time.Millisecond {
		t.Fatalf("the p99 resolution overhead is %s, want at most 2ms (p99 %s, baseline %s)",
			overhead, p99, baseline)
	}
	t.Logf("p99 resolution overhead with %d sessions and %d keys: %s (p99 %s, baseline %s)",
		sessions, keys, overhead, p99, baseline)
}

// measureResolution inserts the given volume and returns the p99 time of one
// credential resolution.
func measureResolution(t *testing.T, s store.Store, sessions, keys int) (time.Duration, time.Duration) {
	t.Helper()
	ctx := context.Background()
	owner := testsupport.NewUser("bench@example.com")
	if err := s.Users().Create(ctx, owner); err != nil {
		t.Fatalf("create user: %v", err)
	}
	handle, ok := s.(interface{ DB() *sql.DB })
	if !ok {
		t.Fatal("the store exposes no database handle")
	}
	db := handle.DB()
	names := schema.DefaultNames()
	now := time.Now().UTC()

	// The rows go in batches, because one insert for each row would dominate
	// the run time of the test.
	insertBatch(t, db, sessions, 500, func(i int) []any {
		return []any{uuidString(i, "s"), owner.ID, sha256Hex("bench-session-" + itoa(i)),
			now, now.Add(time.Hour), now}
	}, "INSERT INTO "+names.Sessions+" (id, user_id, token_hash, created_at, expires_at, last_seen_at) VALUES ", 6)
	insertBatch(t, db, keys, 500, func(i int) []any {
		return []any{uuidString(i, "k"), owner.ID, "bench", "ak_aaaa",
			sha256Hex("bench-key-" + itoa(i)), "viewer", now}
	}, "INSERT INTO "+names.APIKeys+" (id, user_id, name, start, key_hash, role, created_at) VALUES ", 7)

	reader, ok := s.(store.SessionUserReader)
	if !ok {
		t.Fatal("the store reads no joined session")
	}
	target := sha256Hex("bench-session-" + itoa(sessions/2))
	const runs = 1000
	// The baseline measures one empty round trip, so the result names the
	// transport cost of this machine.
	baseline := make([]time.Duration, 0, runs)
	// The first calls open the pooled connections, so they measure the
	// connection setup and not the resolution.
	for range 100 {
		if _, _, err := reader.SessionWithUser(ctx, target); err != nil {
			t.Fatalf("warm up: %v", err)
		}
	}
	measured := make([]time.Duration, 0, runs)
	for range runs {
		start := time.Now()
		if _, _, err := reader.SessionWithUser(ctx, target); err != nil {
			t.Fatalf("resolve: %v", err)
		}
		measured = append(measured, time.Since(start))

		var one int
		start = time.Now()
		if err := db.QueryRowContext(ctx, "SELECT 1").Scan(&one); err != nil {
			t.Fatalf("baseline: %v", err)
		}
		baseline = append(baseline, time.Since(start))
	}
	sort.Slice(measured, func(i, j int) bool { return measured[i] < measured[j] })
	sort.Slice(baseline, func(i, j int) bool { return baseline[i] < baseline[j] })
	t.Logf("resolution p50 %s, p90 %s, p99 %s. baseline p99 %s",
		measured[len(measured)/2], measured[int(float64(len(measured))*0.90)-1],
		measured[int(float64(len(measured))*0.99)-1], baseline[int(float64(len(baseline))*0.99)-1])
	return measured[int(float64(len(measured))*0.99)-1], baseline[int(float64(len(baseline))*0.99)-1]
}

// insertBatch inserts count rows in batches of size.
func insertBatch(t *testing.T, db *sql.DB, count, size int, row func(int) []any, prefix string, columns int) {
	t.Helper()
	ctx := context.Background()
	for start := 0; start < count; start += size {
		end := min(start+size, count)
		var b strings.Builder
		b.WriteString(prefix)
		args := make([]any, 0, (end-start)*columns)
		for i := start; i < end; i++ {
			if i > start {
				b.WriteString(", ")
			}
			b.WriteString("(")
			for c := range columns {
				if c > 0 {
					b.WriteString(", ")
				}
				b.WriteString("$" + itoa(len(args)+c+1))
			}
			b.WriteString(")")
			args = append(args, row(i)...)
		}
		if _, err := db.ExecContext(ctx, b.String(), args...); err != nil {
			t.Fatalf("insert batch: %v", err)
		}
	}
}

// uuidString returns a deterministic identifier of one benchmark row.
func uuidString(i int, kind string) string {
	return kind + "-" + itoa(i) + "-0000-0000-000000000000"
}

// itoa returns the decimal form of one number.
func itoa(value int) string { return strconv.Itoa(value) }
