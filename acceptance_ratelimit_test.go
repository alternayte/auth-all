package authall_test

import (
	"context"
	"database/sql"
	"net/http"
	"strconv"
	"testing"
	"time"

	authall "github.com/alternayte/auth-all"
	"github.com/alternayte/auth-all/apierr"
	"github.com/alternayte/auth-all/internal/testsupport"
	"github.com/alternayte/auth-all/ratelimit"
	"github.com/alternayte/auth-all/ratelimit/storelimit"
	"github.com/alternayte/auth-all/store"
)

// storeLimitHarness returns a harness whose limiter keeps its counters in the
// store.
func storeLimitHarness(t *testing.T, rules []ratelimit.Rule) (*testsupport.Harness, store.Store) {
	t.Helper()
	s := testsupport.NewSQLite(t)
	limiter, err := storelimit.New(s, rules)
	if err != nil {
		t.Fatalf("limiter: %v", err)
	}
	h := testsupport.NewHarnessWithStore(t, s,
		authall.WithEmailPassword(),
		authall.WithRateLimiter(limiter),
	)
	return h, s
}

// signIn sends one sign-in attempt with a wrong password.
func signInAttempt(h *testsupport.Harness, address string) *testsupport.Response {
	return h.Do(http.MethodPost, "/sign-in/email", map[string]string{
		"email": address, "password": "wrong-password-value",
	})
}

// TestSCNRL001TheSixthSignInForOneEmailIsRefused proves REQ-RL-001, REQ-RL-003
// and REQ-RL-005.
func TestSCNRL001TheSixthSignInForOneEmailIsRefused(t *testing.T) {
	h, _ := storeLimitHarness(t, ratelimit.DefaultSignInRules())
	const address = "limited@example.com"
	for i := range 5 {
		resp := signInAttempt(h, address)
		if resp.Status != http.StatusUnauthorized {
			t.Fatalf("attempt %d returned %d: %s", i+1, resp.Status, string(resp.Body))
		}
	}
	resp := signInAttempt(h, address)
	if resp.Status != http.StatusTooManyRequests {
		t.Fatalf("the sixth attempt returned %d: %s", resp.Status, string(resp.Body))
	}
	if code := errorCode(t, resp); code != string(apierr.CodeRateLimited) {
		t.Fatalf("the code is %q", code)
	}
	header := resp.Header.Get("Retry-After")
	seconds, err := strconv.Atoi(header)
	if err != nil {
		t.Fatalf("the Retry-After header is %q", header)
	}
	// The email window is 15 minutes, and no time passed, so the retry time is
	// near the whole window.
	if seconds < 1 || seconds > int((15*time.Minute).Seconds()) {
		t.Fatalf("the retry time is %d seconds", seconds)
	}
}

// TestSCNRL006AStoreFailureRefusesTheRequest proves REQ-RL-009. The limiter
// fails closed.
func TestSCNRL006AStoreFailureRefusesTheRequest(t *testing.T) {
	h, s := storeLimitHarness(t, ratelimit.DefaultSignInRules())
	handle, ok := s.(interface{ DB() *sql.DB })
	if !ok {
		t.Fatal("the store exposes no database handle")
	}
	if err := handle.DB().Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	resp := signInAttempt(h, "closed@example.com")
	if resp.Status != http.StatusInternalServerError {
		t.Fatalf("status %d: %s", resp.Status, string(resp.Body))
	}
	if code := errorCode(t, resp); code != string(apierr.CodeInternal) {
		t.Fatalf("the code is %q", code)
	}
}

// v1Limiter refuses every attempt and implements the v1 interface only.
type v1Limiter struct{}

// Allow implements ratelimit.Limiter.
func (v1Limiter) Allow(context.Context, ratelimit.Key) (bool, error) { return false, nil }

// TestSCNRL008AV1LimiterKeepsTheV1Behavior proves REQ-RL-011.
func TestSCNRL008AV1LimiterKeepsTheV1Behavior(t *testing.T) {
	h := emailPasswordHarness(t, authall.WithRateLimiter(v1Limiter{}))
	resp := signInAttempt(h, "v1@example.com")
	if resp.Status != http.StatusTooManyRequests {
		t.Fatalf("status %d: %s", resp.Status, string(resp.Body))
	}
	if got := resp.Header.Get("Retry-After"); got != "60" {
		t.Fatalf("the Retry-After header is %q, want 60", got)
	}
}

// TestTheStoreLimiterTableJoinsTheEffectiveSchema checks that the limiter
// contributes its counter table, so a migration creates it.
func TestTheStoreLimiterTableJoinsTheEffectiveSchema(t *testing.T) {
	h, s := storeLimitHarness(t, ratelimit.DefaultSignInRules())
	if _, ok := h.Auth.Schema().Table(h.Auth.Schema().Names().RateLimits); !ok {
		t.Fatal("the counter table is not in the effective schema")
	}
	inspector, ok := s.(store.CatalogInspector)
	if !ok {
		t.Fatal("the store cannot read the catalog")
	}
	_, exists, err := inspector.TableColumns(context.Background(), h.Auth.Schema().Names().RateLimits)
	if err != nil || !exists {
		t.Fatalf("the counter table is absent: %v", err)
	}
}
