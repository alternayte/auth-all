package authall_test

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	authall "github.com/alternayte/auth-all"
	"github.com/alternayte/auth-all/apierr"
	"github.com/alternayte/auth-all/internal/testsupport"
	"github.com/alternayte/auth-all/oauth/github"
	"github.com/alternayte/auth-all/ratelimit"
)

func TestConfigurationValidation(t *testing.T) {
	s := testsupport.NewSQLite(t)
	cases := []struct {
		name string
		opts []authall.Option
		want string
	}{
		{"missing store", []authall.Option{authall.WithEmailPassword()}, "store is required"},
		{"oauth without base url", []authall.Option{
			authall.WithStore(s), authall.WithProvider(github.New(
				github.WithClientID("id"), github.WithClientSecret("secret"))),
		}, "base URL"},
		{"provider without credentials", []authall.Option{
			authall.WithStore(s), authall.WithBaseURL("https://app.example.com"),
			authall.WithProvider(github.New()),
		}, "client id"},
		{"verification without sender", []authall.Option{
			authall.WithStore(s),
			authall.WithEmailPassword(authall.EmailPasswordOptions{RequireEmailVerification: true}),
		}, "email sender"},
		{"relative base url", []authall.Option{
			authall.WithStore(s), authall.WithBaseURL("app.example.com"),
		}, "absolute"},
		{"relative trusted origin", []authall.Option{
			authall.WithStore(s), authall.WithTrustedOrigins("app.example.com"),
		}, "absolute"},
		{"invalid trusted proxy", []authall.Option{
			authall.WithStore(s), authall.WithTrustedProxies("10.0.0.0/64"),
		}, "trusted proxy"},
		{"trusted proxy that is not an address", []authall.Option{
			authall.WithStore(s), authall.WithTrustedProxies("proxy.example.com"),
		}, "trusted proxy"},
		{"idle timeout above the absolute lifetime", []authall.Option{
			authall.WithStore(s),
			authall.WithSessionLifetime(48*time.Hour, 24*time.Hour),
		}, "idle timeout"},
		{"impossible password policy", []authall.Option{
			authall.WithStore(s),
			authall.WithPasswordPolicy(authall.PasswordPolicy{MinLength: 12, MaxLength: 4}),
		}, "maximum length"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := authall.New(tc.opts...)
			if err == nil {
				t.Fatalf("the configuration was accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("unexpected error %q, want a mention of %q", err, tc.want)
			}
		})
	}
}

func TestConfigurableBasePathAndCookieName(t *testing.T) {
	h := testsupport.NewHarness(t,
		authall.WithEmailPassword(),
		authall.WithBasePath("/auth"),
		authall.WithCookie(authall.CookieOptions{Name: "my_session", Secure: boolPtr(false)}))
	resp := h.Do(http.MethodPost, "/sign-up/email", map[string]string{
		"email": "paths@example.com", "password": testPassword,
	})
	if resp.Status != http.StatusCreated {
		t.Fatalf("status %d: %s", resp.Status, string(resp.Body))
	}
	if h.Auth.BasePath() != "/auth" {
		t.Fatalf("unexpected base path %q", h.Auth.BasePath())
	}
	found := false
	for _, c := range resp.Cookies {
		if c.Name == "my_session" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the configured cookie name was not used: %+v", resp.Cookies)
	}
}

func TestPasswordPolicyIsConfigurable(t *testing.T) {
	h := testsupport.NewHarness(t,
		authall.WithEmailPassword(),
		authall.WithPasswordPolicy(authall.PasswordPolicy{MinLength: 20, MaxLength: 100}))
	resp := h.Do(http.MethodPost, "/sign-up/email", map[string]string{
		"email": "policy@example.com", "password": "short",
	})
	if code := resp.ErrorCode(t); code != "WEAK_PASSWORD" {
		t.Fatalf("unexpected code %q", code)
	}
	// The default policy imposes no character classes.
	ok := h.Do(http.MethodPost, "/sign-up/email", map[string]string{
		"email": "policy@example.com", "password": "aaaaaaaaaaaaaaaaaaaaaaa",
	})
	if ok.Status != http.StatusCreated {
		t.Fatalf("a long simple password was rejected: %s", string(ok.Body))
	}
}

func TestStableErrorCodes(t *testing.T) {
	// The error codes are part of the public compatibility surface.
	want := map[apierr.Code]int{
		apierr.CodeInvalidRequest:     http.StatusBadRequest,
		apierr.CodeInvalidCredentials: http.StatusUnauthorized,
		apierr.CodeEmailAlreadyExists: http.StatusConflict,
		apierr.CodeWeakPassword:       http.StatusBadRequest,
		apierr.CodeInvalidToken:       http.StatusBadRequest,
		apierr.CodeUnauthorized:       http.StatusUnauthorized,
		apierr.CodeForbidden:          http.StatusForbidden,
		apierr.CodeOriginNotAllowed:   http.StatusForbidden,
		apierr.CodeLastAuthMethod:     http.StatusConflict,
		apierr.CodeRateLimited:        http.StatusTooManyRequests,
		apierr.CodeInternal:           http.StatusInternalServerError,
	}
	actual := map[apierr.Code]int{}
	for _, e := range []*apierr.Error{
		apierr.ErrInvalidRequest, apierr.ErrInvalidCredentials, apierr.ErrEmailAlreadyExists,
		apierr.ErrWeakPassword, apierr.ErrInvalidToken, apierr.ErrUnauthorized,
		apierr.ErrForbidden, apierr.ErrOriginNotAllowed, apierr.ErrLastAuthMethod,
		apierr.ErrRateLimited, apierr.ErrInternal,
	} {
		actual[e.Code] = e.Status
	}
	for code, status := range want {
		if actual[code] != status {
			t.Fatalf("the code %s maps to status %d, want %d", code, actual[code], status)
		}
	}
}

func TestUnknownErrorsBecomeInternal(t *testing.T) {
	e := apierr.From(errString("a database detail with SELECT * FROM auth_users"))
	if e.Code != apierr.CodeInternal {
		t.Fatalf("unexpected code %s", e.Code)
	}
	if strings.Contains(e.Message, "SELECT") {
		t.Fatalf("the public message leaks the cause: %s", e.Message)
	}
	if e.Unwrap() == nil {
		t.Fatalf("the private cause was dropped")
	}
}

type errString string

func (e errString) Error() string { return string(e) }

func boolPtr(v bool) *bool { return &v }

// captureHandler collects the log records of one Auth-All construction.
type captureHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *captureHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r)
	return nil
}

func (h *captureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }

func (h *captureHandler) WithGroup(string) slog.Handler { return h }

// warnings returns the messages of the collected warnings.
func (h *captureHandler) warnings() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []string
	for _, r := range h.records {
		if r.Level == slog.LevelWarn {
			out = append(out, r.Message)
		}
	}
	return out
}

// TestConfigWarnsWithoutARateLimiter checks that a silent production start
// becomes loud. The default configuration has no limiter, so every sensitive
// endpoint accepts unlimited attempts.
func TestConfigWarnsWithoutARateLimiter(t *testing.T) {
	s := testsupport.NewSQLite(t)
	capture := &captureHandler{}
	if _, err := authall.New(
		authall.WithStore(s),
		authall.WithEmailPassword(),
		authall.WithLogger(slog.New(capture)),
	); err != nil {
		t.Fatal(err)
	}
	warnings := capture.warnings()
	if len(warnings) != 1 {
		t.Fatalf("expected exactly one warning, got %d: %v", len(warnings), warnings)
	}
	message := warnings[0]
	for _, want := range []string{"rate limiter", "WithRateLimiter", "WithStrictRateLimiting"} {
		if !strings.Contains(message, want) {
			t.Fatalf("the warning misses %q: %s", want, message)
		}
	}

	// A configured limiter produces no warning.
	quiet := &captureHandler{}
	if _, err := authall.New(
		authall.WithStore(s),
		authall.WithEmailPassword(),
		authall.WithLogger(slog.New(quiet)),
		authall.WithRateLimiter(ratelimit.NewMemory(10, time.Minute)),
	); err != nil {
		t.Fatal(err)
	}
	if got := quiet.warnings(); len(got) != 0 {
		t.Fatalf("a configured limiter still warned: %v", got)
	}
}

// TestConfigStrictRateLimiting checks that the strict option fails the
// construction instead of a warning.
func TestConfigStrictRateLimiting(t *testing.T) {
	s := testsupport.NewSQLite(t)
	_, err := authall.New(
		authall.WithStore(s),
		authall.WithEmailPassword(),
		authall.WithStrictRateLimiting(),
	)
	if err == nil {
		t.Fatalf("the construction accepted a missing rate limiter")
	}
	for _, want := range []string{"rate limiter", "WithRateLimiter"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the error misses %q: %v", want, err)
		}
	}

	// The strict option accepts a configured limiter.
	if _, err := authall.New(
		authall.WithStore(s),
		authall.WithEmailPassword(),
		authall.WithStrictRateLimiting(),
		authall.WithRateLimiter(ratelimit.NewMemory(10, time.Minute)),
	); err != nil {
		t.Fatalf("the strict option rejected a configured limiter: %v", err)
	}
}
