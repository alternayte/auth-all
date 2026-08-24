package authall_test

import (
	"net/http"
	"strings"
	"testing"

	authall "github.com/alternayte/auth-all"
	"github.com/alternayte/auth-all/apierr"
	"github.com/alternayte/auth-all/internal/testsupport"
	"github.com/alternayte/auth-all/oauth/github"
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
