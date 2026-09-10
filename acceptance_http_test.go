package authall_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	authall "github.com/alternayte/auth-all"
	"github.com/alternayte/auth-all/apierr"
	"github.com/alternayte/auth-all/internal/crypto"
	"github.com/alternayte/auth-all/internal/testsupport"
	"github.com/alternayte/auth-all/ratelimit"
)

// TestSCNHTTP001ConstructionRefusesAnUnusableConfiguration proves
// REQ-HTTP-001, REQ-HTTP-002 and REQ-HTTP-003.
func TestSCNHTTP001ConstructionRefusesAnUnusableConfiguration(t *testing.T) {
	s := testsupport.NewSQLite(t)
	for _, name := range []string{"bad name", "bad;name", "bad=name", "bad\tname", "bad\"name"} {
		_, err := authall.New(authall.WithStore(s), authall.WithCookie(authall.CookieOptions{Name: name}))
		if err == nil {
			t.Fatalf("the cookie name %q was accepted", name)
		}
	}
	insecure := false
	auth, err := authall.New(authall.WithStore(s), authall.WithCookie(authall.CookieOptions{
		Name: "app.session", Domain: "example.com", Path: "/app",
		SameSite: http.SameSiteStrictMode, Secure: &insecure,
	}))
	if err != nil {
		t.Fatalf("a valid cookie configuration failed: %v", err)
	}
	if auth == nil {
		t.Fatal("no instance")
	}

	weak := []crypto.Argon2Params{
		{Memory: 8 * 1024, Iterations: 2, Parallelism: 2, SaltLength: 16, KeyLength: 32},
		{Memory: 64 * 1024, Iterations: 0, Parallelism: 2, SaltLength: 16, KeyLength: 32},
		{Memory: 64 * 1024, Iterations: 2, Parallelism: 0, SaltLength: 16, KeyLength: 32},
	}
	for _, p := range weak {
		if _, err := authall.New(authall.WithStore(s), authall.WithArgon2Params(p)); err == nil {
			t.Fatalf("the argon2id parameters %+v were accepted", p)
		}
	}
	strong := crypto.Argon2Params{Memory: 19 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}
	if _, err := authall.New(authall.WithStore(s), authall.WithArgon2Params(strong)); err != nil {
		t.Fatalf("the minimum argon2id parameters were refused: %v", err)
	}
}

// newCodes names every stable error code of the v0.3.0 release with its status.
var newCodes = []struct {
	err    *apierr.Error
	code   string
	status int
}{
	{apierr.ErrInsufficientRole, "INSUFFICIENT_ROLE", http.StatusForbidden},
	{apierr.ErrRoleUnknown, "ROLE_UNKNOWN", http.StatusBadRequest},
	{apierr.ErrRoleNotAllowed, "ROLE_NOT_ALLOWED", http.StatusForbidden},
	{apierr.ErrUserDisabled, "USER_DISABLED", http.StatusForbidden},
	{apierr.ErrPasswordChangeRequired, "PASSWORD_CHANGE_REQUIRED", http.StatusForbidden},
	{apierr.ErrLastAdmin, "LAST_ADMIN", http.StatusConflict},
	{apierr.ErrAPIKeyExpiryTooLong, "API_KEY_EXPIRY_TOO_LONG", http.StatusBadRequest},
	{apierr.ErrAPIKeyExpiryRequired, "API_KEY_EXPIRY_REQUIRED", http.StatusBadRequest},
}

// TestSCNHTTP002EveryNewCodeHasAStatusAndAMessage proves REQ-HTTP-004. The test
// fails when a released code string changes.
func TestSCNHTTP002EveryNewCodeHasAStatusAndAMessage(t *testing.T) {
	for _, c := range newCodes {
		if string(c.err.Code) != c.code {
			t.Fatalf("the code is %q, want %q", c.err.Code, c.code)
		}
		if c.err.Status != c.status {
			t.Fatalf("the code %s has status %d, want %d", c.code, c.err.Status, c.status)
		}
		if strings.TrimSpace(c.err.Message) == "" {
			t.Fatalf("the code %s has no message", c.code)
		}
	}
}

// hostEnvelope is the error shape of the host writer.
type hostEnvelope struct {
	Detail string `json:"detail"`
	Code   string `json:"code"`
	Status int    `json:"status"`
}

// TestSCNHTTP003TheHostWriterShapesEveryError proves REQ-HTTP-005,
// REQ-HTTP-006 and REQ-HTTP-007.
func TestSCNHTTP003TheHostWriterShapesEveryError(t *testing.T) {
	var seenCause bool
	writer := func(w http.ResponseWriter, r *http.Request, e *authall.Error) {
		if e.Unwrap() != nil {
			seenCause = true
		}
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(e.Status)
		_ = json.NewEncoder(w).Encode(hostEnvelope{Detail: e.Message, Code: string(e.Code), Status: e.Status})
	}
	h := testsupport.NewHarness(t,
		authall.WithEmailPassword(),
		authall.WithErrorWriter(writer),
		authall.WithRateLimiter(ratelimit.NewMemory(1, time.Minute)),
	)

	// A core route error takes the host shape.
	resp := h.Do(http.MethodPost, "/sign-in/email", map[string]string{
		"email": "nobody@example.com", "password": "wrong-password-value",
	})
	if resp.Status != http.StatusUnauthorized {
		t.Fatalf("status %d: %s", resp.Status, string(resp.Body))
	}
	var body hostEnvelope
	resp.Decode(t, &body)
	if body.Code != string(apierr.CodeInvalidCredentials) || body.Detail == "" {
		t.Fatalf("the host writer did not shape the error: %+v", body)
	}

	// The second attempt is over the limit. The Retry-After header survives.
	resp = h.Do(http.MethodPost, "/sign-in/email", map[string]string{
		"email": "nobody@example.com", "password": "wrong-password-value",
	})
	if resp.Status != http.StatusTooManyRequests {
		t.Fatalf("status %d: %s", resp.Status, string(resp.Body))
	}
	if resp.Header.Get("Retry-After") == "" {
		t.Fatal("the 429 response has no Retry-After header")
	}
	resp.Decode(t, &body)
	if body.Code != string(apierr.CodeRateLimited) {
		t.Fatalf("the 429 body is not the host shape: %+v", body)
	}

	// RequireAuth takes the host shape too.
	h.Handle("/private", h.Auth.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	out := h.DoURL(http.MethodGet, h.BaseURL+"/private", nil)
	if out.Status != http.StatusUnauthorized {
		t.Fatalf("status %d", out.Status)
	}
	out.Decode(t, &body)
	if body.Code != string(apierr.CodeUnauthorized) {
		t.Fatalf("RequireAuth did not use the host writer: %+v", body)
	}
	if seenCause {
		t.Fatal("the host writer received a private cause")
	}
}

// TestSCNHTTP004TheHandlerServesUnderEveryRouter proves REQ-HTTP-008 and
// REQ-HTTP-009.
func TestSCNHTTP004TheHandlerServesUnderEveryRouter(t *testing.T) {
	s := testsupport.NewSQLite(t)
	insecure := false
	auth, err := authall.New(
		authall.WithStore(s),
		authall.WithEmailPassword(),
		authall.WithBaseURL("https://app.example.com"),
		authall.WithCookie(authall.CookieOptions{Secure: &insecure}),
	)
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	mounts := map[string]http.Handler{}
	// A plain ServeMux mount, which is the documented default.
	plain := http.NewServeMux()
	plain.Handle(auth.BasePath()+"/", auth.Handler())
	mounts["ServeMux"] = plain
	// A router that removes the base path itself, which chi Mount does.
	stripped := http.NewServeMux()
	stripped.Handle(auth.BasePath()+"/", http.StripPrefix(auth.BasePath(), auth.HandlerStripped()))
	mounts["StripPrefix"] = stripped

	for name, handler := range mounts {
		t.Run(name, func(t *testing.T) {
			body := `{"email":"` + strings.ToLower(name) + `@example.com","password":"correct horse battery"}`
			req := httptest.NewRequest(http.MethodPost, auth.BasePath()+"/sign-up/email", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Origin", "https://app.example.com")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusCreated {
				out, _ := io.ReadAll(rec.Body)
				t.Fatalf("status %d: %s", rec.Code, string(out))
			}
		})
	}
}
