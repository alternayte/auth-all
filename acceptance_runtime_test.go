package authall_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"

	authall "github.com/alternayte/auth-all"
	"github.com/alternayte/auth-all/apierr"
	"github.com/alternayte/auth-all/email"
	"github.com/alternayte/auth-all/internal/testsupport"
	"github.com/alternayte/auth-all/oauth"
	"github.com/alternayte/auth-all/oauth/github"
	"github.com/alternayte/auth-all/plugins/magiclink"
	"github.com/alternayte/auth-all/plugins/oauthprovider"
)

// runtimeValue is a host setting that an administrator changes while the
// process runs.
type runtimeValue[T any] struct {
	mu  sync.Mutex
	v   T
	err error
}

func (r *runtimeValue[T]) set(v T) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.v, r.err = v, nil
}

func (r *runtimeValue[T]) fail(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.err = err
}

func (r *runtimeValue[T]) get(context.Context) (T, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.v, r.err
}

func newGitHubProvider(t *testing.T) (oauth.Provider, *testsupport.FakeGitHub) {
	t.Helper()
	gh := testsupport.NewFakeGitHub(t)
	authURL, tokenURL, userURL, emailsURL := gh.Endpoints()
	return github.New(
		github.WithClientID("github-client-id"),
		github.WithClientSecret("github-client-secret"),
		github.WithEndpoints(authURL, tokenURL, userURL, emailsURL),
	), gh
}

// TestOAuthProviderSourceAppliesAtRunTime proves that a provider that the host
// adds after New serves the next request, and that a provider the host removes
// stops at once, also for a flow that started before the change.
func TestOAuthProviderSourceAppliesAtRunTime(t *testing.T) {
	providers := &runtimeValue[[]oauth.Provider]{}
	h := emailPasswordHarness(t, authall.WithProviderSource(providers.get))
	ctx := context.Background()

	if resp := h.Do(http.MethodGet, "/oauth/github", nil); resp.Status != http.StatusNotFound ||
		resp.ErrorCode(t) != string(apierr.CodeProviderNotFound) {
		t.Fatalf("an empty source served a start: %d %s", resp.Status, string(resp.Body))
	}

	gh, _ := newGitHubProvider(t)
	providers.set([]oauth.Provider{gh})
	ids, err := h.Auth.ProviderIDs(ctx)
	if err != nil || len(ids) != 1 || ids[0] != "github" {
		t.Fatalf("ProviderIDs = %v, %v, want [github]", ids, err)
	}
	resp := h.Do(http.MethodGet, "/oauth/github", nil)
	if resp.Status != http.StatusFound {
		t.Fatalf("an added provider got %d: %s", resp.Status, string(resp.Body))
	}
	state := testsupport.QueryParam(t, resp.Location(), "state")
	callback := "/oauth/github/callback?code=valid-code&state=" + state

	// The administrator removes the provider between the start and the
	// callback.
	providers.set(nil)
	out := h.Do(http.MethodGet, callback, nil)
	if out.Status != http.StatusNotFound || out.ErrorCode(t) != string(apierr.CodeProviderNotFound) {
		t.Fatalf("the callback of a removed provider got %d: %s", out.Status, string(out.Body))
	}

	// A source failure is an internal error, never a sign-in.
	providers.fail(errors.New("settings unavailable"))
	if resp := h.Do(http.MethodGet, "/oauth/github", nil); resp.Status != http.StatusInternalServerError {
		t.Fatalf("a failed source got %d, want 500", resp.Status)
	}
}

// TestOAuthProviderSourceChecksEachProvider proves that the checks of New run
// on a provider of a source when a request uses it.
func TestOAuthProviderSourceChecksEachProvider(t *testing.T) {
	gh, _ := newGitHubProvider(t)
	cases := map[string][]oauth.Provider{
		"no client secret": {github.New(github.WithClientID("id"))},
		"a shared id":      {gh, gh},
	}
	for name, list := range cases {
		t.Run(name, func(t *testing.T) {
			providers := &runtimeValue[[]oauth.Provider]{}
			providers.set(list)
			h := emailPasswordHarness(t, authall.WithProviderSource(providers.get))
			if resp := h.Do(http.MethodGet, "/oauth/github", nil); resp.Status != http.StatusInternalServerError {
				t.Fatalf("got %d, want 500: %s", resp.Status, string(resp.Body))
			}
		})
	}
}

// TestConfigEmailSenderSourceAppliesAtRunTime proves that each message goes
// to the sender that the source returns at that moment, and that a nil sender
// keeps the behaviour of no sender.
func TestConfigEmailSenderSourceAppliesAtRunTime(t *testing.T) {
	first, second := &testsupport.MailBox{}, &testsupport.MailBox{}
	sender := &runtimeValue[email.Sender]{}
	sender.set(first)
	// A source lets New accept a required verification, because the host
	// can configure the sender later.
	h := emailPasswordHarness(t, authall.WithEmailSenderSource(sender.get))
	h.SignUp("alice@example.com", testPassword)

	forgot := func() {
		t.Helper()
		resp := h.Do(http.MethodPost, "/password/forgot", map[string]any{"email": "alice@example.com"})
		if resp.Status != http.StatusOK {
			t.Fatalf("forgot got %d: %s", resp.Status, string(resp.Body))
		}
	}
	forgot()
	if first.Count() != 1 {
		t.Fatalf("the first sender got %d messages, want 1", first.Count())
	}
	sender.set(second)
	forgot()
	if first.Count() != 1 || second.Count() != 1 {
		t.Fatalf("after the change the senders got %d and %d messages, want 1 and 1", first.Count(), second.Count())
	}
	sender.set(nil)
	forgot()
	sender.fail(errors.New("settings unavailable"))
	forgot()
	if first.Count() != 1 || second.Count() != 1 || h.Mail.Count() != 0 {
		t.Fatalf("no sender still delivered a message")
	}
}

// TestConfigEmailSenderSourceAcceptsRequiredVerification proves that New does
// not refuse a required verification when the sender comes from a source.
func TestConfigEmailSenderSourceAcceptsRequiredVerification(t *testing.T) {
	sender := &runtimeValue[email.Sender]{}
	_, err := authall.New(
		authall.WithStore(testsupport.NewSQLite(t)),
		authall.WithEmailPassword(authall.EmailPasswordOptions{RequireEmailVerification: true}),
		authall.WithEmailSenderSource(sender.get),
	)
	if err != nil {
		t.Fatalf("New refused a sender source: %v", err)
	}
}

// TestConfigBaseURLSourceAppliesAtRunTime proves that the trusted origin, the
// redirect check, the email links, and the OAuth callback URI follow the base
// URL that the source returns now.
func TestConfigBaseURLSourceAppliesAtRunTime(t *testing.T) {
	const moved = "https://moved.example.com"
	base := &runtimeValue[string]{}
	gh, _ := newGitHubProvider(t)
	h := emailPasswordHarness(t, authall.WithBaseURLSource(base.get), authall.WithProvider(gh))
	h.Handle("/host/write", h.Auth.RequireAuth(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })))
	base.set(h.BaseURL)
	h.SignUp("alice@example.com", testPassword)

	fromMoved := testsupport.WithHeader("Origin", moved)
	change := map[string]any{"currentPassword": testPassword, "newPassword": testPassword}
	if resp := h.Do(http.MethodPost, "/password/change", change, fromMoved); resp.Status != http.StatusForbidden {
		t.Fatalf("an untrusted origin got %d on an Auth-All route, want 403", resp.Status)
	}
	if resp := h.DoURL(http.MethodPost, h.BaseURL+"/host/write", nil, fromMoved); resp.Status != http.StatusForbidden {
		t.Fatalf("an untrusted origin got %d on a host route, want 403", resp.Status)
	}

	base.set(moved + "/")
	if resp := h.Do(http.MethodPost, "/password/change", change, fromMoved); resp.Status != http.StatusOK {
		t.Fatalf("the new origin got %d on an Auth-All route: %s", resp.Status, string(resp.Body))
	}
	if resp := h.DoURL(http.MethodPost, h.BaseURL+"/host/write", nil, fromMoved); resp.Status != http.StatusOK {
		t.Fatalf("the new origin got %d on a host route: %s", resp.Status, string(resp.Body))
	}

	h.Mail.Reset()
	h.Do(http.MethodPost, "/password/forgot", map[string]any{
		"email": "alice@example.com", "redirectTo": moved + "/welcome"})
	msg := h.Mail.Last(t, email.IntentResetPassword)
	if !strings.HasPrefix(msg.URL, moved+"/reset-password?") {
		t.Fatalf("the reset link %q does not use the new base URL", msg.URL)
	}
	if !strings.Contains(msg.URL, "redirectTo=https%3A%2F%2Fmoved.example.com%2Fwelcome") {
		t.Fatalf("the redirect check refused the new origin: %q", msg.URL)
	}

	resp := h.Do(http.MethodGet, "/oauth/github", nil)
	if resp.Status != http.StatusFound {
		t.Fatalf("the start got %d: %s", resp.Status, string(resp.Body))
	}
	want := moved + h.Auth.BasePath() + "/oauth/github/callback"
	if got := testsupport.QueryParam(t, resp.Location(), "redirect_uri"); got != want {
		t.Fatalf("the callback URI = %q, want %q", got, want)
	}

	// A value that is not absolute fails the request that needs it.
	base.set("moved.example.com")
	if resp := h.Do(http.MethodPost, "/password/change", change, fromMoved); resp.Status != http.StatusInternalServerError {
		t.Fatalf("an invalid base URL got %d, want 500", resp.Status)
	}
	if resp := h.Do(http.MethodGet, "/oauth/github", nil); resp.Status != http.StatusInternalServerError {
		t.Fatalf("an invalid base URL served a start: %d", resp.Status)
	}
}

// TestPluginMagicLinkReadsTheRuntimeValues proves that the Magic Link plugin
// sends through the current sender and links to the current base URL.
func TestPluginMagicLinkReadsTheRuntimeValues(t *testing.T) {
	const moved = "https://moved.example.com"
	box := &testsupport.MailBox{}
	sender := &runtimeValue[email.Sender]{}
	base := &runtimeValue[string]{}
	h := testsupport.NewHarness(t,
		authall.WithBaseURLSource(base.get),
		authall.WithEmailSenderSource(sender.get),
		authall.WithPlugins(magiclink.New()))
	base.set(moved)
	sender.set(box)

	resp := h.Do(http.MethodPost, "/magic-link/send", map[string]any{"email": "bob@example.com"})
	if resp.Status != http.StatusOK {
		t.Fatalf("send got %d: %s", resp.Status, string(resp.Body))
	}
	msg := box.Last(t, email.IntentMagicLink)
	if !strings.HasPrefix(msg.URL, moved+h.Auth.BasePath()+"/magic-link/verify?") {
		t.Fatalf("the link %q does not use the new base URL", msg.URL)
	}
	if h.Mail.Count() != 0 {
		t.Fatalf("the plugin used the static sender")
	}
}

// TestPluginOAuthProviderRefusesABaseURLSource proves that the authorization
// server does not build its issuer from a value that can change.
func TestPluginOAuthProviderRefusesABaseURLSource(t *testing.T) {
	base := &runtimeValue[string]{}
	_, err := authall.New(
		authall.WithStore(testsupport.NewSQLite(t)),
		authall.WithBaseURLSource(base.get),
		authall.WithPlugins(oauthprovider.New(
			oauthprovider.KeyEncryptionKey(make([]byte, 32)),
			oauthprovider.LoginPath("/sign-in"),
			oauthprovider.ConsentPath("/consent"),
		)),
	)
	if err == nil || !strings.Contains(err.Error(), "fixed base URL") {
		t.Fatalf("New = %v, want the fixed base URL error", err)
	}
}
