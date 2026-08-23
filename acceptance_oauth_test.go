package authall_test

import (
	"context"
	"net/http"
	"net/url"
	"sync"
	"testing"

	authall "github.com/alternayte/auth-all"
	"github.com/alternayte/auth-all/internal/testsupport"
	"github.com/alternayte/auth-all/oauth/github"
	"github.com/alternayte/auth-all/oauth/google"
)

const googleClientID = "google-client-id"

type oauthFixture struct {
	h      *testsupport.Harness
	github *testsupport.FakeGitHub
	google *testsupport.FakeGoogle
}

func newOAuthFixture(t *testing.T, opts ...authall.Option) *oauthFixture {
	t.Helper()
	gh := testsupport.NewFakeGitHub(t)
	gg := testsupport.NewFakeGoogle(t, googleClientID)
	ghAuth, ghToken, ghUser, ghEmails := gh.Endpoints()
	ggAuth, ggToken, ggJWKS, ggIssuer := gg.Endpoints()

	base := []authall.Option{
		authall.WithEmailPassword(),
		authall.WithProvider(github.New(
			github.WithClientID("github-client-id"),
			github.WithClientSecret("github-client-secret"),
			github.WithEndpoints(ghAuth, ghToken, ghUser, ghEmails),
		)),
		authall.WithProvider(google.New(
			google.WithClientID(googleClientID),
			google.WithClientSecret("google-client-secret"),
			google.WithEndpoints(ggAuth, ggToken, ggJWKS, ggIssuer),
		)),
	}
	h := testsupport.NewHarness(t, append(base, opts...)...)
	return &oauthFixture{h: h, github: gh, google: gg}
}

// startGitHub returns the state of a started GitHub authorization.
func (f *oauthFixture) startGitHub(t *testing.T) string {
	t.Helper()
	resp := f.h.Do(http.MethodGet, "/oauth/github", nil)
	if resp.Status != http.StatusFound {
		t.Fatalf("expected a redirect, got %d: %s", resp.Status, string(resp.Body))
	}
	return testsupport.QueryParam(t, resp.Location(), "state")
}

// startGoogle prepares the fake provider and returns the state.
func (f *oauthFixture) startGoogle(t *testing.T) string {
	t.Helper()
	resp := f.h.Do(http.MethodGet, "/oauth/google", nil)
	if resp.Status != http.StatusFound {
		t.Fatalf("expected a redirect, got %d: %s", resp.Status, string(resp.Body))
	}
	location := resp.Location()
	f.google.SetNonce(testsupport.QueryParam(t, location, "nonce"))
	f.google.SetExpectedChallenge(testsupport.QueryParam(t, location, "code_challenge"))
	if testsupport.QueryParam(t, location, "code_challenge_method") != "S256" {
		t.Fatalf("the Google authorization URL carries no S256 PKCE challenge")
	}
	return testsupport.QueryParam(t, location, "state")
}

func (f *oauthFixture) callback(t *testing.T, provider, code, state string) *testsupport.Response {
	t.Helper()
	target := "/oauth/" + provider + "/callback?code=" + url.QueryEscape(code) + "&state=" + url.QueryEscape(state)
	return f.h.Do(http.MethodGet, target, nil)
}

// TestAUTH014GitHubOAuth covers AUTH-014.
func TestAUTH014GitHubOAuth(t *testing.T) {
	f := newOAuthFixture(t)
	state := f.startGitHub(t)
	resp := f.callback(t, "github", "valid-code", state)
	if resp.Status != http.StatusFound {
		t.Fatalf("callback failed with %d: %s", resp.Status, string(resp.Body))
	}
	session := f.h.GetSession()
	if session.User == nil || session.User.Email != "octo@example.com" {
		t.Fatalf("the callback created no session: %+v", session)
	}
	account, err := f.h.Store.Accounts().GetByProviderAccount(context.Background(), "github", "12345")
	if err != nil {
		t.Fatalf("no external account was created: %v", err)
	}
	if account.UserID != session.User.ID {
		t.Fatalf("the account belongs to another user")
	}
	// A second sign-in resolves the same user instead of creating a new one.
	f.h.ClearCookies()
	state = f.startGitHub(t)
	if resp := f.callback(t, "github", "valid-code", state); resp.Status != http.StatusFound {
		t.Fatalf("the second callback failed: %s", string(resp.Body))
	}
	second := f.h.GetSession()
	if second.User == nil || second.User.ID != session.User.ID {
		t.Fatalf("the second sign-in resolved another user: %+v", second)
	}
}

// TestAUTH015GoogleOAuth covers AUTH-015.
func TestAUTH015GoogleOAuth(t *testing.T) {
	f := newOAuthFixture(t)
	state := f.startGoogle(t)
	resp := f.callback(t, "google", "valid-code", state)
	if resp.Status != http.StatusFound {
		t.Fatalf("callback failed with %d: %s", resp.Status, string(resp.Body))
	}
	session := f.h.GetSession()
	if session.User == nil || session.User.Email != "gopher@example.com" {
		t.Fatalf("the callback created no session: %+v", session)
	}
	if !session.User.EmailVerified {
		t.Fatalf("a verified provider address must mark the user as verified")
	}
	if _, err := f.h.Store.Accounts().GetByProviderAccount(context.Background(), "google", "google-subject-1"); err != nil {
		t.Fatalf("no external account was created: %v", err)
	}
}

// TestAUTH016InvalidOAuthState covers AUTH-016.
func TestAUTH016InvalidOAuthState(t *testing.T) {
	f := newOAuthFixture(t)
	f.startGitHub(t)

	resp := f.callback(t, "github", "valid-code", "not-a-real-state")
	if resp.Status != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d: %s", resp.Status, string(resp.Body))
	}
	if code := resp.ErrorCode(t); code != "OAUTH_STATE_INVALID" {
		t.Fatalf("unexpected code %q", code)
	}
	if session := f.h.GetSession(); session.Session != nil {
		t.Fatalf("an invalid state created a session")
	}
	if _, err := f.h.Store.Accounts().GetByProviderAccount(context.Background(), "github", "12345"); err == nil {
		t.Fatalf("an invalid state created an external account")
	}
}

// TestOAuthStateIsSingleUse checks that a state cannot be replayed.
func TestOAuthStateIsSingleUse(t *testing.T) {
	f := newOAuthFixture(t)
	state := f.startGitHub(t)
	if resp := f.callback(t, "github", "valid-code", state); resp.Status != http.StatusFound {
		t.Fatalf("the first callback failed: %s", string(resp.Body))
	}
	replay := f.callback(t, "github", "valid-code", state)
	if code := replay.ErrorCode(t); code != "OAUTH_STATE_INVALID" {
		t.Fatalf("a replayed state was accepted: %q", code)
	}
}

// TestOAuthStateBelongsToOneProvider checks the provider binding of a state.
func TestOAuthStateBelongsToOneProvider(t *testing.T) {
	f := newOAuthFixture(t)
	state := f.startGitHub(t)
	resp := f.callback(t, "google", "valid-code", state)
	if code := resp.ErrorCode(t); code != "OAUTH_STATE_INVALID" {
		t.Fatalf("a state of another provider was accepted: %q", code)
	}
}

// TestInvalidPKCEVerifierIsRejected covers the PKCE security regression.
func TestInvalidPKCEVerifierIsRejected(t *testing.T) {
	f := newOAuthFixture(t)
	state := f.startGoogle(t)
	// The provider now expects a challenge that the stored verifier cannot
	// produce, which simulates an injected authorization code.
	f.google.SetExpectedChallenge(testsupport.SignChallenge("a-different-verifier"))
	resp := f.callback(t, "google", "valid-code", state)
	if resp.Status != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d: %s", resp.Status, string(resp.Body))
	}
	if code := resp.ErrorCode(t); code != "OAUTH_FAILED" {
		t.Fatalf("unexpected code %q", code)
	}
	if session := f.h.GetSession(); session.Session != nil {
		t.Fatalf("a rejected exchange created a session")
	}
}

// TestInvalidProviderCallbackIsRejected covers the provider error regression.
func TestInvalidProviderCallbackIsRejected(t *testing.T) {
	f := newOAuthFixture(t)
	state := f.startGitHub(t)
	resp := f.callback(t, "github", "invalid-code", state)
	if code := resp.ErrorCode(t); code != "OAUTH_FAILED" {
		t.Fatalf("unexpected code %q", code)
	}

	state = f.startGitHub(t)
	denied := f.h.Do(http.MethodGet, "/oauth/github/callback?error=access_denied&state="+state, nil)
	if code := denied.ErrorCode(t); code != "OAUTH_FAILED" {
		t.Fatalf("unexpected code %q", code)
	}
}

// TestGoogleIdentityTokenValidation checks issuer, nonce, and expiry checks.
func TestGoogleIdentityTokenValidation(t *testing.T) {
	cases := []struct {
		name    string
		prepare func(f *oauthFixture)
	}{
		{"wrong issuer", func(f *oauthFixture) { f.google.SetIssuer("https://evil.example.com") }},
		{"wrong nonce", func(f *oauthFixture) { f.google.SetNonce("a-different-nonce") }},
		{"expired token", func(f *oauthFixture) { f.google.SetExpiryOffset(-2 * 60 * 60 * 1000000000) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newOAuthFixture(t)
			state := f.startGoogle(t)
			tc.prepare(f)
			resp := f.callback(t, "google", "valid-code", state)
			if code := resp.ErrorCode(t); code != "OAUTH_FAILED" {
				t.Fatalf("the invalid identity token was accepted: %q", code)
			}
			if session := f.h.GetSession(); session.Session != nil {
				t.Fatalf("a rejected identity token created a session")
			}
		})
	}
}

// TestAUTH017ExplicitAccountLinking covers AUTH-017.
func TestAUTH017ExplicitAccountLinking(t *testing.T) {
	f := newOAuthFixture(t)
	_, signedUp := f.h.SignUp("linker@example.com", testPassword)

	resp := f.h.Do(http.MethodPost, "/account/link/github", nil)
	if resp.Status != http.StatusOK {
		t.Fatalf("link start failed with %d: %s", resp.Status, string(resp.Body))
	}
	var link struct {
		URL string `json:"url"`
	}
	resp.Decode(t, &link)
	state := testsupport.QueryParam(t, link.URL, "state")

	if cb := f.callback(t, "github", "valid-code", state); cb.Status != http.StatusFound {
		t.Fatalf("the link callback failed: %s", string(cb.Body))
	}
	providers := f.h.Do(http.MethodGet, "/account/providers", nil)
	var list struct {
		Providers []struct {
			Provider  string `json:"provider"`
			AccountID string `json:"accountId"`
		} `json:"providers"`
		HasPassword bool `json:"hasPassword"`
	}
	providers.Decode(t, &list)
	if len(list.Providers) != 1 || list.Providers[0].Provider != "github" {
		t.Fatalf("the provider is not linked: %+v", list)
	}
	if !list.HasPassword {
		t.Fatalf("the password credential disappeared")
	}
	account, err := f.h.Store.Accounts().GetByProviderAccount(context.Background(), "github", "12345")
	if err != nil {
		t.Fatal(err)
	}
	if account.UserID != signedUp.User.ID {
		t.Fatalf("the account was linked to another user")
	}
}

// TestAccountLinkRequiresAuthentication checks the ownership requirement.
func TestAccountLinkRequiresAuthentication(t *testing.T) {
	f := newOAuthFixture(t)
	resp := f.h.Do(http.MethodPost, "/account/link/github", nil)
	if resp.Status != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", resp.Status)
	}
}

// TestProviderIdentityBelongsToOneUser checks the linking ownership invariant.
func TestProviderIdentityBelongsToOneUser(t *testing.T) {
	f := newOAuthFixture(t)
	// The first user links the GitHub identity.
	f.h.SignUp("first@example.com", testPassword)
	resp := f.h.Do(http.MethodPost, "/account/link/github", nil)
	var link struct {
		URL string `json:"url"`
	}
	resp.Decode(t, &link)
	if cb := f.callback(t, "github", "valid-code", testsupport.QueryParam(t, link.URL, "state")); cb.Status != http.StatusFound {
		t.Fatalf("the first link failed")
	}

	// A second user cannot take the same provider identity.
	f.h.ClearCookies()
	f.h.SignUp("second@example.com", testPassword)
	resp = f.h.Do(http.MethodPost, "/account/link/github", nil)
	resp.Decode(t, &link)
	cb := f.callback(t, "github", "valid-code", testsupport.QueryParam(t, link.URL, "state"))
	if code := cb.ErrorCode(t); code != "ACCOUNT_ALREADY_LINKED" {
		t.Fatalf("unexpected code %q", code)
	}
}

// TestAUTH018UnsafeAutoLinkPrevention covers AUTH-018.
func TestAUTH018UnsafeAutoLinkPrevention(t *testing.T) {
	f := newOAuthFixture(t)
	_, signedUp := f.h.SignUp("octo@example.com", testPassword)
	f.h.ClearCookies()

	state := f.startGitHub(t)
	resp := f.callback(t, "github", "valid-code", state)
	if resp.Status != http.StatusConflict {
		t.Fatalf("expected status 409, got %d: %s", resp.Status, string(resp.Body))
	}
	if code := resp.ErrorCode(t); code != "EMAIL_ALREADY_EXISTS" {
		t.Fatalf("unexpected code %q", code)
	}
	if _, err := f.h.Store.Accounts().GetByProviderAccount(context.Background(), "github", "12345"); err == nil {
		t.Fatalf("a matching email silently linked the provider")
	}
	if session := f.h.GetSession(); session.Session != nil {
		t.Fatalf("a matching email created a session for user %s", signedUp.User.ID)
	}
}

// TestVerifiedEmailAutoLinkRequiresOptIn checks the explicit opt-in path.
func TestVerifiedEmailAutoLinkRequiresOptIn(t *testing.T) {
	f := newOAuthFixture(t, authall.WithAccountLinking(authall.AccountLinkingOptions{
		AllowVerifiedEmailAutoLink: true,
	}))
	user, err := f.h.Auth.CreateUser(context.Background(), authall.CreateUserInput{
		Email:         "octo@example.com",
		Password:      testPassword,
		EmailVerified: true,
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	state := f.startGitHub(t)
	if resp := f.callback(t, "github", "valid-code", state); resp.Status != http.StatusFound {
		t.Fatalf("the opt-in auto-link failed: %s", string(resp.Body))
	}
	account, err := f.h.Store.Accounts().GetByProviderAccount(context.Background(), "github", "12345")
	if err != nil {
		t.Fatalf("the account was not linked: %v", err)
	}
	if account.UserID != user.ID {
		t.Fatalf("the account joined the wrong user")
	}
}

// TestAutoLinkNeedsAVerifiedProviderAddress checks the verification requirement.
func TestAutoLinkNeedsAVerifiedProviderAddress(t *testing.T) {
	f := newOAuthFixture(t, authall.WithAccountLinking(authall.AccountLinkingOptions{
		AllowVerifiedEmailAutoLink: true,
	}))
	if _, err := f.h.Auth.CreateUser(context.Background(), authall.CreateUserInput{
		Email: "octo@example.com", Password: testPassword, EmailVerified: true,
	}); err != nil {
		t.Fatal(err)
	}
	f.github.SetAccount(12345, "octo@example.com", false)
	state := f.startGitHub(t)
	resp := f.callback(t, "github", "valid-code", state)
	if code := resp.ErrorCode(t); code != "EMAIL_ALREADY_EXISTS" {
		t.Fatalf("an unverified provider address was auto-linked: %q", code)
	}
}

// TestAUTH019AccountUnlink covers AUTH-019.
func TestAUTH019AccountUnlink(t *testing.T) {
	f := newOAuthFixture(t)
	f.h.SignUp("unlinker@example.com", testPassword)
	resp := f.h.Do(http.MethodPost, "/account/link/github", nil)
	var link struct {
		URL string `json:"url"`
	}
	resp.Decode(t, &link)
	f.callback(t, "github", "valid-code", testsupport.QueryParam(t, link.URL, "state"))

	unlink := f.h.Do(http.MethodPost, "/account/unlink/github", nil)
	if unlink.Status != http.StatusOK {
		t.Fatalf("unlink failed with %d: %s", unlink.Status, string(unlink.Body))
	}
	if _, err := f.h.Store.Accounts().GetByProviderAccount(context.Background(), "github", "12345"); err == nil {
		t.Fatalf("the account is still linked")
	}
	again := f.h.Do(http.MethodPost, "/account/unlink/github", nil)
	if code := again.ErrorCode(t); code != "ACCOUNT_NOT_LINKED" {
		t.Fatalf("unexpected code %q", code)
	}
}

// TestUnlinkKeepsOneAuthenticationMethod covers the AUTH-019 safeguard.
func TestUnlinkKeepsOneAuthenticationMethod(t *testing.T) {
	f := newOAuthFixture(t)
	state := f.startGitHub(t)
	if resp := f.callback(t, "github", "valid-code", state); resp.Status != http.StatusFound {
		t.Fatalf("the OAuth sign-up failed")
	}
	resp := f.h.Do(http.MethodPost, "/account/unlink/github", nil)
	if resp.Status != http.StatusConflict {
		t.Fatalf("expected status 409, got %d: %s", resp.Status, string(resp.Body))
	}
	if code := resp.ErrorCode(t); code != "LAST_AUTH_METHOD" {
		t.Fatalf("unexpected code %q", code)
	}
}

// TestUnknownProviderIsRejected checks the provider lookup.
func TestUnknownProviderIsRejected(t *testing.T) {
	f := newOAuthFixture(t)
	resp := f.h.Do(http.MethodGet, "/oauth/gitlab", nil)
	if code := resp.ErrorCode(t); code != "PROVIDER_NOT_FOUND" {
		t.Fatalf("unexpected code %q", code)
	}
}

// TestConcurrentUnlinkKeepsOneMethod checks that two concurrent unlink
// requests cannot leave a user without an authentication method.
func TestConcurrentUnlinkKeepsOneMethod(t *testing.T) {
	f := newOAuthFixture(t)
	// The user owns two provider accounts and no password.
	state := f.startGitHub(t)
	if resp := f.callback(t, "github", "valid-code", state); resp.Status != http.StatusFound {
		t.Fatalf("the GitHub sign-up failed")
	}
	session := f.h.GetSession()
	resp := f.h.Do(http.MethodPost, "/account/link/google", nil)
	var link struct {
		URL string `json:"url"`
	}
	resp.Decode(t, &link)
	f.google.SetNonce(testsupport.QueryParam(t, link.URL, "nonce"))
	f.google.SetExpectedChallenge(testsupport.QueryParam(t, link.URL, "code_challenge"))
	if cb := f.callback(t, "google", "valid-code", testsupport.QueryParam(t, link.URL, "state")); cb.Status != http.StatusFound {
		t.Fatalf("the Google link failed: %s", string(cb.Body))
	}

	var wg sync.WaitGroup
	for _, provider := range []string{"github", "google"} {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			f.h.Do(http.MethodPost, "/account/unlink/"+p, nil)
		}(provider)
	}
	wg.Wait()

	accounts, err := f.h.Store.Accounts().ListByUser(context.Background(), session.User.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(accounts) == 0 {
		t.Fatalf("the user lost every authentication method")
	}
}

// TestUnlinkCannotRemoveEveryAuthenticationMethod covers the AUTH-019
// safeguard when a user tries to own two accounts of one provider.
func TestUnlinkCannotRemoveEveryAuthenticationMethod(t *testing.T) {
	f := newOAuthFixture(t)
	// The user signs up through GitHub and owns no password.
	state := f.startGitHub(t)
	if resp := f.callback(t, "github", "valid-code", state); resp.Status != http.StatusFound {
		t.Fatalf("the GitHub sign-up failed")
	}
	userID := f.h.GetSession().User.ID

	// A second GitHub identity cannot join the same user.
	f.github.SetAccount(99999, "octo2@example.com", true)
	resp := f.h.Do(http.MethodPost, "/account/link/github", nil)
	var link struct {
		URL string `json:"url"`
	}
	resp.Decode(t, &link)
	second := f.callback(t, "github", "valid-code", testsupport.QueryParam(t, link.URL, "state"))
	if second.Status == http.StatusFound {
		t.Fatalf("a second account of one provider was linked to one user")
	}
	if code := second.ErrorCode(t); code != "ACCOUNT_ALREADY_LINKED" {
		t.Fatalf("unexpected code %q", code)
	}

	// The single remaining method cannot be removed.
	unlink := f.h.Do(http.MethodPost, "/account/unlink/github", nil)
	if unlink.Status != http.StatusConflict {
		t.Fatalf("expected status 409, got %d: %s", unlink.Status, string(unlink.Body))
	}
	accounts, err := f.h.Store.Accounts().ListByUser(context.Background(), userID)
	if err != nil {
		t.Fatal(err)
	}
	_, credErr := f.h.Store.Users().GetCredential(context.Background(), userID)
	if len(accounts) == 0 && credErr != nil {
		t.Fatalf("the user lost every authentication method")
	}
}
