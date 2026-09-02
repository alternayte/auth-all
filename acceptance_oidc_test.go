package authall_test

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	authall "github.com/alternayte/auth-all"
	"github.com/alternayte/auth-all/internal/testsupport"
	"github.com/alternayte/auth-all/oauth/oidc"
)

// oidcFixture holds a harness and the fake issuers behind it.
type oidcFixture struct {
	h      *testsupport.Harness
	first  *testsupport.FakeGoogle
	second *testsupport.FakeGoogle
}

// newOIDCFixture builds a harness with two generic OpenID Connect providers.
func newOIDCFixture(t *testing.T) *oidcFixture {
	t.Helper()
	const clientID = "oidc-app"
	first := testsupport.NewFakeGoogle(t, clientID)
	second := testsupport.NewFakeGoogle(t, clientID)

	h := testsupport.NewHarness(t,
		authall.WithEmailPassword(),
		authall.WithProvider(oidc.New(
			oidc.WithIssuer(first.Issuer()),
			oidc.WithID("first"),
			oidc.WithClientID(clientID),
			oidc.WithClientSecret("secret-1"),
		)),
		authall.WithProvider(oidc.New(
			oidc.WithIssuer(second.Issuer()),
			oidc.WithID("second"),
			oidc.WithClientID(clientID),
			oidc.WithClientSecret("secret-2"),
		)),
	)
	return &oidcFixture{h: h, first: first, second: second}
}

// start begins a sign-in and returns the state.
func (f *oidcFixture) start(t *testing.T, provider string, issuer *testsupport.FakeGoogle) string {
	t.Helper()
	resp := f.h.Do(http.MethodGet, "/oauth/"+provider, nil)
	if resp.Status != http.StatusFound {
		t.Fatalf("expected a redirect, got %d: %s", resp.Status, string(resp.Body))
	}
	location := resp.Location()
	issuer.SetNonce(testsupport.QueryParam(t, location, "nonce"))
	issuer.SetExpectedChallenge(testsupport.QueryParam(t, location, "code_challenge"))
	return testsupport.QueryParam(t, location, "state")
}

// callback completes a sign-in.
func (f *oidcFixture) callback(t *testing.T, provider, state string) *testsupport.Response {
	t.Helper()
	target := "/oauth/" + provider + "/callback?code=" + url.QueryEscape("valid-code") +
		"&state=" + url.QueryEscape(state)
	return f.h.Do(http.MethodGet, target, nil)
}

// TestOIDCProviderSignsAUserIn covers the complete flow through Auth-All. The
// provider reaches the routes, the discovery, and the account table.
func TestOIDCProviderSignsAUserIn(t *testing.T) {
	f := newOIDCFixture(t)
	f.first.SetAccount("subject-1", "person@example.com", true)

	state := f.start(t, "first", f.first)
	resp := f.callback(t, "first", state)
	if resp.Status != http.StatusFound {
		t.Fatalf("the callback returned %d: %s", resp.Status, string(resp.Body))
	}
	session := f.h.GetSession()
	if session.User == nil {
		t.Fatal("the callback opened no session")
	}
	if session.User.Email != "person@example.com" {
		t.Fatalf("the session names %q", session.User.Email)
	}

	// The account is stored under the provider identifier of the issuer.
	accounts, err := f.h.Auth.Accounts(context.Background(), session.User.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(accounts) != 1 || accounts[0].Provider != "first" {
		t.Fatalf("the accounts are %+v", accounts)
	}
	if accounts[0].ProviderAccountID != "subject-1" {
		t.Fatalf("the account id is %q", accounts[0].ProviderAccountID)
	}
}

// TestTwoIssuersWithOneSubjectProduceTwoAccounts covers the property that keeps
// two identity servers apart.
//
// A subject is unique inside one issuer and nowhere else. Two issuers that both
// report "subject-1" name two different people, so a shared account row would
// let one issuer sign in as a user of the other.
func TestTwoIssuersWithOneSubjectProduceTwoAccounts(t *testing.T) {
	f := newOIDCFixture(t)
	const subject = "subject-1"
	f.first.SetAccount(subject, "first-person@example.com", true)
	f.second.SetAccount(subject, "second-person@example.com", true)

	state := f.start(t, "first", f.first)
	if resp := f.callback(t, "first", state); resp.Status != http.StatusFound {
		t.Fatalf("the first callback returned %d", resp.Status)
	}
	firstUser := f.h.GetSession().User
	if firstUser == nil {
		t.Fatal("the first sign-in opened no session")
	}

	f.h.ClearCookies()
	state = f.start(t, "second", f.second)
	if resp := f.callback(t, "second", state); resp.Status != http.StatusFound {
		t.Fatalf("the second callback returned %d", resp.Status)
	}
	secondUser := f.h.GetSession().User
	if secondUser == nil {
		t.Fatal("the second sign-in opened no session")
	}

	if firstUser.ID == secondUser.ID {
		t.Fatal("two issuers that report one subject produced one user")
	}

	// Each account belongs to its own issuer.
	firstAccounts, err := f.h.Auth.Accounts(context.Background(), firstUser.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(firstAccounts) != 1 || firstAccounts[0].Provider != "first" {
		t.Fatalf("the first accounts are %+v", firstAccounts)
	}
	secondAccounts, err := f.h.Auth.Accounts(context.Background(), secondUser.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(secondAccounts) != 1 || secondAccounts[0].Provider != "second" {
		t.Fatalf("the second accounts are %+v", secondAccounts)
	}
}

// TestOIDCProviderRoutesUseTheIdentifier checks that the routes carry the
// configured identifier.
func TestOIDCProviderRoutesUseTheIdentifier(t *testing.T) {
	f := newOIDCFixture(t)
	// An unknown provider is refused, so the identifier is the only key.
	resp := f.h.Do(http.MethodGet, "/oauth/unknown-issuer", nil)
	if resp.Status != http.StatusNotFound {
		t.Fatalf("status %d: %s", resp.Status, string(resp.Body))
	}
	if code := resp.ErrorCode(t); code != "PROVIDER_NOT_FOUND" {
		t.Fatalf("the error code is %q", code)
	}
}
