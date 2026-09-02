package oidc_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/alternayte/auth-all/internal/testsupport"
	"github.com/alternayte/auth-all/oauth"
	"github.com/alternayte/auth-all/oauth/oidc"
)

const testClientID = "oidc-client-id"

// newFixture starts a fake issuer and returns a provider that discovers it.
func newFixture(t *testing.T, opts ...oidc.Option) (*oidc.Provider, *testsupport.FakeGoogle) {
	t.Helper()
	fake := testsupport.NewFakeGoogle(t, testClientID)
	base := []oidc.Option{
		oidc.WithIssuer(fake.Issuer()),
		oidc.WithClientID(testClientID),
		oidc.WithClientSecret("oidc-client-secret"),
	}
	return oidc.New(append(base, opts...)...), fake
}

// exchange runs one code exchange against the fake issuer.
func exchange(t *testing.T, p *oidc.Provider, fake *testsupport.FakeGoogle) (*oauth.Identity, error) {
	t.Helper()
	const nonce = "test-nonce"
	fake.SetNonce(nonce)
	return p.Exchange(context.Background(), oauth.ExchangeRequest{
		Code:        "valid-code",
		RedirectURI: "https://app.example.com/callback",
		Nonce:       nonce,
	})
}

// TestNewDoesNoNetworkCall checks that the constructor stays offline. A
// constructor that fetches would make authall.New fail for a briefly
// unreachable issuer.
func TestNewDoesNoNetworkCall(t *testing.T) {
	p := oidc.New(
		oidc.WithIssuer("https://an-issuer-that-does-not-resolve.invalid"),
		oidc.WithClientID("id"),
		oidc.WithClientSecret("secret"),
	)
	if p == nil {
		t.Fatal("New returned nothing")
	}
	if p.ID() == "" {
		t.Fatal("the provider has no id")
	}
}

// TestExchangeReturnsTheIdentity covers the happy path over discovery.
func TestExchangeReturnsTheIdentity(t *testing.T) {
	p, fake := newFixture(t)
	fake.SetAccount("subject-1", "person@example.com", true)

	identity, err := exchange(t, p, fake)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if identity.ProviderAccountID != "subject-1" {
		t.Fatalf("the account id is %q", identity.ProviderAccountID)
	}
	if identity.Email != "person@example.com" {
		t.Fatalf("the address is %q", identity.Email)
	}
	if !identity.EmailVerified {
		t.Fatal("the identity reports an unverified address")
	}
}

// TestProviderAccountIDIsTheSubject checks that the identity never keys on the
// address. An address changes owner, and a subject does not.
func TestProviderAccountIDIsTheSubject(t *testing.T) {
	p, fake := newFixture(t)
	fake.SetAccount("stable-subject", "first@example.com", true)
	first, err := exchange(t, p, fake)
	if err != nil {
		t.Fatal(err)
	}
	fake.SetAccount("stable-subject", "second@example.com", true)
	second, err := exchange(t, p, fake)
	if err != nil {
		t.Fatal(err)
	}
	if first.ProviderAccountID != second.ProviderAccountID {
		t.Fatal("the account id changed with the address")
	}
	if strings.Contains(first.ProviderAccountID, "@") {
		t.Fatalf("the account id is an address: %q", first.ProviderAccountID)
	}
}

// TestAuthCodeURLCarriesTheParameters covers the authorization URL.
func TestAuthCodeURLCarriesTheParameters(t *testing.T) {
	p, fake := newFixture(t)
	got, err := p.AuthCodeURL(oauth.AuthRequest{
		State:         "the-state",
		RedirectURI:   "https://app.example.com/callback",
		CodeChallenge: "the-challenge",
		Nonce:         "the-nonce",
	})
	if err != nil {
		t.Fatalf("AuthCodeURL: %v", err)
	}
	if !strings.HasPrefix(got, fake.Issuer()+"/authorize") {
		t.Fatalf("the URL points at %q", got)
	}
	for _, want := range []string{
		"state=the-state", "nonce=the-nonce",
		"code_challenge=the-challenge", "code_challenge_method=S256",
		"response_type=code", "client_id=" + testClientID,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the URL %q does not carry %q", got, want)
		}
	}
}

// TestSupportsPKCE checks the capability report.
func TestSupportsPKCE(t *testing.T) {
	p, _ := newFixture(t)
	if !p.SupportsPKCE() {
		t.Fatal("an OpenID Connect provider must support PKCE")
	}
}

// TestDiscoveryIssuerMustMatch covers the guard on the discovery document. The
// document is attacker-controlled input the moment the issuer is misconfigured.
func TestDiscoveryIssuerMustMatch(t *testing.T) {
	p, fake := newFixture(t)
	fake.SetDiscoveryIssuer("https://another-issuer.example.com")

	if _, err := exchange(t, p, fake); err == nil {
		t.Fatal("a discovery document with a foreign issuer was accepted")
	}
}

// TestDiscoveryEndpointsMustBeHTTPS covers the transport guard.
func TestDiscoveryEndpointsMustBeHTTPS(t *testing.T) {
	p, fake := newFixture(t)
	fake.SetDiscoveryTokenURL("http://plain.example.com/token")

	_, err := exchange(t, p, fake)
	if err == nil {
		t.Fatal("a plain HTTP token endpoint was accepted")
	}
}

// TestExchangeRefusesAWrongAudience covers the audience check.
func TestExchangeRefusesAWrongAudience(t *testing.T) {
	fake := testsupport.NewFakeGoogle(t, "a-different-client")
	p := oidc.New(
		oidc.WithIssuer(fake.Issuer()),
		oidc.WithClientID(testClientID),
		oidc.WithClientSecret("secret"),
	)
	_, err := exchange(t, p, fake)
	if err == nil {
		t.Fatal("an identity token for another audience was accepted")
	}
	if !errors.Is(err, oauth.ErrProviderRejected) {
		t.Fatalf("the error is %v", err)
	}
}

// TestExchangeRefusesAnExpiredToken covers the expiry check.
func TestExchangeRefusesAnExpiredToken(t *testing.T) {
	p, fake := newFixture(t)
	fake.SetExpiryOffset(-2 * time.Hour)
	if _, err := exchange(t, p, fake); err == nil {
		t.Fatal("an expired identity token was accepted")
	}
}

// TestExchangeRefusesAWrongNonce covers the replay guard of the flow.
func TestExchangeRefusesAWrongNonce(t *testing.T) {
	p, fake := newFixture(t)
	fake.SetNonce("the-nonce-of-another-request")
	_, err := p.Exchange(context.Background(), oauth.ExchangeRequest{
		Code:        "valid-code",
		RedirectURI: "https://app.example.com/callback",
		Nonce:       "the-nonce-of-this-request",
	})
	if err == nil {
		t.Fatal("an identity token with a foreign nonce was accepted")
	}
}

// TestExchangeRefusesAWrongIssuerClaim covers the issuer claim of the token,
// which is a separate check from the discovery document.
func TestExchangeRefusesAWrongIssuerClaim(t *testing.T) {
	p, fake := newFixture(t)
	fake.SetIssuer("https://a-foreign-issuer.example.com")
	if _, err := exchange(t, p, fake); err == nil {
		t.Fatal("an identity token from a foreign issuer was accepted")
	}
}

// TestDefaultIDIsTheIssuerHost checks that two issuers cannot collide in the
// account table.
func TestDefaultIDIsTheIssuerHost(t *testing.T) {
	p := oidc.New(
		oidc.WithIssuer("https://id.example.com/realms/main"),
		oidc.WithClientID("id"),
		oidc.WithClientSecret("secret"),
	)
	if p.ID() != "id.example.com" {
		t.Fatalf("the provider id is %q", p.ID())
	}

	other := oidc.New(
		oidc.WithIssuer("https://id.other.example.com"),
		oidc.WithClientID("id"),
		oidc.WithClientSecret("secret"),
	)
	if other.ID() == p.ID() {
		t.Fatal("two issuers share one provider id")
	}
}

// TestWithIDOverridesTheDefault covers the explicit identifier.
func TestWithIDOverridesTheDefault(t *testing.T) {
	p := oidc.New(
		oidc.WithIssuer("https://id.example.com"),
		oidc.WithID("keycloak"),
		oidc.WithClientID("id"),
		oidc.WithClientSecret("secret"),
	)
	if p.ID() != "keycloak" {
		t.Fatalf("the provider id is %q", p.ID())
	}
}

// TestValidateRequiresTheCredentials covers the configuration guard.
func TestValidateRequiresTheCredentials(t *testing.T) {
	cases := map[string]*oidc.Provider{
		"no issuer": oidc.New(oidc.WithClientID("id"), oidc.WithClientSecret("secret")),
		"no client id": oidc.New(oidc.WithIssuer("https://id.example.com"),
			oidc.WithClientSecret("secret")),
		"no client secret": oidc.New(oidc.WithIssuer("https://id.example.com"),
			oidc.WithClientID("id")),
		"plain http issuer": oidc.New(oidc.WithIssuer("http://id.example.com"),
			oidc.WithClientID("id"), oidc.WithClientSecret("secret")),
	}
	for name, p := range cases {
		if err := p.Validate(); err == nil {
			t.Errorf("the case %q was accepted", name)
		}
	}
}

// TestDiscoveryRunsOneTime checks that the document is cached, so one exchange
// per request does not fetch it again.
func TestDiscoveryRunsOneTime(t *testing.T) {
	p, fake := newFixture(t)
	if _, err := exchange(t, p, fake); err != nil {
		t.Fatal(err)
	}
	before := fake.DiscoveryCount()
	if before == 0 {
		t.Fatal("the provider fetched no discovery document")
	}
	if _, err := exchange(t, p, fake); err != nil {
		t.Fatal(err)
	}
	if after := fake.DiscoveryCount(); after != before {
		t.Fatalf("the provider fetched the document again: %d then %d", before, after)
	}
}

// TestDiscoveryRetriesAfterAFailure checks that one failed attempt does not
// poison the provider for its lifetime.
func TestDiscoveryRetriesAfterAFailure(t *testing.T) {
	fake := testsupport.NewFakeGoogle(t, testClientID)
	p := oidc.New(
		oidc.WithIssuer(fake.Issuer()),
		oidc.WithClientID(testClientID),
		oidc.WithClientSecret("secret"),
	)
	// The first attempt fails, because the document names a foreign issuer.
	fake.SetDiscoveryIssuer("https://wrong.example.com")
	if _, err := exchange(t, p, fake); err == nil {
		t.Fatal("the first attempt succeeded")
	}
	// The operator repairs the issuer. The provider must recover with no
	// restart.
	fake.SetDiscoveryIssuer("")
	if _, err := exchange(t, p, fake); err != nil {
		t.Fatalf("the provider did not recover: %v", err)
	}
}

// TestWithEndpointsSkipsDiscovery covers an issuer that publishes no document.
func TestWithEndpointsSkipsDiscovery(t *testing.T) {
	fake := testsupport.NewFakeGoogle(t, testClientID)
	authURL, tokenURL, jwksURL, issuer := fake.Endpoints()
	p := oidc.New(
		oidc.WithIssuer(issuer),
		oidc.WithClientID(testClientID),
		oidc.WithClientSecret("secret"),
		oidc.WithEndpoints(authURL, tokenURL, jwksURL),
	)
	if _, err := exchange(t, p, fake); err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if n := fake.DiscoveryCount(); n != 0 {
		t.Fatalf("the provider fetched the document %d times", n)
	}
}

// TestUnverifiedAddressIsReported checks that the identity carries the flag.
// Auth-All never links on an unverified address.
func TestUnverifiedAddressIsReported(t *testing.T) {
	p, fake := newFixture(t)
	fake.SetAccount("subject-2", "unverified@example.com", false)
	identity, err := exchange(t, p, fake)
	if err != nil {
		t.Fatal(err)
	}
	if identity.EmailVerified {
		t.Fatal("an unverified address is reported as verified")
	}
}

// TestExchangeRefusesARejectedCode covers the provider error path.
func TestExchangeRefusesARejectedCode(t *testing.T) {
	p, fake := newFixture(t)
	fake.SetExpectedChallenge("a-challenge-that-the-request-does-not-carry")
	_, err := p.Exchange(context.Background(), oauth.ExchangeRequest{
		Code:         "valid-code",
		RedirectURI:  "https://app.example.com/callback",
		CodeVerifier: "the-wrong-verifier",
	})
	if err == nil {
		t.Fatal("the provider accepted a rejected code")
	}
	if !errors.Is(err, oauth.ErrProviderRejected) {
		t.Fatalf("the error is %v", err)
	}
}

// TestProviderSatisfiesTheInterface is a compile-time check.
func TestProviderSatisfiesTheInterface(t *testing.T) {
	var _ oauth.Provider = (*oidc.Provider)(nil)
	_ = http.DefaultClient
}
