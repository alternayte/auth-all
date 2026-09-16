package oauthprovider

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alternayte/auth-all/internal/jws"
	"github.com/alternayte/auth-all/plugin"
	"github.com/alternayte/auth-all/store"
)

// newTestPlugin returns a plugin with the fields the pure functions read.
func newTestPlugin(t *testing.T, opts ...Option) *Plugin {
	t.Helper()
	base := []Option{
		KeyEncryptionKey(make([]byte, 32)),
		LoginPath("/sign-in"),
		ConsentPath("/consent"),
	}
	p := New(append(base, opts...)...)
	p.issuer = "https://app.example.com/api/auth"
	p.now = func() time.Time { return time.Unix(1700000000, 0).UTC() }
	return p
}

// TestRedirectURIRules covers the registration rules that a relying party
// meets before it ever reaches the authorize route.
func TestRedirectURIRules(t *testing.T) {
	p := newTestPlugin(t, AllowPlainHTTP("intranet.example"))
	accept := []string{
		"https://app.example.com/callback",
		"http://127.0.0.1:1234/callback",
		"http://localhost/callback",
		"http://[::1]:8080/callback",
		"myapp://callback",
		"com.example.app://host/callback",
		"http://intranet.example/callback",
	}
	for _, uri := range accept {
		if err := p.checkRedirectURI(uri); err != nil {
			t.Errorf("the redirect URI %q was rejected: %v", uri, err)
		}
	}
	reject := []string{
		"http://example.com/callback",
		"https://app.example.com/callback#fragment",
		"https://*.example.com/callback",
		"/relative/callback",
		"https:///callback",
	}
	for _, uri := range reject {
		if err := p.checkRedirectURI(uri); err == nil {
			t.Errorf("the redirect URI %q was accepted", uri)
		}
	}
}

// TestRedirectURIMatchIsExact proves that the server rewrites no host and frees
// the loopback port only.
func TestRedirectURIMatchIsExact(t *testing.T) {
	c := client{RedirectURIs: []string{
		"https://app.example.com/callback",
		"http://127.0.0.1/callback",
	}}
	if _, err := c.matchRedirectURI("https://app.example.com/callback"); err != nil {
		t.Fatalf("the registered value did not match: %v", err)
	}
	if _, err := c.matchRedirectURI("http://127.0.0.1:49152/callback"); err != nil {
		t.Fatalf("the loopback port was not free: %v", err)
	}
	for _, candidate := range []string{
		"http://localhost/callback",
		"https://app.example.com/callback2",
		"https://evil.example.com/callback",
		"http://127.0.0.1:49152/other",
	} {
		if _, err := c.matchRedirectURI(candidate); err == nil {
			t.Errorf("the candidate %q matched", candidate)
		}
	}
}

// TestRequestedScopesBoundByClient proves that a client asks for no scope
// beyond its registration.
func TestRequestedScopesBoundByClient(t *testing.T) {
	p := newTestPlugin(t)
	c := client{Scopes: []string{ScopeOpenID, ScopeEmail}}
	got, err := p.requestedScopes("openid email openid", c)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("the duplicate scope survived: %v", got)
	}
	if _, err := p.requestedScopes("openid profile", c); err == nil {
		t.Fatal("the client widened its scopes")
	}
	if _, err := p.requestedScopes("unknown", c); err == nil {
		t.Fatal("an unknown scope passed")
	}
	if _, err := p.requestedScopes("", c); err == nil {
		t.Fatal("an empty scope set passed")
	}
}

// TestRequestedResourcesNeedDeclaration proves the RFC 8707 rules of the
// server.
func TestRequestedResourcesNeedDeclaration(t *testing.T) {
	p := newTestPlugin(t, Resources(
		Resource{Identifier: "https://api.example.com"},
		Resource{Identifier: "https://reports.example.com", Scopes: []string{ScopeOpenID}},
	))
	got, err := p.requestedResources([]string{"https://api.example.com"}, []string{ScopeEmail})
	if err != nil || len(got) != 1 {
		t.Fatalf("a declared resource failed: %v %v", got, err)
	}
	if _, err := p.requestedResources([]string{"https://other.example.com"}, nil); err == nil {
		t.Fatal("an undeclared resource passed")
	}
	if _, err := p.requestedResources(
		[]string{"https://reports.example.com"}, []string{ScopeEmail}); err == nil {
		t.Fatal("a resource accepted a scope it does not allow")
	}
	if _, err := p.requestedResources(
		[]string{"https://api.example.com", "https://reports.example.com"}, []string{ScopeOpenID}); err == nil {
		t.Fatal("one call named two resources")
	}
}

// TestWrapRoundTrip proves that the key encryption key protects the private
// key and that another key cannot read it.
func TestWrapRoundTrip(t *testing.T) {
	p := newTestPlugin(t)
	secret := []byte("the private key material")
	wrapped, err := p.wrap(secret)
	if err != nil {
		t.Fatal(err)
	}
	if string(wrapped) == string(secret) {
		t.Fatal("the stored value is the plaintext")
	}
	back, err := p.unwrap(wrapped)
	if err != nil || string(back) != string(secret) {
		t.Fatalf("round trip: %q %v", back, err)
	}
	other := newTestPlugin(t)
	other.kek = make([]byte, 32)
	other.kek[0] = 1
	if _, err := other.unwrap(wrapped); err == nil {
		t.Fatal("another key encryption key read the private key")
	}
	if _, err := p.unwrap([]byte("short")); err == nil {
		t.Fatal("a truncated value unwrapped")
	}
}

// TestMetadataDescribesTheServer covers the discovery document.
func TestMetadataDescribesTheServer(t *testing.T) {
	p := newTestPlugin(t, AllowDynamicRegistration(),
		Resources(Resource{Identifier: "https://api.example.com"}))
	doc := p.metadata()
	if doc["issuer"] != p.issuer {
		t.Fatalf("issuer %v", doc["issuer"])
	}
	if doc["registration_endpoint"] != p.issuer+PathRegister {
		t.Fatalf("registration endpoint %v", doc["registration_endpoint"])
	}
	if doc["request_parameter_supported"] != false {
		t.Fatal("the server claims a request object")
	}
	if doc["authorization_response_iss_parameter_supported"] != true {
		t.Fatal("the server names no issuer in the response")
	}
}

// TestRegisterRejectsAWeakConfiguration covers the construction rules that keep
// the plugin from failing open.
func TestRegisterRejectsAWeakConfiguration(t *testing.T) {
	cases := map[string][]Option{
		"a short key encryption key": {KeyEncryptionKey([]byte("short")), LoginPath("/a"), ConsentPath("/b")},
		"an unsupported algorithm": {KeyEncryptionKey(make([]byte, 32)), Algorithm("HS256"),
			LoginPath("/a"), ConsentPath("/b")},
		"no login page": {KeyEncryptionKey(make([]byte, 32)), ConsentPath("/b")},
	}
	for name, opts := range cases {
		if err := New(opts...).Register(nil); err == nil {
			t.Errorf("%s registered", name)
		}
	}
}

// TestClaimsAreRejectedWhenReserved proves that a mapping cannot overwrite a
// claim the server stamps.
func TestClaimsAreRejectedWhenReserved(t *testing.T) {
	p := newTestPlugin(t, Claims(ClaimMapping{Claim: "sub", Field: "nickname"}))
	if err := p.checkClaims(); err == nil {
		t.Fatal("a reserved claim was mapped")
	}
	p = newTestPlugin(t, Claims(
		ClaimMapping{Claim: "nickname", Field: "nickname"},
		ClaimMapping{Claim: "nickname", Field: "other"},
	))
	if err := p.checkClaims(); err == nil {
		t.Fatal("one claim was mapped twice")
	}
	p = newTestPlugin(t, Claims(ClaimMapping{Scope: "unknown", Claim: "nickname", Field: "nickname"}))
	if err := p.checkClaims(); err == nil {
		t.Fatal("a claim named an unknown scope")
	}
}

// TestStaticClientRulesAreChecked covers the declaration rules of a first-party
// client.
func TestStaticClientRulesAreChecked(t *testing.T) {
	p := newTestPlugin(t, Clients(StaticClient{ClientID: "app"}))
	if err := p.checkStaticClients(); err == nil {
		t.Fatal("a client without a redirect URI passed")
	}
	p = newTestPlugin(t, Clients(StaticClient{ClientID: "app",
		RedirectURIs: []string{"http://example.com/callback"}}))
	if err := p.checkStaticClients(); err == nil {
		t.Fatal("a plain http redirect URI passed")
	}
	p = newTestPlugin(t, Clients(StaticClient{ClientID: "app",
		RedirectURIs: []string{"https://example.com/callback"}, Scopes: []string{"unknown"}}))
	if err := p.checkStaticClients(); err == nil {
		t.Fatal("an unknown scope passed")
	}
	p = newTestPlugin(t, Clients(StaticClient{ClientID: "machine",
		GrantTypes: []string{GrantClientCredentials}, Secret: "s"}))
	if err := p.checkStaticClients(); err != nil {
		t.Fatalf("a client credentials client needs no redirect URI: %v", err)
	}
}

// TestResourceIdentifiersAreAbsolute covers the resource declaration rules.
func TestResourceIdentifiersAreAbsolute(t *testing.T) {
	p := newTestPlugin(t, Resources(Resource{Identifier: "/api"}))
	if err := p.checkResources(); err == nil {
		t.Fatal("a relative resource passed")
	}
	p = newTestPlugin(t, Resources(Resource{Identifier: "https://api.example.com/#part"}))
	if err := p.checkResources(); err == nil {
		t.Fatal("a resource with a fragment passed")
	}
	p = newTestPlugin(t, Resources(Resource{Identifier: "https://api.example.com", Scopes: []string{"nope"}}))
	if err := p.checkResources(); err == nil {
		t.Fatal("a resource named an unknown scope")
	}
}

// TestSecretComparison covers the client secret check.
func TestSecretComparison(t *testing.T) {
	p := newTestPlugin(t)
	c := p.staticToClient(StaticClient{ClientID: "app", Secret: "right",
		RedirectURIs: []string{"https://example.com/cb"}})
	if !c.secretMatches("right") {
		t.Fatal("the right secret failed")
	}
	if c.secretMatches("wrong") || c.secretMatches("") {
		t.Fatal("a wrong secret passed")
	}
	public := p.staticToClient(StaticClient{ClientID: "spa",
		RedirectURIs: []string{"https://example.com/cb"}})
	if public.AuthMethod != AuthNone || public.secretMatches("") {
		t.Fatal("the public client holds a secret")
	}
}

// TestThumbprintIsStable proves that the DPoP confirmation value follows RFC
// 7638.
func TestThumbprintIsStable(t *testing.T) {
	// The example key of RFC 7638 section 3.1 has a published thumbprint.
	jwk := map[string]any{
		"kty": "RSA",
		"n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7a" +
			"PFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93l" +
			"qt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6" +
			"qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHa" +
			"Q-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
		"e": "AQAB",
	}
	got, err := jws.Thumbprint(jwk)
	if err != nil {
		t.Fatal(err)
	}
	const want = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
	if got != want {
		t.Fatalf("thumbprint %q, want %q", got, want)
	}
	if _, err := jws.Thumbprint(map[string]any{"kty": "oct"}); err == nil {
		t.Fatal("an unsupported key type produced a thumbprint")
	}
}

// TestOptionsChangeTheConfiguration covers the option setters that a host uses
// to tune the lifetimes and the scope set.
func TestOptionsChangeTheConfiguration(t *testing.T) {
	p := newTestPlugin(t,
		Scopes(ScopeOpenID, "reports"),
		AccessTokenTTL(time.Minute),
		RefreshTokenTTL(2*time.Hour),
		CodeTTL(20*time.Second),
		RequestTTL(5*time.Minute),
		RotationGrace(time.Second),
		Algorithm(jws.RS256),
	)
	if !p.knownScope("reports") || p.knownScope(ScopeEmail) {
		t.Fatalf("the scope set is %v", p.scopes)
	}
	if p.accessTokenTTL != time.Minute || p.refreshTokenTTL != 2*time.Hour ||
		p.codeTTL != 20*time.Second || p.requestTTL != 5*time.Minute ||
		p.rotationGrace != time.Second || p.algorithm != jws.RS256 {
		t.Fatal("an option changed nothing")
	}
}

// TestCoversComparesLists covers the consent comparison.
func TestCoversComparesLists(t *testing.T) {
	if !covers([]string{"a", "b"}, []string{"a"}) {
		t.Fatal("a granted scope was missing")
	}
	if covers([]string{"a"}, []string{"a", "b"}) {
		t.Fatal("a missing scope counted as granted")
	}
	if !covers(nil, nil) {
		t.Fatal("two empty lists did not match")
	}
}

// TestSameRequestURIComparesTheTarget covers the htu comparison of a DPoP
// proof, which drops the query and the fragment.
func TestSameRequestURIComparesTheTarget(t *testing.T) {
	p := newTestPlugin(t)
	p.svc = staticServices{baseURL: "https://app.example.com", basePath: "/api/auth"}
	r := httptest.NewRequest(http.MethodPost, "/api/auth/oauth2/token?x=1", nil)
	for _, htu := range []string{
		"https://app.example.com/api/auth/oauth2/token",
		"https://app.example.com/api/auth/oauth2/token?other=2",
		"https://app.example.com/api/auth/oauth2/token#part",
	} {
		if !p.sameRequestURI(htu, r) {
			t.Errorf("the target %q did not match", htu)
		}
	}
	for _, htu := range []string{
		"", "https://app.example.com/oauth2/token", "https://evil.example.com/api/auth/oauth2/token",
	} {
		if p.sameRequestURI(htu, r) {
			t.Errorf("the target %q matched", htu)
		}
	}
}

// TestBearerSchemeReadsTheHeader covers the Authorization header split.
func TestBearerSchemeReadsTheHeader(t *testing.T) {
	cases := map[string][2]string{
		"Bearer abc": {"bearer", "abc"},
		"DPoP xyz":   {"dpop", "xyz"},
		"bearer  a":  {"bearer", "a"},
		"Bearer":     {"", ""},
		"":           {"", ""},
	}
	for header, want := range cases {
		scheme, token := bearerScheme(header)
		if scheme != want[0] || token != want[1] {
			t.Errorf("%q returned %q %q", header, scheme, token)
		}
	}
}

// TestRowToClientFillsTheScopes proves that a stored client without scopes
// takes the scopes of the server.
func TestRowToClientFillsTheScopes(t *testing.T) {
	p := newTestPlugin(t)
	c := p.rowToClient(&store.OAuthClient{ClientID: "one", TokenEndpointAuthMethod: AuthNone})
	if len(c.Scopes) != len(p.scopes) {
		t.Fatalf("the client holds the scopes %v", c.Scopes)
	}
	withScopes := p.rowToClient(&store.OAuthClient{ClientID: "two", Scopes: []string{ScopeEmail}})
	if len(withScopes.Scopes) != 1 {
		t.Fatalf("the stored scopes changed: %v", withScopes.Scopes)
	}
}

// staticServices answers the two configuration reads that the pure functions
// make. It implements no other part of plugin.Services.
type staticServices struct {
	plugin.Services
	baseURL  string
	basePath string
}

func (s staticServices) BaseURL() string  { return s.baseURL }
func (s staticServices) BasePath() string { return s.basePath }

// TestClaimsOfReadsStoredFieldsOnly covers the claim assembly of the userinfo
// route.
func TestClaimsOfReadsStoredFieldsOnly(t *testing.T) {
	p := newTestPlugin(t,
		Claims(
			ClaimMapping{Scope: ScopeProfile, Claim: "nickname", Field: "nickname"},
			ClaimMapping{Scope: ScopeEmail, Claim: "department", Field: "department"},
		),
		ClaimsFrom(func(user *store.User, scopes []string) map[string]any {
			return map[string]any{"tier": "gold", "sub": "forged"}
		}),
	)
	verified := time.Unix(1600000000, 0).UTC()
	extra := store.NewExtraFields(map[string]any{"nickname": "Ada", "department": nil})
	user := &store.User{ID: "user-1", Email: "ada@example.com", EmailVerifiedAt: &verified,
		DisplayName: "Ada Lovelace", ImageURL: "https://example.com/ada.png", Extra: extra}

	all := p.claimsOf(user, []string{ScopeOpenID, ScopeEmail, ScopeProfile})
	if all["sub"] != "user-1" || all["email"] != "ada@example.com" || all["email_verified"] != true {
		t.Fatalf("the identity claims are wrong: %v", all)
	}
	if all["name"] != "Ada Lovelace" || all["picture"] != "https://example.com/ada.png" {
		t.Fatalf("the profile claims are wrong: %v", all)
	}
	if all["nickname"] != "Ada" {
		t.Fatalf("the mapped field is missing: %v", all)
	}
	if _, present := all["department"]; present {
		t.Fatal("an empty field produced a claim")
	}
	if all["tier"] != "gold" || all["sub"] == "forged" {
		t.Fatalf("the claims function wrote the wrong claims: %v", all)
	}
	if _, split := all["given_name"]; split {
		t.Fatal("the server derived a given name")
	}

	// A narrower scope set grants fewer claims.
	narrow := p.claimsOf(user, []string{ScopeOpenID})
	if len(narrow) != 2 || narrow["sub"] != "user-1" {
		t.Fatalf("the openid scope alone granted %v", narrow)
	}

	// A user without a display name and without an image produces no empty
	// claim.
	bare := p.claimsOf(&store.User{ID: "user-2"}, []string{ScopeProfile, ScopeEmail})
	if _, present := bare["name"]; present {
		t.Fatalf("an empty display name produced a claim: %v", bare)
	}
	if bare["email_verified"] != false {
		t.Fatalf("an unverified address is verified: %v", bare)
	}
}

// TestTokenTypeNamesTheScheme covers the presentation scheme of an issued
// token.
func TestTokenTypeNamesTheScheme(t *testing.T) {
	if tokenType("") != "Bearer" || tokenType("thumb") != "DPoP" {
		t.Fatal("the token type is wrong")
	}
}

// TestLookupClientPrefersTheStaticDeclaration proves that host source outranks
// a stored row of the same identifier.
func TestLookupClientPrefersTheStaticDeclaration(t *testing.T) {
	p := newTestPlugin(t, Clients(StaticClient{ClientID: "app",
		Name: "Static", RedirectURIs: []string{"https://app.example.com/cb"}}))
	c, err := p.lookupClient(context.Background(), "app")
	if err != nil || !c.Static || c.Name != "Static" {
		t.Fatalf("the static declaration lost: %+v %v", c, err)
	}
}
