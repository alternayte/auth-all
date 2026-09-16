package authall_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	authall "github.com/alternayte/auth-all"
	"github.com/alternayte/auth-all/internal/jws"
	"github.com/alternayte/auth-all/internal/testsupport"
	"github.com/alternayte/auth-all/plugins/admin"
	"github.com/alternayte/auth-all/plugins/oauthprovider"
	"github.com/alternayte/auth-all/plugins/roles"
	"github.com/alternayte/auth-all/store"
)

// providerHarness builds an instance with the OAuth provider plugin and one
// registered relying party.
func providerHarness(t *testing.T, opts ...oauthprovider.Option) (*testsupport.Harness, *oauthprovider.Plugin) {
	t.Helper()
	base := []oauthprovider.Option{
		oauthprovider.KeyEncryptionKey(make([]byte, 32)),
		oauthprovider.LoginPath("/sign-in"),
		oauthprovider.ConsentPath("/consent"),
		oauthprovider.Clients(oauthprovider.StaticClient{
			ClientID:     "first-party",
			Secret:       "first-party-secret",
			AuthMethod:   "client_secret_post",
			Name:         "First Party",
			RedirectURIs: []string{"https://app.example.com/callback", "http://127.0.0.1/callback"},
		}),
		oauthprovider.Resources(oauthprovider.Resource{Identifier: "https://api.example.com"}),
	}
	p := oauthprovider.New(append(base, opts...)...)
	h := testsupport.NewHarness(t,
		authall.WithEmailPassword(authall.EmailPasswordOptions{}),
		authall.WithPlugins(
			roles.New(roles.Hierarchy("viewer", "admin"), roles.Default("viewer")),
			admin.New(admin.AdminRole("admin")),
			p,
		),
	)
	return h, p
}

// pkcePair returns a verifier and its S256 challenge.
func pkcePair(t *testing.T) (verifier, challenge string) {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	verifier = jws.Encode(raw)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, jws.Encode(sum[:])
}

// authorizeURL returns the authorize path with the query of one request.
func authorizeURL(challenge string, extra url.Values) string {
	q := url.Values{
		"client_id":             {"first-party"},
		"redirect_uri":          {"https://app.example.com/callback"},
		"response_type":         {"code"},
		"scope":                 {"openid email offline_access"},
		"state":                 {"state-value"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	for name, values := range extra {
		q[name] = values
	}
	return "/oauth2/authorize?" + q.Encode()
}

// codeFor runs the browser part of the flow and returns the authorization
// code.
func providerCodeFor(t *testing.T, h *testsupport.Harness, challenge string, extra url.Values) string {
	t.Helper()
	h.SignUp("owner@example.com", "Password123!")
	resp := h.Do(http.MethodGet, authorizeURL(challenge, extra), nil)
	if resp.Status != http.StatusSeeOther {
		t.Fatalf("authorize: status %d body %s", resp.Status, resp.Body)
	}
	target, err := url.Parse(resp.Location())
	if err != nil {
		t.Fatal(err)
	}
	code := target.Query().Get("code")
	if code == "" {
		t.Fatalf("authorize returned no code: %s", resp.Location())
	}
	if target.Query().Get("iss") == "" {
		t.Fatal("the authorization response names no issuer")
	}
	return code
}

// TestOAuthProviderCodeFlowIssuesSignedTokens runs the code flow end to end and
// verifies the identity token against the published key set.
func TestOAuthProviderCodeFlowIssuesSignedTokens(t *testing.T) {
	h, _ := providerHarness(t)
	verifier, challenge := pkcePair(t)
	code := providerCodeFor(t, h, challenge, nil)

	resp := h.DoForm(h.URL("/oauth2/token"), map[string]string{
		"grant_type":    "authorization_code",
		"code":          code,
		"redirect_uri":  "https://app.example.com/callback",
		"code_verifier": verifier,
		"client_id":     "first-party",
		"client_secret": "first-party-secret",
	})
	if resp.Status != http.StatusOK {
		t.Fatalf("token: status %d body %s", resp.Status, resp.Body)
	}
	var token struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		TokenType    string `json:"token_type"`
	}
	resp.Decode(t, &token)
	if token.AccessToken == "" || token.RefreshToken == "" || token.IDToken == "" {
		t.Fatalf("the token response is incomplete: %s", resp.Body)
	}
	if token.TokenType != "Bearer" {
		t.Fatalf("token type %q", token.TokenType)
	}

	// The access token is a signed at+jwt, never an opaque value.
	header, _, err := jws.Parse(token.AccessToken)
	if err != nil {
		t.Fatalf("parse access token: %v", err)
	}
	if header.Type != "at+jwt" {
		t.Fatalf("access token type %q", header.Type)
	}

	// The identity token verifies against the published key set.
	keys := h.Do(http.MethodGet, "/oauth2/jwks", nil)
	var set struct {
		Keys []map[string]any `json:"keys"`
	}
	keys.Decode(t, &set)
	if len(set.Keys) != 1 {
		t.Fatalf("the key set holds %d keys", len(set.Keys))
	}
	pub, err := jws.PublicKeyFromJWK(set.Keys[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := jws.Verify(token.IDToken, pub); err != nil {
		t.Fatalf("the identity token does not verify: %v", err)
	}

	// Userinfo reads the claims that the scopes grant.
	info := h.Do(http.MethodGet, "/oauth2/userinfo", nil,
		testsupport.WithBearer(token.AccessToken))
	if info.Status != http.StatusOK {
		t.Fatalf("userinfo: status %d body %s", info.Status, info.Body)
	}
	var claims map[string]any
	info.Decode(t, &claims)
	if claims["email"] != "owner@example.com" {
		t.Fatalf("userinfo claims: %v", claims)
	}
}

// TestOAuthProviderCodeIsSingleUse proves that a replayed code reaches no
// second token.
func TestOAuthProviderCodeIsSingleUse(t *testing.T) {
	h, _ := providerHarness(t)
	verifier, challenge := pkcePair(t)
	code := providerCodeFor(t, h, challenge, nil)
	fields := map[string]string{
		"grant_type": "authorization_code", "code": code,
		"redirect_uri": "https://app.example.com/callback", "code_verifier": verifier,
		"client_id": "first-party", "client_secret": "first-party-secret",
	}
	if first := h.DoForm(h.URL("/oauth2/token"), fields); first.Status != http.StatusOK {
		t.Fatalf("first exchange: %d %s", first.Status, first.Body)
	}
	second := h.DoForm(h.URL("/oauth2/token"), fields)
	if second.Status != http.StatusBadRequest {
		t.Fatalf("the replay returned %d", second.Status)
	}
}

// TestOAuthProviderRefreshReplayRevokesTheGrant proves the rotation rule: a
// retry inside the grace window succeeds, and a replay after it kills the
// grant.
func TestOAuthProviderRefreshReplayRevokesTheGrant(t *testing.T) {
	h, _ := providerHarness(t, oauthprovider.RotationGrace(0))
	verifier, challenge := pkcePair(t)
	code := providerCodeFor(t, h, challenge, nil)
	resp := h.DoForm(h.URL("/oauth2/token"), map[string]string{
		"grant_type": "authorization_code", "code": code,
		"redirect_uri": "https://app.example.com/callback", "code_verifier": verifier,
		"client_id": "first-party", "client_secret": "first-party-secret",
	})
	var first struct {
		RefreshToken string `json:"refresh_token"`
	}
	resp.Decode(t, &first)

	refresh := map[string]string{
		"grant_type": "refresh_token", "refresh_token": first.RefreshToken,
		"client_id": "first-party", "client_secret": "first-party-secret",
	}
	rotated := h.DoForm(h.URL("/oauth2/token"), refresh)
	if rotated.Status != http.StatusOK {
		t.Fatalf("rotation: %d %s", rotated.Status, rotated.Body)
	}
	var second struct {
		RefreshToken string `json:"refresh_token"`
	}
	rotated.Decode(t, &second)

	// The first token is spent. Its presentation after the window revokes the
	// whole grant.
	replay := h.DoForm(h.URL("/oauth2/token"), refresh)
	if replay.Status != http.StatusBadRequest {
		t.Fatalf("the replay returned %d", replay.Status)
	}
	after := h.DoForm(h.URL("/oauth2/token"), map[string]string{
		"grant_type": "refresh_token", "refresh_token": second.RefreshToken,
		"client_id": "first-party", "client_secret": "first-party-secret",
	})
	if after.Status != http.StatusBadRequest {
		t.Fatalf("the successor still works after the replay: %d %s", after.Status, after.Body)
	}
}

// TestOAuthProviderForeignAudienceOpensNoHostRoute proves the audience test of
// the credential resolver.
func TestOAuthProviderForeignAudienceOpensNoHostRoute(t *testing.T) {
	h, _ := providerHarness(t)
	verifier, challenge := pkcePair(t)
	code := providerCodeFor(t, h, challenge,
		url.Values{"resource": {"https://api.example.com"}, "scope": {"openid email"}})
	resp := h.DoForm(h.URL("/oauth2/token"), map[string]string{
		"grant_type": "authorization_code", "code": code,
		"redirect_uri": "https://app.example.com/callback", "code_verifier": verifier,
		"client_id": "first-party", "client_secret": "first-party-secret",
	})
	var token struct {
		AccessToken string `json:"access_token"`
	}
	resp.Decode(t, &token)

	// The token names the resource server, so the host session route refuses
	// it. A confused deputy would accept it here. The cookie jar loses the
	// browser session first, because a cookie would answer the route instead.
	// The consents route runs behind the Auth-All authentication middleware,
	// so it answers only a credential that resolves.
	h.Client.Jar = nil
	session := h.Do(http.MethodGet, "/oauth2/consents", nil, testsupport.WithBearer(token.AccessToken))
	if session.Status == http.StatusOK {
		t.Fatal("a token of another resource server opened a host route")
	}
	info := h.Do(http.MethodGet, "/oauth2/userinfo", nil, testsupport.WithBearer(token.AccessToken))
	if info.Status != http.StatusUnauthorized {
		t.Fatalf("userinfo accepted a foreign audience: %d", info.Status)
	}
}

// TestOAuthProviderIssuerAudienceOpensAHostRoute proves the other half: a token
// of the issuer itself authenticates a host route.
func TestOAuthProviderIssuerAudienceOpensAHostRoute(t *testing.T) {
	h, _ := providerHarness(t)
	verifier, challenge := pkcePair(t)
	code := providerCodeFor(t, h, challenge, url.Values{"scope": {"openid email"}})
	resp := h.DoForm(h.URL("/oauth2/token"), map[string]string{
		"grant_type": "authorization_code", "code": code,
		"redirect_uri": "https://app.example.com/callback", "code_verifier": verifier,
		"client_id": "first-party", "client_secret": "first-party-secret",
	})
	var token struct {
		AccessToken string `json:"access_token"`
	}
	resp.Decode(t, &token)
	h.Client.Jar = nil
	session := h.Do(http.MethodGet, "/oauth2/consents", nil, testsupport.WithBearer(token.AccessToken))
	if session.Status != http.StatusOK {
		t.Fatalf("the issuer token opened no host route: %d %s", session.Status, session.Body)
	}
}

// TestOAuthProviderRedirectURIMatchesExactly proves that the server rewrites no
// host and registers no wildcard.
func TestOAuthProviderRedirectURIMatchesExactly(t *testing.T) {
	h, _ := providerHarness(t)
	_, challenge := pkcePair(t)
	h.SignUp("owner@example.com", "Password123!")

	// localhost is not 127.0.0.1, so the unregistered form fails.
	resp := h.Do(http.MethodGet, authorizeURL(challenge,
		url.Values{"redirect_uri": {"http://localhost/callback"}}), nil)
	if resp.Status != http.StatusBadRequest {
		t.Fatalf("localhost matched a 127.0.0.1 registration: %d", resp.Status)
	}
	// The loopback port is free, because a native application picks it at run
	// time.
	ok := h.Do(http.MethodGet, authorizeURL(challenge,
		url.Values{"redirect_uri": {"http://127.0.0.1:51234/callback"}}), nil)
	if ok.Status != http.StatusSeeOther {
		t.Fatalf("the loopback port was not free: %d %s", ok.Status, ok.Body)
	}
}

// TestOAuthProviderRegistrationRejectsPlainHTTP proves the registration rules
// of a dynamic client.
func TestOAuthProviderRegistrationRejectsPlainHTTP(t *testing.T) {
	h, _ := providerHarness(t, oauthprovider.AllowDynamicRegistration())
	bad := h.Do(http.MethodPost, "/oauth2/register", map[string]any{
		"client_name":   "Bad",
		"redirect_uris": []string{"http://example.com/callback"},
	})
	if bad.Status != http.StatusBadRequest {
		t.Fatalf("a plain http redirect URI registered: %d %s", bad.Status, bad.Body)
	}
	good := h.Do(http.MethodPost, "/oauth2/register", map[string]any{
		"client_name":   "Desktop",
		"redirect_uris": []string{"myapp://callback"},
	})
	if good.Status != http.StatusCreated {
		t.Fatalf("a private-use scheme did not register: %d %s", good.Status, good.Body)
	}
	var out struct {
		ClientID                string `json:"client_id"`
		RegistrationAccessToken string `json:"registration_access_token"`
		RegistrationClientURI   string `json:"registration_client_uri"`
	}
	good.Decode(t, &out)
	if out.RegistrationAccessToken == "" || out.RegistrationClientURI == "" {
		t.Fatalf("the registration response carries no management fields: %s", good.Body)
	}
	// RFC 7592: the registration access token reads the client back.
	read := h.Do(http.MethodGet, "/oauth2/register/"+out.ClientID, nil,
		testsupport.WithBearer(out.RegistrationAccessToken))
	if read.Status != http.StatusOK {
		t.Fatalf("the management read failed: %d %s", read.Status, read.Body)
	}
	denied := h.Do(http.MethodGet, "/oauth2/register/"+out.ClientID, nil,
		testsupport.WithBearer("wrong-token"))
	if denied.Status != http.StatusUnauthorized {
		t.Fatalf("a wrong registration token read the client: %d", denied.Status)
	}
}

// TestOAuthProviderMetadataNamesTheIssuer proves that the issuer identifier and
// the metadata agree.
func TestOAuthProviderMetadataNamesTheIssuer(t *testing.T) {
	h, _ := providerHarness(t)
	resp := h.Do(http.MethodGet, "/.well-known/openid-configuration", nil)
	if resp.Status != http.StatusOK {
		t.Fatalf("metadata: %d", resp.Status)
	}
	var doc map[string]any
	resp.Decode(t, &doc)
	want := h.BaseURL + h.Auth.BasePath()
	if doc["issuer"] != want {
		t.Fatalf("issuer %v, want %s", doc["issuer"], want)
	}
	if doc["jwks_uri"] != want+"/oauth2/jwks" {
		t.Fatalf("jwks_uri %v", doc["jwks_uri"])
	}
	methods, _ := doc["code_challenge_methods_supported"].([]any)
	if len(methods) != 1 || methods[0] != "S256" {
		t.Fatalf("the server offers other PKCE methods: %v", methods)
	}
}

// TestOAuthProviderStoresNoReadablePrivateKey proves that a database dump holds
// no usable signing key.
func TestOAuthProviderStoresNoReadablePrivateKey(t *testing.T) {
	h, _ := providerHarness(t)
	// The first read of the key set creates the key.
	h.Do(http.MethodGet, "/oauth2/jwks", nil)
	rows, ok := h.Store.(store.OAuthProviderStore)
	if !ok {
		t.Fatal("the store holds no OAuth provider row")
	}
	keys, err := rows.ListOAuthKeys(context.Background())
	if err != nil || len(keys) != 1 {
		t.Fatalf("keys %d, err %v", len(keys), err)
	}
	if _, err := x509.ParsePKCS8PrivateKey(keys[0].WrappedPrivate); err == nil {
		t.Fatal("the stored private key is readable")
	}
}

// TestOAuthProviderDPoPBindsTheToken proves that a bound token needs its proof.
func TestOAuthProviderDPoPBindsTheToken(t *testing.T) {
	h, _ := providerHarness(t)
	verifier, challenge := pkcePair(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := jws.PublicJWK(&key.PublicKey, jws.ES256, "")
	if err != nil {
		t.Fatal(err)
	}
	delete(jwk, "kid")
	delete(jwk, "use")
	delete(jwk, "alg")
	thumb, err := jws.Thumbprint(jwk)
	if err != nil {
		t.Fatal(err)
	}
	code := providerCodeFor(t, h, challenge, url.Values{
		"scope": {"openid email"}, "dpop_jkt": {thumb},
	})
	proof := dpopProof(t, key, jwk, http.MethodPost, h.URL("/oauth2/token"), "")
	resp := h.DoForm(h.URL("/oauth2/token"), map[string]string{
		"grant_type": "authorization_code", "code": code,
		"redirect_uri": "https://app.example.com/callback", "code_verifier": verifier,
		"client_id": "first-party", "client_secret": "first-party-secret",
	}, testsupport.WithHeader("DPoP", proof))
	if resp.Status != http.StatusOK {
		t.Fatalf("the DPoP exchange failed: %d %s", resp.Status, resp.Body)
	}
	var token struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	resp.Decode(t, &token)
	if token.TokenType != "DPoP" {
		t.Fatalf("token type %q", token.TokenType)
	}
	// The bound token is no bearer token.
	bearer := h.Do(http.MethodGet, "/oauth2/userinfo", nil,
		testsupport.WithBearer(token.AccessToken))
	if bearer.Status != http.StatusUnauthorized {
		t.Fatalf("a bound token passed as a bearer token: %d", bearer.Status)
	}
	// With the proof of the same key it passes.
	sum := sha256.Sum256([]byte(token.AccessToken))
	userProof := dpopProof(t, key, jwk, http.MethodGet, h.URL("/oauth2/userinfo"), jws.Encode(sum[:]))
	ok := h.Do(http.MethodGet, "/oauth2/userinfo", nil,
		testsupport.WithHeader("Authorization", "DPoP "+token.AccessToken),
		testsupport.WithHeader("DPoP", userProof))
	if ok.Status != http.StatusOK {
		t.Fatalf("the bound token failed with its proof: %d %s", ok.Status, ok.Body)
	}
}

// dpopProof returns one DPoP proof of a key.
func dpopProof(t *testing.T, key *ecdsa.PrivateKey, jwk map[string]any, method, target, ath string) string {
	t.Helper()
	claims := map[string]any{
		"jti": strings.ReplaceAll(target, "/", "") + time.Now().Format(time.RFC3339Nano),
		"htm": method,
		"htu": target,
		"iat": time.Now().Unix(),
	}
	if ath != "" {
		claims["ath"] = ath
	}
	header := map[string]any{"alg": jws.ES256, "typ": "dpop+jwt", "jwk": jwk}
	rawHeader, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	rawClaims, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signing := jws.Encode(rawHeader) + "." + jws.Encode(rawClaims)
	sum := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signing + "." + jws.Encode(sig)
}

// TestOAuthProviderConsentPageDrivesTheFlow proves the host page contract: the
// authorize route redirects with an identifier only, and the decision routes
// carry the flow.
func TestOAuthProviderConsentPageDrivesTheFlow(t *testing.T) {
	h, _ := providerHarness(t, oauthprovider.AllowDynamicRegistration())
	created := h.Do(http.MethodPost, "/oauth2/register", map[string]any{
		"client_name":                "Third Party",
		"redirect_uris":              []string{"https://third.example.com/callback"},
		"token_endpoint_auth_method": "client_secret_post",
	})
	var client struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	created.Decode(t, &client)

	h.SignUp("owner@example.com", "Password123!")
	verifier, challenge := pkcePair(t)
	authorize := authorizeURL(challenge, url.Values{
		"client_id":    {client.ClientID},
		"redirect_uri": {"https://third.example.com/callback"},
		"scope":        {"openid email"},
	})
	resp := h.Do(http.MethodGet, authorize, nil)
	if resp.Status != http.StatusSeeOther {
		t.Fatalf("authorize: %d %s", resp.Status, resp.Body)
	}
	target, err := url.Parse(resp.Location())
	if err != nil {
		t.Fatal(err)
	}
	if target.Path != "/consent" {
		t.Fatalf("the browser went to %s", resp.Location())
	}
	requestID := target.Query().Get("request_id")
	if requestID == "" {
		t.Fatal("the consent page received no request identifier")
	}
	if target.Query().Get("scope") != "" || target.Query().Get("redirect_uri") != "" {
		t.Fatalf("the redirect carries request detail: %s", resp.Location())
	}

	// The page reads the request through the JSON route.
	read := h.Do(http.MethodGet, "/oauth2/request?request_id="+requestID, nil)
	if read.Status != http.StatusOK {
		t.Fatalf("request read: %d %s", read.Status, read.Body)
	}
	var detail struct {
		ClientName     string   `json:"clientName"`
		Scopes         []string `json:"scopes"`
		FirstParty     bool     `json:"firstParty"`
		NeedsSignIn    bool     `json:"needsSignIn"`
		ConsentGranted bool     `json:"consentGranted"`
	}
	read.Decode(t, &detail)
	if detail.ClientName != "Third Party" || detail.FirstParty || detail.NeedsSignIn ||
		detail.ConsentGranted || len(detail.Scopes) != 2 {
		t.Fatalf("the request detail is wrong: %s", read.Body)
	}

	// The page posts the decision and receives the redirect target.
	decide := h.Do(http.MethodPost, "/oauth2/decide",
		map[string]any{"requestId": requestID, "approve": true})
	if decide.Status != http.StatusOK {
		t.Fatalf("decide: %d %s", decide.Status, decide.Body)
	}
	var decision struct {
		RedirectTo string `json:"redirectTo"`
	}
	decide.Decode(t, &decision)
	back, err := url.Parse(decision.RedirectTo)
	if err != nil {
		t.Fatal(err)
	}
	code := back.Query().Get("code")
	if code == "" {
		t.Fatalf("the decision returned no code: %s", decision.RedirectTo)
	}
	token := h.DoForm(h.URL("/oauth2/token"), map[string]string{
		"grant_type": "authorization_code", "code": code,
		"redirect_uri": "https://third.example.com/callback", "code_verifier": verifier,
		"client_id": client.ClientID, "client_secret": client.ClientSecret,
	})
	if token.Status != http.StatusOK {
		t.Fatalf("token: %d %s", token.Status, token.Body)
	}

	// The consent now stands, so a second authorize call needs no page.
	second := h.Do(http.MethodGet, authorize, nil)
	if second.Status != http.StatusSeeOther ||
		!strings.HasPrefix(second.Location(), "https://third.example.com/callback") {
		t.Fatalf("the standing consent was not used: %s", second.Location())
	}

	// Withdrawing the consent revokes the grant.
	consents := h.Do(http.MethodGet, "/oauth2/consents", nil)
	if consents.Status != http.StatusOK {
		t.Fatalf("consents: %d %s", consents.Status, consents.Body)
	}
	withdraw := h.Do(http.MethodDelete, "/oauth2/consents/"+client.ClientID, nil)
	if withdraw.Status != http.StatusOK {
		t.Fatalf("withdraw: %d %s", withdraw.Status, withdraw.Body)
	}
	var first struct {
		RefreshToken string `json:"refresh_token"`
	}
	token.Decode(t, &first)
	if first.RefreshToken != "" {
		after := h.DoForm(h.URL("/oauth2/token"), map[string]string{
			"grant_type": "refresh_token", "refresh_token": first.RefreshToken,
			"client_id": client.ClientID, "client_secret": client.ClientSecret,
		})
		if after.Status == http.StatusOK {
			t.Fatal("the withdrawn consent left a live refresh token")
		}
	}
}

// TestOAuthProviderDeniedRequestReturnsAccessDenied proves the denial path.
func TestOAuthProviderDeniedRequestReturnsAccessDenied(t *testing.T) {
	h, _ := providerHarness(t, oauthprovider.AllowDynamicRegistration())
	created := h.Do(http.MethodPost, "/oauth2/register", map[string]any{
		"client_name":   "Third Party",
		"redirect_uris": []string{"https://third.example.com/callback"},
	})
	var client struct {
		ClientID string `json:"client_id"`
	}
	created.Decode(t, &client)
	h.SignUp("owner@example.com", "Password123!")
	_, challenge := pkcePair(t)
	resp := h.Do(http.MethodGet, authorizeURL(challenge, url.Values{
		"client_id":    {client.ClientID},
		"redirect_uri": {"https://third.example.com/callback"},
		"scope":        {"openid email"},
	}), nil)
	target, err := url.Parse(resp.Location())
	if err != nil {
		t.Fatal(err)
	}
	decide := h.Do(http.MethodPost, "/oauth2/decide", map[string]any{
		"requestId": target.Query().Get("request_id"), "approve": false,
	})
	var decision struct {
		RedirectTo string `json:"redirectTo"`
	}
	decide.Decode(t, &decision)
	back, err := url.Parse(decision.RedirectTo)
	if err != nil {
		t.Fatal(err)
	}
	if back.Query().Get("error") != "access_denied" {
		t.Fatalf("the denial returned %q", back.Query().Get("error"))
	}
}

// TestOAuthProviderClientCredentialsNamesTheClient proves the machine grant.
func TestOAuthProviderClientCredentialsNamesTheClient(t *testing.T) {
	h, _ := providerHarness(t, oauthprovider.Clients(oauthprovider.StaticClient{
		ClientID: "machine", Secret: "machine-secret", AuthMethod: "client_secret_post",
		GrantTypes: []string{"client_credentials"}, Scopes: []string{"email"},
	}))
	resp := h.DoForm(h.URL("/oauth2/token"), map[string]string{
		"grant_type": "client_credentials", "scope": "email",
		"client_id": "machine", "client_secret": "machine-secret",
	})
	if resp.Status != http.StatusOK {
		t.Fatalf("client credentials: %d %s", resp.Status, resp.Body)
	}
	var token struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	resp.Decode(t, &token)
	if token.RefreshToken != "" {
		t.Fatal("a machine token carries a refresh token")
	}
	_, payload, err := jws.Parse(token.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	if claims["sub"] != "machine" {
		t.Fatalf("the machine token names %v", claims["sub"])
	}
	// The openid scope belongs to a user, so the machine grant refuses it.
	denied := h.DoForm(h.URL("/oauth2/token"), map[string]string{
		"grant_type": "client_credentials", "scope": "openid",
		"client_id": "machine", "client_secret": "machine-secret",
	})
	if denied.Status == http.StatusOK {
		t.Fatal("a machine token carries a user scope")
	}
}

// TestOAuthProviderIntrospectionAndRevocation covers RFC 7662 and RFC 7009.
func TestOAuthProviderIntrospectionAndRevocation(t *testing.T) {
	h, _ := providerHarness(t)
	verifier, challenge := pkcePair(t)
	code := providerCodeFor(t, h, challenge, nil)
	resp := h.DoForm(h.URL("/oauth2/token"), map[string]string{
		"grant_type": "authorization_code", "code": code,
		"redirect_uri": "https://app.example.com/callback", "code_verifier": verifier,
		"client_id": "first-party", "client_secret": "first-party-secret",
	})
	var token struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	resp.Decode(t, &token)

	active := h.DoForm(h.URL("/oauth2/introspect"), map[string]string{
		"token": token.AccessToken, "client_id": "first-party", "client_secret": "first-party-secret",
	})
	var body map[string]any
	active.Decode(t, &body)
	if body["active"] != true || body["client_id"] != "first-party" {
		t.Fatalf("introspection: %s", active.Body)
	}
	unknown := h.DoForm(h.URL("/oauth2/introspect"), map[string]string{
		"token": "not-a-token", "client_id": "first-party", "client_secret": "first-party-secret",
	})
	unknown.Decode(t, &body)
	if body["active"] != false {
		t.Fatalf("an unknown token is active: %s", unknown.Body)
	}

	// Revoking the refresh token ends the grant, so the access token dies too.
	revoke := h.DoForm(h.URL("/oauth2/revoke"), map[string]string{
		"token": token.RefreshToken, "client_id": "first-party", "client_secret": "first-party-secret",
	})
	if revoke.Status != http.StatusOK {
		t.Fatalf("revoke: %d %s", revoke.Status, revoke.Body)
	}
	after := h.DoForm(h.URL("/oauth2/introspect"), map[string]string{
		"token": token.AccessToken, "client_id": "first-party", "client_secret": "first-party-secret",
	})
	after.Decode(t, &body)
	if body["active"] != false {
		t.Fatalf("the revoked token is still active: %s", after.Body)
	}
}

// TestOAuthProviderRotationGraceAnswersARetry proves that a client that lost
// the response recovers inside the window.
func TestOAuthProviderRotationGraceAnswersARetry(t *testing.T) {
	h, _ := providerHarness(t)
	verifier, challenge := pkcePair(t)
	code := providerCodeFor(t, h, challenge, nil)
	resp := h.DoForm(h.URL("/oauth2/token"), map[string]string{
		"grant_type": "authorization_code", "code": code,
		"redirect_uri": "https://app.example.com/callback", "code_verifier": verifier,
		"client_id": "first-party", "client_secret": "first-party-secret",
	})
	var first struct {
		RefreshToken string `json:"refresh_token"`
	}
	resp.Decode(t, &first)
	refresh := map[string]string{
		"grant_type": "refresh_token", "refresh_token": first.RefreshToken,
		"client_id": "first-party", "client_secret": "first-party-secret",
	}
	if r := h.DoForm(h.URL("/oauth2/token"), refresh); r.Status != http.StatusOK {
		t.Fatalf("rotation: %d %s", r.Status, r.Body)
	}
	retry := h.DoForm(h.URL("/oauth2/token"), refresh)
	if retry.Status != http.StatusOK {
		t.Fatalf("the retry inside the grace window failed: %d %s", retry.Status, retry.Body)
	}
	var second struct {
		AccessToken string `json:"access_token"`
	}
	retry.Decode(t, &second)
	if second.AccessToken == "" {
		t.Fatalf("the retry returned no access token: %s", retry.Body)
	}
}

// TestOAuthProviderRotationKeepsTheOldKeyVerifying proves that a rotation
// breaks no cached key set.
func TestOAuthProviderRotationKeepsTheOldKeyVerifying(t *testing.T) {
	h, p := providerHarness(t)
	verifier, challenge := pkcePair(t)
	code := providerCodeFor(t, h, challenge, url.Values{"scope": {"openid email"}})
	resp := h.DoForm(h.URL("/oauth2/token"), map[string]string{
		"grant_type": "authorization_code", "code": code,
		"redirect_uri": "https://app.example.com/callback", "code_verifier": verifier,
		"client_id": "first-party", "client_secret": "first-party-secret",
	})
	var token struct {
		AccessToken string `json:"access_token"`
	}
	resp.Decode(t, &token)
	if err := p.Rotate(context.Background()); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	keys := h.Do(http.MethodGet, "/oauth2/jwks", nil)
	var set struct {
		Keys []map[string]any `json:"keys"`
	}
	keys.Decode(t, &set)
	if len(set.Keys) != 2 {
		t.Fatalf("the key set holds %d keys after a rotation", len(set.Keys))
	}
	// The token of the retired key still passes, because the key set keeps it.
	info := h.Do(http.MethodGet, "/oauth2/userinfo", nil, testsupport.WithBearer(token.AccessToken))
	if info.Status != http.StatusOK {
		t.Fatalf("the rotation broke a live token: %d %s", info.Status, info.Body)
	}
}

// TestOAuthProviderDisabledUserLosesEveryGrant covers the revocation cascade.
func TestOAuthProviderDisabledUserLosesEveryGrant(t *testing.T) {
	h, _ := providerHarness(t)
	verifier, challenge := pkcePair(t)
	code := providerCodeFor(t, h, challenge, url.Values{"scope": {"openid email"}})
	resp := h.DoForm(h.URL("/oauth2/token"), map[string]string{
		"grant_type": "authorization_code", "code": code,
		"redirect_uri": "https://app.example.com/callback", "code_verifier": verifier,
		"client_id": "first-party", "client_secret": "first-party-secret",
	})
	var token struct {
		AccessToken string `json:"access_token"`
	}
	resp.Decode(t, &token)
	// A second user holds the administrator role, because an administrator
	// disables no own account.
	target, err := h.Store.Users().GetByNormalizedEmail(context.Background(), "owner@example.com")
	if err != nil {
		t.Fatal(err)
	}
	h.ClearCookies()
	h.SignUp("root@example.com", "Password123!")
	setRole(t, h.Store, "root@example.com", "admin")
	h.ClearCookies()
	h.SignIn("root@example.com", "Password123!")
	disable := h.Do(http.MethodPost, "/admin/users/"+target.ID+"/disable", nil)
	if disable.Status != http.StatusOK {
		t.Fatalf("disable: %d %s", disable.Status, disable.Body)
	}
	info := h.Do(http.MethodGet, "/oauth2/userinfo", nil, testsupport.WithBearer(token.AccessToken))
	if info.Status == http.StatusOK {
		t.Fatal("a disabled user kept a live access token")
	}
}

// TestOAuthProviderCleanupRemovesSpentRows covers the host cleanup call.
func TestOAuthProviderCleanupRemovesSpentRows(t *testing.T) {
	h, p := providerHarness(t)
	verifier, challenge := pkcePair(t)
	code := providerCodeFor(t, h, challenge, nil)
	h.DoForm(h.URL("/oauth2/token"), map[string]string{
		"grant_type": "authorization_code", "code": code,
		"redirect_uri": "https://app.example.com/callback", "code_verifier": verifier,
		"client_id": "first-party", "client_secret": "first-party-secret",
	})
	if _, err := p.Cleanup(context.Background()); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
}

// TestOAuthProviderManagedClientsBelongToTheCaller covers the authenticated
// management routes.
func TestOAuthProviderManagedClientsBelongToTheCaller(t *testing.T) {
	h, _ := providerHarness(t)
	h.SignUp("owner@example.com", "Password123!")
	created := h.Do(http.MethodPost, "/oauth2/clients", map[string]any{
		"client_name":   "My Integration",
		"redirect_uris": []string{"https://integration.example.com/callback"},
	})
	if created.Status != http.StatusCreated {
		t.Fatalf("create: %d %s", created.Status, created.Body)
	}
	var client struct {
		ClientID     string `json:"clientId"`
		ClientSecret string `json:"clientSecret"`
		Name         string `json:"name"`
	}
	created.Decode(t, &client)
	if client.ClientSecret == "" || client.Name != "My Integration" {
		t.Fatalf("the created client is incomplete: %s", created.Body)
	}
	list := h.Do(http.MethodGet, "/oauth2/clients", nil)
	var listed struct {
		Clients []struct {
			ClientID     string `json:"clientId"`
			ClientSecret string `json:"clientSecret"`
		} `json:"clients"`
	}
	list.Decode(t, &listed)
	if len(listed.Clients) != 1 || listed.Clients[0].ClientID != client.ClientID {
		t.Fatalf("the list is wrong: %s", list.Body)
	}
	if listed.Clients[0].ClientSecret != "" {
		t.Fatal("the list repeats the client secret")
	}

	// Another user reaches neither the list nor the delete.
	h.ClearCookies()
	h.SignUp("other@example.com", "Password123!")
	other := h.Do(http.MethodGet, "/oauth2/clients", nil)
	other.Decode(t, &listed)
	if len(listed.Clients) != 0 {
		t.Fatalf("another user saw the clients: %s", other.Body)
	}
	denied := h.Do(http.MethodDelete, "/oauth2/clients/"+client.ClientID, nil)
	if denied.Status != http.StatusNotFound {
		t.Fatalf("another user deleted the client: %d", denied.Status)
	}
	h.ClearCookies()
	h.SignIn("owner@example.com", "Password123!")
	deleted := h.Do(http.MethodDelete, "/oauth2/clients/"+client.ClientID, nil)
	if deleted.Status != http.StatusOK {
		t.Fatalf("delete: %d %s", deleted.Status, deleted.Body)
	}
}

// TestOAuthProviderRegistrationManagementUpdatesAndDeletes covers the rest of
// RFC 7592.
func TestOAuthProviderRegistrationManagementUpdatesAndDeletes(t *testing.T) {
	h, _ := providerHarness(t, oauthprovider.AllowDynamicRegistration())
	created := h.Do(http.MethodPost, "/oauth2/register", map[string]any{
		"client_name":   "Desktop",
		"redirect_uris": []string{"myapp://callback"},
	})
	var client struct {
		ClientID                string `json:"client_id"`
		RegistrationAccessToken string `json:"registration_access_token"`
	}
	created.Decode(t, &client)

	updated := h.Do(http.MethodPut, "/oauth2/register/"+client.ClientID, map[string]any{
		"client_name":   "Desktop 2",
		"redirect_uris": []string{"myapp://callback", "http://127.0.0.1/callback"},
	}, testsupport.WithBearer(client.RegistrationAccessToken))
	if updated.Status != http.StatusOK {
		t.Fatalf("update: %d %s", updated.Status, updated.Body)
	}
	var back struct {
		ClientID     string   `json:"client_id"`
		ClientName   string   `json:"client_name"`
		RedirectURIs []string `json:"redirect_uris"`
	}
	updated.Decode(t, &back)
	if back.ClientID != client.ClientID || back.ClientName != "Desktop 2" || len(back.RedirectURIs) != 2 {
		t.Fatalf("the update lost fields: %s", updated.Body)
	}
	bad := h.Do(http.MethodPut, "/oauth2/register/"+client.ClientID, map[string]any{
		"client_name":   "Desktop 3",
		"redirect_uris": []string{"http://example.com/callback"},
	}, testsupport.WithBearer(client.RegistrationAccessToken))
	if bad.Status != http.StatusBadRequest {
		t.Fatalf("the update accepted a plain http redirect URI: %d", bad.Status)
	}
	removed := h.Do(http.MethodDelete, "/oauth2/register/"+client.ClientID, nil,
		testsupport.WithBearer(client.RegistrationAccessToken))
	if removed.Status != http.StatusNoContent {
		t.Fatalf("delete: %d %s", removed.Status, removed.Body)
	}
	gone := h.Do(http.MethodGet, "/oauth2/register/"+client.ClientID, nil,
		testsupport.WithBearer(client.RegistrationAccessToken))
	if gone.Status != http.StatusUnauthorized {
		t.Fatalf("the deleted client still answers: %d", gone.Status)
	}
}

// TestOAuthProviderMetadataHandlerServesTheOriginRoot proves the mount that the
// host adds at the origin root.
func TestOAuthProviderMetadataHandlerServesTheOriginRoot(t *testing.T) {
	h, p := providerHarness(t)
	h.Handle("/.well-known/", p.MetadataHandler())
	base := h.Auth.BasePath()
	for _, path := range []string{
		"/.well-known/oauth-authorization-server" + base,
		"/.well-known/openid-configuration" + base,
		"/.well-known/openid-configuration",
	} {
		resp := h.DoURL(http.MethodGet, h.BaseURL+path, nil)
		if resp.Status != http.StatusOK {
			t.Fatalf("%s: %d", path, resp.Status)
		}
		var doc map[string]any
		resp.Decode(t, &doc)
		if doc["issuer"] != h.BaseURL+base {
			t.Fatalf("%s names the issuer %v", path, doc["issuer"])
		}
	}
	missing := h.DoURL(http.MethodGet, h.BaseURL+"/.well-known/openid-configuration/other", nil)
	if missing.Status != http.StatusNotFound {
		t.Fatalf("a foreign path answered: %d", missing.Status)
	}
	other := h.DoURL(http.MethodGet, h.BaseURL+"/.well-known/something-else", nil)
	if other.Status != http.StatusNotFound {
		t.Fatalf("an unknown well-known path answered: %d", other.Status)
	}
}

// TestOAuthProviderAuthorizeRejectsABadRequest covers the validation of the
// authorize route, including the errors that travel back to the client.
func TestOAuthProviderAuthorizeRejectsABadRequest(t *testing.T) {
	h, _ := providerHarness(t)
	h.SignUp("owner@example.com", "Password123!")
	_, challenge := pkcePair(t)

	// A request without a client, and one with an unknown client, answer at the
	// server, because no validated redirect URI exists yet.
	for _, query := range []url.Values{
		{"redirect_uri": {"https://app.example.com/callback"}},
		{"client_id": {"nobody"}, "redirect_uri": {"https://app.example.com/callback"}},
	} {
		target := "/oauth2/authorize?" + query.Encode()
		if resp := h.Do(http.MethodGet, target, nil); resp.Status != http.StatusBadRequest {
			t.Fatalf("%s returned %d", target, resp.Status)
		}
	}

	// A validated redirect URI receives the error, as RFC 6749 asks.
	cases := map[string]url.Values{
		"unsupported_response_type": {"response_type": {"token"}},
		"invalid_request":           {"code_challenge_method": {"plain"}},
		"invalid_scope":             {"scope": {"unknown"}},
		"invalid_target":            {"resource": {"https://nowhere.example.com"}},
	}
	for want, extra := range cases {
		resp := h.Do(http.MethodGet, authorizeURL(challenge, extra), nil)
		if resp.Status != http.StatusSeeOther {
			t.Fatalf("%s: status %d body %s", want, resp.Status, resp.Body)
		}
		back, err := url.Parse(resp.Location())
		if err != nil {
			t.Fatal(err)
		}
		if back.Query().Get("error") != want {
			t.Fatalf("the request returned %q, want %q", back.Query().Get("error"), want)
		}
		if back.Query().Get("state") != "state-value" {
			t.Fatal("the error lost the state")
		}
	}

	// A request object is out of scope, and the server says so.
	resp := h.Do(http.MethodGet, authorizeURL(challenge, url.Values{"request": {"a.b.c"}}), nil)
	back, err := url.Parse(resp.Location())
	if err != nil {
		t.Fatal(err)
	}
	if back.Query().Get("error") != "invalid_request" {
		t.Fatalf("a request object passed: %s", resp.Location())
	}
}

// TestOAuthProviderTokenRejectsABadCall covers the failure paths of the token
// endpoint.
func TestOAuthProviderTokenRejectsABadCall(t *testing.T) {
	h, _ := providerHarness(t)
	verifier, challenge := pkcePair(t)
	code := providerCodeFor(t, h, challenge, nil)
	valid := map[string]string{
		"grant_type": "authorization_code", "code": code,
		"redirect_uri": "https://app.example.com/callback", "code_verifier": verifier,
		"client_id": "first-party", "client_secret": "first-party-secret",
	}
	type call struct {
		fields map[string]string
		status int
	}
	clone := func(changes map[string]string) map[string]string {
		out := map[string]string{}
		for k, v := range valid {
			out[k] = v
		}
		for k, v := range changes {
			if v == "" {
				delete(out, k)
				continue
			}
			out[k] = v
		}
		return out
	}
	cases := map[string]call{
		"a wrong secret":    {clone(map[string]string{"client_secret": "wrong"}), http.StatusUnauthorized},
		"no client":         {clone(map[string]string{"client_id": "", "client_secret": ""}), http.StatusUnauthorized},
		"an unknown client": {clone(map[string]string{"client_id": "nobody"}), http.StatusUnauthorized},
		"a wrong verifier":  {clone(map[string]string{"code_verifier": "wrong"}), http.StatusBadRequest},
		"a wrong redirect":  {clone(map[string]string{"redirect_uri": "http://127.0.0.1/callback"}), http.StatusBadRequest},
		"no verifier":       {clone(map[string]string{"code_verifier": ""}), http.StatusBadRequest},
		"an unknown grant":  {clone(map[string]string{"grant_type": "password"}), http.StatusBadRequest},
		"an unknown code":   {clone(map[string]string{"code": "nope"}), http.StatusBadRequest},
		"no refresh token":  {map[string]string{"grant_type": "refresh_token", "client_id": "first-party", "client_secret": "first-party-secret"}, http.StatusBadRequest},
		"a foreign refresh": {map[string]string{"grant_type": "refresh_token", "refresh_token": "nope", "client_id": "first-party", "client_secret": "first-party-secret"}, http.StatusBadRequest},
		"no machine grant":  {map[string]string{"grant_type": "client_credentials", "scope": "email", "client_id": "first-party", "client_secret": "first-party-secret"}, http.StatusBadRequest},
	}
	for name, c := range cases {
		resp := h.DoForm(h.URL("/oauth2/token"), c.fields)
		if resp.Status != c.status {
			t.Errorf("%s returned %d, want %d: %s", name, resp.Status, c.status, resp.Body)
		}
	}
	// A code that met a wrong verifier is spent, so a later correct call reaches
	// no token. The single use of the code holds through a failed attempt.
	if resp := h.DoForm(h.URL("/oauth2/token"), valid); resp.Status != http.StatusBadRequest {
		t.Fatalf("a code survived a failed exchange: %d %s", resp.Status, resp.Body)
	}
}

// TestOAuthProviderClaimsComeFromStoredFields proves the claim rules: no claim
// is derived, and a host field reaches userinfo through a mapping.
func TestOAuthProviderClaimsComeFromStoredFields(t *testing.T) {
	h, _ := providerHarness(t,
		oauthprovider.Claims(oauthprovider.ClaimMapping{
			Scope: "profile", Claim: "nickname", Field: "nickname",
		}),
		oauthprovider.ClaimsFrom(func(user *store.User, scopes []string) map[string]any {
			// A reserved name is dropped, so a function cannot overwrite sub.
			return map[string]any{"sub": "forged", "tier": "gold"}
		}),
	)
	verifier, challenge := pkcePair(t)
	code := providerCodeFor(t, h, challenge, url.Values{"scope": {"openid email profile"}})
	resp := h.DoForm(h.URL("/oauth2/token"), map[string]string{
		"grant_type": "authorization_code", "code": code,
		"redirect_uri": "https://app.example.com/callback", "code_verifier": verifier,
		"client_id": "first-party", "client_secret": "first-party-secret",
	})
	var token struct {
		AccessToken string `json:"access_token"`
	}
	resp.Decode(t, &token)
	info := h.Do(http.MethodGet, "/oauth2/userinfo", nil, testsupport.WithBearer(token.AccessToken))
	var claims map[string]any
	info.Decode(t, &claims)
	if claims["name"] != "Test User" {
		t.Fatalf("the display name is missing: %v", claims)
	}
	if _, split := claims["given_name"]; split {
		t.Fatal("the server derived a given name from the display name")
	}
	if claims["tier"] != "gold" {
		t.Fatalf("the claims function reached no claim: %v", claims)
	}
	if claims["sub"] == "forged" {
		t.Fatal("the claims function overwrote a reserved claim")
	}
}

// TestOAuthProviderPromptRules covers login_required, prompt=login, prompt=none
// and max_age.
func TestOAuthProviderPromptRules(t *testing.T) {
	h, _ := providerHarness(t)
	_, challenge := pkcePair(t)

	// A signed-out visitor with prompt=none receives login_required.
	resp := h.Do(http.MethodGet, authorizeURL(challenge, url.Values{"prompt": {"none"}}), nil)
	back, err := url.Parse(resp.Location())
	if err != nil {
		t.Fatal(err)
	}
	if back.Query().Get("error") != "login_required" {
		t.Fatalf("a signed-out request returned %q", back.Query().Get("error"))
	}

	// A signed-out visitor without a prompt goes to the login page.
	resp = h.Do(http.MethodGet, authorizeURL(challenge, nil), nil)
	if target, _ := url.Parse(resp.Location()); target.Path != "/sign-in" {
		t.Fatalf("the visitor went to %s", resp.Location())
	}

	// A signed-in user with prompt=login sees the login page again.
	h.SignUp("owner@example.com", "Password123!")
	resp = h.Do(http.MethodGet, authorizeURL(challenge, url.Values{"prompt": {"login"}}), nil)
	if target, _ := url.Parse(resp.Location()); target.Path != "/sign-in" {
		t.Fatalf("prompt=login went to %s", resp.Location())
	}

	// A max_age of zero makes every session too old.
	resp = h.Do(http.MethodGet, authorizeURL(challenge, url.Values{"max_age": {"0"}}), nil)
	if target, _ := url.Parse(resp.Location()); target.Path != "/sign-in" {
		t.Fatalf("max_age=0 went to %s", resp.Location())
	}
	bad := h.Do(http.MethodGet, authorizeURL(challenge, url.Values{"max_age": {"soon"}}), nil)
	if target, _ := url.Parse(bad.Location()); target.Query().Get("error") != "invalid_request" {
		t.Fatalf("a wrong max age returned %s", bad.Location())
	}

	// A first-party client needs no consent, so the flow completes.
	resp = h.Do(http.MethodGet, authorizeURL(challenge, nil), nil)
	if !strings.HasPrefix(resp.Location(), "https://app.example.com/callback") {
		t.Fatalf("the first-party client saw a consent page: %s", resp.Location())
	}
}

// TestOAuthProviderRequestRoutesRefuseAnUnknownRequest covers the host page
// routes on a spent or missing identifier.
func TestOAuthProviderRequestRoutesRefuseAnUnknownRequest(t *testing.T) {
	h, _ := providerHarness(t)
	if resp := h.Do(http.MethodGet, "/oauth2/request", nil); resp.Status != http.StatusBadRequest {
		t.Fatalf("a call without an identifier returned %d", resp.Status)
	}
	if resp := h.Do(http.MethodGet, "/oauth2/request?request_id=nope", nil); resp.Status != http.StatusNotFound {
		t.Fatalf("an unknown identifier returned %d", resp.Status)
	}
	if resp := h.Do(http.MethodPost, "/oauth2/decide", map[string]any{}); resp.Status != http.StatusBadRequest {
		t.Fatalf("a decision without an identifier returned %d", resp.Status)
	}
	resp := h.Do(http.MethodPost, "/oauth2/decide",
		map[string]any{"requestId": "nope", "approve": true})
	if resp.Status != http.StatusNotFound {
		t.Fatalf("a decision on an unknown request returned %d", resp.Status)
	}

	// A decision needs a signed-in user.
	_, challenge := pkcePair(t)
	h.Do(http.MethodGet, authorizeURL(challenge, nil), nil)
	if resp := h.Do(http.MethodGet, "/oauth2/consents", nil); resp.Status != http.StatusUnauthorized {
		t.Fatalf("the consent list answered a signed-out caller: %d", resp.Status)
	}
	if resp := h.Do(http.MethodDelete, "/oauth2/consents/first-party", nil); resp.Status != http.StatusUnauthorized {
		t.Fatalf("the withdrawal answered a signed-out caller: %d", resp.Status)
	}
}

// TestOAuthProviderDPoPRejectsABadProof covers the proof checks of RFC 9449.
func TestOAuthProviderDPoPRejectsABadProof(t *testing.T) {
	h, _ := providerHarness(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := jws.PublicJWK(&key.PublicKey, jws.ES256, "")
	if err != nil {
		t.Fatal(err)
	}
	delete(jwk, "kid")
	delete(jwk, "use")
	delete(jwk, "alg")

	fields := map[string]string{
		"grant_type": "refresh_token", "refresh_token": "nope",
		"client_id": "first-party", "client_secret": "first-party-secret",
	}
	// A proof of another route fails.
	wrongRoute := dpopProof(t, key, jwk, http.MethodPost, h.URL("/oauth2/revoke"), "")
	resp := h.DoForm(h.URL("/oauth2/token"), fields, testsupport.WithHeader("DPoP", wrongRoute))
	if resp.Status != http.StatusBadRequest {
		t.Fatalf("a proof of another route passed: %d %s", resp.Status, resp.Body)
	}
	// A proof of another method fails.
	wrongMethod := dpopProof(t, key, jwk, http.MethodGet, h.URL("/oauth2/token"), "")
	resp = h.DoForm(h.URL("/oauth2/token"), fields, testsupport.WithHeader("DPoP", wrongMethod))
	if resp.Status != http.StatusBadRequest {
		t.Fatalf("a proof of another method passed: %d", resp.Status)
	}
	// A malformed proof fails.
	resp = h.DoForm(h.URL("/oauth2/token"), fields, testsupport.WithHeader("DPoP", "not-a-proof"))
	if resp.Status != http.StatusBadRequest {
		t.Fatalf("a malformed proof passed: %d", resp.Status)
	}
	// One proof is single use.
	proof := dpopProof(t, key, jwk, http.MethodPost, h.URL("/oauth2/token"), "")
	h.DoForm(h.URL("/oauth2/token"), fields, testsupport.WithHeader("DPoP", proof))
	again := h.DoForm(h.URL("/oauth2/token"), fields, testsupport.WithHeader("DPoP", proof))
	var body map[string]string
	again.Decode(t, &body)
	if body["error"] != "invalid_dpop_proof" {
		t.Fatalf("a replayed proof passed: %s", again.Body)
	}
}

// TestOAuthProviderRS256SignsForAnOlderRelyingParty covers the second
// algorithm.
func TestOAuthProviderRS256SignsForAnOlderRelyingParty(t *testing.T) {
	h, _ := providerHarness(t, oauthprovider.Algorithm("RS256"))
	verifier, challenge := pkcePair(t)
	code := providerCodeFor(t, h, challenge, url.Values{"scope": {"openid email"}})
	resp := h.DoForm(h.URL("/oauth2/token"), map[string]string{
		"grant_type": "authorization_code", "code": code,
		"redirect_uri": "https://app.example.com/callback", "code_verifier": verifier,
		"client_id": "first-party", "client_secret": "first-party-secret",
	})
	var token struct {
		IDToken string `json:"id_token"`
	}
	resp.Decode(t, &token)
	header, _, err := jws.Parse(token.IDToken)
	if err != nil {
		t.Fatal(err)
	}
	if header.Algorithm != "RS256" {
		t.Fatalf("the identity token uses %q", header.Algorithm)
	}
	keys := h.Do(http.MethodGet, "/oauth2/jwks", nil)
	var set struct {
		Keys []map[string]any `json:"keys"`
	}
	keys.Decode(t, &set)
	pub, err := jws.PublicKeyFromJWK(set.Keys[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := jws.Verify(token.IDToken, pub); err != nil {
		t.Fatalf("the RS256 token does not verify: %v", err)
	}
}

// TestOAuthProviderUserInfoNeedsTheOpenIDScope proves that a token without the
// openid scope reads no claims.
func TestOAuthProviderUserInfoNeedsTheOpenIDScope(t *testing.T) {
	h, _ := providerHarness(t)
	verifier, challenge := pkcePair(t)
	code := providerCodeFor(t, h, challenge, url.Values{"scope": {"email"}})
	resp := h.DoForm(h.URL("/oauth2/token"), map[string]string{
		"grant_type": "authorization_code", "code": code,
		"redirect_uri": "https://app.example.com/callback", "code_verifier": verifier,
		"client_id": "first-party", "client_secret": "first-party-secret",
	})
	var token struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
	}
	resp.Decode(t, &token)
	if token.IDToken != "" {
		t.Fatal("a request without the openid scope received an identity token")
	}
	info := h.Do(http.MethodGet, "/oauth2/userinfo", nil, testsupport.WithBearer(token.AccessToken))
	if info.Status != http.StatusUnauthorized {
		t.Fatalf("userinfo answered without the openid scope: %d", info.Status)
	}
	empty := h.Do(http.MethodGet, "/oauth2/userinfo", nil)
	if empty.Status != http.StatusUnauthorized {
		t.Fatalf("userinfo answered without a token: %d", empty.Status)
	}
	forged := h.Do(http.MethodGet, "/oauth2/userinfo", nil, testsupport.WithBearer("a.b.c"))
	if forged.Status != http.StatusUnauthorized {
		t.Fatalf("userinfo answered a forged token: %d", forged.Status)
	}
}

// TestOAuthProviderIntrospectionIsPerClient proves that one client learns
// nothing about the token of another client.
func TestOAuthProviderIntrospectionIsPerClient(t *testing.T) {
	h, _ := providerHarness(t, oauthprovider.Clients(oauthprovider.StaticClient{
		ClientID: "second", Secret: "second-secret", AuthMethod: "client_secret_post",
		RedirectURIs: []string{"https://second.example.com/callback"},
	}))
	verifier, challenge := pkcePair(t)
	code := providerCodeFor(t, h, challenge, nil)
	resp := h.DoForm(h.URL("/oauth2/token"), map[string]string{
		"grant_type": "authorization_code", "code": code,
		"redirect_uri": "https://app.example.com/callback", "code_verifier": verifier,
		"client_id": "first-party", "client_secret": "first-party-secret",
	})
	var token struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	resp.Decode(t, &token)

	var body map[string]any
	foreign := h.DoForm(h.URL("/oauth2/introspect"), map[string]string{
		"token": token.AccessToken, "client_id": "second", "client_secret": "second-secret",
	})
	foreign.Decode(t, &body)
	if body["active"] != false {
		t.Fatalf("a client introspected a foreign token: %s", foreign.Body)
	}
	// The refresh token of the own client is active and names its kind.
	own := h.DoForm(h.URL("/oauth2/introspect"), map[string]string{
		"token": token.RefreshToken, "client_id": "first-party", "client_secret": "first-party-secret",
	})
	own.Decode(t, &body)
	if body["active"] != true || body["token_type"] != "refresh_token" {
		t.Fatalf("the refresh token introspection is wrong: %s", own.Body)
	}
	// A public caller reaches no introspection.
	public := h.DoForm(h.URL("/oauth2/introspect"), map[string]string{"token": token.AccessToken})
	if public.Status != http.StatusUnauthorized {
		t.Fatalf("an unauthenticated introspection returned %d", public.Status)
	}
	// An empty token is inactive, and a revocation of an unknown token answers
	// with 200, as RFC 7009 asks.
	empty := h.DoForm(h.URL("/oauth2/introspect"), map[string]string{
		"client_id": "first-party", "client_secret": "first-party-secret",
	})
	empty.Decode(t, &body)
	if body["active"] != false {
		t.Fatalf("an empty token is active: %s", empty.Body)
	}
	unknown := h.DoForm(h.URL("/oauth2/revoke"), map[string]string{
		"client_id": "first-party", "client_secret": "first-party-secret",
	})
	if unknown.Status != http.StatusOK {
		t.Fatalf("the revocation of an unknown token returned %d", unknown.Status)
	}
	// Revoking an access token of another client changes nothing.
	other := h.DoForm(h.URL("/oauth2/revoke"), map[string]string{
		"token": token.AccessToken, "client_id": "second", "client_secret": "second-secret",
	})
	if other.Status != http.StatusOK {
		t.Fatalf("the foreign revocation returned %d", other.Status)
	}
	still := h.DoForm(h.URL("/oauth2/introspect"), map[string]string{
		"token": token.AccessToken, "client_id": "first-party", "client_secret": "first-party-secret",
	})
	still.Decode(t, &body)
	if body["active"] != true {
		t.Fatal("another client revoked the token")
	}
}

// TestOAuthProviderRegistrationIsClosedByDefault proves that the registration
// route needs the host option, and that bad metadata fails.
func TestOAuthProviderRegistrationIsClosedByDefault(t *testing.T) {
	h, _ := providerHarness(t)
	closed := h.Do(http.MethodPost, "/oauth2/register", map[string]any{
		"client_name": "Desktop", "redirect_uris": []string{"myapp://callback"},
	})
	if closed.Status != http.StatusNotFound && closed.Status != http.StatusMethodNotAllowed {
		t.Fatalf("the closed server answered the registration with %d", closed.Status)
	}

	open, _ := providerHarness(t, oauthprovider.AllowDynamicRegistration())
	cases := []map[string]any{
		{"client_name": "No URI"},
		{"client_name": "Token flow", "redirect_uris": []string{"https://a.example.com/cb"},
			"response_types": []string{"token"}},
		{"client_name": "Unknown scope", "redirect_uris": []string{"https://a.example.com/cb"},
			"scope": "unknown"},
		{"client_name": "Unknown auth", "redirect_uris": []string{"https://a.example.com/cb"},
			"token_endpoint_auth_method": "private_key_jwt"},
		{"client_name": "Public machine", "redirect_uris": []string{"https://a.example.com/cb"},
			"grant_types": []string{"client_credentials"}, "token_endpoint_auth_method": "none"},
		{"client_name": "No supported grant", "redirect_uris": []string{"https://a.example.com/cb"},
			"grant_types": []string{"password"}},
	}
	for _, body := range cases {
		resp := open.Do(http.MethodPost, "/oauth2/register", body)
		if resp.Status != http.StatusBadRequest {
			t.Errorf("the metadata %v registered with %d", body["client_name"], resp.Status)
		}
	}
	// An unsupported grant next to a supported one drops out, so the client
	// still registers.
	mixed := open.Do(http.MethodPost, "/oauth2/register", map[string]any{
		"client_name": "Mixed", "redirect_uris": []string{"https://a.example.com/cb"},
		"grant_types": []string{"authorization_code", "urn:ietf:params:oauth:grant-type:device_code"},
	})
	if mixed.Status != http.StatusCreated {
		t.Fatalf("a mixed grant list failed: %d %s", mixed.Status, mixed.Body)
	}
}

// TestOAuthProviderResolverAcceptsOnlyItsOwnTokens covers the credential
// resolver directly, including the values it must refuse.
func TestOAuthProviderResolverAcceptsOnlyItsOwnTokens(t *testing.T) {
	h, p := providerHarness(t)
	verifier, challenge := pkcePair(t)
	code := providerCodeFor(t, h, challenge, url.Values{"scope": {"openid email"}})
	resp := h.DoForm(h.URL("/oauth2/token"), map[string]string{
		"grant_type": "authorization_code", "code": code,
		"redirect_uri": "https://app.example.com/callback", "code_verifier": verifier,
		"client_id": "first-party", "client_secret": "first-party-secret",
	})
	var token struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
	}
	resp.Decode(t, &token)

	// The resolver claims an access token of this server and nothing else.
	if !p.Claims(token.AccessToken) {
		t.Fatal("the resolver claims no access token")
	}
	for _, value := range []string{token.IDToken, "opaque-session-token", "a.b.c", ""} {
		if p.Claims(value) {
			t.Fatalf("the resolver claimed %q", value)
		}
	}
	principal, err := p.Resolve(context.Background(), token.AccessToken)
	if err != nil || principal == nil || principal.User == nil {
		t.Fatalf("the resolver refused its own token: %v", err)
	}
	if principal.Method != "oauthprovider" {
		t.Fatalf("the principal names the method %q", principal.Method)
	}
	if _, err := p.Resolve(context.Background(), "a.b.c"); err == nil {
		t.Fatal("the resolver accepted a malformed token")
	}

	// A token of another audience never resolves.
	verifier, challenge = pkcePair(t)
	code = providerCodeFor(t, h, challenge,
		url.Values{"scope": {"openid email"}, "resource": {"https://api.example.com"}})
	foreign := h.DoForm(h.URL("/oauth2/token"), map[string]string{
		"grant_type": "authorization_code", "code": code,
		"redirect_uri": "https://app.example.com/callback", "code_verifier": verifier,
		"client_id": "first-party", "client_secret": "first-party-secret",
	})
	foreign.Decode(t, &token)
	if _, err := p.Resolve(context.Background(), token.AccessToken); err == nil {
		t.Fatal("the resolver accepted a token of another resource server")
	}
}

// TestOAuthProviderRefusesAForeignKey proves that a token of an unknown key and
// a token of another issuer both fail.
func TestOAuthProviderRefusesAForeignKey(t *testing.T) {
	h, p := providerHarness(t)
	key, err := jws.Generate(jws.ES256, "not-a-server-key")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	issuer := h.BaseURL + h.Auth.BasePath()
	forged, err := key.Sign("at+jwt", map[string]any{
		"iss": issuer, "sub": "someone", "aud": issuer, "client_id": "first-party",
		"scope": "openid", "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
		"jti": "forged",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Resolve(context.Background(), forged); err == nil {
		t.Fatal("a token of an unknown key resolved")
	}
	info := h.Do(http.MethodGet, "/oauth2/userinfo", nil, testsupport.WithBearer(forged))
	if info.Status != http.StatusUnauthorized {
		t.Fatalf("userinfo accepted a token of an unknown key: %d", info.Status)
	}

	// A token of another issuer fails even when this server signed it.
	verifier, challenge := pkcePair(t)
	code := providerCodeFor(t, h, challenge, url.Values{"scope": {"openid email"}})
	resp := h.DoForm(h.URL("/oauth2/token"), map[string]string{
		"grant_type": "authorization_code", "code": code,
		"redirect_uri": "https://app.example.com/callback", "code_verifier": verifier,
		"client_id": "first-party", "client_secret": "first-party-secret",
	})
	var token struct {
		AccessToken string `json:"access_token"`
	}
	resp.Decode(t, &token)
	// The identity token is no access token, so the resource routes refuse it.
	id := h.Do(http.MethodGet, "/oauth2/userinfo", nil, testsupport.WithBearer(token.AccessToken+"x"))
	if id.Status != http.StatusUnauthorized {
		t.Fatalf("a changed signature passed: %d", id.Status)
	}
}

// TestOAuthProviderRefusesAStoreWithoutItsRows proves that the plugin fails
// closed on an adapter that cannot hold its tables.
func TestOAuthProviderRefusesAStoreWithoutItsRows(t *testing.T) {
	_, err := authall.New(
		authall.WithStore(rowlessStore{testsupport.NewSQLite(t)}),
		authall.WithBaseURL("https://app.example.com"),
		authall.WithPlugins(
			roles.New(roles.Hierarchy("viewer", "admin"), roles.Default("viewer")),
			oauthprovider.New(
				oauthprovider.KeyEncryptionKey(make([]byte, 32)),
				oauthprovider.LoginPath("/sign-in"),
				oauthprovider.ConsentPath("/consent"),
			),
		),
	)
	if err == nil {
		t.Fatal("the plugin registered over a store that holds no OAuth provider row")
	}
	if !strings.Contains(err.Error(), "OAuth provider row") {
		t.Fatalf("the error names another cause: %v", err)
	}
}

// rowlessStore hides the OAuth provider rows of an adapter.
type rowlessStore struct{ store.Store }

// TestOAuthProviderCrossClientTheftKillsTheGrant proves that a code or a
// refresh token presented by another client ends the authorization.
func TestOAuthProviderCrossClientTheftKillsTheGrant(t *testing.T) {
	h, _ := providerHarness(t, oauthprovider.Clients(oauthprovider.StaticClient{
		ClientID: "thief", Secret: "thief-secret", AuthMethod: "client_secret_post",
		RedirectURIs: []string{"https://thief.example.com/callback"},
	}))
	verifier, challenge := pkcePair(t)
	code := providerCodeFor(t, h, challenge, nil)

	// The thief presents the code of the first client.
	stolen := h.DoForm(h.URL("/oauth2/token"), map[string]string{
		"grant_type": "authorization_code", "code": code,
		"redirect_uri": "https://app.example.com/callback", "code_verifier": verifier,
		"client_id": "thief", "client_secret": "thief-secret",
	})
	if stolen.Status != http.StatusBadRequest {
		t.Fatalf("the thief exchanged the code: %d %s", stolen.Status, stolen.Body)
	}
	// The owner reaches no token either, because the grant died with the theft.
	owner := h.DoForm(h.URL("/oauth2/token"), map[string]string{
		"grant_type": "authorization_code", "code": code,
		"redirect_uri": "https://app.example.com/callback", "code_verifier": verifier,
		"client_id": "first-party", "client_secret": "first-party-secret",
	})
	if owner.Status == http.StatusOK {
		t.Fatal("the stolen code still produced a token")
	}

	// The same rule holds for a refresh token.
	verifier, challenge = pkcePair(t)
	code = providerCodeFor(t, h, challenge, nil)
	issued := h.DoForm(h.URL("/oauth2/token"), map[string]string{
		"grant_type": "authorization_code", "code": code,
		"redirect_uri": "https://app.example.com/callback", "code_verifier": verifier,
		"client_id": "first-party", "client_secret": "first-party-secret",
	})
	var token struct {
		RefreshToken string `json:"refresh_token"`
	}
	issued.Decode(t, &token)
	foreign := h.DoForm(h.URL("/oauth2/token"), map[string]string{
		"grant_type": "refresh_token", "refresh_token": token.RefreshToken,
		"client_id": "thief", "client_secret": "thief-secret",
	})
	if foreign.Status != http.StatusBadRequest {
		t.Fatalf("the thief refreshed the token: %d", foreign.Status)
	}
	back := h.DoForm(h.URL("/oauth2/token"), map[string]string{
		"grant_type": "refresh_token", "refresh_token": token.RefreshToken,
		"client_id": "first-party", "client_secret": "first-party-secret",
	})
	if back.Status == http.StatusOK {
		t.Fatal("the grant survived the theft of its refresh token")
	}
}

// TestOAuthProviderRefreshNarrowsAndNeverWidens proves the scope and resource
// rules of a refresh call.
func TestOAuthProviderRefreshNarrowsAndNeverWidens(t *testing.T) {
	h, _ := providerHarness(t)
	verifier, challenge := pkcePair(t)
	code := providerCodeFor(t, h, challenge,
		url.Values{"scope": {"openid email offline_access"}})
	resp := h.DoForm(h.URL("/oauth2/token"), map[string]string{
		"grant_type": "authorization_code", "code": code,
		"redirect_uri": "https://app.example.com/callback", "code_verifier": verifier,
		"client_id": "first-party", "client_secret": "first-party-secret",
	})
	var token struct {
		RefreshToken string `json:"refresh_token"`
	}
	resp.Decode(t, &token)

	wider := h.DoForm(h.URL("/oauth2/token"), map[string]string{
		"grant_type": "refresh_token", "refresh_token": token.RefreshToken,
		"scope":     "openid email profile offline_access",
		"client_id": "first-party", "client_secret": "first-party-secret",
	})
	if wider.Status != http.StatusBadRequest {
		t.Fatalf("a refresh widened the scopes: %d %s", wider.Status, wider.Body)
	}
	// A resource that the grant never held fails too.
	other := h.DoForm(h.URL("/oauth2/token"), map[string]string{
		"grant_type": "refresh_token", "refresh_token": token.RefreshToken,
		"resource":  "https://api.example.com",
		"client_id": "first-party", "client_secret": "first-party-secret",
	})
	if other.Status != http.StatusBadRequest {
		t.Fatalf("a refresh named a new resource: %d %s", other.Status, other.Body)
	}
	narrower := h.DoForm(h.URL("/oauth2/token"), map[string]string{
		"grant_type": "refresh_token", "refresh_token": token.RefreshToken,
		"scope":     "openid offline_access",
		"client_id": "first-party", "client_secret": "first-party-secret",
	})
	if narrower.Status != http.StatusOK {
		t.Fatalf("a refresh could not narrow the scopes: %d %s", narrower.Status, narrower.Body)
	}
	var narrowed struct {
		Scope string `json:"scope"`
	}
	narrower.Decode(t, &narrowed)
	if narrowed.Scope != "openid offline_access" {
		t.Fatalf("the narrowed token carries %q", narrowed.Scope)
	}
}

// TestOAuthProviderPublicClientHoldsNoSecret proves the rules of a public
// client and of a client that requires DPoP.
func TestOAuthProviderPublicClientHoldsNoSecret(t *testing.T) {
	h, _ := providerHarness(t,
		oauthprovider.Clients(
			oauthprovider.StaticClient{ClientID: "spa",
				RedirectURIs: []string{"https://spa.example.com/callback"}},
			oauthprovider.StaticClient{ClientID: "bound", Secret: "bound-secret",
				AuthMethod:   "client_secret_post",
				DPoPRequired: true,
				RedirectURIs: []string{"https://bound.example.com/callback"}},
		))
	// A public client that presents a secret fails.
	resp := h.DoForm(h.URL("/oauth2/token"), map[string]string{
		"grant_type": "authorization_code", "code": "any", "code_verifier": "any",
		"client_id": "spa", "client_secret": "invented",
	})
	if resp.Status != http.StatusUnauthorized {
		t.Fatalf("a public client presented a secret: %d %s", resp.Status, resp.Body)
	}
	// A client that requires DPoP reaches no token without a proof.
	bound := h.DoForm(h.URL("/oauth2/token"), map[string]string{
		"grant_type": "refresh_token", "refresh_token": "any",
		"client_id": "bound", "client_secret": "bound-secret",
	})
	var body map[string]string
	bound.Decode(t, &body)
	if body["error"] != "invalid_dpop_proof" {
		t.Fatalf("the bound client passed without a proof: %s", bound.Body)
	}
	// A confidential client that authenticates in the body reaches no Basic
	// scheme, and the reverse holds too.
	basic := h.DoForm(h.URL("/oauth2/token"), map[string]string{
		"grant_type": "refresh_token", "refresh_token": "any",
	}, testsupport.WithHeader("Authorization", "Basic Ym91bmQ6Ym91bmQtc2VjcmV0"))
	basic.Decode(t, &body)
	if body["error"] != "invalid_client" {
		t.Fatalf("the Basic scheme passed for a body client: %s", basic.Body)
	}
}

// TestOAuthProviderWithdrawUnknownConsentSucceeds proves that a withdrawal of a
// consent that never existed still revokes and answers.
func TestOAuthProviderWithdrawUnknownConsentSucceeds(t *testing.T) {
	h, _ := providerHarness(t)
	h.SignUp("owner@example.com", "Password123!")
	resp := h.Do(http.MethodDelete, "/oauth2/consents/never-granted", nil)
	if resp.Status != http.StatusOK {
		t.Fatalf("the withdrawal returned %d %s", resp.Status, resp.Body)
	}
}

// TestOAuthProviderMachineTokenReadsNoUserInfo proves that a client credentials
// token names no user at the userinfo route.
func TestOAuthProviderMachineTokenReadsNoUserInfo(t *testing.T) {
	h, _ := providerHarness(t, oauthprovider.Clients(oauthprovider.StaticClient{
		ClientID: "machine", Secret: "machine-secret", AuthMethod: "client_secret_post",
		GrantTypes: []string{"client_credentials"}, Scopes: []string{"email"},
	}))
	resp := h.DoForm(h.URL("/oauth2/token"), map[string]string{
		"grant_type": "client_credentials", "scope": "email",
		"client_id": "machine", "client_secret": "machine-secret",
	})
	var token struct {
		AccessToken string `json:"access_token"`
	}
	resp.Decode(t, &token)
	info := h.Do(http.MethodGet, "/oauth2/userinfo", nil, testsupport.WithBearer(token.AccessToken))
	if info.Status != http.StatusUnauthorized {
		t.Fatalf("userinfo answered a machine token: %d %s", info.Status, info.Body)
	}
	// The same token opens no host route, because it names no user.
	h.ClearCookies()
	route := h.Do(http.MethodGet, "/oauth2/consents", nil, testsupport.WithBearer(token.AccessToken))
	if route.Status == http.StatusOK {
		t.Fatal("a machine token opened a user route")
	}
	// A client credentials call needs a grant that the client holds.
	denied := h.DoForm(h.URL("/oauth2/token"), map[string]string{
		"grant_type": "client_credentials", "scope": "unknown",
		"client_id": "machine", "client_secret": "machine-secret",
	})
	if denied.Status != http.StatusBadRequest {
		t.Fatalf("an unknown scope passed: %d", denied.Status)
	}
	resource := h.DoForm(h.URL("/oauth2/token"), map[string]string{
		"grant_type": "client_credentials", "scope": "email",
		"resource":  "https://nowhere.example.com",
		"client_id": "machine", "client_secret": "machine-secret",
	})
	if resource.Status != http.StatusBadRequest {
		t.Fatalf("an undeclared resource passed: %d", resource.Status)
	}
}

// TestOAuthProviderPostUserInfoAnswersTheSameClaims proves the second method of
// the userinfo route.
func TestOAuthProviderPostUserInfoAnswersTheSameClaims(t *testing.T) {
	h, _ := providerHarness(t)
	verifier, challenge := pkcePair(t)
	code := providerCodeFor(t, h, challenge, url.Values{"scope": {"openid email"}})
	resp := h.DoForm(h.URL("/oauth2/token"), map[string]string{
		"grant_type": "authorization_code", "code": code,
		"redirect_uri": "https://app.example.com/callback", "code_verifier": verifier,
		"client_id": "first-party", "client_secret": "first-party-secret",
	})
	var token struct {
		AccessToken string `json:"access_token"`
	}
	resp.Decode(t, &token)
	info := h.Do(http.MethodPost, "/oauth2/userinfo", nil, testsupport.WithBearer(token.AccessToken))
	if info.Status != http.StatusOK {
		t.Fatalf("the post form of userinfo returned %d %s", info.Status, info.Body)
	}
	var claims map[string]any
	info.Decode(t, &claims)
	if claims["email"] != "owner@example.com" {
		t.Fatalf("the claims are wrong: %v", claims)
	}
	// A DPoP scheme without a bound token fails.
	wrong := h.Do(http.MethodGet, "/oauth2/userinfo", nil,
		testsupport.WithHeader("Authorization", "DPoP "+token.AccessToken))
	if wrong.Status != http.StatusUnauthorized {
		t.Fatalf("a bearer token passed as a DPoP token: %d", wrong.Status)
	}
	// An unknown scheme fails too.
	basic := h.Do(http.MethodGet, "/oauth2/userinfo", nil,
		testsupport.WithHeader("Authorization", "Basic abc"))
	if basic.Status != http.StatusUnauthorized {
		t.Fatalf("the Basic scheme passed: %d", basic.Status)
	}
}
