package authall_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	authall "github.com/alternayte/auth-all"
	"github.com/alternayte/auth-all/internal/testsupport"
	"github.com/alternayte/auth-all/plugins/apikeys"
	"github.com/alternayte/auth-all/plugins/oauthprovider"
	"github.com/alternayte/auth-all/plugins/roles"
)

// mcpResource is the identifier of the MCP endpoint of the tests. The test
// server answers on another origin, so a test reads the metadata path from it.
const mcpResource = "https://app.example.com/mcp"

// mcpMetadataURL is the RFC 9728 location of mcpResource.
const mcpMetadataURL = "https://app.example.com/.well-known/oauth-protected-resource/mcp"

// mcpPrincipal is what the MCP handler of the tests saw.
type mcpPrincipal struct {
	Method   string   `json:"method"`
	Email    string   `json:"email"`
	ClientID string   `json:"clientId"`
	Scopes   []string `json:"scopes"`
	Audience string   `json:"audience"`
	MCP      bool     `json:"mcp"`
	Admin    bool     `json:"admin"`
	Via      string   `json:"via"`
}

// mcpHandler reports the principal of the request.
func mcpHandler(via string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := authall.PrincipalFrom(r.Context())
		out := mcpPrincipal{Via: via}
		if p != nil {
			out.Method = p.Method
			out.Email = p.User.Email
			out.MCP = p.HasScope("mcp")
			out.Admin = p.HasScope("mcp:admin")
			if p.OAuth != nil {
				out.ClientID = p.OAuth.ClientID
				out.Scopes = p.OAuth.Scopes
				out.Audience = p.OAuth.Audience
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
}

// mcpHarness builds a provider with an MCP resource, dynamic registration, and
// API keys. /mcp needs the mcp scope, /mcp-admin needs mcp:admin, and an API
// key on /mcp reaches the fallback.
func mcpHarness(t *testing.T) (*testsupport.Harness, *oauthprovider.Plugin) {
	t.Helper()
	p := oauthprovider.New(
		oauthprovider.KeyEncryptionKey(make([]byte, 32)),
		oauthprovider.LoginPath("/sign-in"),
		oauthprovider.ConsentPath("/consent"),
		oauthprovider.Scopes("openid", "email", "offline_access", "mcp", "mcp:admin"),
		oauthprovider.Resources(
			oauthprovider.Resource{Identifier: mcpResource, Scopes: []string{"mcp", "mcp:admin", "offline_access"}},
			oauthprovider.Resource{Identifier: "https://api.example.com"},
		),
		oauthprovider.AllowDynamicRegistration(),
	)
	keys := apikeys.New()
	h := testsupport.NewHarness(t,
		authall.WithEmailPassword(authall.EmailPasswordOptions{}),
		authall.WithPlugins(roles.New(roles.Hierarchy("viewer", "admin"), roles.Default("viewer")), keys, p),
	)
	fallback := h.Auth.RequireAuth(mcpHandler("fallback"))
	h.Handle("/mcp", p.RequireAudience(mcpResource, mcpHandler("oauth"),
		oauthprovider.RequireAudienceOptions{Fallback: fallback, Scopes: []string{"mcp"}}))
	h.Handle("/mcp-admin", p.RequireAudience(mcpResource, mcpHandler("oauth"),
		oauthprovider.RequireAudienceOptions{Scopes: []string{"mcp:admin"}}))
	h.Handle("/mcp-bare", p.RequireAudience(mcpResource, mcpHandler("oauth")))
	h.Handle("/host", h.Auth.RequireAuth(mcpHandler("host")))
	prm := p.ProtectedResourceHandler(mcpResource)
	h.Handle("/.well-known/oauth-protected-resource", prm)
	h.Handle("/.well-known/oauth-protected-resource/", prm)
	h.Handle("/.well-known/", p.MetadataHandler())
	return h, p
}

// registerPublicClient registers an MCP client through RFC 7591, as a client
// without a metadata document does.
func registerPublicClient(t *testing.T, h *testsupport.Harness) string {
	t.Helper()
	resp := h.Do(http.MethodPost, "/oauth2/register", map[string]any{
		"client_name":                "Acme Desktop",
		"redirect_uris":              []string{"http://127.0.0.1/callback"},
		"token_endpoint_auth_method": "none",
		"scope":                      "openid email offline_access mcp mcp:admin",
	})
	if resp.Status != http.StatusCreated {
		t.Fatalf("register: %d %s", resp.Status, resp.Body)
	}
	var out struct {
		ClientID string `json:"client_id"`
	}
	resp.Decode(t, &out)
	return out.ClientID
}

// mcpToken runs authorize, consent, and token for one public client and
// returns the access token. resource is the indicator of both calls.
func mcpToken(t *testing.T, h *testsupport.Harness, clientID, scope, resource string) string {
	t.Helper()
	verifier, challenge := pkcePair(t)
	q := url.Values{
		"client_id": {clientID}, "redirect_uri": {"http://127.0.0.1:4711/callback"},
		"response_type": {"code"}, "scope": {scope}, "state": {"s"},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}
	if resource != "" {
		q.Set("resource", resource)
	}
	resp := h.Do(http.MethodGet, "/oauth2/authorize?"+q.Encode(), nil)
	if resp.Status != http.StatusSeeOther {
		t.Fatalf("authorize: %d %s", resp.Status, resp.Body)
	}
	target, err := url.Parse(resp.Location())
	if err != nil {
		t.Fatal(err)
	}
	code := target.Query().Get("code")
	if code == "" {
		requestID := target.Query().Get("request_id")
		if requestID == "" {
			t.Fatalf("authorize went to %s", resp.Location())
		}
		decide := h.Do(http.MethodPost, "/oauth2/decide", map[string]any{"requestId": requestID, "approve": true})
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
		code = back.Query().Get("code")
	}
	fields := map[string]string{
		"grant_type": "authorization_code", "code": code, "client_id": clientID,
		"redirect_uri": "http://127.0.0.1:4711/callback", "code_verifier": verifier,
	}
	if resource != "" {
		fields["resource"] = resource
	}
	token := h.DoForm(h.URL("/oauth2/token"), fields)
	if token.Status != http.StatusOK {
		t.Fatalf("token: %d %s", token.Status, token.Body)
	}
	var out struct {
		AccessToken string `json:"access_token"`
	}
	token.Decode(t, &out)
	return out.AccessToken
}

// callMCP calls one MCP route with an access token and no cookie.
func callMCP(t *testing.T, h *testsupport.Harness, path, token string) (*testsupport.Response, mcpPrincipal) {
	t.Helper()
	jar := h.SaveCookies()
	h.Client.Jar = nil
	defer h.RestoreCookies(jar)
	opts := []testsupport.RequestOption{}
	if token != "" {
		opts = append(opts, testsupport.WithBearer(token))
	}
	resp := h.DoURL(http.MethodGet, h.BaseURL+path, nil, opts...)
	var seen mcpPrincipal
	if resp.Status == http.StatusOK {
		resp.Decode(t, &seen)
	}
	return resp, seen
}

// TestOAuthProviderMCPChallengeLeadsToTheMetadata proves the discovery path of
// an MCP client: a 401 names the resource metadata, which names the issuer,
// whose metadata names the endpoints.
func TestOAuthProviderMCPChallengeLeadsToTheMetadata(t *testing.T) {
	h, _ := mcpHarness(t)
	resp, _ := callMCP(t, h, "/mcp-bare", "")
	if resp.Status != http.StatusUnauthorized {
		t.Fatalf("no token: %d %s", resp.Status, resp.Body)
	}
	challenge := resp.Header.Get("WWW-Authenticate")
	if challenge != `Bearer resource_metadata="`+mcpMetadataURL+`"` {
		t.Fatalf("the challenge is %q", challenge)
	}

	for _, path := range []string{"/.well-known/oauth-protected-resource/mcp", "/.well-known/oauth-protected-resource"} {
		doc := h.DoURL(http.MethodGet, h.BaseURL+path, nil)
		if doc.Status != http.StatusOK {
			t.Fatalf("%s: %d", path, doc.Status)
		}
		var meta struct {
			Resource             string   `json:"resource"`
			AuthorizationServers []string `json:"authorization_servers"`
			ScopesSupported      []string `json:"scopes_supported"`
		}
		doc.Decode(t, &meta)
		issuer := h.BaseURL + h.Auth.BasePath()
		if meta.Resource != mcpResource || len(meta.AuthorizationServers) != 1 ||
			meta.AuthorizationServers[0] != issuer ||
			!slices.Equal(meta.ScopesSupported, []string{"mcp", "mcp:admin", "offline_access"}) {
			t.Fatalf("%s: the metadata is %s", path, doc.Body)
		}
	}
	if other := h.DoURL(http.MethodGet, h.BaseURL+"/.well-known/oauth-protected-resource/other", nil); other.Status != http.StatusNotFound {
		t.Fatalf("another resource path answered: %d", other.Status)
	}
	if post := h.DoURL(http.MethodPost, h.BaseURL+"/.well-known/oauth-protected-resource/mcp", nil); post.Status != http.StatusMethodNotAllowed {
		t.Fatalf("a POST answered: %d", post.Status)
	}

	// The issuer metadata names none among the authentication methods, and
	// it offers no metadata document without the option.
	as := h.DoURL(http.MethodGet, h.BaseURL+"/.well-known/oauth-authorization-server"+h.Auth.BasePath(), nil)
	var server map[string]any
	as.Decode(t, &server)
	methods, _ := server["token_endpoint_auth_methods_supported"].([]any)
	if !slices.Contains(methods, any("none")) {
		t.Fatalf("the metadata lacks none: %s", as.Body)
	}
	if _, ok := server["client_id_metadata_document_supported"]; ok {
		t.Fatal("the metadata offers metadata documents without the option")
	}

	// A malformed token of the server's shape gets invalid_token and the
	// metadata URL.
	bad, _ := callMCP(t, h, "/mcp", "eyJhbGciOiJFUzI1NiIsInR5cCI6ImF0K2p3dCJ9.e30.c2ln")
	if bad.Status != http.StatusUnauthorized ||
		!strings.Contains(bad.Header.Get("WWW-Authenticate"), `error="invalid_token"`) ||
		!strings.Contains(bad.Header.Get("WWW-Authenticate"), `resource_metadata="`+mcpMetadataURL+`"`) {
		t.Fatalf("a bad token: %d %q", bad.Status, bad.Header.Get("WWW-Authenticate"))
	}
}

// TestOAuthProviderMCPTokenCarriesTheGrantedScopes runs the flow of a
// registered MCP client and proves the principal of the MCP route.
func TestOAuthProviderMCPTokenCarriesTheGrantedScopes(t *testing.T) {
	h, _ := mcpHarness(t)
	h.SignUp("owner@example.com", "Password123!")
	clientID := registerPublicClient(t, h)

	// The consent page learns the kind and the host of the client.
	_, challenge := pkcePair(t)
	q := url.Values{
		"client_id": {clientID}, "redirect_uri": {"http://127.0.0.1:4711/callback"},
		"response_type": {"code"}, "scope": {"mcp"}, "resource": {mcpResource},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}
	authorize := h.Do(http.MethodGet, "/oauth2/authorize?"+q.Encode(), nil)
	target, _ := url.Parse(authorize.Location())
	read := h.Do(http.MethodGet, "/oauth2/request?request_id="+target.Query().Get("request_id"), nil)
	var detail struct {
		ClientKind string `json:"clientKind"`
		ClientHost string `json:"clientHost"`
		ClientName string `json:"clientName"`
	}
	read.Decode(t, &detail)
	if detail.ClientKind != "dynamic" || detail.ClientHost != "127.0.0.1:4711" || detail.ClientName != "Acme Desktop" {
		t.Fatalf("the request detail is %s", read.Body)
	}

	token := mcpToken(t, h, clientID, "mcp", mcpResource)
	resp, seen := callMCP(t, h, "/mcp", token)
	if resp.Status != http.StatusOK {
		t.Fatalf("mcp: %d %s", resp.Status, resp.Body)
	}
	if seen.Via != "oauth" || seen.Method != authall.MethodOAuth || seen.Email != "owner@example.com" ||
		seen.ClientID != clientID || !slices.Equal(seen.Scopes, []string{"mcp"}) ||
		seen.Audience != mcpResource || !seen.MCP || seen.Admin {
		t.Fatalf("the MCP route saw %+v", seen)
	}

	// The token lacks mcp:admin, so the admin route answers 403 and names the
	// scope.
	admin, _ := callMCP(t, h, "/mcp-admin", token)
	header := admin.Header.Get("WWW-Authenticate")
	if admin.Status != http.StatusForbidden || !strings.Contains(header, `error="insufficient_scope"`) ||
		!strings.Contains(header, `scope="mcp:admin"`) || !strings.Contains(header, `resource_metadata="`+mcpMetadataURL+`"`) {
		t.Fatalf("a scope shortfall: %d %q", admin.Status, header)
	}

	// The MCP token opens no host route, because its audience is the MCP
	// resource and not the issuer.
	if host, _ := callMCP(t, h, "/host", token); host.Status == http.StatusOK {
		t.Fatal("an MCP token opened a host route")
	}
}

// TestOAuthProviderMCPRefusesAnotherAudience proves the audience check: a
// token for another resource and a token for the issuer both get 401.
func TestOAuthProviderMCPRefusesAnotherAudience(t *testing.T) {
	h, _ := mcpHarness(t)
	h.SignUp("owner@example.com", "Password123!")
	clientID := registerPublicClient(t, h)
	for name, resource := range map[string]string{"another resource": "https://api.example.com", "the issuer": ""} {
		token := mcpToken(t, h, clientID, "openid email", resource)
		resp, _ := callMCP(t, h, "/mcp", token)
		if resp.Status != http.StatusUnauthorized ||
			!strings.Contains(resp.Header.Get("WWW-Authenticate"), `error="invalid_token"`) {
			t.Fatalf("a token for %s: %d %s", name, resp.Status, resp.Body)
		}
	}
}

// TestOAuthProviderMCPTokenRouteNarrowsTheResource proves that the resource of
// a token call must be the resource of the authorization.
func TestOAuthProviderMCPTokenRouteNarrowsTheResource(t *testing.T) {
	h, _ := mcpHarness(t)
	h.SignUp("owner@example.com", "Password123!")
	clientID := registerPublicClient(t, h)
	verifier, challenge := pkcePair(t)
	q := url.Values{
		"client_id": {clientID}, "redirect_uri": {"http://127.0.0.1:4711/callback"},
		"response_type": {"code"}, "scope": {"mcp"}, "resource": {mcpResource},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}
	authorize := h.Do(http.MethodGet, "/oauth2/authorize?"+q.Encode(), nil)
	target, _ := url.Parse(authorize.Location())
	decide := h.Do(http.MethodPost, "/oauth2/decide",
		map[string]any{"requestId": target.Query().Get("request_id"), "approve": true})
	var decision struct {
		RedirectTo string `json:"redirectTo"`
	}
	decide.Decode(t, &decision)
	back, _ := url.Parse(decision.RedirectTo)
	resp := h.DoForm(h.URL("/oauth2/token"), map[string]string{
		"grant_type": "authorization_code", "code": back.Query().Get("code"), "client_id": clientID,
		"redirect_uri": "http://127.0.0.1:4711/callback", "code_verifier": verifier,
		"resource": "https://api.example.com",
	})
	var body struct {
		Error string `json:"error"`
	}
	resp.Decode(t, &body)
	if resp.Status != http.StatusBadRequest || body.Error != "invalid_target" {
		t.Fatalf("a token call for another resource: %d %s", resp.Status, resp.Body)
	}
}

// TestOAuthProviderMCPAPIKeyReachesTheFallback proves that a host keeps its
// API keys on the MCP route.
func TestOAuthProviderMCPAPIKeyReachesTheFallback(t *testing.T) {
	h, _ := mcpHarness(t)
	h.SignUp("owner@example.com", "Password123!")
	created := h.Do(http.MethodPost, "/api-keys", map[string]any{"name": "agent"})
	if created.Status != http.StatusCreated {
		t.Fatalf("create key: %d %s", created.Status, created.Body)
	}
	var key struct {
		Plaintext string `json:"plaintext"`
	}
	created.Decode(t, &key)
	resp, seen := callMCP(t, h, "/mcp", key.Plaintext)
	if resp.Status != http.StatusOK || seen.Via != "fallback" || seen.Method != authall.MethodAPIKey {
		t.Fatalf("the API key: %d %+v", resp.Status, seen)
	}
	// Without a fallback, the key gets the challenge.
	bare, _ := callMCP(t, h, "/mcp-bare", key.Plaintext)
	if bare.Status != http.StatusUnauthorized ||
		!strings.Contains(bare.Header.Get("WWW-Authenticate"), "resource_metadata=") {
		t.Fatalf("an API key without a fallback: %d", bare.Status)
	}
}

// TestOAuthProviderMCPDisabledUserAndRevokedGrantFail proves that the check
// reads the user and the grant on each request.
func TestOAuthProviderMCPDisabledUserAndRevokedGrantFail(t *testing.T) {
	h, _ := mcpHarness(t)
	h.SignUp("owner@example.com", "Password123!")
	clientID := registerPublicClient(t, h)
	token := mcpToken(t, h, clientID, "mcp", mcpResource)
	if resp, _ := callMCP(t, h, "/mcp", token); resp.Status != http.StatusOK {
		t.Fatalf("mcp: %d %s", resp.Status, resp.Body)
	}

	// The store write skips the hook that revokes the grants, so only the
	// read of the user can refuse the token.
	ctx := context.Background()
	user, err := h.Store.Users().GetByNormalizedEmail(ctx, "owner@example.com")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	user.DisabledAt = &now
	if err := h.Store.Users().Update(ctx, user); err != nil {
		t.Fatal(err)
	}
	if resp, _ := callMCP(t, h, "/mcp", token); resp.Status != http.StatusUnauthorized {
		t.Fatalf("a disabled user: %d %s", resp.Status, resp.Body)
	}
	user.DisabledAt = nil
	if err := h.Store.Users().Update(ctx, user); err != nil {
		t.Fatal(err)
	}
	if resp, _ := callMCP(t, h, "/mcp", token); resp.Status != http.StatusOK {
		t.Fatalf("an enabled user again: %d %s", resp.Status, resp.Body)
	}

	// A withdrawn consent revokes the grant, and the token stops at once.
	if resp := h.Do(http.MethodDelete, "/oauth2/consents/"+clientID, nil); resp.Status != http.StatusOK {
		t.Fatalf("withdraw: %d %s", resp.Status, resp.Body)
	}
	if resp, _ := callMCP(t, h, "/mcp", token); resp.Status != http.StatusUnauthorized {
		t.Fatalf("a revoked grant: %d %s", resp.Status, resp.Body)
	}
}

// TestOAuthProviderMCPIssuerTokenHoldsItsScopes proves that HasScope reads the
// scopes of an OAuth token on a host route too.
func TestOAuthProviderMCPIssuerTokenHoldsItsScopes(t *testing.T) {
	h, _ := mcpHarness(t)
	h.SignUp("owner@example.com", "Password123!")
	clientID := registerPublicClient(t, h)
	token := mcpToken(t, h, clientID, "openid email", "")
	resp, seen := callMCP(t, h, "/host", token)
	if resp.Status != http.StatusOK {
		t.Fatalf("host: %d %s", resp.Status, resp.Body)
	}
	if seen.Method != authall.MethodOAuth || !slices.Equal(seen.Scopes, []string{"openid", "email"}) ||
		seen.MCP || seen.Audience != h.BaseURL+h.Auth.BasePath() {
		t.Fatalf("the host route saw %+v", seen)
	}
}

// TestOAuthProviderMCPUndeclaredResourcePanics proves that a typing error in
// the resource fails at startup.
func TestOAuthProviderMCPUndeclaredResourcePanics(t *testing.T) {
	_, p := mcpHarness(t)
	for name, call := range map[string]func(){
		"RequireAudience":          func() { p.RequireAudience("https://app.example.com/other", http.NotFoundHandler()) },
		"ProtectedResourceHandler": func() { p.ProtectedResourceHandler("https://app.example.com/other") },
		"unknown scope": func() {
			p.RequireAudience(mcpResource, http.NotFoundHandler(),
				oauthprovider.RequireAudienceOptions{Scopes: []string{"nope"}})
		},
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Fatalf("%s did not panic", name)
				}
			}()
			call()
		}()
	}
}

// TestOAuthProviderMCPResourceMetadataURL pins the path insertion of RFC 9728.
func TestOAuthProviderMCPResourceMetadataURL(t *testing.T) {
	for identifier, want := range map[string]string{
		"https://app.example.com/mcp":       "https://app.example.com/.well-known/oauth-protected-resource/mcp",
		"https://app.example.com":           "https://app.example.com/.well-known/oauth-protected-resource",
		"https://app.example.com/":          "https://app.example.com/.well-known/oauth-protected-resource",
		"https://app.example.com:8443/a/b":  "https://app.example.com:8443/.well-known/oauth-protected-resource/a/b",
		"https://app.example.com/mcp?t=one": "https://app.example.com/.well-known/oauth-protected-resource/mcp?t=one",
	} {
		got, err := oauthprovider.ResourceMetadataURL(identifier)
		if err != nil || got != want {
			t.Fatalf("%s: got %q, %v", identifier, got, err)
		}
	}
	for _, bad := range []string{"/mcp", "https://app.example.com/mcp#x", "::"} {
		if _, err := oauthprovider.ResourceMetadataURL(bad); err == nil {
			t.Fatalf("%s gave a metadata URL", bad)
		}
	}
}
