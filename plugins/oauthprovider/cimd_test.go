package oauthprovider

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	authall "github.com/alternayte/auth-all"
	"github.com/alternayte/auth-all/internal/jws"
	"github.com/alternayte/auth-all/internal/testsupport"
)

// loopbackOnly lets a test fetch from its own TLS server and nothing else.
func loopbackOnly(addr netip.Addr) bool { return addr.Unmap().IsLoopback() }

// docServer is a TLS server that serves one metadata document per path.
type docServer struct {
	srv   *httptest.Server
	mu    sync.Mutex
	hits  map[string]int
	serve map[string]http.HandlerFunc
}

func newDocServer(t *testing.T) *docServer {
	t.Helper()
	d := &docServer{hits: map[string]int{}, serve: map[string]http.HandlerFunc{}}
	d.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		d.hits[r.URL.Path]++
		h := d.serve[r.URL.Path]
		d.mu.Unlock()
		if h == nil {
			http.NotFound(w, r)
			return
		}
		h(w, r)
	}))
	t.Cleanup(d.srv.Close)
	return d
}

// url returns the client identifier of a path.
func (d *docServer) url(path string) string { return d.srv.URL + path }

// handle serves a path.
func (d *docServer) handle(path string, h http.HandlerFunc) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.serve[path] = h
}

// count returns the number of fetches of a path.
func (d *docServer) count(path string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.hits[path]
}

// roots returns the pool that trusts the server.
func (d *docServer) roots() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(d.srv.Certificate())
	return pool
}

// document returns a valid metadata document of a client identifier.
func document(id string, extra map[string]any) map[string]any {
	doc := map[string]any{
		"client_id":                  id,
		"client_name":                "Acme Assistant",
		"redirect_uris":              []string{"https://assistant.example.com/callback"},
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
	}
	for k, v := range extra {
		if v == nil {
			delete(doc, k)
			continue
		}
		doc[k] = v
	}
	return doc
}

// serveJSON returns a handler that writes a document with headers.
func serveJSON(doc any, headers map[string]string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		for k, v := range headers {
			w.Header().Set(k, v)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	}
}

// fetcherClock is a movable clock.
type fetcherClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fetcherClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fetcherClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// testFetcher returns a fetcher over a plugin with a movable clock.
func testFetcher(t *testing.T, d *docServer, o CIMDOptions, permit func(netip.Addr) bool) (*cimdFetcher, *fetcherClock) {
	t.Helper()
	p := newTestPlugin(t)
	clock := &fetcherClock{now: time.Unix(1700000000, 0).UTC()}
	p.now = clock.Now
	var roots *x509.CertPool
	if d != nil {
		roots = d.roots()
	}
	f, err := newCIMDFetcher(p, o, permit, roots)
	if err != nil {
		t.Fatal(err)
	}
	return f, clock
}

// refusal returns the message of a refused document, and fails the test on
// any other result.
func refusal(t *testing.T, err error) string {
	t.Helper()
	var refused *cimdError
	if !errors.As(err, &refused) {
		t.Fatalf("the document was not refused: %v", err)
	}
	return refused.Error()
}

// TestOAuthProviderCIMDAddressGuard pins the address ranges the fetch never
// reaches.
func TestOAuthProviderCIMDAddressGuard(t *testing.T) {
	for _, blocked := range []string{
		"127.0.0.1", "127.8.9.10", "::1", "10.0.0.1", "172.16.5.4", "192.168.1.1", "169.254.169.254",
		"fe80::1", "fc00::1", "fd12:3456::1", "0.0.0.0", "::", "100.64.0.1", "192.0.0.8",
		"198.18.0.1", "224.0.0.1", "255.255.255.255", "240.0.0.1", "::ffff:127.0.0.1",
		"::ffff:10.0.0.1", "64:ff9b::a00:1", "2002:a00:1::1", "2001:0:a00:1::1", "fec0::1", "ff02::1",
		"192.0.2.1", "2001:db8::1",
	} {
		if publicAddress(netip.MustParseAddr(blocked)) {
			t.Fatalf("the guard permits %s", blocked)
		}
	}
	for _, public := range []string{"93.184.216.34", "1.1.1.1", "2606:4700:4700::1111", "::ffff:8.8.8.8"} {
		if !publicAddress(netip.MustParseAddr(public)) {
			t.Fatalf("the guard refuses %s", public)
		}
	}
}

// TestOAuthProviderCIMDClientIDForm pins the URL form of a client identifier.
func TestOAuthProviderCIMDClientIDForm(t *testing.T) {
	if _, err := checkCIMDClientID("https://assistant.example.com/oauth/client.json"); err != nil {
		t.Fatalf("a valid identifier: %v", err)
	}
	for _, bad := range []string{
		"http://assistant.example.com/client.json",
		"https://assistant.example.com",
		"https://assistant.example.com/",
		"https://user:pass@assistant.example.com/client.json",
		"https://assistant.example.com/client.json#frag",
		"https://assistant.example.com/a/../client.json",
		"https://assistant.example.com/./client.json",
		"https:///client.json",
		"https://assistant.example.com/" + strings.Repeat("a", cimdMaxClientIDLength),
	} {
		if _, err := checkCIMDClientID(bad); err == nil {
			t.Fatalf("%s passed", bad)
		}
	}
}

// TestOAuthProviderCIMDRefusesAPrivateAddress proves that the fetch refuses an
// address that is not public after the name resolution, and that it sends
// nothing to it.
func TestOAuthProviderCIMDRefusesAPrivateAddress(t *testing.T) {
	d := newDocServer(t)
	d.handle("/client.json", serveJSON(document(d.url("/client.json"), nil), nil))
	f, _ := testFetcher(t, d, CIMDOptions{}, nil)

	port := d.srv.Listener.Addr().(interface{ String() string }).String()
	port = port[strings.LastIndex(port, ":")+1:]
	for _, id := range []string{
		d.url("/client.json"),                        // 127.0.0.1
		"https://localhost:" + port + "/client.json", // a name that resolves to loopback
		"https://10.0.0.1/client.json",
		"https://[::1]:" + port + "/client.json",
		"https://169.254.169.254/latest/meta-data",
	} {
		_, err := f.client(context.Background(), id)
		if msg := refusal(t, err); !strings.Contains(msg, "not public") {
			t.Fatalf("%s: %s", id, msg)
		}
	}
	if d.count("/client.json") != 0 {
		t.Fatal("the guarded fetch reached the server")
	}
}

// TestOAuthProviderCIMDRefusesABadAnswer covers the limits of one fetch: no
// redirect, the size bound, the time bound, and the document rules.
func TestOAuthProviderCIMDRefusesABadAnswer(t *testing.T) {
	d := newDocServer(t)
	f, _ := testFetcher(t, d, CIMDOptions{Timeout: 300 * time.Millisecond}, loopbackOnly)
	ctx := context.Background()

	d.handle("/redirect.json", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/client.json", http.StatusFound)
	})
	d.handle("/client.json", serveJSON(document(d.url("/redirect.json"), nil), nil))
	if msg := refusal(t, second(f.client(ctx, d.url("/redirect.json")))); !strings.Contains(msg, "status 302") {
		t.Fatalf("a redirect: %s", msg)
	}
	if d.count("/client.json") != 0 {
		t.Fatal("the fetch followed a redirect")
	}

	big := document(d.url("/big.json"), map[string]any{"client_name": strings.Repeat("a", 6<<10)})
	d.handle("/big.json", serveJSON(big, nil))
	if msg := refusal(t, second(f.client(ctx, d.url("/big.json")))); !strings.Contains(msg, "larger than 5120") {
		t.Fatalf("a large document: %s", msg)
	}
	// A chunked body names no length, and the read stops at the bound.
	d.handle("/chunked.json", func(w http.ResponseWriter, _ *http.Request) {
		flusher := w.(http.Flusher)
		_, _ = w.Write([]byte(`{"client_id":"`))
		flusher.Flush()
		_, _ = w.Write([]byte(strings.Repeat("a", 6<<10)))
	})
	if msg := refusal(t, second(f.client(ctx, d.url("/chunked.json")))); !strings.Contains(msg, "larger than") {
		t.Fatalf("a chunked document: %s", msg)
	}

	d.handle("/slow.json", func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(2 * time.Second):
		case <-r.Context().Done():
		}
		serveJSON(document(d.url("/slow.json"), nil), nil)(w, r)
	})
	started := time.Now()
	if msg := refusal(t, second(f.client(ctx, d.url("/slow.json")))); !strings.Contains(msg, "could not be fetched") {
		t.Fatalf("a slow document: %s", msg)
	}
	if time.Since(started) > 1500*time.Millisecond {
		t.Fatal("the fetch outlived its timeout")
	}

	for name, tc := range map[string]struct {
		extra map[string]any
		want  string
	}{
		"another client_id":    {map[string]any{"client_id": "https://evil.example.com/client.json"}, "another client identifier"},
		"a secret":             {map[string]any{"client_secret": "s"}, "client secret"},
		"a secret method":      {map[string]any{"token_endpoint_auth_method": "client_secret_basic"}, "method none"},
		"no redirect URI":      {map[string]any{"redirect_uris": nil}, "no redirect URI"},
		"a plain http URI":     {map[string]any{"redirect_uris": []string{"http://assistant.example.com/cb"}}, "uses http"},
		"a token response":     {map[string]any{"response_types": []string{"token"}}, "a code and nothing else"},
		"no code grant":        {map[string]any{"grant_types": []string{"client_credentials"}}, "no authorization code grant"},
		"no JSON":              {map[string]any{"__raw": true}, "no JSON"},
		"a missing doc (404)":  {map[string]any{"__status": http.StatusNotFound}, "status 404"},
		"a wildcard redirect":  {map[string]any{"redirect_uris": []string{"https://*.example.com/cb"}}, "wildcard"},
		"a fragment redirect":  {map[string]any{"redirect_uris": []string{"https://a.example.com/cb#x"}}, "fragment"},
		"an expiring secret":   {map[string]any{"client_secret_expires_at": 0}, "client secret"},
		"another id by a char": {map[string]any{"__suffix": "x"}, "another client identifier"},
	} {
		path := "/" + strings.ReplaceAll(name, " ", "-") + ".json"
		id := d.url(path)
		doc := document(id, tc.extra)
		switch {
		case tc.extra["__raw"] == true:
			d.handle(path, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("<html>")) })
		case tc.extra["__status"] != nil:
			status := tc.extra["__status"].(int)
			d.handle(path, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) })
		case tc.extra["__suffix"] != nil:
			doc["client_id"] = id + "x"
			delete(doc, "__suffix")
			d.handle(path, serveJSON(doc, nil))
		default:
			d.handle(path, serveJSON(doc, nil))
		}
		if msg := refusal(t, second(f.client(ctx, id))); !strings.Contains(msg, tc.want) {
			t.Fatalf("%s: %s", name, msg)
		}
	}
}

// second returns the error of a client lookup.
func second(_ client, err error) error { return err }

// TestOAuthProviderCIMDCacheHonoursTheHeaders proves the cache rules: the
// lifetime of Cache-Control between the floor and the ceiling, the ETag
// revalidation, and the cached copy on a failure until the ceiling.
func TestOAuthProviderCIMDCacheHonoursTheHeaders(t *testing.T) {
	d := newDocServer(t)
	f, clock := testFetcher(t, d, CIMDOptions{CacheTTL: time.Hour}, loopbackOnly)
	ctx := context.Background()

	// A max-age inside the bounds holds for its lifetime, and an ETag
	// revalidates.
	id := d.url("/etag.json")
	var notModified atomic.Int32
	d.handle("/etag.json", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `"v1"` {
			notModified.Add(1)
			w.Header().Set("Cache-Control", "max-age=600")
			w.WriteHeader(http.StatusNotModified)
			return
		}
		serveJSON(document(id, nil), map[string]string{"Cache-Control": "max-age=600", "ETag": `"v1"`})(w, r)
	})
	c, err := f.client(ctx, id)
	if err != nil || c.Name != "Acme Assistant" || c.Kind != kindCIMD || c.AuthMethod != AuthNone {
		t.Fatalf("first fetch: %+v %v", c, err)
	}
	clock.Advance(9 * time.Minute)
	if _, err := f.client(ctx, id); err != nil || d.count("/etag.json") != 1 {
		t.Fatalf("a fresh document was fetched again: %d %v", d.count("/etag.json"), err)
	}
	clock.Advance(2 * time.Minute)
	if _, err := f.client(ctx, id); err != nil || d.count("/etag.json") != 2 || notModified.Load() != 1 {
		t.Fatalf("the revalidation: %d %d %v", d.count("/etag.json"), notModified.Load(), err)
	}

	// A lifetime below the floor and no-store both hold for the floor.
	for path, cc := range map[string]string{"/short.json": "max-age=1", "/nostore.json": "no-store"} {
		pid := d.url(path)
		d.handle(path, serveJSON(document(pid, nil), map[string]string{"Cache-Control": cc}))
		if _, err := f.client(ctx, pid); err != nil {
			t.Fatal(err)
		}
		clock.Advance(4 * time.Minute)
		if _, err := f.client(ctx, pid); err != nil || d.count(path) != 1 {
			t.Fatalf("%s: the floor did not hold: %d", path, d.count(path))
		}
		clock.Advance(2 * time.Minute)
		if _, err := f.client(ctx, pid); err != nil || d.count(path) != 2 {
			t.Fatalf("%s: the floor did not end: %d", path, d.count(path))
		}
	}

	// A lifetime above the ceiling holds for the ceiling.
	long := d.url("/long.json")
	d.handle("/long.json", serveJSON(document(long, nil), map[string]string{"Cache-Control": "max-age=999999"}))
	if _, err := f.client(ctx, long); err != nil {
		t.Fatal(err)
	}
	clock.Advance(61 * time.Minute)
	if _, err := f.client(ctx, long); err != nil || d.count("/long.json") != 2 {
		t.Fatalf("the ceiling did not hold: %d", d.count("/long.json"))
	}

	// A failure of the host serves the cached copy until the ceiling after
	// the last successful fetch, and then the document fails.
	flaky := d.url("/flaky.json")
	d.handle("/flaky.json", serveJSON(document(flaky, nil), map[string]string{"Cache-Control": "max-age=300"}))
	if _, err := f.client(ctx, flaky); err != nil {
		t.Fatal(err)
	}
	d.handle("/flaky.json", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadGateway) })
	clock.Advance(6 * time.Minute)
	if c, err := f.client(ctx, flaky); err != nil || c.ClientID != flaky {
		t.Fatalf("an outage dropped the cached copy: %v", err)
	}
	clock.Advance(55 * time.Minute)
	if _, err := f.client(ctx, flaky); err == nil {
		t.Fatal("the cached copy outlived the ceiling")
	}

	// A removed document ends the client at once, without the cached copy.
	gone := d.url("/gone.json")
	d.handle("/gone.json", serveJSON(document(gone, nil), nil))
	if _, err := f.client(ctx, gone); err != nil {
		t.Fatal(err)
	}
	d.handle("/gone.json", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusGone) })
	clock.Advance(6 * time.Minute)
	if _, err := f.client(ctx, gone); err == nil {
		t.Fatal("a removed document kept its client")
	}
	if _, ok := f.cached(gone); ok {
		t.Fatal("a removed document stayed in the cache")
	}
}

// TestOAuthProviderCIMDCacheStaysBounded proves that an unknown party cannot
// grow the cache without a bound.
func TestOAuthProviderCIMDCacheStaysBounded(t *testing.T) {
	f, clock := testFetcher(t, nil, CIMDOptions{}, nil)
	now := clock.Now()
	for i := 0; i < cimdCacheEntries+50; i++ {
		f.store(fmt.Sprintf("https://c%d.example.com/client.json", i),
			&cimdEntry{validated: now.Add(time.Duration(i) * time.Second)}, now)
	}
	if len(f.entries) != cimdCacheEntries {
		t.Fatalf("the cache holds %d entries", len(f.entries))
	}
	if _, ok := f.entries["https://c0.example.com/client.json"]; ok {
		t.Fatal("the oldest entry survived")
	}
}

// TestOAuthProviderCIMDOptionsAreChecked proves the construction rules.
func TestOAuthProviderCIMDOptionsAreChecked(t *testing.T) {
	p := newTestPlugin(t)
	for _, o := range []CIMDOptions{{MaxBytes: -1}, {Timeout: -1}, {CacheTTL: time.Minute}} {
		if _, err := newCIMDFetcher(p, o, nil, nil); err == nil {
			t.Fatalf("%+v passed", o)
		}
	}
}

// cimdHarness builds an instance that accepts metadata documents from the TLS
// test server, with an MCP resource behind RequireAudience.
func cimdHarness(t *testing.T, d *docServer) (*testsupport.Harness, *Plugin) {
	t.Helper()
	p := New(
		KeyEncryptionKey(make([]byte, 32)),
		LoginPath("/sign-in"),
		ConsentPath("/consent"),
		Scopes("openid", "email", "offline_access", "mcp"),
		Resources(Resource{Identifier: "https://app.example.com/mcp", Scopes: []string{"mcp", "offline_access"}}),
		AllowClientIDMetadataDocuments(CIMDOptions{}),
	)
	p.cimdPermit = loopbackOnly
	p.cimdRoots = d.roots()
	h := testsupport.NewHarness(t,
		authall.WithEmailPassword(authall.EmailPasswordOptions{}),
		authall.WithPlugins(p),
	)
	h.Handle("/mcp", p.RequireAudience("https://app.example.com/mcp",
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			pr := authall.PrincipalFrom(r.Context())
			_ = json.NewEncoder(w).Encode(map[string]any{
				"method": pr.Method, "client": pr.OAuth.ClientID, "scopes": pr.OAuth.Scopes,
				"mcp": pr.HasScope("mcp"),
			})
		})))
	h.Handle("/.well-known/", p.MetadataHandler())
	return h, p
}

// TestOAuthProviderCIMDClientCompletesTheMCPFlow drives an MCP client with a
// metadata document through authorize, consent, token, and the MCP route.
func TestOAuthProviderCIMDClientCompletesTheMCPFlow(t *testing.T) {
	d := newDocServer(t)
	id := d.url("/oauth/client.json")
	redirect := "https://assistant.example.com/callback"
	d.handle("/oauth/client.json", serveJSON(document(id, map[string]any{
		"logo_uri": "https://assistant.example.com/logo.png",
	}), map[string]string{"Cache-Control": "max-age=3600"}))
	h, _ := cimdHarness(t, d)

	// The metadata says what Claude needs before it uses a document.
	meta := h.DoURL(http.MethodGet, h.BaseURL+"/.well-known/oauth-authorization-server"+h.Auth.BasePath(), nil)
	var server map[string]any
	meta.Decode(t, &server)
	if server["client_id_metadata_document_supported"] != true {
		t.Fatalf("the metadata offers no metadata document: %s", meta.Body)
	}

	h.SignUp("owner@example.com", "Password123!")
	verifier := "a-verifier-of-enough-length-for-pkce-0123456789"
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{
		"client_id": {id}, "redirect_uri": {redirect}, "response_type": {"code"},
		"scope": {"mcp offline_access"}, "state": {"st"}, "resource": {"https://app.example.com/mcp"},
		"code_challenge": {jws.Encode(sum[:])}, "code_challenge_method": {"S256"},
	}

	// A redirect URI the document does not list gets no redirect.
	wrong := url.Values{}
	for k, v := range q {
		wrong[k] = v
	}
	wrong.Set("redirect_uri", "https://evil.example.com/callback")
	if resp := h.Do(http.MethodGet, "/oauth2/authorize?"+wrong.Encode(), nil); resp.Status != http.StatusBadRequest {
		t.Fatalf("an unlisted redirect URI: %d %s", resp.Status, resp.Location())
	}
	// A request without the resource fails, because the token route needs it.
	noResource := url.Values{}
	for k, v := range q {
		noResource[k] = v
	}
	noResource.Del("resource")
	if resp := h.Do(http.MethodGet, "/oauth2/authorize?"+noResource.Encode(), nil); resp.Status != http.StatusSeeOther ||
		!strings.Contains(resp.Location(), "error=invalid_target") {
		t.Fatalf("a request without the resource: %d %s", resp.Status, resp.Location())
	}

	// No administrator vetted the client, so the consent page shows it with
	// its host, even for a user who signed in.
	resp := h.Do(http.MethodGet, "/oauth2/authorize?"+q.Encode(), nil)
	target, _ := url.Parse(resp.Location())
	if resp.Status != http.StatusSeeOther || target.Path != "/consent" {
		t.Fatalf("authorize: %d %s", resp.Status, resp.Location())
	}
	requestID := target.Query().Get("request_id")
	read := h.Do(http.MethodGet, "/oauth2/request?request_id="+requestID, nil)
	var detail struct {
		ClientID   string `json:"clientId"`
		ClientName string `json:"clientName"`
		ClientKind string `json:"clientKind"`
		ClientHost string `json:"clientHost"`
		LogoURI    string `json:"logoUri"`
		FirstParty bool   `json:"firstParty"`
	}
	read.Decode(t, &detail)
	host := strings.TrimPrefix(d.srv.URL, "https://")
	if detail.ClientID != id || detail.ClientName != "Acme Assistant" || detail.ClientKind != "cimd" ||
		detail.ClientHost != host || detail.FirstParty || detail.LogoURI == "" {
		t.Fatalf("the consent detail: %s", read.Body)
	}
	decide := h.Do(http.MethodPost, "/oauth2/decide", map[string]any{"requestId": requestID, "approve": true})
	var decision struct {
		RedirectTo string `json:"redirectTo"`
	}
	decide.Decode(t, &decision)
	back, err := url.Parse(decision.RedirectTo)
	if err != nil || !strings.HasPrefix(decision.RedirectTo, redirect) {
		t.Fatalf("decide: %d %s", decide.Status, decide.Body)
	}
	if back.Query().Get("iss") != h.BaseURL+h.Auth.BasePath() || back.Query().Get("state") != "st" {
		t.Fatalf("the authorization response lacks iss or state: %s", decision.RedirectTo)
	}

	fields := map[string]string{
		"grant_type": "authorization_code", "code": back.Query().Get("code"), "client_id": id,
		"redirect_uri": redirect, "code_verifier": verifier, "resource": "https://app.example.com/mcp",
	}
	// A public client presents no secret.
	withSecret := map[string]string{"client_secret": "guess"}
	for k, v := range fields {
		withSecret[k] = v
	}
	if bad := h.DoForm(h.URL("/oauth2/token"), withSecret); bad.Status != http.StatusUnauthorized {
		t.Fatalf("a secret: %d %s", bad.Status, bad.Body)
	}
	noTarget := map[string]string{}
	for k, v := range fields {
		if k != "resource" {
			noTarget[k] = v
		}
	}
	if bad := h.DoForm(h.URL("/oauth2/token"), noTarget); bad.Status != http.StatusBadRequest ||
		!strings.Contains(string(bad.Body), "invalid_target") {
		t.Fatalf("a token call without the resource: %d %s", bad.Status, bad.Body)
	}
	// The refused call spent the code. The consent stands, so the next
	// authorize call returns a code at once.
	resp = h.Do(http.MethodGet, "/oauth2/authorize?"+q.Encode(), nil)
	back, _ = url.Parse(resp.Location())
	if back.Query().Get("code") == "" {
		t.Fatalf("the standing consent was not used: %s", resp.Location())
	}
	fields["code"] = back.Query().Get("code")
	token := h.DoForm(h.URL("/oauth2/token"), fields)
	if token.Status != http.StatusOK {
		t.Fatalf("token: %d %s", token.Status, token.Body)
	}
	var tok struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	token.Decode(t, &tok)

	jar := h.SaveCookies()
	h.Client.Jar = nil
	call := h.DoURL(http.MethodGet, h.BaseURL+"/mcp", nil, testsupport.WithBearer(tok.AccessToken))
	h.RestoreCookies(jar)
	var seen struct {
		Method string   `json:"method"`
		Client string   `json:"client"`
		Scopes []string `json:"scopes"`
		MCP    bool     `json:"mcp"`
	}
	call.Decode(t, &seen)
	if call.Status != http.StatusOK || seen.Method != authall.MethodOAuth || seen.Client != id || !seen.MCP {
		t.Fatalf("mcp: %d %s", call.Status, call.Body)
	}

	// The refresh needs the resource too.
	refresh := map[string]string{"grant_type": "refresh_token", "refresh_token": tok.RefreshToken, "client_id": id}
	if bad := h.DoForm(h.URL("/oauth2/token"), refresh); bad.Status != http.StatusBadRequest {
		t.Fatalf("a refresh without the resource: %d %s", bad.Status, bad.Body)
	}
	refresh["resource"] = "https://app.example.com/mcp"
	if ok := h.DoForm(h.URL("/oauth2/token"), refresh); ok.Status != http.StatusOK {
		t.Fatalf("a refresh: %d %s", ok.Status, ok.Body)
	}

	// One fetch served the whole flow, because the document allows an hour.
	if d.count("/oauth/client.json") != 1 {
		t.Fatalf("the document was fetched %d times", d.count("/oauth/client.json"))
	}

	// The consent list names the client from the cache, and the withdrawal
	// takes a URL identifier.
	consents := h.Do(http.MethodGet, "/oauth2/consents", nil)
	if !strings.Contains(string(consents.Body), "Acme Assistant") {
		t.Fatalf("consents: %s", consents.Body)
	}
	if w := h.Do(http.MethodDelete, "/oauth2/consents/"+url.PathEscape(id), nil); w.Status != http.StatusOK {
		t.Fatalf("withdraw: %d %s", w.Status, w.Body)
	}
	h.Client.Jar = nil
	after := h.DoURL(http.MethodGet, h.BaseURL+"/mcp", nil, testsupport.WithBearer(tok.AccessToken))
	if after.Status != http.StatusUnauthorized {
		t.Fatalf("a withdrawn consent: %d", after.Status)
	}
}

// TestOAuthProviderCIMDAuthorizeRefusesAPrivateHost proves the guard at the
// authorize route, with the default address check.
func TestOAuthProviderCIMDAuthorizeRefusesAPrivateHost(t *testing.T) {
	d := newDocServer(t)
	id := d.url("/client.json")
	d.handle("/client.json", serveJSON(document(id, nil), nil))
	h, p := cimdHarness(t, d)
	p.cimd, _ = newCIMDFetcher(p, CIMDOptions{}, nil, d.roots())
	for _, clientID := range []string{id, "https://10.0.0.1/client.json", "http://assistant.example.com/client.json"} {
		q := url.Values{
			"client_id": {clientID}, "redirect_uri": {"https://assistant.example.com/callback"},
			"response_type": {"code"}, "scope": {"mcp"}, "resource": {"https://app.example.com/mcp"},
			"code_challenge": {"x"}, "code_challenge_method": {"S256"},
		}
		resp := h.Do(http.MethodGet, "/oauth2/authorize?"+q.Encode(), nil)
		if resp.Status != http.StatusBadRequest || !strings.Contains(string(resp.Body), "invalid_client") {
			t.Fatalf("%s: %d %s", clientID, resp.Status, resp.Body)
		}
	}
	if d.count("/client.json") != 0 {
		t.Fatal("the guarded authorize reached the loopback server")
	}
}
