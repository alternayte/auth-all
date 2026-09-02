// Package oidc implements a generic OpenID Connect provider for Auth-All.
//
// The provider reaches every conformant issuer, so an application needs no
// provider package of its own for a standard identity server.
//
//	authall.WithProvider(oidc.New(
//	    oidc.WithIssuer("https://id.example.com"),
//	    oidc.WithClientID(id),
//	    oidc.WithClientSecret(secret),
//	))
//
// The provider discovers the endpoints on the first use, not in New. A
// constructor that performs network input and output would make authall.New
// fail for a briefly unreachable issuer.
package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/alternayte/auth-all/internal/jwt"
	"github.com/alternayte/auth-all/oauth"
)

// DiscoveryPath is the well-known path of an OpenID Connect discovery
// document.
const DiscoveryPath = "/.well-known/openid-configuration"

// Provider is a generic OpenID Connect provider.
type Provider struct {
	id           string
	issuer       string
	clientID     string
	clientSecret string
	scopes       []string
	client       *http.Client
	now          func() time.Time

	// The endpoints come from discovery, or from WithEndpoints.
	mu       sync.Mutex
	static   bool
	authURL  string
	tokenURL string
	jwksURL  string
	keys     *jwt.KeySet
	resolved bool
}

// Option configures the provider.
type Option func(*Provider)

// WithIssuer sets the issuer URL. The provider appends the well-known path to
// find the discovery document, and it requires the document to name this
// issuer.
func WithIssuer(v string) Option {
	return func(p *Provider) { p.issuer = strings.TrimSuffix(v, "/") }
}

// WithID sets the stable provider identifier used in routes and storage.
//
// The default is the host of the issuer, so two issuers cannot collide. Set
// this when one host serves two issuers, or when the route should read better.
//
// Auth-All refuses two providers that share an identifier, so a collision
// with a preset such as google fails the construction with a named error.
//
// Changing the identifier of a live provider orphans the existing links,
// because the account table keys on it.
func WithID(v string) Option { return func(p *Provider) { p.id = v } }

// WithClientID sets the OAuth client id.
func WithClientID(v string) Option { return func(p *Provider) { p.clientID = v } }

// WithClientSecret sets the OAuth client secret.
func WithClientSecret(v string) Option { return func(p *Provider) { p.clientSecret = v } }

// WithScopes replaces the requested scopes. The default is openid, email, and
// profile.
func WithScopes(v ...string) Option { return func(p *Provider) { p.scopes = v } }

// WithHTTPClient sets the HTTP client used for provider calls.
func WithHTTPClient(c *http.Client) Option { return func(p *Provider) { p.client = c } }

// WithEndpoints sets the endpoints and skips discovery. Use it for an issuer
// that publishes no discovery document, and in a test that points at a
// deterministic server.
func WithEndpoints(authURL, tokenURL, jwksURL string) Option {
	return func(p *Provider) {
		p.authURL, p.tokenURL, p.jwksURL = authURL, tokenURL, jwksURL
		p.static = true
	}
}

// WithClock replaces the clock used for token expiry validation.
func WithClock(now func() time.Time) Option { return func(p *Provider) { p.now = now } }

// New returns a generic OpenID Connect provider. It performs no network call.
func New(opts ...Option) *Provider {
	p := &Provider{
		scopes: []string{"openid", "email", "profile"},
		client: http.DefaultClient,
		now:    time.Now,
	}
	for _, o := range opts {
		o(p)
	}
	return p
}

// ID implements oauth.Provider. It defaults to the host of the issuer, so two
// issuers cannot collide in the account table.
func (p *Provider) ID() string {
	if p.id != "" {
		return p.id
	}
	if u, err := url.Parse(p.issuer); err == nil && u.Host != "" {
		return u.Host
	}
	return "oidc"
}

// SupportsPKCE implements oauth.Provider. OpenID Connect providers accept a
// PKCE challenge.
func (p *Provider) SupportsPKCE() bool { return true }

// Validate reports missing or unsafe configuration.
func (p *Provider) Validate() error {
	if p.issuer == "" {
		return fmt.Errorf("authall/oauth/oidc: the issuer is required")
	}
	if err := requireHTTPS(p.issuer, "the issuer"); err != nil {
		return err
	}
	if p.clientID == "" || p.clientSecret == "" {
		return fmt.Errorf("authall/oauth/oidc: the client id and the client secret are required")
	}
	return nil
}

// requireHTTPS reports an endpoint that is not HTTPS.
//
// A token endpoint carries the client secret, and an identity endpoint carries
// the proof of the user. Neither belongs on a plain connection.
func requireHTTPS(raw, name string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("authall/oauth/oidc: %s is not a URL: %w", name, err)
	}
	if u.Scheme == "https" {
		return nil
	}
	// A loopback host serves a local development issuer, which cannot hold a
	// certificate. Every other plain endpoint is refused.
	if u.Scheme == "http" && isLoopback(u.Hostname()) {
		return nil
	}
	return fmt.Errorf("authall/oauth/oidc: %s must use HTTPS, and it is %q", name, raw)
}

// isLoopback reports a host that never leaves the machine.
func isLoopback(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "[::1]"
}

// discovery is the subset of the discovery document that Auth-All reads.
type discovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// resolve returns the endpoints of the provider. It fetches the discovery
// document one time and caches the result.
//
// A failed attempt caches nothing, so an issuer that is briefly unreachable
// recovers with no restart.
func (p *Provider) resolve(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.resolved {
		return nil
	}
	if p.static {
		if p.keys == nil {
			p.keys = jwt.NewKeySet(p.jwksURL, p.client)
		}
		p.resolved = true
		return nil
	}
	doc, err := p.fetchDiscovery(ctx)
	if err != nil {
		return err
	}
	p.authURL, p.tokenURL, p.jwksURL = doc.AuthorizationEndpoint, doc.TokenEndpoint, doc.JWKSURI
	p.keys = jwt.NewKeySet(p.jwksURL, p.client)
	p.resolved = true
	return nil
}

// fetchDiscovery reads and validates the discovery document.
//
// The document is attacker-controlled input the moment the issuer is
// misconfigured, so every field is checked before it is used.
func (p *Provider) fetchDiscovery(ctx context.Context) (*discovery, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.issuer+DiscoveryPath, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("authall/oauth/oidc: cannot reach the discovery document: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("authall/oauth/oidc: the discovery document returned %d", resp.StatusCode)
	}
	var doc discovery
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("authall/oauth/oidc: the discovery document is malformed: %w", err)
	}
	// The document must name the configured issuer. A document that names
	// another issuer redirects the sign-in to a server that the operator did
	// not choose.
	if strings.TrimSuffix(doc.Issuer, "/") != p.issuer {
		return nil, fmt.Errorf(
			"authall/oauth/oidc: the discovery document names the issuer %q and the configuration names %q",
			doc.Issuer, p.issuer)
	}
	if doc.AuthorizationEndpoint == "" || doc.TokenEndpoint == "" || doc.JWKSURI == "" {
		return nil, fmt.Errorf("authall/oauth/oidc: the discovery document names no complete endpoint set")
	}
	for name, endpoint := range map[string]string{
		"the authorization endpoint": doc.AuthorizationEndpoint,
		"the token endpoint":         doc.TokenEndpoint,
		"the key set endpoint":       doc.JWKSURI,
	} {
		if err := requireHTTPS(endpoint, name); err != nil {
			return nil, err
		}
	}
	return &doc, nil
}

// AuthCodeURL implements oauth.Provider.
func (p *Provider) AuthCodeURL(req oauth.AuthRequest) (string, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}
	if err := p.resolve(context.Background()); err != nil {
		return "", err
	}
	p.mu.Lock()
	authURL := p.authURL
	p.mu.Unlock()

	q := url.Values{}
	q.Set("client_id", p.clientID)
	q.Set("redirect_uri", req.RedirectURI)
	q.Set("response_type", "code")
	q.Set("scope", strings.Join(p.scopes, " "))
	q.Set("state", req.State)
	if req.Nonce != "" {
		q.Set("nonce", req.Nonce)
	}
	if req.CodeChallenge != "" {
		q.Set("code_challenge", req.CodeChallenge)
		q.Set("code_challenge_method", "S256")
	}
	sep := "?"
	if strings.Contains(authURL, "?") {
		sep = "&"
	}
	return authURL + sep + q.Encode(), nil
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	Error       string `json:"error"`
}

// Exchange implements oauth.Provider. It validates the signature, the issuer,
// the audience, the nonce, and the expiry of the identity token.
func (p *Provider) Exchange(ctx context.Context, req oauth.ExchangeRequest) (*oauth.Identity, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if err := p.resolve(ctx); err != nil {
		return nil, err
	}
	p.mu.Lock()
	tokenURL, keys := p.tokenURL, p.keys
	p.mu.Unlock()

	form := url.Values{}
	form.Set("client_id", p.clientID)
	form.Set("client_secret", p.clientSecret)
	form.Set("code", req.Code)
	form.Set("redirect_uri", req.RedirectURI)
	form.Set("grant_type", "authorization_code")
	if req.CodeVerifier != "" {
		form.Set("code_verifier", req.CodeVerifier)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpReq.Header.Set("Accept", "application/json")
	resp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var token tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return nil, fmt.Errorf("%w: the token response is malformed", oauth.ErrProviderRejected)
	}
	if token.Error != "" || token.IDToken == "" {
		return nil, fmt.Errorf("%w: the token exchange failed", oauth.ErrProviderRejected)
	}
	claims, err := keys.Verify(ctx, token.IDToken, jwt.Verification{
		Issuer:   p.issuer,
		Audience: p.clientID,
		Nonce:    req.Nonce,
		Now:      p.now(),
		Leeway:   time.Minute,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: the identity token is invalid", oauth.ErrProviderRejected)
	}
	// The subject keys the account. An address changes owner, and a subject
	// does not.
	return &oauth.Identity{
		ProviderAccountID: claims.Subject,
		Email:             claims.Email,
		EmailVerified:     claims.VerifiedEmail(),
		DisplayName:       claims.Name,
		ImageURL:          claims.Picture,
	}, nil
}
