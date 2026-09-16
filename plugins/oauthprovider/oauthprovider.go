// Package oauthprovider turns Auth-All into an OAuth 2.1 and OpenID Connect
// authorization server.
//
// A relying party runs the authorization code flow with PKCE, receives an ID
// token and a signed access token, and reads claims from the userinfo route.
// The host renders the login page and the consent page. The plugin holds every
// authorization request as server state, so no request detail travels in a
// URL.
//
//	p := oauthprovider.New(
//	    oauthprovider.KeyEncryptionKey(key),
//	    oauthprovider.LoginPath("/sign-in"),
//	    oauthprovider.ConsentPath("/consent"),
//	)
//	auth, err := authall.New(authall.WithStore(s), authall.WithPlugins(p))
//	mux.Handle("/.well-known/", p.MetadataHandler())
package oauthprovider

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/alternayte/auth-all/hook"
	"github.com/alternayte/auth-all/internal/jws"
	"github.com/alternayte/auth-all/plugin"
	"github.com/alternayte/auth-all/schema"
	"github.com/alternayte/auth-all/store"
)

// ID is the stable plugin identifier.
const ID = "oauthprovider"

// The scopes the plugin understands without host configuration.
const (
	ScopeOpenID        = "openid"
	ScopeProfile       = "profile"
	ScopeEmail         = "email"
	ScopeOfflineAccess = "offline_access"
)

// Default lifetimes.
const (
	DefaultAccessTokenTTL  = 10 * time.Minute
	DefaultRefreshTokenTTL = 30 * 24 * time.Hour
	DefaultCodeTTL         = time.Minute
	DefaultRequestTTL      = 15 * time.Minute
	DefaultRotationGrace   = 10 * time.Second
	// DefaultDPoPProofWindow bounds the age of an accepted DPoP proof.
	DefaultDPoPProofWindow = 60 * time.Second
)

// keyEncryptionKeySize is the required length of the key encryption key.
const keyEncryptionKeySize = 32

// StaticClient is a first-party client declared in host source. It holds no
// row, so no runtime route edits it and it needs no consent.
type StaticClient struct {
	// ClientID identifies the client.
	ClientID string
	// Secret authenticates a confidential client. An empty value declares a
	// public client, which must use PKCE and holds no secret.
	Secret string
	// AuthMethod names how the client authenticates at the token endpoint. The
	// default of a confidential client is client_secret_basic. The server
	// enforces the named method, so a leaked secret cannot arrive another way.
	AuthMethod string
	// Name appears on the consent page of another client of the same user.
	Name string
	// RedirectURIs holds the exact registered values.
	RedirectURIs []string
	// Scopes bounds what the client may request. An empty value allows the
	// configured scopes of the server.
	Scopes []string
	// GrantTypes bounds the grants. The default is authorization_code and
	// refresh_token.
	GrantTypes []string
	// DPoPRequired refuses a bearer presentation of a token of this client.
	DPoPRequired bool
}

// Resource is one protected resource that a client names with the resource
// parameter of RFC 8707. The identifier becomes the aud claim of the access
// token.
type Resource struct {
	// Identifier is the absolute URI of the resource. It carries no fragment.
	Identifier string
	// Scopes bounds the scopes an access token for this resource may carry. An
	// empty value allows the configured scopes of the server.
	Scopes []string
	// AccessTokenTTL overrides the server lifetime for this resource.
	AccessTokenTTL time.Duration
}

// ClaimMapping publishes a host-declared user field as a claim under a scope.
// The field must be a user field that the host declared with Returned set.
type ClaimMapping struct {
	// Scope grants the claim. An empty value grants it with the profile scope.
	Scope string
	// Claim is the claim name at the userinfo route.
	Claim string
	// Field is the name of the host-declared user field.
	Field string
}

// ClaimsFunc adds claims to the userinfo response. It receives the granted
// scopes, and it must return no reserved claim name.
type ClaimsFunc func(user *store.User, scopes []string) map[string]any

// Plugin is the OAuth provider plugin.
type Plugin struct {
	kek             []byte
	algorithm       string
	loginPath       string
	consentPath     string
	scopes          []string
	staticClients   map[string]StaticClient
	resources       map[string]Resource
	claimMappings   []ClaimMapping
	claims          ClaimsFunc
	dynamic         bool
	plainHTTPHosts  map[string]bool
	accessTokenTTL  time.Duration
	refreshTokenTTL time.Duration
	codeTTL         time.Duration
	requestTTL      time.Duration
	rotationGrace   time.Duration

	svc        plugin.Services
	rows       store.OAuthProviderStore
	hooks      *hook.Hooks
	principals plugin.PrincipalService
	protect    func(http.Handler) http.Handler
	now        func() time.Time
	issuer     string

	keyMu  sync.Mutex
	signer *jws.Key
	// verifiers holds the public key of every live key by identifier.
	verifiers map[string]any
}

// Option configures the plugin.
type Option func(*Plugin)

// KeyEncryptionKey supplies the 32 bytes that wrap every signing key at rest.
// The plugin refuses to register without it.
func KeyEncryptionKey(key []byte) Option {
	return func(p *Plugin) { p.kek = append([]byte(nil), key...) }
}

// Algorithm selects the signing algorithm. The default is ES256. A relying
// party that accepts RS256 only needs RS256.
func Algorithm(name string) Option { return func(p *Plugin) { p.algorithm = name } }

// LoginPath is the host page that authenticates a user. The authorize route
// redirects to it with the identifier of the authorization request.
func LoginPath(path string) Option { return func(p *Plugin) { p.loginPath = path } }

// ConsentPath is the host page that asks for consent.
func ConsentPath(path string) Option { return func(p *Plugin) { p.consentPath = path } }

// Scopes replaces the scopes the server offers.
func Scopes(names ...string) Option {
	return func(p *Plugin) { p.scopes = append([]string(nil), names...) }
}

// Clients declares the static first-party clients.
func Clients(clients ...StaticClient) Option {
	return func(p *Plugin) {
		for _, c := range clients {
			p.staticClients[c.ClientID] = c
		}
	}
}

// Resources declares the protected resources a client may name.
func Resources(resources ...Resource) Option {
	return func(p *Plugin) {
		for _, r := range resources {
			p.resources[r.Identifier] = r
		}
	}
}

// Claims maps host-declared user fields to claims.
func Claims(mappings ...ClaimMapping) Option {
	return func(p *Plugin) { p.claimMappings = append(p.claimMappings, mappings...) }
}

// ClaimsFrom adds a function that returns further claims.
func ClaimsFrom(f ClaimsFunc) Option { return func(p *Plugin) { p.claims = f } }

// AllowDynamicRegistration opens the RFC 7591 registration route. A client
// that registers through it manages itself with the RFC 7592 registration
// access token.
func AllowDynamicRegistration() Option { return func(p *Plugin) { p.dynamic = true } }

// AllowPlainHTTP names the hosts that may register a plain http redirect URI.
// A self-hosted deployment without TLS needs it. Loopback and a private-use
// scheme need no entry.
func AllowPlainHTTP(hosts ...string) Option {
	return func(p *Plugin) {
		for _, h := range hosts {
			p.plainHTTPHosts[strings.ToLower(h)] = true
		}
	}
}

// AccessTokenTTL sets the access token lifetime.
func AccessTokenTTL(d time.Duration) Option { return func(p *Plugin) { p.accessTokenTTL = d } }

// RefreshTokenTTL sets the refresh token lifetime.
func RefreshTokenTTL(d time.Duration) Option { return func(p *Plugin) { p.refreshTokenTTL = d } }

// CodeTTL sets the authorization code lifetime.
func CodeTTL(d time.Duration) Option { return func(p *Plugin) { p.codeTTL = d } }

// RequestTTL sets the lifetime of an authorization request. It bounds how long
// the host pages have to complete the flow.
func RequestTTL(d time.Duration) Option { return func(p *Plugin) { p.requestTTL = d } }

// RotationGrace sets the window in which a rotated refresh token answers a
// retry with the same successor pair.
func RotationGrace(d time.Duration) Option { return func(p *Plugin) { p.rotationGrace = d } }

// New returns the OAuth provider plugin.
func New(opts ...Option) *Plugin {
	p := &Plugin{
		algorithm:       jws.ES256,
		scopes:          []string{ScopeOpenID, ScopeProfile, ScopeEmail, ScopeOfflineAccess},
		staticClients:   map[string]StaticClient{},
		resources:       map[string]Resource{},
		plainHTTPHosts:  map[string]bool{},
		accessTokenTTL:  DefaultAccessTokenTTL,
		refreshTokenTTL: DefaultRefreshTokenTTL,
		codeTTL:         DefaultCodeTTL,
		requestTTL:      DefaultRequestTTL,
		rotationGrace:   DefaultRotationGrace,
		verifiers:       map[string]any{},
	}
	for _, o := range opts {
		o(p)
	}
	return p
}

// ID implements plugin.Plugin.
func (p *Plugin) ID() string { return ID }

// reservedClaims names the claims the server stamps itself. A mapping or a
// claims function must not write one.
var reservedClaims = map[string]bool{
	"iss": true, "sub": true, "aud": true, "exp": true, "iat": true, "nbf": true,
	"jti": true, "client_id": true, "azp": true, "scope": true, "cnf": true,
	"auth_time": true, "nonce": true, "token_type": true, "active": true,
}

// Register implements plugin.Plugin.
func (p *Plugin) Register(r *plugin.Registry) error {
	if len(p.kek) != keyEncryptionKeySize {
		return fmt.Errorf("authall/oauthprovider: the key encryption key needs %d bytes",
			keyEncryptionKeySize)
	}
	if p.algorithm != jws.ES256 && p.algorithm != jws.RS256 {
		return fmt.Errorf("authall/oauthprovider: the algorithm %q is neither ES256 nor RS256",
			p.algorithm)
	}
	if p.loginPath == "" || p.consentPath == "" {
		return errors.New("authall/oauthprovider: the login path and the consent path are required")
	}
	svc := r.Services()
	rows, ok := svc.Store().(store.OAuthProviderStore)
	if !ok {
		return errors.New("authall/oauthprovider: the configured store holds no OAuth provider row")
	}
	if err := p.checkClaims(); err != nil {
		return err
	}
	if err := p.checkStaticClients(); err != nil {
		return err
	}
	if err := p.checkResources(); err != nil {
		return err
	}
	principals, ok := svc.(plugin.PrincipalServices)
	if !ok {
		return errors.New("authall/oauthprovider: this Auth-All version has no principal service")
	}
	protector, ok := svc.(plugin.ProtectService)
	if !ok {
		return errors.New("authall/oauthprovider: this Auth-All version has no authentication middleware")
	}
	p.svc = svc
	p.rows = rows
	p.principals = principals.Principals()
	p.protect = protector.Protect
	p.hooks = r.Hooks()
	p.now = svc.Now
	p.issuer = strings.TrimRight(svc.BaseURL(), "/") + svc.BasePath()

	options := schema.DefaultOptions()
	if reporter, ok := svc.(plugin.SchemaService); ok {
		options = reporter.SchemaOptions()
	}
	for _, t := range schema.OAuthProviderTables(options) {
		r.Schema(t)
	}
	units, err := schema.OAuthProviderUnits(options, ID)
	if err != nil {
		return err
	}
	for _, u := range units {
		r.Unit(u)
	}
	r.Resolver(p)
	p.registerRoutes(r)
	p.registerHooks(r)
	return nil
}

// checkClaims rejects a mapping or a function that would overwrite a claim the
// server stamps.
func (p *Plugin) checkClaims() error {
	seen := map[string]bool{}
	for _, m := range p.claimMappings {
		if m.Claim == "" || m.Field == "" {
			return errors.New("authall/oauthprovider: a claim mapping needs a claim and a field")
		}
		if reservedClaims[m.Claim] {
			return fmt.Errorf("authall/oauthprovider: the claim %q is reserved", m.Claim)
		}
		if seen[m.Claim] {
			return fmt.Errorf("authall/oauthprovider: the claim %q is mapped twice", m.Claim)
		}
		seen[m.Claim] = true
		if m.Scope != "" && !p.knownScope(m.Scope) {
			return fmt.Errorf("authall/oauthprovider: the claim scope %q is not offered", m.Scope)
		}
	}
	return nil
}

// checkStaticClients rejects a static client the server could not serve.
func (p *Plugin) checkStaticClients() error {
	for id, c := range p.staticClients {
		if id == "" {
			return errors.New("authall/oauthprovider: a static client needs a client identifier")
		}
		if len(c.RedirectURIs) == 0 && !hasGrant(c.GrantTypes, GrantClientCredentials) {
			return fmt.Errorf("authall/oauthprovider: the static client %q registers no redirect URI", id)
		}
		for _, uri := range c.RedirectURIs {
			if err := p.checkRedirectURI(uri); err != nil {
				return fmt.Errorf("authall/oauthprovider: the static client %q: %w", id, err)
			}
		}
		for _, s := range c.Scopes {
			if !p.knownScope(s) {
				return fmt.Errorf("authall/oauthprovider: the static client %q asks for the unknown scope %q",
					id, s)
			}
		}
	}
	return nil
}

// checkResources rejects a resource identifier that RFC 8707 forbids.
func (p *Plugin) checkResources() error {
	for id, res := range p.resources {
		u, err := url.Parse(id)
		if err != nil || !u.IsAbs() || u.Fragment != "" {
			return fmt.Errorf("authall/oauthprovider: the resource %q is no absolute URI without a fragment", id)
		}
		for _, s := range res.Scopes {
			if !p.knownScope(s) {
				return fmt.Errorf("authall/oauthprovider: the resource %q asks for the unknown scope %q", id, s)
			}
		}
	}
	return nil
}

// knownScope reports whether the server offers the scope.
func (p *Plugin) knownScope(name string) bool {
	for _, s := range p.scopes {
		if s == name {
			return true
		}
	}
	return false
}

// MetadataHandler serves the authorization server metadata of RFC 8414 and the
// OpenID Connect discovery document. The host mounts it at the origin root,
// because the well-known location lives there and a plugin route cannot reach
// it:
//
//	mux.Handle("/.well-known/", provider.MetadataHandler())
func (p *Plugin) MetadataHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.writeMetadata(w, r)
	})
}
