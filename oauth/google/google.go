// Package google implements the Google OpenID Connect provider for Auth-All.
//
// Google is a conformant OpenID Connect issuer, so this package is a preset
// over the generic provider in oauth/oidc. One code path carries the identity
// token verification, so a defect is repaired one time.
package google

import (
	"context"
	"net/http"
	"time"

	"github.com/alternayte/auth-all/oauth"
	"github.com/alternayte/auth-all/oauth/oidc"
)

// ProviderID is the stable identifier of this provider.
const ProviderID = "google"

// Default Google endpoints.
const (
	DefaultAuthURL  = "https://accounts.google.com/o/oauth2/v2/auth"
	DefaultTokenURL = "https://oauth2.googleapis.com/token"
	DefaultJWKSURL  = "https://www.googleapis.com/oauth2/v3/certs"
	DefaultIssuer   = "https://accounts.google.com"
)

// Provider is the Google OpenID Connect provider.
type Provider struct {
	opts  []oidc.Option
	inner *oidc.Provider
}

// Option configures the provider.
type Option func(*Provider)

// WithClientID sets the OAuth client id.
func WithClientID(v string) Option { return add(oidc.WithClientID(v)) }

// WithClientSecret sets the OAuth client secret.
func WithClientSecret(v string) Option { return add(oidc.WithClientSecret(v)) }

// WithScopes replaces the requested scopes.
func WithScopes(v ...string) Option { return add(oidc.WithScopes(v...)) }

// WithHTTPClient sets the HTTP client used for provider calls.
func WithHTTPClient(c *http.Client) Option { return add(oidc.WithHTTPClient(c)) }

// WithEndpoints overrides the provider endpoints and the expected issuer. Tests
// use it to point at a deterministic fake Google server.
func WithEndpoints(authURL, tokenURL, jwksURL, issuer string) Option {
	return func(p *Provider) {
		p.opts = append(p.opts,
			oidc.WithEndpoints(authURL, tokenURL, jwksURL),
			oidc.WithIssuer(issuer))
	}
}

// WithClock replaces the clock used for token expiry validation.
func WithClock(now func() time.Time) Option { return add(oidc.WithClock(now)) }

// add lifts a generic option into a Google option.
func add(o oidc.Option) Option {
	return func(p *Provider) { p.opts = append(p.opts, o) }
}

// New returns a Google provider.
//
// Google publishes a discovery document, and this preset names the endpoints
// directly. The endpoints are stable and documented, so the first sign-in needs
// no extra round trip.
func New(opts ...Option) *Provider {
	p := &Provider{}
	for _, o := range opts {
		o(p)
	}
	base := []oidc.Option{
		oidc.WithID(ProviderID),
		oidc.WithIssuer(DefaultIssuer),
		oidc.WithEndpoints(DefaultAuthURL, DefaultTokenURL, DefaultJWKSURL),
	}
	p.inner = oidc.New(append(base, p.opts...)...)
	return p
}

// ID implements oauth.Provider.
func (p *Provider) ID() string { return ProviderID }

// SupportsPKCE implements oauth.Provider.
func (p *Provider) SupportsPKCE() bool { return p.inner.SupportsPKCE() }

// Validate reports missing configuration.
func (p *Provider) Validate() error { return p.inner.Validate() }

// AuthCodeURL implements oauth.Provider.
func (p *Provider) AuthCodeURL(req oauth.AuthRequest) (string, error) {
	return p.inner.AuthCodeURL(req)
}

// Exchange implements oauth.Provider. It validates the issuer, the audience,
// the nonce, the expiry, and the signature of the identity token.
func (p *Provider) Exchange(ctx context.Context, req oauth.ExchangeRequest) (*oauth.Identity, error) {
	return p.inner.Exchange(ctx, req)
}
