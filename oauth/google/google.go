// Package google implements the Google OpenID Connect provider for Auth-All.
package google

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/alternayte/auth-all/internal/jwt"
	"github.com/alternayte/auth-all/oauth"
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
	clientID     string
	clientSecret string
	scopes       []string
	authURL      string
	tokenURL     string
	issuer       string
	client       *http.Client
	keys         *jwt.KeySet
	now          func() time.Time
}

// Option configures the provider.
type Option func(*Provider)

// WithClientID sets the OAuth client id.
func WithClientID(v string) Option { return func(p *Provider) { p.clientID = v } }

// WithClientSecret sets the OAuth client secret.
func WithClientSecret(v string) Option { return func(p *Provider) { p.clientSecret = v } }

// WithScopes replaces the requested scopes.
func WithScopes(v ...string) Option { return func(p *Provider) { p.scopes = v } }

// WithHTTPClient sets the HTTP client used for provider calls.
func WithHTTPClient(c *http.Client) Option { return func(p *Provider) { p.client = c } }

// WithEndpoints overrides the provider endpoints and the expected issuer. Tests
// use it to point at a deterministic fake Google server.
func WithEndpoints(authURL, tokenURL, jwksURL, issuer string) Option {
	return func(p *Provider) {
		p.authURL, p.tokenURL, p.issuer = authURL, tokenURL, issuer
		p.keys = jwt.NewKeySet(jwksURL, p.client)
	}
}

// WithClock replaces the clock used for token expiry validation.
func WithClock(now func() time.Time) Option { return func(p *Provider) { p.now = now } }

// New returns a Google provider.
func New(opts ...Option) *Provider {
	p := &Provider{
		scopes:   []string{"openid", "email", "profile"},
		authURL:  DefaultAuthURL,
		tokenURL: DefaultTokenURL,
		issuer:   DefaultIssuer,
		client:   http.DefaultClient,
		now:      time.Now,
	}
	for _, o := range opts {
		o(p)
	}
	if p.keys == nil {
		p.keys = jwt.NewKeySet(DefaultJWKSURL, p.client)
	}
	return p
}

// ID implements oauth.Provider.
func (p *Provider) ID() string { return ProviderID }

// SupportsPKCE implements oauth.Provider.
func (p *Provider) SupportsPKCE() bool { return true }

// Validate reports missing configuration.
func (p *Provider) Validate() error {
	if p.clientID == "" || p.clientSecret == "" {
		return fmt.Errorf("authall/oauth/google: the client id and the client secret are required")
	}
	return nil
}

// AuthCodeURL implements oauth.Provider.
func (p *Provider) AuthCodeURL(req oauth.AuthRequest) (string, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}
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
	return p.authURL + "?" + q.Encode(), nil
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	Error       string `json:"error"`
}

// Exchange implements oauth.Provider. It validates the issuer, the audience,
// the nonce, the expiry, and the signature of the identity token.
func (p *Provider) Exchange(ctx context.Context, req oauth.ExchangeRequest) (*oauth.Identity, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	form := url.Values{}
	form.Set("client_id", p.clientID)
	form.Set("client_secret", p.clientSecret)
	form.Set("code", req.Code)
	form.Set("redirect_uri", req.RedirectURI)
	form.Set("grant_type", "authorization_code")
	if req.CodeVerifier != "" {
		form.Set("code_verifier", req.CodeVerifier)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.tokenURL, strings.NewReader(form.Encode()))
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
	claims, err := p.keys.Verify(ctx, token.IDToken, jwt.Verification{
		Issuer:   p.issuer,
		Audience: p.clientID,
		Nonce:    req.Nonce,
		Now:      p.now(),
		Leeway:   time.Minute,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %s", oauth.ErrProviderRejected, "the identity token is invalid")
	}
	return &oauth.Identity{
		ProviderAccountID: claims.Subject,
		Email:             claims.Email,
		EmailVerified:     claims.VerifiedEmail(),
		DisplayName:       claims.Name,
		ImageURL:          claims.Picture,
	}, nil
}
