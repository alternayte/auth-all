// Package github implements the GitHub OAuth provider for Auth-All.
package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/alternayte/auth-all/oauth"
)

// ProviderID is the stable identifier of this provider.
const ProviderID = "github"

// Default GitHub endpoints.
const (
	DefaultAuthURL   = "https://github.com/login/oauth/authorize"
	DefaultTokenURL  = "https://github.com/login/oauth/access_token"
	DefaultUserURL   = "https://api.github.com/user"
	DefaultEmailsURL = "https://api.github.com/user/emails"
)

// Provider is the GitHub OAuth provider.
type Provider struct {
	clientID     string
	clientSecret string
	scopes       []string
	authURL      string
	tokenURL     string
	userURL      string
	emailsURL    string
	client       *http.Client
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

// WithEndpoints overrides the provider endpoints. Tests use it to point at a
// deterministic fake GitHub server.
func WithEndpoints(authURL, tokenURL, userURL, emailsURL string) Option {
	return func(p *Provider) {
		p.authURL, p.tokenURL, p.userURL, p.emailsURL = authURL, tokenURL, userURL, emailsURL
	}
}

// New returns a GitHub provider.
func New(opts ...Option) *Provider {
	p := &Provider{
		scopes:    []string{"read:user", "user:email"},
		authURL:   DefaultAuthURL,
		tokenURL:  DefaultTokenURL,
		userURL:   DefaultUserURL,
		emailsURL: DefaultEmailsURL,
		client:    http.DefaultClient,
	}
	for _, o := range opts {
		o(p)
	}
	return p
}

// ID implements oauth.Provider.
func (p *Provider) ID() string { return ProviderID }

// SupportsPKCE implements oauth.Provider. GitHub does not accept a PKCE
// challenge on the OAuth app authorization endpoint.
func (p *Provider) SupportsPKCE() bool { return false }

// Validate reports missing configuration.
func (p *Provider) Validate() error {
	if p.clientID == "" || p.clientSecret == "" {
		return fmt.Errorf("authall/oauth/github: the client id and the client secret are required")
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
	q.Set("state", req.State)
	q.Set("scope", strings.Join(p.scopes, " "))
	q.Set("allow_signup", "true")
	return p.authURL + "?" + q.Encode(), nil
}

type tokenResponse struct {
	AccessToken      string `json:"access_token"`
	TokenType        string `json:"token_type"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

type githubUser struct {
	ID        int64  `json:"id"`
	Login     string `json:"login"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url"`
}

type githubEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

// Exchange implements oauth.Provider.
func (p *Provider) Exchange(ctx context.Context, req oauth.ExchangeRequest) (*oauth.Identity, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	form := url.Values{}
	form.Set("client_id", p.clientID)
	form.Set("client_secret", p.clientSecret)
	form.Set("code", req.Code)
	form.Set("redirect_uri", req.RedirectURI)

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
	if token.Error != "" || token.AccessToken == "" {
		return nil, fmt.Errorf("%w: the token exchange failed", oauth.ErrProviderRejected)
	}

	var user githubUser
	if err := p.get(ctx, p.userURL, token.AccessToken, &user); err != nil {
		return nil, err
	}
	if user.ID == 0 {
		return nil, fmt.Errorf("%w: the user response has no account id", oauth.ErrProviderRejected)
	}
	identity := &oauth.Identity{
		ProviderAccountID: strconv.FormatInt(user.ID, 10),
		DisplayName:       user.Name,
		ImageURL:          user.AvatarURL,
	}
	if identity.DisplayName == "" {
		identity.DisplayName = user.Login
	}

	var emails []githubEmail
	if err := p.get(ctx, p.emailsURL, token.AccessToken, &emails); err == nil {
		for _, e := range emails {
			if e.Primary && e.Verified {
				identity.Email = e.Email
				identity.EmailVerified = true
				break
			}
		}
		if identity.Email == "" {
			for _, e := range emails {
				if e.Verified {
					identity.Email = e.Email
					identity.EmailVerified = true
					break
				}
			}
		}
	}
	if identity.Email == "" && user.Email != "" {
		// A profile email is not proven, so it stays unverified.
		identity.Email = user.Email
	}
	return identity, nil
}

func (p *Provider) get(ctx context.Context, endpoint, accessToken string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: the provider returned status %d", oauth.ErrProviderRejected, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(dst); err != nil {
		return fmt.Errorf("%w: the provider response is malformed", oauth.ErrProviderRejected)
	}
	return nil
}
