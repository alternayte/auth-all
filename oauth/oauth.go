// Package oauth defines the OAuth provider boundary of Auth-All. Provider
// specific behavior belongs in a provider package, not in core.
package oauth

import (
	"context"
	"errors"
)

// ErrProviderRejected reports that the provider refused the exchange.
var ErrProviderRejected = errors.New("authall/oauth: the provider rejected the request")

// Identity is the verified provider identity of one end user.
type Identity struct {
	// ProviderAccountID is the stable identifier of the account at the
	// provider. It is never an email address.
	ProviderAccountID string
	// Email is the address the provider reports. It can be empty.
	Email string
	// EmailVerified reports whether the provider states that it verified the
	// address. Auth-All never links on an unverified address.
	EmailVerified bool
	DisplayName   string
	ImageURL      string
	// Username is the stable, human-readable account name at the provider,
	// for example the GitHub login. It can be empty.
	Username string
	// Claims holds every claim of the verified ID token, for example groups.
	// A provider that verifies no ID token leaves it nil. The field is a
	// pointer, so Identity stays comparable.
	Claims *Claims
}

// Claims is the read-only set of the verified ID token claims. A number
// arrives as float64, and a list as []any, as encoding/json decodes them. Every
// method is safe on a nil value.
type Claims struct {
	values map[string]any
}

// NewClaims returns a claim set over a copy of values.
func NewClaims(values map[string]any) *Claims {
	c := &Claims{values: make(map[string]any, len(values))}
	for k, v := range values {
		c.values[k] = v
	}
	return c
}

// Get returns one claim. The second result is false when the token does not
// carry the claim.
func (c *Claims) Get(name string) (any, bool) {
	if c == nil {
		return nil, false
	}
	v, ok := c.values[name]
	return v, ok
}

// Strings returns a claim that holds a list of strings, for example groups. A
// single string gives a list of one. Any other value gives nil.
func (c *Claims) Strings(name string) []string {
	v, _ := c.Get(name)
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		out := make([]string, 0, len(t))
		for _, item := range t {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// Map returns a copy of every claim.
func (c *Claims) Map() map[string]any {
	if c == nil {
		return nil
	}
	out := make(map[string]any, len(c.values))
	for k, v := range c.values {
		out[k] = v
	}
	return out
}

// AuthRequest is the data core supplies to build an authorization URL.
type AuthRequest struct {
	State       string
	RedirectURI string
	// CodeChallenge is the S256 PKCE challenge. It is empty when the provider
	// does not support PKCE.
	CodeChallenge string
	// Nonce is supplied for an OpenID Connect provider.
	Nonce string
}

// ExchangeRequest is the data core supplies to redeem an authorization code.
type ExchangeRequest struct {
	Code         string
	RedirectURI  string
	CodeVerifier string
	Nonce        string
}

// Provider is one OAuth or OpenID Connect provider.
type Provider interface {
	// ID returns the stable provider identifier used in routes and storage.
	ID() string
	// SupportsPKCE reports whether the provider accepts a PKCE challenge.
	SupportsPKCE() bool
	// AuthCodeURL returns the provider authorization URL.
	AuthCodeURL(req AuthRequest) (string, error)
	// Exchange redeems the authorization code and returns a verified identity.
	Exchange(ctx context.Context, req ExchangeRequest) (*Identity, error)
}
