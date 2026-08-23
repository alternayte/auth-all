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
