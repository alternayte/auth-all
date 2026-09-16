package oauthprovider

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/alternayte/auth-all/store"
)

// The grant types the server supports.
const (
	GrantAuthorizationCode = "authorization_code"
	GrantRefreshToken      = "refresh_token"
	GrantClientCredentials = "client_credentials"
)

// The client authentication methods the server supports.
const (
	AuthClientSecretBasic = "client_secret_basic"
	AuthClientSecretPost  = "client_secret_post"
	AuthNone              = "none"
)

// errUnknownClient reports a client identifier that no static declaration and
// no row names.
var errUnknownClient = errors.New("authall/oauthprovider: the client is unknown")

// client is one relying party, from a static declaration or from a row. The
// flows read this type only, so a static client and a registered client take
// one path.
type client struct {
	ClientID     string
	SecretHash   string
	Name         string
	LogoURI      string
	RedirectURIs []string
	GrantTypes   []string
	Scopes       []string
	AuthMethod   string
	DPoPRequired bool
	// Static reports a client declared in host source. It skips consent,
	// because the host already decided for it.
	Static bool
	// Row is the stored client. A static client holds nil.
	Row *store.OAuthClient
}

// staticClient converts a declaration into a client.
func (p *Plugin) staticToClient(c StaticClient) client {
	out := client{
		ClientID:     c.ClientID,
		Name:         c.Name,
		RedirectURIs: c.RedirectURIs,
		GrantTypes:   c.GrantTypes,
		Scopes:       c.Scopes,
		AuthMethod:   AuthNone,
		DPoPRequired: c.DPoPRequired,
		Static:       true,
	}
	if len(out.GrantTypes) == 0 {
		out.GrantTypes = []string{GrantAuthorizationCode, GrantRefreshToken}
	}
	if len(out.Scopes) == 0 {
		out.Scopes = p.scopes
	}
	if c.Secret != "" {
		out.SecretHash = digest(c.Secret)
		out.AuthMethod = AuthClientSecretBasic
		if c.AuthMethod != "" {
			out.AuthMethod = c.AuthMethod
		}
	}
	return out
}

// rowToClient converts a row into a client.
func (p *Plugin) rowToClient(row *store.OAuthClient) client {
	scopes := row.Scopes
	if len(scopes) == 0 {
		scopes = p.scopes
	}
	return client{
		ClientID:     row.ClientID,
		SecretHash:   row.SecretHash,
		Name:         row.Name,
		LogoURI:      row.LogoURI,
		RedirectURIs: row.RedirectURIs,
		GrantTypes:   row.GrantTypes,
		Scopes:       scopes,
		AuthMethod:   row.TokenEndpointAuthMethod,
		DPoPRequired: row.DPoPRequired,
		Row:          row,
	}
}

// lookupClient returns one client. A static declaration wins, because host
// source is the higher authority and no runtime route may shadow it.
func (p *Plugin) lookupClient(ctx context.Context, clientID string) (client, error) {
	if c, ok := p.staticClients[clientID]; ok {
		return p.staticToClient(c), nil
	}
	row, err := p.rows.OAuthClientByClientID(ctx, clientID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return client{}, errUnknownClient
		}
		return client{}, err
	}
	return p.rowToClient(row), nil
}

// digest returns the SHA-256 hex digest of a secret.
func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

// secretMatches compares a presented secret in constant time.
func (c client) secretMatches(secret string) bool {
	if c.SecretHash == "" || secret == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(c.SecretHash), []byte(digest(secret))) == 1
}

// allowsGrant reports whether the client may use the grant type.
func (c client) allowsGrant(name string) bool { return hasGrant(c.GrantTypes, name) }

func hasGrant(list []string, name string) bool {
	for _, g := range list {
		if g == name {
			return true
		}
	}
	return false
}

// matchRedirectURI returns the registered value that the candidate matches.
//
// The comparison is exact. The plugin rewrites no host, so localhost and
// 127.0.0.1 stay separate registrations. A loopback URI ignores the port,
// because a native app picks its port at run time.
func (c client) matchRedirectURI(candidate string) (string, error) {
	for _, registered := range c.RedirectURIs {
		if registered == candidate {
			return registered, nil
		}
	}
	got, err := url.Parse(candidate)
	if err != nil || !got.IsAbs() {
		return "", errors.New("the redirect URI is no absolute URI")
	}
	if !isLoopback(got) {
		return "", errors.New("the redirect URI is not registered")
	}
	for _, registered := range c.RedirectURIs {
		want, err := url.Parse(registered)
		if err != nil || !isLoopback(want) {
			continue
		}
		if want.Scheme == got.Scheme && want.Hostname() == got.Hostname() && want.Path == got.Path {
			return candidate, nil
		}
	}
	return "", errors.New("the redirect URI is not registered")
}

// isLoopback reports a redirect URI of a native application on the loopback
// interface.
func isLoopback(u *url.URL) bool {
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	host := u.Hostname()
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// checkRedirectURI reports whether a redirect URI may be registered.
//
// A private-use scheme registers with or without an authority, because a
// desktop client sends both forms. A plain http URI needs a loopback host, or
// a host the deployment named.
func (p *Plugin) checkRedirectURI(value string) error {
	u, err := url.Parse(value)
	if err != nil || !u.IsAbs() {
		return fmt.Errorf("the redirect URI %q is no absolute URI", value)
	}
	if u.Fragment != "" || strings.Contains(value, "#") {
		return fmt.Errorf("the redirect URI %q carries a fragment", value)
	}
	if strings.Contains(value, "*") {
		return fmt.Errorf("the redirect URI %q carries a wildcard", value)
	}
	switch u.Scheme {
	case "https":
		if u.Hostname() == "" {
			return fmt.Errorf("the redirect URI %q names no host", value)
		}
		return nil
	case "http":
		if isLoopback(u) {
			return nil
		}
		if p.plainHTTPHosts[strings.ToLower(u.Hostname())] {
			return nil
		}
		return fmt.Errorf("the redirect URI %q uses http and names no permitted host", value)
	default:
		// A private-use scheme belongs to the application. It registers with
		// an authority, as in myapp://host/callback, and without one, as in
		// myapp://callback, because a desktop client sends both forms.
		if u.Scheme != strings.ToLower(u.Scheme) {
			return fmt.Errorf("the redirect URI %q uses an upper case scheme", value)
		}
		return nil
	}
}
