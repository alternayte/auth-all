package oauthprovider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/alternayte/auth-all/apierr"
	"github.com/alternayte/auth-all/plugin"
)

// protectedResourcePath is the well-known location of RFC 9728.
const protectedResourcePath = "/.well-known/oauth-protected-resource"

// The error codes of RFC 6750 that a resource answers with.
const (
	// ErrorInvalidToken answers a token that is missing a part, expired,
	// revoked, or minted for another resource.
	ErrorInvalidToken = "invalid_token"
	// ErrorInsufficientScope answers a valid token that lacks a scope.
	ErrorInsufficientScope = "insufficient_scope"
)

// ResourceMetadataURL returns the RFC 9728 metadata URL of a resource
// identifier. The well-known path goes between the host and the path of the
// identifier, so https://app.example.com/mcp has its metadata at
// https://app.example.com/.well-known/oauth-protected-resource/mcp.
func ResourceMetadataURL(identifier string) (string, error) {
	u, err := url.Parse(identifier)
	if err != nil || !u.IsAbs() || u.Host == "" || u.Fragment != "" {
		return "", fmt.Errorf("authall/oauthprovider: the resource %q is no absolute URI with a host", identifier)
	}
	path := u.EscapedPath()
	if path == "/" {
		path = ""
	}
	out := u.Scheme + "://" + u.Host + protectedResourcePath + path
	if u.RawQuery != "" {
		out += "?" + u.RawQuery
	}
	return out, nil
}

// Challenge is the answer of a resource to a request it refuses.
type Challenge struct {
	// Resource is the identifier of the refusing resource. The challenge
	// names its metadata URL, so an MCP client finds the authorization server.
	Resource string
	// Status is 401 for a missing or bad token, and 403 for a scope shortfall.
	// Zero means 401.
	Status int
	// Error is the RFC 6750 error code. It stays empty when the request
	// carries no token, as RFC 6750 asks.
	Error string
	// Description explains the error to a developer. The header carries it
	// only beside an Error, and the body always.
	Description string
	// Scopes names the scopes the request needs. A 403 insufficient_scope
	// answer lists them.
	Scopes []string
}

// WriteChallenge answers a refused resource request with a WWW-Authenticate
// header that carries resource_metadata, as RFC 9728 and the MCP authorization
// specification ask, and with a JSON error body. A host handler that checks a
// scope itself calls it with ErrorInsufficientScope.
func WriteChallenge(w http.ResponseWriter, c Challenge) {
	status := c.Status
	if status == 0 {
		status = http.StatusUnauthorized
	}
	params := []string{}
	if target, err := ResourceMetadataURL(c.Resource); err == nil {
		params = append(params, `resource_metadata="`+quoteSafe(target)+`"`)
	}
	if c.Error != "" {
		params = append(params, `error="`+quoteSafe(c.Error)+`"`)
		if c.Description != "" {
			params = append(params, `error_description="`+quoteSafe(c.Description)+`"`)
		}
	}
	if len(c.Scopes) > 0 {
		params = append(params, `scope="`+quoteSafe(strings.Join(c.Scopes, " "))+`"`)
	}
	challenge := "Bearer"
	if len(params) > 0 {
		challenge += " " + strings.Join(params, ", ")
	}
	w.Header().Set("WWW-Authenticate", challenge)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	body := map[string]string{}
	if c.Error != "" {
		body["error"] = c.Error
	}
	if c.Description != "" {
		body["error_description"] = c.Description
	}
	_ = json.NewEncoder(w).Encode(body)
}

// quoteSafe drops the characters that would end a quoted header parameter. The
// values are server-written, so nothing of meaning is lost.
func quoteSafe(value string) string {
	return strings.Map(func(r rune) rune {
		if r == '"' || r == '\\' || r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, value)
}

// declaredResource returns a declared resource, and panics on an undeclared
// one. The server mints no token for an undeclared resource, so such a route
// could never open, and the typing error fails at startup.
func (p *Plugin) declaredResource(identifier, caller string) Resource {
	res, ok := p.resources[identifier]
	if !ok {
		panic(fmt.Sprintf("authall/oauthprovider: %s names the undeclared resource %q. "+
			"Declare it with oauthprovider.Resources", caller, identifier))
	}
	if _, err := ResourceMetadataURL(identifier); err != nil {
		panic(err.Error())
	}
	return res
}

// ProtectedResourceHandler serves the RFC 9728 metadata of one declared
// resource. It answers the path-suffixed location of the identifier, such as
// /.well-known/oauth-protected-resource/mcp, and the plain location, which an
// older client reads. The host mounts both at the origin root:
//
//	prm := provider.ProtectedResourceHandler("https://app.example.com/mcp")
//	mux.Handle("/.well-known/oauth-protected-resource", prm)
//	mux.Handle("/.well-known/oauth-protected-resource/", prm)
//
// The document names the issuer as the only authorization server, and it
// lists the scopes of the resource. It panics on an undeclared resource.
func (p *Plugin) ProtectedResourceHandler(identifier string) http.Handler {
	res := p.declaredResource(identifier, "ProtectedResourceHandler")
	target, _ := ResourceMetadataURL(identifier)
	u, _ := url.Parse(target)
	suffixed := u.EscapedPath()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		path := r.URL.EscapedPath()
		if path != suffixed && strings.TrimSuffix(path, "/") != protectedResourcePath {
			http.NotFound(w, r)
			return
		}
		if p.svc == nil {
			http.Error(w, "the OAuth provider plugin is not registered", http.StatusInternalServerError)
			return
		}
		scopes := res.Scopes
		if len(scopes) == 0 {
			scopes = p.scopes
		}
		w.Header().Set("Cache-Control", "public, max-age=300")
		p.svc.HTTP().WriteJSON(w, http.StatusOK, map[string]any{
			"resource":                          identifier,
			"authorization_servers":             []string{p.issuer},
			"scopes_supported":                  scopes,
			"bearer_methods_supported":          []string{"header"},
			"dpop_signing_alg_values_supported": []string{"ES256", "RS256"},
		})
	})
}

// RequireAudienceOptions configures RequireAudience.
type RequireAudienceOptions struct {
	// Fallback serves a request that carries no access token of this server,
	// for example an API key or a session cookie. A nil Fallback answers such
	// a request with 401 and the resource metadata challenge.
	Fallback http.Handler
	// Scopes names the scopes every token must carry. A token without one
	// gets 403 insufficient_scope.
	Scopes []string
}

// RequireAudience accepts an access token of this server only when its aud
// claim equals the identifier, and it then attaches the principal, so the
// handler reads it with authall.PrincipalFrom. The principal has the method
// authall.MethodOAuth and the client, scopes, and audience of the token.
//
// A missing or bad token gets 401 with WWW-Authenticate: Bearer
// resource_metadata="<metadata URL>", which is how an MCP client finds the
// authorization server. A token of a disabled user, of a revoked grant, or of
// another resource gets the same 401. The check reads the token, the grant,
// and the user on each request.
//
// At most one options value is accepted. RequireAudience panics on an
// undeclared resource and on a second options value.
func (p *Plugin) RequireAudience(identifier string, next http.Handler, opts ...RequireAudienceOptions) http.Handler {
	p.declaredResource(identifier, "RequireAudience")
	if len(opts) > 1 {
		panic("authall/oauthprovider: RequireAudience takes one options value")
	}
	var o RequireAudienceOptions
	if len(opts) == 1 {
		o = opts[0]
	}
	for _, s := range o.Scopes {
		if !p.knownScope(s) {
			panic(fmt.Sprintf("authall/oauthprovider: RequireAudience asks for the unknown scope %q", s))
		}
	}
	required := append([]string(nil), o.Scopes...)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p.svc == nil {
			http.Error(w, "the OAuth provider plugin is not registered", http.StatusInternalServerError)
			return
		}
		scheme, token := presentedToken(r)
		ours := token != "" && (scheme == "bearer" || scheme == "dpop") && p.Claims(token)
		if !ours {
			if o.Fallback != nil {
				o.Fallback.ServeHTTP(w, r)
				return
			}
			// RFC 6750 names no error for a request with no credential.
			WriteChallenge(w, Challenge{Resource: identifier,
				Description: "the request carries no access token"})
			return
		}
		principal, err := p.resourcePrincipal(r, identifier)
		if err != nil {
			var apiErr *apierr.Error
			if errors.As(err, &apiErr) {
				p.svc.HTTP().WriteError(w, apiErr)
				return
			}
			WriteChallenge(w, Challenge{Resource: identifier, Error: ErrorInvalidToken,
				Description: err.Error()})
			return
		}
		if !covers(principal.OAuth.Scopes, required) {
			WriteChallenge(w, Challenge{Resource: identifier, Status: http.StatusForbidden,
				Error: ErrorInsufficientScope, Description: "the access token lacks a required scope",
				Scopes: required})
			return
		}
		next.ServeHTTP(w, p.attach(r, principal))
	})
}

// resourcePrincipal verifies the access token of a request for one audience
// and returns its principal. A user that must change the password gets the
// error of the core middleware.
func (p *Plugin) resourcePrincipal(r *http.Request, audience string) (*plugin.Principal, error) {
	verified, err := p.authenticateResourceRequest(r, audience)
	if err != nil {
		return nil, err
	}
	principal, err := p.tokenPrincipal(r.Context(), verified)
	if err != nil {
		return nil, err
	}
	if principal.User.MustChangePassword {
		return nil, apierr.ErrPasswordChangeRequired
	}
	return principal, nil
}

// tokenPrincipal returns the principal of a verified token. A token of no
// user, of an unknown user, and of a disabled user has none.
func (p *Plugin) tokenPrincipal(ctx context.Context, verified *verifiedToken) (*plugin.Principal, error) {
	if verified.Row.UserID == nil {
		return nil, errors.New("the access token names no user")
	}
	user, err := p.svc.Users().ByID(ctx, *verified.Row.UserID)
	if err != nil {
		return nil, errors.New("the user of the access token is unknown")
	}
	if user.DisabledAt != nil {
		return nil, errors.New("the user of the access token is disabled")
	}
	return &plugin.Principal{User: user, Role: user.Role, Method: ID, OAuth: oauthGrantOf(verified)}, nil
}

// oauthGrantOf returns the authority of a verified token.
func oauthGrantOf(verified *verifiedToken) *plugin.OAuthGrant {
	return &plugin.OAuthGrant{
		ClientID: verified.Claims.ClientID,
		Scopes:   append([]string(nil), verified.Row.Scopes...),
		Audience: verified.Claims.Audience,
	}
}
