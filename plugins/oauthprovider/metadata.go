package oauthprovider

import (
	"net/http"
	"strings"
)

// Route paths of the plugin, relative to the Auth-All base path.
const (
	PathAuthorize  = "/oauth2/authorize"
	PathToken      = "/oauth2/token"
	PathUserInfo   = "/oauth2/userinfo"
	PathJWKS       = "/oauth2/jwks"
	PathRegister   = "/oauth2/register"
	PathClient     = "/oauth2/register/"
	PathIntrospect = "/oauth2/introspect"
	PathRevoke     = "/oauth2/revoke"
	PathRequest    = "/oauth2/request"
	PathDecide     = "/oauth2/decide"
	PathConsents   = "/oauth2/consents"
	PathClients    = "/oauth2/clients"
)

// metadata returns the authorization server metadata document.
//
// The issuer identifier is the base URL plus the base path, which RFC 8414
// allows. The metadata therefore belongs at the origin root under
// /.well-known/oauth-authorization-server/<base path>.
func (p *Plugin) metadata() map[string]any {
	doc := map[string]any{
		"issuer":                                p.issuer,
		"authorization_endpoint":                p.issuer + PathAuthorize,
		"token_endpoint":                        p.issuer + PathToken,
		"userinfo_endpoint":                     p.issuer + PathUserInfo,
		"jwks_uri":                              p.issuer + PathJWKS,
		"introspection_endpoint":                p.issuer + PathIntrospect,
		"revocation_endpoint":                   p.issuer + PathRevoke,
		"scopes_supported":                      p.scopes,
		"response_types_supported":              []string{"code"},
		"response_modes_supported":              []string{"query"},
		"grant_types_supported":                 []string{GrantAuthorizationCode, GrantRefreshToken, GrantClientCredentials},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{AuthClientSecretBasic, AuthClientSecretPost, AuthNone},
		"id_token_signing_alg_values_supported": []string{p.algorithm},
		"subject_types_supported":               []string{"public"},
		"claims_supported": []string{"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce",
			"email", "email_verified", "name", "picture"},
		"claims_parameter_supported":                     false,
		"request_parameter_supported":                    false,
		"request_uri_parameter_supported":                false,
		"authorization_response_iss_parameter_supported": true,
		"dpop_signing_alg_values_supported":              []string{"ES256", "RS256"},
		"resource_indicators_supported":                  true,
		"introspection_endpoint_auth_methods_supported":  []string{AuthClientSecretBasic, AuthClientSecretPost},
		"revocation_endpoint_auth_methods_supported":     []string{AuthClientSecretBasic, AuthClientSecretPost},
		"require_pushed_authorization_requests":          false,
		"tls_client_certificate_bound_access_tokens":     false,
		"backchannel_logout_supported":                   false,
	}
	if p.dynamic {
		doc["registration_endpoint"] = p.issuer + PathRegister
	}
	if len(p.resources) > 0 {
		list := make([]string, 0, len(p.resources))
		for id := range p.resources {
			list = append(list, id)
		}
		doc["resource_indicators_endpoints_supported"] = list
	}
	return doc
}

// writeMetadata serves the two well-known documents. The handler answers the
// path-inserted location of RFC 8414 and the plain location, so a relying
// party that ignores the path insertion also finds the document.
func (p *Plugin) writeMetadata(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimSuffix(r.URL.Path, "/")
	known := ""
	switch {
	case strings.HasPrefix(path, "/.well-known/oauth-authorization-server"):
		known = strings.TrimPrefix(path, "/.well-known/oauth-authorization-server")
	case strings.HasPrefix(path, "/.well-known/openid-configuration"):
		known = strings.TrimPrefix(path, "/.well-known/openid-configuration")
	default:
		http.NotFound(w, r)
		return
	}
	base := strings.TrimSuffix(p.svc.BasePath(), "/")
	if known != "" && known != base {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	p.svc.HTTP().WriteJSON(w, http.StatusOK, p.metadata())
}
