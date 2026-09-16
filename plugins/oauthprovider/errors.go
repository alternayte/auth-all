package oauthprovider

import (
	"net/http"
	"net/url"
)

// The OAuth 2.0 error codes the server returns.
const (
	errInvalidRequest       = "invalid_request"
	errInvalidClient        = "invalid_client"
	errInvalidGrant         = "invalid_grant"
	errUnauthorizedClient   = "unauthorized_client"
	errUnsupportedGrantType = "unsupported_grant_type"
	errInvalidScope         = "invalid_scope"
	errInvalidTarget        = "invalid_target"
	errAccessDenied         = "access_denied"
	errServerError          = "server_error"
	errInvalidToken         = "invalid_token"
	errInvalidDPoPProof     = "invalid_dpop_proof"
	errInvalidRedirectURI   = "invalid_redirect_uri"
	errInvalidClientMeta    = "invalid_client_metadata"
	errUnsupportedResponse  = "unsupported_response_type"
	errLoginRequired        = "login_required"
	errConsentRequired      = "consent_required"
	errInteractionRequired  = "interaction_required"
)

// writeOAuthError writes the error object of RFC 6749 section 5.2.
func (p *Plugin) writeOAuthError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Cache-Control", "no-store")
	if code == errInvalidClient {
		// A client that failed authentication learns which scheme to use.
		w.Header().Set("WWW-Authenticate", `Basic realm="oauth", charset="UTF-8"`)
	}
	p.svc.HTTP().WriteJSON(w, status, map[string]string{
		"error":             code,
		"error_description": description,
	})
}

// redirectError returns the client to its redirect URI with the error. The
// state travels back unchanged, and the issuer identifier travels with it, so
// a client detects a mix-up of two authorization servers.
func (p *Plugin) redirectError(w http.ResponseWriter, r *http.Request, target, state, code, description string) {
	u, err := url.Parse(target)
	if err != nil {
		p.writeOAuthError(w, http.StatusBadRequest, errInvalidRequest, "the redirect URI is unusable")
		return
	}
	q := u.Query()
	q.Set("error", code)
	if description != "" {
		q.Set("error_description", description)
	}
	if state != "" {
		q.Set("state", state)
	}
	q.Set("iss", p.issuer)
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusSeeOther)
}
