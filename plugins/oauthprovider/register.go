package oauthprovider

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/alternayte/auth-all/apierr"
	"github.com/alternayte/auth-all/plugin"
	"github.com/alternayte/auth-all/store"
)

// registrationRequest is the client metadata of RFC 7591.
type registrationRequest struct {
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	Scope                   string   `json:"scope"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	LogoURI                 string   `json:"logo_uri"`
	DPoPBoundAccessTokens   bool     `json:"dpop_bound_access_tokens"`
}

// registrationResponse is the answer of RFC 7591 with the management fields of
// RFC 7592.
type registrationResponse struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientName              string   `json:"client_name,omitempty"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	Scope                   string   `json:"scope"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	LogoURI                 string   `json:"logo_uri,omitempty"`
	DPoPBoundAccessTokens   bool     `json:"dpop_bound_access_tokens"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
	RegistrationAccessToken string   `json:"registration_access_token,omitempty"`
	RegistrationClientURI   string   `json:"registration_client_uri,omitempty"`
}

// handleRegister serves RFC 7591 dynamic client registration.
func (p *Plugin) handleRegister(w http.ResponseWriter, r *http.Request) {
	if !p.dynamic {
		p.writeOAuthError(w, http.StatusForbidden, errInvalidClientMeta,
			"the server accepts no dynamic registration")
		return
	}
	var in registrationRequest
	if err := p.svc.HTTP().DecodeJSON(r, &in); err != nil {
		p.writeOAuthError(w, http.StatusBadRequest, errInvalidClientMeta, "the body is unreadable")
		return
	}
	row, secret, registrationToken, err := p.buildClient(r.Context(), in, nil, nil)
	if err != nil {
		p.writeOAuthError(w, http.StatusBadRequest, errInvalidRedirectURI, err.Error())
		return
	}
	if err := p.rows.CreateOAuthClient(r.Context(), row); err != nil {
		p.writeOAuthError(w, http.StatusInternalServerError, errServerError, "the client could not be stored")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	p.svc.HTTP().WriteJSON(w, http.StatusCreated,
		p.registrationBody(row, secret, registrationToken))
}

// buildClient validates the metadata and returns the row, the client secret,
// and the registration access token.
func (p *Plugin) buildClient(ctx context.Context, in registrationRequest,
	owner *string, org *string) (*store.OAuthClient, string, string, error) {
	grants := in.GrantTypes
	if len(grants) == 0 {
		grants = []string{GrantAuthorizationCode, GrantRefreshToken}
	}
	kept := make([]string, 0, len(grants))
	for _, g := range grants {
		switch g {
		case GrantAuthorizationCode, GrantRefreshToken, GrantClientCredentials:
			kept = append(kept, g)
		default:
			// An unsupported grant next to a supported one drops out, so a
			// client that asks for more than the server serves still
			// registers.
			continue
		}
	}
	if len(kept) == 0 {
		return nil, "", "", errors.New("the metadata names no supported grant type")
	}
	for _, rt := range in.ResponseTypes {
		if rt != "code" {
			return nil, "", "", errors.New("the server issues a code and nothing else")
		}
	}
	if hasGrant(kept, GrantAuthorizationCode) && len(in.RedirectURIs) == 0 {
		return nil, "", "", errors.New("the metadata names no redirect URI")
	}
	for _, uri := range in.RedirectURIs {
		if err := p.checkRedirectURI(uri); err != nil {
			return nil, "", "", err
		}
	}
	scopes := strings.Fields(in.Scope)
	if len(scopes) == 0 {
		scopes = p.scopes
	}
	for _, s := range scopes {
		if !p.knownScope(s) {
			return nil, "", "", errors.New("the server offers the scope " + s + " not")
		}
	}
	method := in.TokenEndpointAuthMethod
	switch method {
	case "":
		method = AuthClientSecretBasic
	case AuthClientSecretBasic, AuthClientSecretPost, AuthNone:
	default:
		return nil, "", "", errors.New("the server supports the authentication method not")
	}
	if method == AuthNone && hasGrant(kept, GrantClientCredentials) {
		return nil, "", "", errors.New("a public client runs no client credentials grant")
	}
	clientID, err := randomToken(16)
	if err != nil {
		return nil, "", "", err
	}
	secret := ""
	secretHash := ""
	if method != AuthNone {
		secret, err = randomToken(requestIDBytes)
		if err != nil {
			return nil, "", "", err
		}
		secretHash = digest(secret)
	}
	registrationToken := ""
	var tokenHash *string
	if owner == nil {
		registrationToken, err = randomToken(requestIDBytes)
		if err != nil {
			return nil, "", "", err
		}
		h := digest(registrationToken)
		tokenHash = &h
	}
	now := p.now()
	row := &store.OAuthClient{
		ID: uuid.NewString(), ClientID: clientID, SecretHash: secretHash,
		Name: in.ClientName, LogoURI: in.LogoURI, RedirectURIs: in.RedirectURIs,
		GrantTypes: kept, Scopes: scopes, TokenEndpointAuthMethod: method,
		DPoPRequired: in.DPoPBoundAccessTokens, OwnerUserID: owner, OrgID: org,
		RegistrationTokenHash: tokenHash, CreatedAt: now, UpdatedAt: now,
	}
	return row, secret, registrationToken, nil
}

// registrationBody returns the registration response of a client row.
func (p *Plugin) registrationBody(row *store.OAuthClient, secret, registrationToken string) registrationResponse {
	out := registrationResponse{
		ClientID: row.ClientID, ClientSecret: secret, ClientName: row.Name,
		RedirectURIs: row.RedirectURIs, GrantTypes: row.GrantTypes,
		ResponseTypes: []string{"code"}, Scope: strings.Join(row.Scopes, " "),
		TokenEndpointAuthMethod: row.TokenEndpointAuthMethod, LogoURI: row.LogoURI,
		DPoPBoundAccessTokens: row.DPoPRequired, ClientIDIssuedAt: row.CreatedAt.Unix(),
	}
	if registrationToken != "" {
		out.RegistrationAccessToken = registrationToken
		out.RegistrationClientURI = p.issuer + PathRegister + "/" + row.ClientID
	}
	return out
}

// clientFromRegistrationToken reads the client behind an RFC 7592 registration
// access token.
func (p *Plugin) clientFromRegistrationToken(ctx context.Context, r *http.Request,
	clientID string) (*store.OAuthClient, error) {
	scheme, token := bearerScheme(r.Header.Get("Authorization"))
	if scheme != "bearer" || token == "" {
		return nil, errors.New("the call carries no registration access token")
	}
	row, err := p.rows.OAuthClientByClientID(ctx, clientID)
	if err != nil {
		return nil, errors.New("the client is unknown")
	}
	if row.RegistrationTokenHash == nil || *row.RegistrationTokenHash != digest(token) {
		return nil, errors.New("the registration access token is wrong")
	}
	return row, nil
}

// handleReadClient serves the RFC 7592 read of one client.
func (p *Plugin) handleReadClient(w http.ResponseWriter, r *http.Request) {
	row, err := p.clientFromRegistrationToken(r.Context(), r, r.PathValue("clientID"))
	if err != nil {
		p.writeOAuthError(w, http.StatusUnauthorized, errInvalidClient, err.Error())
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	p.svc.HTTP().WriteJSON(w, http.StatusOK, p.registrationBody(row, "", ""))
}

// handleUpdateClient serves the RFC 7592 update of one client.
func (p *Plugin) handleUpdateClient(w http.ResponseWriter, r *http.Request) {
	row, err := p.clientFromRegistrationToken(r.Context(), r, r.PathValue("clientID"))
	if err != nil {
		p.writeOAuthError(w, http.StatusUnauthorized, errInvalidClient, err.Error())
		return
	}
	var in registrationRequest
	if err := p.svc.HTTP().DecodeJSON(r, &in); err != nil {
		p.writeOAuthError(w, http.StatusBadRequest, errInvalidClientMeta, "the body is unreadable")
		return
	}
	updated, _, _, err := p.buildClient(r.Context(), in, row.OwnerUserID, row.OrgID)
	if err != nil {
		p.writeOAuthError(w, http.StatusBadRequest, errInvalidRedirectURI, err.Error())
		return
	}
	// The identifier, the secret, and the registration token survive an
	// update, so the client keeps its credentials.
	updated.ID = row.ID
	updated.ClientID = row.ClientID
	updated.SecretHash = row.SecretHash
	updated.RegistrationTokenHash = row.RegistrationTokenHash
	updated.CreatedAt = row.CreatedAt
	updated.UpdatedAt = p.now()
	if err := p.rows.UpdateOAuthClient(r.Context(), updated); err != nil {
		p.writeOAuthError(w, http.StatusInternalServerError, errServerError, "the client could not be stored")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	p.svc.HTTP().WriteJSON(w, http.StatusOK, p.registrationBody(updated, "", ""))
}

// handleDeleteClient serves the RFC 7592 delete of one client.
func (p *Plugin) handleDeleteClient(w http.ResponseWriter, r *http.Request) {
	row, err := p.clientFromRegistrationToken(r.Context(), r, r.PathValue("clientID"))
	if err != nil {
		p.writeOAuthError(w, http.StatusUnauthorized, errInvalidClient, err.Error())
		return
	}
	if err := p.rows.DeleteOAuthClient(r.Context(), row.ClientID); err != nil {
		p.writeOAuthError(w, http.StatusInternalServerError, errServerError, "the client could not be removed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// managedClientDTO is the shape of a client of the authenticated management
// route.
type managedClientDTO struct {
	ClientID     string   `json:"clientId"`
	ClientSecret string   `json:"clientSecret,omitempty"`
	Name         string   `json:"name"`
	RedirectURIs []string `json:"redirectUris"`
	GrantTypes   []string `json:"grantTypes"`
	Scopes       []string `json:"scopes"`
	AuthMethod   string   `json:"tokenEndpointAuthMethod"`
	DPoPRequired bool     `json:"dpopRequired"`
	CreatedAt    string   `json:"createdAt"`
}

// toManagedDTO returns the management shape of a client row.
func toManagedDTO(row *store.OAuthClient, secret string) managedClientDTO {
	return managedClientDTO{
		ClientID: row.ClientID, ClientSecret: secret, Name: row.Name,
		RedirectURIs: row.RedirectURIs, GrantTypes: row.GrantTypes, Scopes: row.Scopes,
		AuthMethod: row.TokenEndpointAuthMethod, DPoPRequired: row.DPoPRequired,
		CreatedAt: row.CreatedAt.UTC().Format(time.RFC3339),
	}
}

// handleCreateManagedClient registers a client for the signed-in caller.
func (p *Plugin) handleCreateManagedClient(w http.ResponseWriter, r *http.Request) {
	if err := p.svc.HTTP().CheckOrigin(r); err != nil {
		p.svc.HTTP().WriteError(w, err)
		return
	}
	principal := p.currentPrincipal(r)
	if principal == nil {
		p.svc.HTTP().WriteError(w, apierr.ErrUnauthorized)
		return
	}
	var in registrationRequest
	if err := p.svc.HTTP().DecodeJSON(r, &in); err != nil {
		p.svc.HTTP().WriteError(w, err)
		return
	}
	var org *string
	if principal.Organization != nil {
		org = &principal.Organization.ID
	}
	row, secret, _, err := p.buildClient(r.Context(), in, &principal.User.ID, org)
	if err != nil {
		p.svc.HTTP().WriteError(w, apierr.New(apierr.CodeInvalidRequest,
			http.StatusBadRequest, err.Error()))
		return
	}
	if err := p.rows.CreateOAuthClient(r.Context(), row); err != nil {
		p.svc.HTTP().WriteError(w, apierr.ErrInternal)
		return
	}
	p.svc.HTTP().WriteJSON(w, http.StatusCreated, toManagedDTO(row, secret))
}

// handleListManagedClients lists the clients of the signed-in caller.
func (p *Plugin) handleListManagedClients(w http.ResponseWriter, r *http.Request) {
	principal := p.currentPrincipal(r)
	if principal == nil {
		p.svc.HTTP().WriteError(w, apierr.ErrUnauthorized)
		return
	}
	rows, err := p.rows.ListOAuthClients(r.Context(), principal.User.ID)
	if err != nil {
		p.svc.HTTP().WriteError(w, apierr.ErrInternal)
		return
	}
	out := make([]managedClientDTO, 0, len(rows))
	for i := range rows {
		out = append(out, toManagedDTO(&rows[i], ""))
	}
	p.svc.HTTP().WriteJSON(w, http.StatusOK, map[string]any{"clients": out})
}

// handleDeleteManagedClient removes a client of the signed-in caller.
func (p *Plugin) handleDeleteManagedClient(w http.ResponseWriter, r *http.Request) {
	if err := p.svc.HTTP().CheckOrigin(r); err != nil {
		p.svc.HTTP().WriteError(w, err)
		return
	}
	principal := p.currentPrincipal(r)
	if principal == nil {
		p.svc.HTTP().WriteError(w, apierr.ErrUnauthorized)
		return
	}
	row, err := p.rows.OAuthClientByClientID(r.Context(), r.PathValue("clientID"))
	if err != nil || row.OwnerUserID == nil || *row.OwnerUserID != principal.User.ID {
		p.svc.HTTP().WriteError(w, apierr.New(apierr.CodeOAuthClientUnknown,
			http.StatusNotFound, "The client is unknown."))
		return
	}
	if err := p.rows.DeleteOAuthClient(r.Context(), row.ClientID); err != nil {
		p.svc.HTTP().WriteError(w, apierr.ErrInternal)
		return
	}
	p.svc.HTTP().WriteJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

// currentPrincipal returns the principal of a management request.
func (p *Plugin) currentPrincipal(r *http.Request) *plugin.Principal {
	if p.principals == nil {
		return nil
	}
	return p.principals.Current(r.Context())
}
