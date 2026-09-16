package oauthprovider

import (
	"errors"
	"net/http"

	"github.com/google/uuid"

	"github.com/alternayte/auth-all/apierr"
	"github.com/alternayte/auth-all/store"
)

// requestDTO is what the host login page and the host consent page read. It
// names the client and what the client asks for, and it carries no token.
type requestDTO struct {
	RequestID   string   `json:"requestId"`
	ClientID    string   `json:"clientId"`
	ClientName  string   `json:"clientName"`
	LogoURI     string   `json:"logoUri,omitempty"`
	Scopes      []string `json:"scopes"`
	Resources   []string `json:"resources,omitempty"`
	FirstParty  bool     `json:"firstParty"`
	NeedsSignIn bool     `json:"needsSignIn"`
	// ConsentGranted reports that the user already granted the request, so the
	// page can post the decision without asking again.
	ConsentGranted bool `json:"consentGranted"`
}

// decisionDTO is the answer of the host consent page.
type decisionDTO struct {
	RequestID string `json:"requestId"`
	Approve   bool   `json:"approve"`
}

// decisionResultDTO carries the URL that returns the browser to the client.
type decisionResultDTO struct {
	RedirectTo string `json:"redirectTo"`
}

// consentDTO is one standing consent of the signed-in user.
type consentDTO struct {
	ClientID   string   `json:"clientId"`
	ClientName string   `json:"clientName"`
	Scopes     []string `json:"scopes"`
	Resources  []string `json:"resources,omitempty"`
}

// handleRequest returns the authorization request behind an identifier.
func (p *Plugin) handleRequest(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("request_id")
	if id == "" {
		p.svc.HTTP().WriteError(w, apierr.New(apierr.CodeOAuthRequestInvalid, http.StatusBadRequest,
			"The request identifier is missing."))
		return
	}
	row, err := p.rows.OAuthRequestByID(r.Context(), id)
	if err != nil || row.ConsumedAt != nil || !row.ExpiresAt.After(p.now()) {
		p.svc.HTTP().WriteError(w, apierr.New(apierr.CodeOAuthRequestInvalid, http.StatusNotFound,
			"The authorization request is unknown or spent."))
		return
	}
	c, err := p.lookupClient(r.Context(), row.ClientID)
	if err != nil {
		p.svc.HTTP().WriteError(w, apierr.New(apierr.CodeOAuthClientUnknown, http.StatusNotFound,
			"The client of the request is unknown."))
		return
	}
	_, user, err := p.svc.Sessions().Current(r.Context(), r)
	if err != nil {
		p.svc.HTTP().WriteError(w, apierr.ErrInternal)
		return
	}
	out := requestDTO{
		RequestID:   row.ID,
		ClientID:    c.ClientID,
		ClientName:  c.Name,
		LogoURI:     c.LogoURI,
		Scopes:      row.Scopes,
		Resources:   row.Resources,
		FirstParty:  c.Static,
		NeedsSignIn: user == nil,
	}
	if user != nil {
		out.ConsentGranted = !p.consentMissing(r.Context(), row, c, user)
	}
	p.svc.HTTP().WriteJSON(w, http.StatusOK, out)
}

// handleDecide records the decision of the user and returns the URL that
// carries the browser back to the client.
func (p *Plugin) handleDecide(w http.ResponseWriter, r *http.Request) {
	if err := p.svc.HTTP().CheckOrigin(r); err != nil {
		p.svc.HTTP().WriteError(w, err)
		return
	}
	var in decisionDTO
	if err := p.svc.HTTP().DecodeJSON(r, &in); err != nil {
		p.svc.HTTP().WriteError(w, err)
		return
	}
	if in.RequestID == "" {
		p.svc.HTTP().WriteError(w, apierr.New(apierr.CodeOAuthRequestInvalid, http.StatusBadRequest,
			"The request identifier is missing."))
		return
	}
	row, err := p.rows.OAuthRequestByID(r.Context(), in.RequestID)
	if err != nil || row.ConsumedAt != nil || !row.ExpiresAt.After(p.now()) {
		p.svc.HTTP().WriteError(w, apierr.New(apierr.CodeOAuthRequestInvalid, http.StatusNotFound,
			"The authorization request is unknown or spent."))
		return
	}
	session, user, err := p.svc.Sessions().Current(r.Context(), r)
	if err != nil || user == nil {
		p.svc.HTTP().WriteError(w, apierr.ErrUnauthorized)
		return
	}
	c, err := p.lookupClient(r.Context(), row.ClientID)
	if err != nil {
		p.svc.HTTP().WriteError(w, apierr.New(apierr.CodeOAuthClientUnknown, http.StatusNotFound,
			"The client of the request is unknown."))
		return
	}
	if !in.Approve {
		if _, err := p.rows.ConsumeOAuthRequest(r.Context(), row.ID, p.now()); err != nil {
			p.svc.HTTP().WriteError(w, apierr.New(apierr.CodeOAuthRequestInvalid, http.StatusNotFound,
				"The authorization request is unknown or spent."))
			return
		}
		target, err := redirectWith(row.RedirectURI, map[string]string{
			"error": errAccessDenied, "state": row.State, "iss": p.issuer,
		})
		if err != nil {
			p.svc.HTTP().WriteError(w, apierr.ErrInvalidRequest)
			return
		}
		p.svc.HTTP().WriteJSON(w, http.StatusOK, decisionResultDTO{RedirectTo: target})
		return
	}
	now := p.now()
	consent := &store.OAuthConsent{ID: uuid.NewString(), ClientID: c.ClientID, UserID: user.ID,
		Scopes: row.Scopes, Resources: row.Resources, CreatedAt: now, UpdatedAt: now}
	if !c.Static {
		if err := p.rows.UpsertOAuthConsent(r.Context(), consent); err != nil {
			p.svc.HTTP().WriteError(w, apierr.ErrInternal)
			return
		}
	}
	target, err := p.finishRequest(r.Context(), row, c, session, user)
	if err != nil {
		p.svc.HTTP().WriteError(w, apierr.New(apierr.CodeOAuthRequestInvalid, http.StatusBadRequest, err.Error()))
		return
	}
	p.svc.HTTP().WriteJSON(w, http.StatusOK, decisionResultDTO{RedirectTo: target})
}

// handleConsents lists the standing consents of the caller.
//
// The route runs behind the Auth-All authentication middleware, so it reads the
// principal. A session cookie and an access token of this server both reach it.
func (p *Plugin) handleConsents(w http.ResponseWriter, r *http.Request) {
	principal := p.currentPrincipal(r)
	if principal == nil {
		p.svc.HTTP().WriteError(w, apierr.ErrUnauthorized)
		return
	}
	user := principal.User
	rows, err := p.rows.ListOAuthConsents(r.Context(), user.ID)
	if err != nil {
		p.svc.HTTP().WriteError(w, apierr.ErrInternal)
		return
	}
	out := make([]consentDTO, 0, len(rows))
	for _, row := range rows {
		name := row.ClientID
		if c, err := p.lookupClient(r.Context(), row.ClientID); err == nil && c.Name != "" {
			name = c.Name
		}
		out = append(out, consentDTO{ClientID: row.ClientID, ClientName: name,
			Scopes: row.Scopes, Resources: row.Resources})
	}
	p.svc.HTTP().WriteJSON(w, http.StatusOK, map[string]any{"consents": out})
}

// handleWithdrawConsent removes one consent and revokes every grant behind it.
func (p *Plugin) handleWithdrawConsent(w http.ResponseWriter, r *http.Request) {
	if err := p.svc.HTTP().CheckOrigin(r); err != nil {
		p.svc.HTTP().WriteError(w, err)
		return
	}
	principal := p.currentPrincipal(r)
	if principal == nil {
		p.svc.HTTP().WriteError(w, apierr.ErrUnauthorized)
		return
	}
	user := principal.User
	clientID := r.PathValue("clientID")
	if clientID == "" {
		p.svc.HTTP().WriteError(w, apierr.New(apierr.CodeOAuthClientUnknown, http.StatusBadRequest,
			"The client identifier is missing."))
		return
	}
	if err := p.rows.DeleteOAuthConsent(r.Context(), user.ID, clientID); err != nil &&
		!errors.Is(err, store.ErrNotFound) {
		p.svc.HTTP().WriteError(w, apierr.ErrInternal)
		return
	}
	if err := p.rows.RevokeOAuthGrantsOfConsent(r.Context(), user.ID, clientID, p.now()); err != nil {
		p.svc.HTTP().WriteError(w, apierr.ErrInternal)
		return
	}
	p.svc.HTTP().WriteJSON(w, http.StatusOK, map[string]any{"withdrawn": true})
}
