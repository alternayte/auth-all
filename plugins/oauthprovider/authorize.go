package oauthprovider

import (
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/alternayte/auth-all/internal/jws"
	"github.com/alternayte/auth-all/store"
)

// requestIDBytes is the entropy of one authorization request identifier.
const requestIDBytes = 32

// randomToken returns a base64url value with the given entropy.
func randomToken(size int) (string, error) {
	raw := make([]byte, size)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return jws.Encode(raw), nil
}

// handleAuthorize starts the authorization code flow.
//
// The route validates the request, writes it as a row, and redirects to the
// host login page or the host consent page with the identifier of that row.
// Nothing of the request travels in the redirect, so the URL leaks nothing
// through the browser history or a Referer header.
func (p *Plugin) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	if clientID == "" {
		p.writeOAuthError(w, http.StatusBadRequest, errInvalidRequest, "the request names no client")
		return
	}
	c, err := p.lookupClient(r.Context(), clientID)
	if err != nil {
		if errors.Is(err, errUnknownClient) {
			p.writeOAuthError(w, http.StatusBadRequest, errInvalidClient, "the client is unknown")
			return
		}
		p.writeOAuthError(w, http.StatusInternalServerError, errServerError, "the client read failed")
		return
	}
	// The redirect URI is validated before anything else redirects, because an
	// unvalidated URI must never receive an error.
	redirectURI := q.Get("redirect_uri")
	if redirectURI == "" {
		p.writeOAuthError(w, http.StatusBadRequest, errInvalidRequest, "the request names no redirect URI")
		return
	}
	matched, err := c.matchRedirectURI(redirectURI)
	if err != nil {
		p.writeOAuthError(w, http.StatusBadRequest, errInvalidRequest, err.Error())
		return
	}
	state := q.Get("state")
	if !c.allowsGrant(GrantAuthorizationCode) {
		p.redirectError(w, r, matched, state, errUnauthorizedClient,
			"the client holds no authorization code grant")
		return
	}
	if q.Get("response_type") != "code" {
		p.redirectError(w, r, matched, state, errUnsupportedResponse,
			"the server issues a code and nothing else")
		return
	}
	if q.Get("request") != "" || q.Get("request_uri") != "" {
		p.redirectError(w, r, matched, state, errInvalidRequest,
			"the server reads no request object")
		return
	}
	challenge := q.Get("code_challenge")
	if challenge == "" {
		p.redirectError(w, r, matched, state, errInvalidRequest, "the request carries no PKCE challenge")
		return
	}
	if q.Get("code_challenge_method") != "S256" {
		p.redirectError(w, r, matched, state, errInvalidRequest, "the PKCE method must be S256")
		return
	}
	scopes, err := p.requestedScopes(q.Get("scope"), c)
	if err != nil {
		p.redirectError(w, r, matched, state, errInvalidScope, err.Error())
		return
	}
	resources, err := p.requestedResources(q["resource"], scopes)
	if err != nil {
		p.redirectError(w, r, matched, state, errInvalidTarget, err.Error())
		return
	}
	var maxAge *int
	if raw := q.Get("max_age"); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil || v < 0 {
			p.redirectError(w, r, matched, state, errInvalidRequest, "the max age is no whole number")
			return
		}
		maxAge = &v
	}
	id, err := randomToken(requestIDBytes)
	if err != nil {
		p.redirectError(w, r, matched, state, errServerError, "the request identifier failed")
		return
	}
	now := p.now()
	row := &store.OAuthAuthorizationRequest{
		ID:                  id,
		ClientID:            c.ClientID,
		RedirectURI:         matched,
		Scopes:              scopes,
		Resources:           resources,
		State:               state,
		Nonce:               q.Get("nonce"),
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		Prompt:              strings.Fields(q.Get("prompt")),
		MaxAge:              maxAge,
		DPoPJKT:             q.Get("dpop_jkt"),
		CreatedAt:           now,
		ExpiresAt:           now.Add(p.requestTTL),
	}
	if err := p.rows.CreateOAuthRequest(r.Context(), row); err != nil {
		p.redirectError(w, r, matched, state, errServerError, "the request could not be stored")
		return
	}
	p.continueRequest(w, r, row, c)
}

// continueRequest sends the browser to the page the request needs next.
func (p *Plugin) continueRequest(w http.ResponseWriter, r *http.Request,
	row *store.OAuthAuthorizationRequest, c client) {
	session, user, err := p.svc.Sessions().Current(r.Context(), r)
	if err != nil {
		p.redirectError(w, r, row.RedirectURI, row.State, errServerError, "the session read failed")
		return
	}
	prompts := map[string]bool{}
	for _, v := range row.Prompt {
		prompts[v] = true
	}
	if prompts["none"] && (user == nil || p.consentMissing(r.Context(), row, c, user)) {
		code := errLoginRequired
		if user != nil {
			code = errConsentRequired
		}
		p.redirectError(w, r, row.RedirectURI, row.State, code, "the request needs interaction")
		return
	}
	if user == nil || prompts["login"] || p.tooOld(row, session) {
		http.Redirect(w, r, p.pageURL(p.loginPath, row.ID), http.StatusSeeOther)
		return
	}
	if prompts["consent"] || p.consentMissing(r.Context(), row, c, user) {
		http.Redirect(w, r, p.pageURL(p.consentPath, row.ID), http.StatusSeeOther)
		return
	}
	p.completeRequest(w, r, row, c, session, user)
}

// tooOld reports whether the session authenticated the user longer ago than
// the max age of the request.
func (p *Plugin) tooOld(row *store.OAuthAuthorizationRequest, session *store.Session) bool {
	if row.MaxAge == nil || session == nil {
		return false
	}
	return p.now().Sub(session.CreatedAt) > time.Duration(*row.MaxAge)*time.Second
}

// consentMissing reports whether the user must see the consent page. A static
// first-party client never needs it, because host source already decided.
func (p *Plugin) consentMissing(ctx context.Context, row *store.OAuthAuthorizationRequest,
	c client, user *store.User) bool {
	if c.Static {
		return false
	}
	consent, err := p.rows.OAuthConsent(ctx, user.ID, c.ClientID)
	if err != nil {
		return true
	}
	return !covers(consent.Scopes, row.Scopes) || !covers(consent.Resources, row.Resources)
}

// covers reports whether granted holds every wanted value.
func covers(granted, wanted []string) bool {
	have := map[string]bool{}
	for _, g := range granted {
		have[g] = true
	}
	for _, w := range wanted {
		if !have[w] {
			return false
		}
	}
	return true
}

// pageURL returns the host page with the request identifier.
func (p *Plugin) pageURL(path, requestID string) string {
	target := path
	if !strings.HasPrefix(path, "http") {
		target = strings.TrimRight(p.svc.BaseURL(), "/") + path
	}
	u, err := url.Parse(target)
	if err != nil {
		return path
	}
	q := u.Query()
	q.Set("request_id", requestID)
	u.RawQuery = q.Encode()
	return u.String()
}

// completeRequest issues the code and returns the browser to the client.
func (p *Plugin) completeRequest(w http.ResponseWriter, r *http.Request,
	row *store.OAuthAuthorizationRequest, c client, session *store.Session, user *store.User) {
	target, err := p.finishRequest(r.Context(), row, c, session, user)
	if err != nil {
		p.redirectError(w, r, row.RedirectURI, row.State, errServerError, err.Error())
		return
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

// finishRequest consumes the authorization request, issues the grant and the
// code, and returns the URL that carries the browser back to the client.
func (p *Plugin) finishRequest(ctx context.Context, row *store.OAuthAuthorizationRequest,
	c client, session *store.Session, user *store.User) (string, error) {
	consumed, err := p.rows.ConsumeOAuthRequest(ctx, row.ID, p.now())
	if err != nil {
		return "", errors.New("the authorization request is spent")
	}
	now := p.now()
	authTime := session.CreatedAt
	grant := &store.OAuthGrant{
		ID:        uuid.NewString(),
		ClientID:  c.ClientID,
		UserID:    &user.ID,
		Scopes:    consumed.Scopes,
		Resources: consumed.Resources,
		AuthTime:  &authTime,
		SessionID: &session.ID,
		CreatedAt: now,
	}
	if err := p.rows.CreateOAuthGrant(ctx, grant); err != nil {
		return "", errors.New("the grant failed")
	}
	code, err := randomToken(requestIDBytes)
	if err != nil {
		return "", errors.New("the code failed")
	}
	codeRow := &store.OAuthCode{
		ID:            uuid.NewString(),
		CodeHash:      digest(code),
		GrantID:       grant.ID,
		ClientID:      c.ClientID,
		RedirectURI:   consumed.RedirectURI,
		CodeChallenge: consumed.CodeChallenge,
		Nonce:         consumed.Nonce,
		Scopes:        consumed.Scopes,
		Resources:     consumed.Resources,
		DPoPJKT:       consumed.DPoPJKT,
		CreatedAt:     now,
		ExpiresAt:     now.Add(p.codeTTL),
	}
	if err := p.rows.CreateOAuthCode(ctx, codeRow); err != nil {
		return "", errors.New("the code could not be stored")
	}
	return redirectWith(consumed.RedirectURI, map[string]string{
		"code": code, "state": consumed.State, "iss": p.issuer,
	})
}

// redirectWith returns the redirect URI with the added query values. An empty
// value adds no parameter.
func redirectWith(target string, values map[string]string) (string, error) {
	u, err := url.Parse(target)
	if err != nil {
		return "", errors.New("the redirect URI is unusable")
	}
	q := u.Query()
	for k, v := range values {
		if v != "" {
			q.Set(k, v)
		}
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// requestedScopes returns the scopes of a request. An unknown scope and a
// scope the client may not ask for both fail.
func (p *Plugin) requestedScopes(raw string, c client) ([]string, error) {
	wanted := strings.Fields(raw)
	if len(wanted) == 0 {
		return nil, errors.New("the request names no scope")
	}
	allowed := map[string]bool{}
	for _, s := range c.Scopes {
		allowed[s] = true
	}
	out := make([]string, 0, len(wanted))
	seen := map[string]bool{}
	for _, s := range wanted {
		if !p.knownScope(s) {
			return nil, errors.New("the server offers the scope " + s + " not")
		}
		if !allowed[s] {
			return nil, errors.New("the client may not ask for the scope " + s)
		}
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out, nil
}

// requestedResources returns the resource indicators of a request. Every
// indicator must be declared, and it must allow every requested scope.
func (p *Plugin) requestedResources(values []string, scopes []string) ([]string, error) {
	out := make([]string, 0, len(values))
	seen := map[string]bool{}
	for _, v := range values {
		res, ok := p.resources[v]
		if !ok {
			return nil, errors.New("the resource " + v + " is not declared")
		}
		if len(res.Scopes) > 0 && !covers(res.Scopes, scopes) {
			return nil, errors.New("the resource " + v + " allows the requested scopes not")
		}
		if seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	if len(out) > 1 {
		// One access token carries one audience, so a request that names two
		// resources would produce a token for the wrong one.
		return nil, errors.New("one request names one resource")
	}
	return out, nil
}
