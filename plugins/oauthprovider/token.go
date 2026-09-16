package oauthprovider

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/alternayte/auth-all/internal/jws"
	"github.com/alternayte/auth-all/store"
)

// tokenResponse is the answer of the token endpoint.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope"`
}

// accessClaims are the claims of an RFC 9068 access token.
type accessClaims struct {
	Issuer    string         `json:"iss"`
	Subject   string         `json:"sub"`
	Audience  string         `json:"aud"`
	ClientID  string         `json:"client_id"`
	Scope     string         `json:"scope"`
	IssuedAt  int64          `json:"iat"`
	Expiry    int64          `json:"exp"`
	ID        string         `json:"jti"`
	AuthTime  int64          `json:"auth_time,omitempty"`
	Confirm   map[string]any `json:"cnf,omitempty"`
	GrantID   string         `json:"grant_id"`
	TokenType string         `json:"token_use,omitempty"`
}

// idClaims are the claims of an ID token. The ID token carries the
// authentication claims and nothing else, because OIDC Core section 5.4 puts
// the scope-granted claims at the userinfo route.
type idClaims struct {
	Issuer   string `json:"iss"`
	Subject  string `json:"sub"`
	Audience string `json:"aud"`
	IssuedAt int64  `json:"iat"`
	Expiry   int64  `json:"exp"`
	AuthTime int64  `json:"auth_time,omitempty"`
	Nonce    string `json:"nonce,omitempty"`
}

// handleToken serves the token endpoint.
func (p *Plugin) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		p.writeOAuthError(w, http.StatusBadRequest, errInvalidRequest, "the form is unreadable")
		return
	}
	c, ok := p.authenticateClient(w, r)
	if !ok {
		return
	}
	// A DPoP proof binds every token of this call. The token endpoint proof
	// carries no ath claim, because no access token exists yet.
	jkt := ""
	if proof, err := p.checkDPoP(r, ""); err == nil {
		jkt = proof
	} else if !errors.Is(err, errNoProof) {
		p.writeOAuthError(w, http.StatusBadRequest, errInvalidDPoPProof, err.Error())
		return
	}
	if c.DPoPRequired && jkt == "" {
		p.writeOAuthError(w, http.StatusBadRequest, errInvalidDPoPProof,
			"the client must present a DPoP proof")
		return
	}
	switch r.PostForm.Get("grant_type") {
	case GrantAuthorizationCode:
		p.tokenFromCode(w, r, c, jkt)
	case GrantRefreshToken:
		p.tokenFromRefresh(w, r, c, jkt)
	case GrantClientCredentials:
		p.tokenFromClientCredentials(w, r, c, jkt)
	default:
		p.writeOAuthError(w, http.StatusBadRequest, errUnsupportedGrantType,
			"the server serves the authorization code, the refresh token, and the client credentials grant")
	}
}

// authenticateClient reads and verifies the client credentials of a token
// call. It writes the error itself and reports whether the caller continues.
func (p *Plugin) authenticateClient(w http.ResponseWriter, r *http.Request) (client, bool) {
	clientID, secret, hasBasic := r.BasicAuth()
	if !hasBasic {
		clientID = r.PostForm.Get("client_id")
		secret = r.PostForm.Get("client_secret")
	}
	if clientID == "" {
		p.writeOAuthError(w, http.StatusUnauthorized, errInvalidClient, "the call names no client")
		return client{}, false
	}
	c, err := p.lookupClient(r.Context(), clientID)
	if err != nil {
		// An unknown client is an authentication failure, so a client that
		// lost its registration learns to register again.
		p.writeOAuthError(w, http.StatusUnauthorized, errInvalidClient, "the client is unknown")
		return client{}, false
	}
	if c.AuthMethod == AuthNone {
		if secret != "" {
			p.writeOAuthError(w, http.StatusUnauthorized, errInvalidClient,
				"the client is public and presents a secret")
			return client{}, false
		}
		return c, true
	}
	if c.AuthMethod == AuthClientSecretBasic && !hasBasic {
		p.writeOAuthError(w, http.StatusUnauthorized, errInvalidClient,
			"the client authenticates with the Basic scheme")
		return client{}, false
	}
	if c.AuthMethod == AuthClientSecretPost && hasBasic {
		p.writeOAuthError(w, http.StatusUnauthorized, errInvalidClient,
			"the client authenticates in the request body")
		return client{}, false
	}
	if !c.secretMatches(secret) {
		p.writeOAuthError(w, http.StatusUnauthorized, errInvalidClient, "the client secret is wrong")
		return client{}, false
	}
	return c, true
}

// tokenFromCode exchanges an authorization code.
func (p *Plugin) tokenFromCode(w http.ResponseWriter, r *http.Request, c client, jkt string) {
	if !c.allowsGrant(GrantAuthorizationCode) {
		p.writeOAuthError(w, http.StatusBadRequest, errUnauthorizedClient,
			"the client holds no authorization code grant")
		return
	}
	code := r.PostForm.Get("code")
	verifier := r.PostForm.Get("code_verifier")
	if code == "" || verifier == "" {
		p.writeOAuthError(w, http.StatusBadRequest, errInvalidRequest,
			"the call needs the code and the PKCE verifier")
		return
	}
	row, err := p.rows.ConsumeOAuthCode(r.Context(), digest(code), p.now())
	if err != nil {
		p.writeOAuthError(w, http.StatusBadRequest, errInvalidGrant, "the code is spent or unknown")
		return
	}
	if row.ClientID != c.ClientID {
		// The code belongs to another client. Its grant dies, because the code
		// leaked.
		_ = p.rows.RevokeOAuthGrant(r.Context(), row.GrantID, p.now())
		p.writeOAuthError(w, http.StatusBadRequest, errInvalidGrant, "the code belongs to another client")
		return
	}
	if redirect := r.PostForm.Get("redirect_uri"); redirect != row.RedirectURI {
		p.writeOAuthError(w, http.StatusBadRequest, errInvalidGrant,
			"the redirect URI differs from the authorize call")
		return
	}
	sum := sha256.Sum256([]byte(verifier))
	if jws.Encode(sum[:]) != row.CodeChallenge {
		p.writeOAuthError(w, http.StatusBadRequest, errInvalidGrant, "the PKCE verifier is wrong")
		return
	}
	if row.DPoPJKT != "" && row.DPoPJKT != jkt {
		p.writeOAuthError(w, http.StatusBadRequest, errInvalidDPoPProof,
			"the proof key differs from the authorize call")
		return
	}
	grant, err := p.rows.OAuthGrantByID(r.Context(), row.GrantID)
	if err != nil || grant.RevokedAt != nil {
		p.writeOAuthError(w, http.StatusBadRequest, errInvalidGrant, "the grant is revoked")
		return
	}
	p.issueTokens(w, r, c, grant, row.Scopes, row.Resources, row.Nonce, jkt)
}

// tokenFromRefresh rotates a refresh token.
//
// The rotated token stays valid inside the grace window and answers with the
// same successor, so a client that lost the response recovers. A presentation
// after the window revokes the whole grant, because that is theft.
func (p *Plugin) tokenFromRefresh(w http.ResponseWriter, r *http.Request, c client, jkt string) {
	if !c.allowsGrant(GrantRefreshToken) {
		p.writeOAuthError(w, http.StatusBadRequest, errUnauthorizedClient,
			"the client holds no refresh token grant")
		return
	}
	presented := r.PostForm.Get("refresh_token")
	if presented == "" {
		p.writeOAuthError(w, http.StatusBadRequest, errInvalidRequest, "the call names no refresh token")
		return
	}
	row, err := p.rows.OAuthRefreshTokenByHash(r.Context(), digest(presented))
	if err != nil {
		p.writeOAuthError(w, http.StatusBadRequest, errInvalidGrant, "the refresh token is unknown")
		return
	}
	now := p.now()
	if row.ClientID != c.ClientID {
		_ = p.rows.RevokeOAuthGrant(r.Context(), row.GrantID, now)
		p.writeOAuthError(w, http.StatusBadRequest, errInvalidGrant,
			"the refresh token belongs to another client")
		return
	}
	if row.RevokedAt != nil || !row.ExpiresAt.After(now) {
		p.writeOAuthError(w, http.StatusBadRequest, errInvalidGrant, "the refresh token is spent")
		return
	}
	if row.JKT != "" && row.JKT != jkt {
		p.writeOAuthError(w, http.StatusBadRequest, errInvalidDPoPProof,
			"the proof key differs from the issuing call")
		return
	}
	if row.RotatedAt != nil {
		if now.Sub(*row.RotatedAt) > p.rotationGrace || row.SuccessorID == nil {
			_ = p.rows.RevokeOAuthGrant(r.Context(), row.GrantID, now)
			p.writeOAuthError(w, http.StatusBadRequest, errInvalidGrant,
				"the refresh token is replayed")
			return
		}
		// The retry answers with the successor pair of the first call.
		p.replayRotation(w, r, c, row, jkt)
		return
	}
	grant, err := p.rows.OAuthGrantByID(r.Context(), row.GrantID)
	if err != nil || grant.RevokedAt != nil {
		p.writeOAuthError(w, http.StatusBadRequest, errInvalidGrant, "the grant is revoked")
		return
	}
	scopes := row.Scopes
	if raw := r.PostForm.Get("scope"); raw != "" {
		wanted := strings.Fields(raw)
		if !covers(row.Scopes, wanted) {
			p.writeOAuthError(w, http.StatusBadRequest, errInvalidScope,
				"a refresh widens no scope")
			return
		}
		scopes = wanted
	}
	resources := row.Resources
	if values := r.PostForm["resource"]; len(values) > 0 {
		narrowed, err := p.requestedResources(values, scopes)
		if err != nil {
			p.writeOAuthError(w, http.StatusBadRequest, errInvalidTarget, err.Error())
			return
		}
		if !covers(row.Resources, narrowed) {
			p.writeOAuthError(w, http.StatusBadRequest, errInvalidTarget,
				"a refresh names no other resource")
			return
		}
		resources = narrowed
	}
	successor := uuid.NewString()
	if err := p.rows.RotateOAuthRefreshToken(r.Context(), row.ID, successor, now); err != nil {
		p.writeOAuthError(w, http.StatusBadRequest, errInvalidGrant, "the refresh token is spent")
		return
	}
	p.issueTokensWithID(w, r, c, grant, scopes, resources, "", jkt, successor)
}

// replayRotation answers a retry inside the grace window with a fresh access
// token of the successor refresh token. The successor row answers the retry,
// so the server stores no response body.
func (p *Plugin) replayRotation(w http.ResponseWriter, r *http.Request, c client,
	row *store.OAuthRefreshToken, jkt string) {
	successor, err := p.rows.OAuthRefreshTokenByID(r.Context(), *row.SuccessorID)
	if err != nil || successor.RevokedAt != nil {
		p.writeOAuthError(w, http.StatusBadRequest, errInvalidGrant, "the refresh token is spent")
		return
	}
	grant, err := p.rows.OAuthGrantByID(r.Context(), successor.GrantID)
	if err != nil || grant.RevokedAt != nil {
		p.writeOAuthError(w, http.StatusBadRequest, errInvalidGrant, "the grant is revoked")
		return
	}
	access, expires, err := p.mintAccessToken(r.Context(), c, grant, successor.Scopes,
		successor.Resources, jkt)
	if err != nil {
		p.writeOAuthError(w, http.StatusInternalServerError, errServerError, "the token failed")
		return
	}
	p.writeTokenResponse(w, tokenResponse{
		AccessToken: access,
		TokenType:   tokenType(jkt),
		ExpiresIn:   int(expires.Sub(p.now()).Seconds()),
		Scope:       strings.Join(successor.Scopes, " "),
	})
}

// tokenFromClientCredentials issues a token that names the client itself.
func (p *Plugin) tokenFromClientCredentials(w http.ResponseWriter, r *http.Request, c client, jkt string) {
	if !c.allowsGrant(GrantClientCredentials) {
		p.writeOAuthError(w, http.StatusBadRequest, errUnauthorizedClient,
			"the client holds no client credentials grant")
		return
	}
	if c.AuthMethod == AuthNone {
		p.writeOAuthError(w, http.StatusUnauthorized, errInvalidClient,
			"a public client runs no client credentials grant")
		return
	}
	scopes, err := p.requestedScopes(r.PostForm.Get("scope"), c)
	if err != nil {
		p.writeOAuthError(w, http.StatusBadRequest, errInvalidScope, err.Error())
		return
	}
	for _, s := range scopes {
		if s == ScopeOpenID || s == ScopeOfflineAccess {
			p.writeOAuthError(w, http.StatusBadRequest, errInvalidScope,
				"a client credentials token carries no user scope")
			return
		}
	}
	resources, err := p.requestedResources(r.PostForm["resource"], scopes)
	if err != nil {
		p.writeOAuthError(w, http.StatusBadRequest, errInvalidTarget, err.Error())
		return
	}
	now := p.now()
	grant := &store.OAuthGrant{ID: uuid.NewString(), ClientID: c.ClientID, Scopes: scopes,
		Resources: resources, CreatedAt: now}
	if err := p.rows.CreateOAuthGrant(r.Context(), grant); err != nil {
		p.writeOAuthError(w, http.StatusInternalServerError, errServerError, "the grant failed")
		return
	}
	access, expires, err := p.mintAccessToken(r.Context(), c, grant, scopes, resources, jkt)
	if err != nil {
		p.writeOAuthError(w, http.StatusInternalServerError, errServerError, "the token failed")
		return
	}
	p.writeTokenResponse(w, tokenResponse{
		AccessToken: access,
		TokenType:   tokenType(jkt),
		ExpiresIn:   int(expires.Sub(now).Seconds()),
		Scope:       strings.Join(scopes, " "),
	})
}

// issueTokens issues the token set of a grant with a new refresh identifier.
func (p *Plugin) issueTokens(w http.ResponseWriter, r *http.Request, c client,
	grant *store.OAuthGrant, scopes, resources []string, nonce, jkt string) {
	p.issueTokensWithID(w, r, c, grant, scopes, resources, nonce, jkt, uuid.NewString())
}

// issueTokensWithID issues the access token, the refresh token, and the ID
// token of a grant.
func (p *Plugin) issueTokensWithID(w http.ResponseWriter, r *http.Request, c client,
	grant *store.OAuthGrant, scopes, resources []string, nonce, jkt, refreshID string) {
	now := p.now()
	access, expires, err := p.mintAccessToken(r.Context(), c, grant, scopes, resources, jkt)
	if err != nil {
		p.writeOAuthError(w, http.StatusInternalServerError, errServerError, "the token failed")
		return
	}
	out := tokenResponse{
		AccessToken: access,
		TokenType:   tokenType(jkt),
		ExpiresIn:   int(expires.Sub(now).Seconds()),
		Scope:       strings.Join(scopes, " "),
	}
	if contains(scopes, ScopeOfflineAccess) {
		plaintext, err := randomToken(requestIDBytes)
		if err != nil {
			p.writeOAuthError(w, http.StatusInternalServerError, errServerError, "the token failed")
			return
		}
		row := &store.OAuthRefreshToken{
			ID: refreshID, TokenHash: digest(plaintext), GrantID: grant.ID, ClientID: c.ClientID,
			UserID: grant.UserID, Scopes: scopes, Resources: resources, JKT: jkt,
			CreatedAt: now, ExpiresAt: now.Add(p.refreshTokenTTL),
		}
		if err := p.rows.CreateOAuthRefreshToken(r.Context(), row); err != nil {
			p.writeOAuthError(w, http.StatusInternalServerError, errServerError, "the token failed")
			return
		}
		out.RefreshToken = plaintext
	}
	if contains(scopes, ScopeOpenID) && grant.UserID != nil {
		id, err := p.mintIDToken(r.Context(), c, grant, nonce)
		if err != nil {
			p.writeOAuthError(w, http.StatusInternalServerError, errServerError, "the identity token failed")
			return
		}
		out.IDToken = id
	}
	p.writeTokenResponse(w, out)
}

// mintAccessToken signs one RFC 9068 access token and records its identifier.
//
// The token is always a signed JWT. The audience is the named resource, or the
// issuer itself, so the shape never varies and a resource server validates it
// offline.
func (p *Plugin) mintAccessToken(ctx context.Context, c client, grant *store.OAuthGrant,
	scopes, resources []string, jkt string) (string, time.Time, error) {
	key, err := p.signingKey(ctx)
	if err != nil {
		return "", time.Time{}, err
	}
	now := p.now()
	audience := p.issuer
	ttl := p.accessTokenTTL
	if len(resources) == 1 {
		audience = resources[0]
		if res, ok := p.resources[audience]; ok && res.AccessTokenTTL > 0 {
			ttl = res.AccessTokenTTL
		}
	}
	expires := now.Add(ttl)
	subject := c.ClientID
	if grant.UserID != nil {
		subject = *grant.UserID
	}
	claims := accessClaims{
		Issuer: p.issuer, Subject: subject, Audience: audience, ClientID: c.ClientID,
		Scope: strings.Join(scopes, " "), IssuedAt: now.Unix(), Expiry: expires.Unix(),
		ID: uuid.NewString(), GrantID: grant.ID,
	}
	if grant.AuthTime != nil {
		claims.AuthTime = grant.AuthTime.Unix()
	}
	if jkt != "" {
		claims.Confirm = map[string]any{"jkt": jkt}
	}
	token, err := key.Sign("at+jwt", claims)
	if err != nil {
		return "", time.Time{}, err
	}
	row := &store.OAuthAccessToken{ID: claims.ID, GrantID: grant.ID, ClientID: c.ClientID,
		UserID: grant.UserID, Scopes: scopes, Audience: audience, JKT: jkt,
		CreatedAt: now, ExpiresAt: expires}
	if err := p.rows.CreateOAuthAccessToken(ctx, row); err != nil {
		return "", time.Time{}, err
	}
	return token, expires, nil
}

// mintIDToken signs the identity token of a grant.
func (p *Plugin) mintIDToken(ctx context.Context, c client, grant *store.OAuthGrant,
	nonce string) (string, error) {
	key, err := p.signingKey(ctx)
	if err != nil {
		return "", err
	}
	now := p.now()
	claims := idClaims{Issuer: p.issuer, Subject: *grant.UserID, Audience: c.ClientID,
		IssuedAt: now.Unix(), Expiry: now.Add(p.accessTokenTTL).Unix(), Nonce: nonce}
	if grant.AuthTime != nil {
		claims.AuthTime = grant.AuthTime.Unix()
	}
	return key.Sign("JWT", claims)
}

// writeTokenResponse writes the token response with the headers RFC 6749 asks
// for.
func (p *Plugin) writeTokenResponse(w http.ResponseWriter, body tokenResponse) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	p.svc.HTTP().WriteJSON(w, http.StatusOK, body)
}

// tokenType names the presentation scheme of an issued token.
func tokenType(jkt string) string {
	if jkt != "" {
		return "DPoP"
	}
	return "Bearer"
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
