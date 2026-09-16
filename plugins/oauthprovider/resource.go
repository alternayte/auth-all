package oauthprovider

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/alternayte/auth-all/internal/jws"
	"github.com/alternayte/auth-all/plugin"
	"github.com/alternayte/auth-all/store"
)

// verifiedToken is one access token that passed verification.
type verifiedToken struct {
	Claims accessClaims
	Row    *store.OAuthAccessToken
}

// verifyAccessToken checks the signature, the issuer, the expiry, and the
// revocation record of an access token.
func (p *Plugin) verifyAccessToken(ctx context.Context, token string) (*verifiedToken, error) {
	header, _, err := jws.Parse(token)
	if err != nil {
		return nil, err
	}
	if header.Type != "at+jwt" {
		return nil, errors.New("authall/oauthprovider: the token is no access token")
	}
	pub, err := p.verifier(ctx, header.KeyID)
	if err != nil {
		return nil, err
	}
	payload, err := jws.Verify(token, pub)
	if err != nil {
		return nil, err
	}
	var claims accessClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}
	now := p.now()
	if claims.Issuer != p.issuer || claims.Expiry <= now.Unix() {
		return nil, errors.New("authall/oauthprovider: the token is expired or foreign")
	}
	row, err := p.rows.OAuthAccessTokenByID(ctx, claims.ID)
	if err != nil {
		return nil, err
	}
	if row.RevokedAt != nil {
		return nil, errors.New("authall/oauthprovider: the token is revoked")
	}
	grant, err := p.rows.OAuthGrantByID(ctx, row.GrantID)
	if err != nil || grant.RevokedAt != nil {
		return nil, errors.New("authall/oauthprovider: the grant is revoked")
	}
	return &verifiedToken{Claims: claims, Row: row}, nil
}

// presentedToken reads the access token of a resource request and reports the
// scheme it arrived with.
func presentedToken(r *http.Request) (scheme, token string) {
	return bearerScheme(r.Header.Get("Authorization"))
}

// authenticateResourceRequest verifies the access token of a request against
// the audience the caller expects.
func (p *Plugin) authenticateResourceRequest(r *http.Request, audience string) (*verifiedToken, error) {
	scheme, token := presentedToken(r)
	if token == "" || (scheme != "bearer" && scheme != "dpop") {
		return nil, errors.New("the request carries no access token")
	}
	verified, err := p.verifyAccessToken(r.Context(), token)
	if err != nil {
		return nil, errors.New("the access token is invalid")
	}
	if audience != "" && verified.Claims.Audience != audience {
		// A token minted for another resource server must not open this one.
		return nil, errors.New("the access token names another audience")
	}
	if verified.Row.JKT != "" {
		if scheme != "dpop" {
			return nil, errors.New("the token is bound to a key and arrives as a bearer token")
		}
		jkt, err := p.checkDPoP(r, token)
		if err != nil {
			return nil, err
		}
		if jkt != verified.Row.JKT {
			return nil, errors.New("the DPoP proof names another key")
		}
	} else if scheme == "dpop" {
		return nil, errors.New("the token is no DPoP token")
	}
	return verified, nil
}

// handleUserInfo serves the claims of the user behind an access token.
func (p *Plugin) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	verified, err := p.authenticateResourceRequest(r, p.issuer)
	if err != nil {
		p.writeResourceError(w, err.Error())
		return
	}
	if verified.Row.UserID == nil {
		p.writeResourceError(w, "the token names no user")
		return
	}
	if !contains(verified.Row.Scopes, ScopeOpenID) {
		p.writeResourceError(w, "the token carries no openid scope")
		return
	}
	user, err := p.svc.Users().ByID(r.Context(), *verified.Row.UserID)
	if err != nil {
		p.writeResourceError(w, "the user is unknown")
		return
	}
	p.svc.HTTP().WriteJSON(w, http.StatusOK, p.claimsOf(user, verified.Row.Scopes))
}

// claimsOf returns the userinfo claims a scope set grants.
//
// Every claim comes from a stored field. No claim is derived by parsing
// another claim, so a user with one name keeps one name.
func (p *Plugin) claimsOf(user *store.User, scopes []string) map[string]any {
	out := map[string]any{"sub": user.ID}
	if contains(scopes, ScopeEmail) {
		out["email"] = user.Email
		out["email_verified"] = user.EmailVerifiedAt != nil
	}
	if contains(scopes, ScopeProfile) {
		if user.DisplayName != "" {
			out["name"] = user.DisplayName
		}
		if user.ImageURL != "" {
			out["picture"] = user.ImageURL
		}
	}
	for _, m := range p.claimMappings {
		scope := m.Scope
		if scope == "" {
			scope = ScopeProfile
		}
		if !contains(scopes, scope) || user.Extra == nil {
			continue
		}
		if value, ok := user.Extra.Get(m.Field); ok && value != nil {
			out[m.Claim] = value
		}
	}
	if p.claims != nil {
		for name, value := range p.claims(user, scopes) {
			if reservedClaims[name] {
				continue
			}
			out[name] = value
		}
	}
	return out
}

// writeResourceError answers a protected resource request of RFC 6750 and RFC
// 9449.
func (p *Plugin) writeResourceError(w http.ResponseWriter, description string) {
	w.Header().Set("WWW-Authenticate",
		`Bearer error="invalid_token", error_description="`+description+`"`)
	p.writeOAuthError(w, http.StatusUnauthorized, errInvalidToken, description)
}

// handleIntrospect answers RFC 7662 for a client that holds a secret.
func (p *Plugin) handleIntrospect(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		p.writeOAuthError(w, http.StatusBadRequest, errInvalidRequest, "the form is unreadable")
		return
	}
	c, ok := p.authenticateClient(w, r)
	if !ok {
		return
	}
	if c.AuthMethod == AuthNone {
		p.writeOAuthError(w, http.StatusUnauthorized, errInvalidClient,
			"introspection needs a client secret")
		return
	}
	token := r.PostForm.Get("token")
	inactive := map[string]any{"active": false}
	if token == "" {
		p.svc.HTTP().WriteJSON(w, http.StatusOK, inactive)
		return
	}
	verified, err := p.verifyAccessToken(r.Context(), token)
	if err != nil {
		// The value can be a refresh token. The client learns nothing about a
		// token of another client either way.
		row, refreshErr := p.rows.OAuthRefreshTokenByHash(r.Context(), digest(token))
		if refreshErr != nil || row.ClientID != c.ClientID || row.RevokedAt != nil ||
			row.RotatedAt != nil || !row.ExpiresAt.After(p.now()) {
			p.svc.HTTP().WriteJSON(w, http.StatusOK, inactive)
			return
		}
		p.svc.HTTP().WriteJSON(w, http.StatusOK, map[string]any{
			"active": true, "client_id": row.ClientID, "scope": strings.Join(row.Scopes, " "),
			"exp": row.ExpiresAt.Unix(), "token_type": "refresh_token",
		})
		return
	}
	if verified.Claims.ClientID != c.ClientID {
		p.svc.HTTP().WriteJSON(w, http.StatusOK, inactive)
		return
	}
	body := map[string]any{
		"active": true, "client_id": verified.Claims.ClientID, "scope": verified.Claims.Scope,
		"sub": verified.Claims.Subject, "aud": verified.Claims.Audience,
		"exp": verified.Claims.Expiry, "iat": verified.Claims.IssuedAt,
		"iss": verified.Claims.Issuer, "jti": verified.Claims.ID,
		"token_type": tokenType(verified.Row.JKT),
	}
	if verified.Row.JKT != "" {
		body["cnf"] = map[string]any{"jkt": verified.Row.JKT}
	}
	p.svc.HTTP().WriteJSON(w, http.StatusOK, body)
}

// handleRevoke answers RFC 7009. A revoked refresh token takes its grant with
// it, because the client asked to end the authorization.
func (p *Plugin) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		p.writeOAuthError(w, http.StatusBadRequest, errInvalidRequest, "the form is unreadable")
		return
	}
	c, ok := p.authenticateClient(w, r)
	if !ok {
		return
	}
	token := r.PostForm.Get("token")
	if token == "" {
		// RFC 7009 asks for 200 on an unknown token.
		p.svc.HTTP().WriteJSON(w, http.StatusOK, map[string]any{"revoked": true})
		return
	}
	now := p.now()
	if row, err := p.rows.OAuthRefreshTokenByHash(r.Context(), digest(token)); err == nil {
		if row.ClientID == c.ClientID {
			_ = p.rows.RevokeOAuthGrant(r.Context(), row.GrantID, now)
		}
		p.svc.HTTP().WriteJSON(w, http.StatusOK, map[string]any{"revoked": true})
		return
	}
	if verified, err := p.verifyAccessToken(r.Context(), token); err == nil {
		if verified.Claims.ClientID == c.ClientID {
			_ = p.rows.RevokeOAuthAccessToken(r.Context(), verified.Claims.ID, now)
		}
	}
	p.svc.HTTP().WriteJSON(w, http.StatusOK, map[string]any{"revoked": true})
}

// Claims implements plugin.CredentialResolver. It looks at the shape of the
// value only, so the check makes no database call. An access token of this
// server is a compact JWS with the at+jwt type.
func (p *Plugin) Claims(bearer string) bool {
	header, _, err := jws.Parse(bearer)
	if err != nil {
		return false
	}
	return header.Type == "at+jwt"
}

// Resolve implements plugin.CredentialResolver.
//
// The resolver accepts a token whose audience is the issuer itself, and it
// rejects a token that names another resource server. Without that test, a
// token a third-party relying party holds would open the host API.
func (p *Plugin) Resolve(ctx context.Context, bearer string) (*plugin.Principal, error) {
	verified, err := p.verifyAccessToken(ctx, bearer)
	if err != nil {
		return nil, err
	}
	if verified.Claims.Audience != p.issuer {
		return nil, errors.New("authall/oauthprovider: the token names another resource server")
	}
	if verified.Row.JKT != "" {
		// A bound token proves possession of its key, and that proof lives in
		// the request. ResolveRequest reads it.
		return nil, errors.New("authall/oauthprovider: the bound token needs a DPoP proof")
	}
	if verified.Row.UserID == nil {
		return nil, errors.New("authall/oauthprovider: the token names no user")
	}
	user, err := p.svc.Users().ByID(ctx, *verified.Row.UserID)
	if err != nil {
		return nil, err
	}
	if user.DisabledAt != nil {
		return nil, errors.New("authall/oauthprovider: the user is disabled")
	}
	return &plugin.Principal{User: user, Role: user.Role, Method: ID}, nil
}

// ResolveRequest implements plugin.RequestResolver. It enforces the DPoP proof
// of a bound token, which the bearer value alone cannot carry.
func (p *Plugin) ResolveRequest(ctx context.Context, bearer string, r *http.Request) (*plugin.Principal, error) {
	verified, err := p.authenticateResourceRequest(r, p.issuer)
	if err != nil {
		return nil, err
	}
	if verified.Row.UserID == nil {
		return nil, errors.New("authall/oauthprovider: the token names no user")
	}
	user, err := p.svc.Users().ByID(ctx, *verified.Row.UserID)
	if err != nil {
		return nil, err
	}
	if user.DisabledAt != nil {
		return nil, errors.New("authall/oauthprovider: the user is disabled")
	}
	return &plugin.Principal{User: user, Role: user.Role, Method: ID}, nil
}

// cleanupWindow is the age at which the host may delete spent rows.
const cleanupWindow = time.Hour

// Cleanup removes the spent and expired rows of the plugin. The host calls it,
// because Auth-All runs no background work of its own.
func (p *Plugin) Cleanup(ctx context.Context) (int, error) {
	return p.rows.DeleteExpiredOAuthRows(ctx, p.now().Add(-cleanupWindow))
}
