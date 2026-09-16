package sqlstore

import (
	"context"
	"database/sql"
	"encoding/base64"
	"strings"
	"time"

	"github.com/alternayte/auth-all/store"
)

// The OAuth provider rows. A list column holds a space-separated list, so the
// shared SQL implementation needs no array type.

// joinList encodes a list column.
func joinList(v []string) string { return strings.Join(v, " ") }

// splitList decodes a list column.
func splitList(v string) []string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	return strings.Fields(v)
}

// listScan reads a list column into a string slice.
type listScan struct{ dst *[]string }

func (l listScan) Scan(src any) error {
	switch v := src.(type) {
	case nil:
		*l.dst = nil
	case string:
		*l.dst = splitList(v)
	case []byte:
		*l.dst = splitList(string(v))
	}
	return nil
}

// nullIntScan reads a nullable integer column into an int pointer.
type nullIntScan struct{ dst **int }

func (n nullIntScan) Scan(src any) error {
	if src == nil {
		*n.dst = nil
		return nil
	}
	var value sql.NullInt64
	if err := value.Scan(src); err != nil {
		return err
	}
	out := int(value.Int64)
	*n.dst = &out
	return nil
}

// nullInt returns the bound value of an optional integer column.
func nullInt(v *int) any {
	if v == nil {
		return nil
	}
	return *v
}

const oauthKeyColumns = "id, algorithm, wrapped_private, public_jwk, created_at, retired_at"

// CreateOAuthKey implements store.OAuthProviderStore.
func (s *Store) CreateOAuthKey(ctx context.Context, k *store.OAuthKey) error {
	_, err := s.exec(ctx,
		"INSERT INTO "+s.op.Keys+" ("+oauthKeyColumns+") VALUES (?, ?, ?, ?, ?, ?)",
		k.ID, k.Algorithm, base64.StdEncoding.EncodeToString(k.WrappedPrivate), k.PublicJWK,
		s.bindTime(k.CreatedAt), s.bindNullTime(k.RetiredAt))
	return s.mapErr(err)
}

// ListOAuthKeys implements store.OAuthProviderStore.
func (s *Store) ListOAuthKeys(ctx context.Context) ([]store.OAuthKey, error) {
	rows, err := s.query(ctx,
		"SELECT "+oauthKeyColumns+" FROM "+s.op.Keys+" ORDER BY created_at DESC, id DESC")
	if err != nil {
		return nil, s.mapErr(err)
	}
	defer rows.Close()
	var out []store.OAuthKey
	for rows.Next() {
		var m store.OAuthKey
		var wrapped string
		if err := rows.Scan(&m.ID, &m.Algorithm, &wrapped, &m.PublicJWK,
			timeScan{&m.CreatedAt}, nullTimeScan{&m.RetiredAt}); err != nil {
			return nil, s.mapErr(err)
		}
		raw, err := base64.StdEncoding.DecodeString(wrapped)
		if err != nil {
			return nil, err
		}
		m.WrappedPrivate = raw
		out = append(out, m)
	}
	return out, s.mapErr(rows.Err())
}

// RetireOAuthKeys implements store.OAuthProviderStore.
func (s *Store) RetireOAuthKeys(ctx context.Context, id string, at time.Time) error {
	_, err := s.exec(ctx,
		"UPDATE "+s.op.Keys+" SET retired_at = ? WHERE id <> ? AND retired_at IS NULL",
		s.bindTime(at), id)
	return s.mapErr(err)
}

const oauthClientColumns = "id, client_id, secret_hash, name, logo_uri, redirect_uris, grant_types, " +
	"scopes, token_endpoint_auth_method, dpop_required, owner_user_id, org_id, " +
	"registration_token_hash, created_at, updated_at"

func scanOAuthClient(m *store.OAuthClient) []any {
	return []any{&m.ID, &m.ClientID, &m.SecretHash, &m.Name, &m.LogoURI,
		listScan{&m.RedirectURIs}, listScan{&m.GrantTypes}, listScan{&m.Scopes},
		&m.TokenEndpointAuthMethod, &m.DPoPRequired, nullStringScan{&m.OwnerUserID},
		nullStringScan{&m.OrgID}, nullStringScan{&m.RegistrationTokenHash},
		timeScan{&m.CreatedAt}, timeScan{&m.UpdatedAt}}
}

// CreateOAuthClient implements store.OAuthProviderStore.
func (s *Store) CreateOAuthClient(ctx context.Context, c *store.OAuthClient) error {
	_, err := s.exec(ctx,
		"INSERT INTO "+s.op.Clients+" ("+oauthClientColumns+
			") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		c.ID, c.ClientID, c.SecretHash, c.Name, c.LogoURI, joinList(c.RedirectURIs),
		joinList(c.GrantTypes), joinList(c.Scopes), c.TokenEndpointAuthMethod, c.DPoPRequired,
		nullString(c.OwnerUserID), nullString(c.OrgID), nullString(c.RegistrationTokenHash),
		s.bindTime(c.CreatedAt), s.bindTime(c.UpdatedAt))
	return s.mapErr(err)
}

// OAuthClientByClientID implements store.OAuthProviderStore.
func (s *Store) OAuthClientByClientID(ctx context.Context, clientID string) (*store.OAuthClient, error) {
	row := s.queryRow(ctx,
		"SELECT "+oauthClientColumns+" FROM "+s.op.Clients+" WHERE client_id = ?", clientID)
	var m store.OAuthClient
	if err := row.Scan(scanOAuthClient(&m)...); err != nil {
		return nil, s.mapErr(err)
	}
	return &m, nil
}

// UpdateOAuthClient implements store.OAuthProviderStore.
func (s *Store) UpdateOAuthClient(ctx context.Context, c *store.OAuthClient) error {
	res, err := s.exec(ctx,
		"UPDATE "+s.op.Clients+" SET secret_hash = ?, name = ?, logo_uri = ?, redirect_uris = ?, "+
			"grant_types = ?, scopes = ?, token_endpoint_auth_method = ?, dpop_required = ?, "+
			"registration_token_hash = ?, updated_at = ? WHERE client_id = ?",
		c.SecretHash, c.Name, c.LogoURI, joinList(c.RedirectURIs), joinList(c.GrantTypes),
		joinList(c.Scopes), c.TokenEndpointAuthMethod, c.DPoPRequired,
		nullString(c.RegistrationTokenHash), s.bindTime(c.UpdatedAt), c.ClientID)
	if err != nil {
		return s.mapErr(err)
	}
	return requireAffected(res)
}

// DeleteOAuthClient implements store.OAuthProviderStore.
func (s *Store) DeleteOAuthClient(ctx context.Context, clientID string) error {
	res, err := s.exec(ctx, "DELETE FROM "+s.op.Clients+" WHERE client_id = ?", clientID)
	if err != nil {
		return s.mapErr(err)
	}
	return requireAffected(res)
}

// ListOAuthClients implements store.OAuthProviderStore.
func (s *Store) ListOAuthClients(ctx context.Context, ownerUserID string) ([]store.OAuthClient, error) {
	query := "SELECT " + oauthClientColumns + " FROM " + s.op.Clients + " ORDER BY created_at DESC, id DESC"
	args := []any{}
	if ownerUserID != "" {
		query = "SELECT " + oauthClientColumns + " FROM " + s.op.Clients +
			" WHERE owner_user_id = ? ORDER BY created_at DESC, id DESC"
		args = append(args, ownerUserID)
	}
	rows, err := s.query(ctx, query, args...)
	if err != nil {
		return nil, s.mapErr(err)
	}
	defer rows.Close()
	var out []store.OAuthClient
	for rows.Next() {
		var m store.OAuthClient
		if err := rows.Scan(scanOAuthClient(&m)...); err != nil {
			return nil, s.mapErr(err)
		}
		out = append(out, m)
	}
	return out, s.mapErr(rows.Err())
}

const oauthRequestColumns = "id, client_id, redirect_uri, scopes, resources, state, nonce, " +
	"code_challenge, code_challenge_method, prompt, max_age, dpop_jkt, created_at, expires_at, consumed_at"

func scanOAuthRequest(m *store.OAuthAuthorizationRequest) []any {
	return []any{&m.ID, &m.ClientID, &m.RedirectURI, listScan{&m.Scopes}, listScan{&m.Resources},
		&m.State, &m.Nonce, &m.CodeChallenge, &m.CodeChallengeMethod, listScan{&m.Prompt},
		nullIntScan{&m.MaxAge}, &m.DPoPJKT, timeScan{&m.CreatedAt}, timeScan{&m.ExpiresAt},
		nullTimeScan{&m.ConsumedAt}}
}

// CreateOAuthRequest implements store.OAuthProviderStore.
func (s *Store) CreateOAuthRequest(ctx context.Context, a *store.OAuthAuthorizationRequest) error {
	_, err := s.exec(ctx,
		"INSERT INTO "+s.op.Requests+" ("+oauthRequestColumns+
			") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		a.ID, a.ClientID, a.RedirectURI, joinList(a.Scopes), joinList(a.Resources), a.State,
		a.Nonce, a.CodeChallenge, a.CodeChallengeMethod, joinList(a.Prompt), nullInt(a.MaxAge), a.DPoPJKT,
		s.bindTime(a.CreatedAt), s.bindTime(a.ExpiresAt), s.bindNullTime(a.ConsumedAt))
	return s.mapErr(err)
}

// OAuthRequestByID implements store.OAuthProviderStore.
func (s *Store) OAuthRequestByID(ctx context.Context, id string) (*store.OAuthAuthorizationRequest, error) {
	row := s.queryRow(ctx, "SELECT "+oauthRequestColumns+" FROM "+s.op.Requests+" WHERE id = ?", id)
	var m store.OAuthAuthorizationRequest
	if err := row.Scan(scanOAuthRequest(&m)...); err != nil {
		return nil, s.mapErr(err)
	}
	return &m, nil
}

// ConsumeOAuthRequest implements store.OAuthProviderStore. The update carries
// the consumed test, so two concurrent calls produce at most one success.
func (s *Store) ConsumeOAuthRequest(ctx context.Context, id string, at time.Time) (*store.OAuthAuthorizationRequest, error) {
	res, err := s.exec(ctx,
		"UPDATE "+s.op.Requests+" SET consumed_at = ? WHERE id = ? AND consumed_at IS NULL AND expires_at > ?",
		s.bindTime(at), id, s.bindTime(at))
	if err != nil {
		return nil, s.mapErr(err)
	}
	if err := requireAffected(res); err != nil {
		return nil, err
	}
	return s.OAuthRequestByID(ctx, id)
}

const oauthGrantColumns = "id, client_id, user_id, scopes, resources, auth_time, session_id, created_at, revoked_at"

func scanOAuthGrant(m *store.OAuthGrant) []any {
	return []any{&m.ID, &m.ClientID, nullStringScan{&m.UserID}, listScan{&m.Scopes},
		listScan{&m.Resources}, nullTimeScan{&m.AuthTime}, nullStringScan{&m.SessionID},
		timeScan{&m.CreatedAt}, nullTimeScan{&m.RevokedAt}}
}

// CreateOAuthGrant implements store.OAuthProviderStore.
func (s *Store) CreateOAuthGrant(ctx context.Context, g *store.OAuthGrant) error {
	_, err := s.exec(ctx,
		"INSERT INTO "+s.op.Grants+" ("+oauthGrantColumns+") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
		g.ID, g.ClientID, nullString(g.UserID), joinList(g.Scopes), joinList(g.Resources),
		s.bindNullTime(g.AuthTime), nullString(g.SessionID), s.bindTime(g.CreatedAt),
		s.bindNullTime(g.RevokedAt))
	return s.mapErr(err)
}

// OAuthGrantByID implements store.OAuthProviderStore.
func (s *Store) OAuthGrantByID(ctx context.Context, id string) (*store.OAuthGrant, error) {
	row := s.queryRow(ctx, "SELECT "+oauthGrantColumns+" FROM "+s.op.Grants+" WHERE id = ?", id)
	var m store.OAuthGrant
	if err := row.Scan(scanOAuthGrant(&m)...); err != nil {
		return nil, s.mapErr(err)
	}
	return &m, nil
}

// revokeGrantRows revokes the grants that the condition selects, and every
// token of them.
func (s *Store) revokeGrantRows(ctx context.Context, where string, at time.Time, args ...any) error {
	selector := "SELECT id FROM " + s.op.Grants + " WHERE " + where
	for _, table := range []string{s.op.AccessTokens, s.op.RefreshTokens} {
		if _, err := s.exec(ctx,
			"UPDATE "+table+" SET revoked_at = ? WHERE revoked_at IS NULL AND grant_id IN ("+selector+")",
			append([]any{s.bindTime(at)}, args...)...); err != nil {
			return s.mapErr(err)
		}
	}
	_, err := s.exec(ctx,
		"UPDATE "+s.op.Grants+" SET revoked_at = ? WHERE revoked_at IS NULL AND "+where,
		append([]any{s.bindTime(at)}, args...)...)
	return s.mapErr(err)
}

// RevokeOAuthGrant implements store.OAuthProviderStore.
func (s *Store) RevokeOAuthGrant(ctx context.Context, id string, at time.Time) error {
	return s.revokeGrantRows(ctx, "id = ?", at, id)
}

// RevokeOAuthGrantsOfUser implements store.OAuthProviderStore.
func (s *Store) RevokeOAuthGrantsOfUser(ctx context.Context, userID string, at time.Time) error {
	return s.revokeGrantRows(ctx, "user_id = ?", at, userID)
}

// RevokeOAuthGrantsOfConsent implements store.OAuthProviderStore.
func (s *Store) RevokeOAuthGrantsOfConsent(ctx context.Context, userID, clientID string, at time.Time) error {
	return s.revokeGrantRows(ctx, "user_id = ? AND client_id = ?", at, userID, clientID)
}

const oauthCodeColumns = "id, code_hash, grant_id, client_id, redirect_uri, code_challenge, nonce, " +
	"scopes, resources, dpop_jkt, created_at, expires_at, consumed_at"

func scanOAuthCode(m *store.OAuthCode) []any {
	return []any{&m.ID, &m.CodeHash, &m.GrantID, &m.ClientID, &m.RedirectURI, &m.CodeChallenge,
		&m.Nonce, listScan{&m.Scopes}, listScan{&m.Resources}, &m.DPoPJKT,
		timeScan{&m.CreatedAt}, timeScan{&m.ExpiresAt}, nullTimeScan{&m.ConsumedAt}}
}

// CreateOAuthCode implements store.OAuthProviderStore.
func (s *Store) CreateOAuthCode(ctx context.Context, c *store.OAuthCode) error {
	_, err := s.exec(ctx,
		"INSERT INTO "+s.op.Codes+" ("+oauthCodeColumns+") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		c.ID, c.CodeHash, c.GrantID, c.ClientID, c.RedirectURI, c.CodeChallenge, c.Nonce,
		joinList(c.Scopes), joinList(c.Resources), c.DPoPJKT, s.bindTime(c.CreatedAt),
		s.bindTime(c.ExpiresAt), s.bindNullTime(c.ConsumedAt))
	return s.mapErr(err)
}

// OAuthCodeByHash implements store.OAuthProviderStore.
func (s *Store) OAuthCodeByHash(ctx context.Context, codeHash string) (*store.OAuthCode, error) {
	row := s.queryRow(ctx, "SELECT "+oauthCodeColumns+" FROM "+s.op.Codes+" WHERE code_hash = ?", codeHash)
	var m store.OAuthCode
	if err := row.Scan(scanOAuthCode(&m)...); err != nil {
		return nil, s.mapErr(err)
	}
	return &m, nil
}

// ConsumeOAuthCode implements store.OAuthProviderStore. Two concurrent calls
// for one code produce at most one success, so a replayed code reaches no
// second token.
func (s *Store) ConsumeOAuthCode(ctx context.Context, codeHash string, at time.Time) (*store.OAuthCode, error) {
	res, err := s.exec(ctx,
		"UPDATE "+s.op.Codes+" SET consumed_at = ? WHERE code_hash = ? AND consumed_at IS NULL AND expires_at > ?",
		s.bindTime(at), codeHash, s.bindTime(at))
	if err != nil {
		return nil, s.mapErr(err)
	}
	if err := requireAffected(res); err != nil {
		return nil, err
	}
	return s.OAuthCodeByHash(ctx, codeHash)
}

const oauthAccessTokenColumns = "id, grant_id, client_id, user_id, scopes, audience, jkt, " +
	"created_at, expires_at, revoked_at"

// CreateOAuthAccessToken implements store.OAuthProviderStore.
func (s *Store) CreateOAuthAccessToken(ctx context.Context, t *store.OAuthAccessToken) error {
	_, err := s.exec(ctx,
		"INSERT INTO "+s.op.AccessTokens+" ("+oauthAccessTokenColumns+
			") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		t.ID, t.GrantID, t.ClientID, nullString(t.UserID), joinList(t.Scopes), t.Audience, t.JKT,
		s.bindTime(t.CreatedAt), s.bindTime(t.ExpiresAt), s.bindNullTime(t.RevokedAt))
	return s.mapErr(err)
}

// OAuthAccessTokenByID implements store.OAuthProviderStore.
func (s *Store) OAuthAccessTokenByID(ctx context.Context, id string) (*store.OAuthAccessToken, error) {
	row := s.queryRow(ctx,
		"SELECT "+oauthAccessTokenColumns+" FROM "+s.op.AccessTokens+" WHERE id = ?", id)
	var m store.OAuthAccessToken
	if err := row.Scan(&m.ID, &m.GrantID, &m.ClientID, nullStringScan{&m.UserID},
		listScan{&m.Scopes}, &m.Audience, &m.JKT, timeScan{&m.CreatedAt},
		timeScan{&m.ExpiresAt}, nullTimeScan{&m.RevokedAt}); err != nil {
		return nil, s.mapErr(err)
	}
	return &m, nil
}

// RevokeOAuthAccessToken implements store.OAuthProviderStore.
func (s *Store) RevokeOAuthAccessToken(ctx context.Context, id string, at time.Time) error {
	_, err := s.exec(ctx,
		"UPDATE "+s.op.AccessTokens+" SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
		s.bindTime(at), id)
	return s.mapErr(err)
}

const oauthRefreshColumns = "id, token_hash, grant_id, client_id, user_id, scopes, resources, jkt, " +
	"created_at, expires_at, rotated_at, successor_id, revoked_at"

func scanOAuthRefresh(m *store.OAuthRefreshToken) []any {
	return []any{&m.ID, &m.TokenHash, &m.GrantID, &m.ClientID, nullStringScan{&m.UserID},
		listScan{&m.Scopes}, listScan{&m.Resources}, &m.JKT, timeScan{&m.CreatedAt},
		timeScan{&m.ExpiresAt}, nullTimeScan{&m.RotatedAt}, nullStringScan{&m.SuccessorID},
		nullTimeScan{&m.RevokedAt}}
}

// CreateOAuthRefreshToken implements store.OAuthProviderStore.
func (s *Store) CreateOAuthRefreshToken(ctx context.Context, t *store.OAuthRefreshToken) error {
	_, err := s.exec(ctx,
		"INSERT INTO "+s.op.RefreshTokens+" ("+oauthRefreshColumns+
			") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		t.ID, t.TokenHash, t.GrantID, t.ClientID, nullString(t.UserID), joinList(t.Scopes),
		joinList(t.Resources), t.JKT, s.bindTime(t.CreatedAt), s.bindTime(t.ExpiresAt),
		s.bindNullTime(t.RotatedAt), nullString(t.SuccessorID), s.bindNullTime(t.RevokedAt))
	return s.mapErr(err)
}

// OAuthRefreshTokenByHash implements store.OAuthProviderStore.
func (s *Store) OAuthRefreshTokenByHash(ctx context.Context, tokenHash string) (*store.OAuthRefreshToken, error) {
	row := s.queryRow(ctx,
		"SELECT "+oauthRefreshColumns+" FROM "+s.op.RefreshTokens+" WHERE token_hash = ?", tokenHash)
	var m store.OAuthRefreshToken
	if err := row.Scan(scanOAuthRefresh(&m)...); err != nil {
		return nil, s.mapErr(err)
	}
	return &m, nil
}

// OAuthRefreshTokenByID implements store.OAuthProviderStore.
func (s *Store) OAuthRefreshTokenByID(ctx context.Context, id string) (*store.OAuthRefreshToken, error) {
	row := s.queryRow(ctx,
		"SELECT "+oauthRefreshColumns+" FROM "+s.op.RefreshTokens+" WHERE id = ?", id)
	var m store.OAuthRefreshToken
	if err := row.Scan(scanOAuthRefresh(&m)...); err != nil {
		return nil, s.mapErr(err)
	}
	return &m, nil
}

// RotateOAuthRefreshToken implements store.OAuthProviderStore. The update
// carries the rotation test, so two concurrent rotations of one token produce
// at most one successor.
func (s *Store) RotateOAuthRefreshToken(ctx context.Context, id, successorID string, at time.Time) error {
	res, err := s.exec(ctx,
		"UPDATE "+s.op.RefreshTokens+" SET rotated_at = ?, successor_id = ? "+
			"WHERE id = ? AND rotated_at IS NULL AND revoked_at IS NULL",
		s.bindTime(at), successorID, id)
	if err != nil {
		return s.mapErr(err)
	}
	return requireAffected(res)
}

const oauthConsentColumns = "id, client_id, user_id, scopes, resources, created_at, updated_at"

func scanOAuthConsent(m *store.OAuthConsent) []any {
	return []any{&m.ID, &m.ClientID, &m.UserID, listScan{&m.Scopes}, listScan{&m.Resources},
		timeScan{&m.CreatedAt}, timeScan{&m.UpdatedAt}}
}

// UpsertOAuthConsent implements store.OAuthProviderStore.
func (s *Store) UpsertOAuthConsent(ctx context.Context, c *store.OAuthConsent) error {
	res, err := s.exec(ctx,
		"UPDATE "+s.op.Consents+" SET scopes = ?, resources = ?, updated_at = ? "+
			"WHERE user_id = ? AND client_id = ?",
		joinList(c.Scopes), joinList(c.Resources), s.bindTime(c.UpdatedAt), c.UserID, c.ClientID)
	if err != nil {
		return s.mapErr(err)
	}
	if requireAffected(res) == nil {
		return nil
	}
	_, err = s.exec(ctx,
		"INSERT INTO "+s.op.Consents+" ("+oauthConsentColumns+") VALUES (?, ?, ?, ?, ?, ?, ?)",
		c.ID, c.ClientID, c.UserID, joinList(c.Scopes), joinList(c.Resources),
		s.bindTime(c.CreatedAt), s.bindTime(c.UpdatedAt))
	return s.mapErr(err)
}

// OAuthConsent implements store.OAuthProviderStore.
func (s *Store) OAuthConsent(ctx context.Context, userID, clientID string) (*store.OAuthConsent, error) {
	row := s.queryRow(ctx,
		"SELECT "+oauthConsentColumns+" FROM "+s.op.Consents+" WHERE user_id = ? AND client_id = ?",
		userID, clientID)
	var m store.OAuthConsent
	if err := row.Scan(scanOAuthConsent(&m)...); err != nil {
		return nil, s.mapErr(err)
	}
	return &m, nil
}

// ListOAuthConsents implements store.OAuthProviderStore.
func (s *Store) ListOAuthConsents(ctx context.Context, userID string) ([]store.OAuthConsent, error) {
	rows, err := s.query(ctx,
		"SELECT "+oauthConsentColumns+" FROM "+s.op.Consents+
			" WHERE user_id = ? ORDER BY created_at DESC, id DESC", userID)
	if err != nil {
		return nil, s.mapErr(err)
	}
	defer rows.Close()
	var out []store.OAuthConsent
	for rows.Next() {
		var m store.OAuthConsent
		if err := rows.Scan(scanOAuthConsent(&m)...); err != nil {
			return nil, s.mapErr(err)
		}
		out = append(out, m)
	}
	return out, s.mapErr(rows.Err())
}

// DeleteOAuthConsent implements store.OAuthProviderStore.
func (s *Store) DeleteOAuthConsent(ctx context.Context, userID, clientID string) error {
	res, err := s.exec(ctx,
		"DELETE FROM "+s.op.Consents+" WHERE user_id = ? AND client_id = ?", userID, clientID)
	if err != nil {
		return s.mapErr(err)
	}
	return requireAffected(res)
}

// ClaimOAuthProof implements store.OAuthProviderStore. The primary key
// rejects a replay, because the second insert conflicts.
func (s *Store) ClaimOAuthProof(ctx context.Context, id string, expiresAt time.Time) error {
	_, err := s.exec(ctx, "INSERT INTO "+s.op.Proofs+" (id, expires_at) VALUES (?, ?)",
		id, s.bindTime(expiresAt))
	return s.mapErr(err)
}

// DeleteExpiredOAuthRows implements store.OAuthProviderStore.
func (s *Store) DeleteExpiredOAuthRows(ctx context.Context, before time.Time) (int, error) {
	total := 0
	for _, table := range []string{s.op.Requests, s.op.Codes, s.op.AccessTokens,
		s.op.RefreshTokens, s.op.Proofs} {
		res, err := s.exec(ctx, "DELETE FROM "+table+" WHERE expires_at < ?", s.bindTime(before))
		if err != nil {
			return total, s.mapErr(err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return total, err
		}
		total += int(n)
	}
	return total, nil
}
