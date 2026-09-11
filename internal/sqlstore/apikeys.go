package sqlstore

import (
	"context"
	"time"

	"github.com/alternayte/auth-all/store"
)

const apiKeyColumns = "id, user_id, name, start, key_hash, role, org_id, created_at, expires_at, last_used_at, revoked_at, revoked_by"

// scanAPIKey returns the scan targets of apiKeyColumns, in that order.
func scanAPIKey(m *store.APIKey) []any {
	return []any{&m.ID, &m.UserID, &m.Name, &m.Start, &m.KeyHash, &m.Role,
		nullStringScan{&m.OrgID}, timeScan{&m.CreatedAt}, nullTimeScan{&m.ExpiresAt}, nullTimeScan{&m.LastUsedAt},
		nullTimeScan{&m.RevokedAt}, nullStringScan{&m.RevokedBy}}
}

// CreateAPIKey implements store.APIKeyStore.
func (s *Store) CreateAPIKey(ctx context.Context, k *store.APIKey) error {
	_, err := s.exec(ctx,
		"INSERT INTO "+s.n.APIKeys+" ("+apiKeyColumns+") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		k.ID, k.UserID, k.Name, k.Start, k.KeyHash, k.Role, nullString(k.OrgID), s.bindTime(k.CreatedAt),
		s.bindNullTime(k.ExpiresAt), s.bindNullTime(k.LastUsedAt), s.bindNullTime(k.RevokedAt),
		nullString(k.RevokedBy))
	return s.mapErr(err)
}

// APIKeyByHash implements store.APIKeyStore. The join keeps the credential
// resolution at one round trip.
func (s *Store) APIKeyByHash(ctx context.Context, keyHash string) (*store.APIKey, *store.User, error) {
	row := s.queryRow(ctx,
		"SELECT "+prefixColumns("k", apiKeyColumns)+", "+prefixColumns("u", s.userColumnList())+
			" FROM "+s.n.APIKeys+" k JOIN "+s.n.Users+" u ON u.id = k.user_id WHERE k.key_hash = ?",
		keyHash)
	var key store.APIKey
	var user store.User
	extra := make([]any, len(s.fields))
	targets := append(scanAPIKey(&key), s.scanUserRow(&user, extra)...)
	if err := row.Scan(targets...); err != nil {
		return nil, nil, s.mapErr(err)
	}
	s.collectExtra(&user, extra)
	return &key, &user, nil
}

// APIKeyByID implements store.APIKeyStore.
func (s *Store) APIKeyByID(ctx context.Context, id string) (*store.APIKey, error) {
	row := s.queryRow(ctx, "SELECT "+apiKeyColumns+" FROM "+s.n.APIKeys+" WHERE id = ?", id)
	var m store.APIKey
	if err := row.Scan(scanAPIKey(&m)...); err != nil {
		return nil, s.mapErr(err)
	}
	return &m, nil
}

// ListAPIKeys implements store.APIKeyStore.
func (s *Store) ListAPIKeys(ctx context.Context, userID string) ([]store.APIKey, error) {
	rows, err := s.query(ctx,
		"SELECT "+apiKeyColumns+" FROM "+s.n.APIKeys+
			" WHERE user_id = ? ORDER BY created_at DESC, id DESC", userID)
	if err != nil {
		return nil, s.mapErr(err)
	}
	defer rows.Close()
	var out []store.APIKey
	for rows.Next() {
		var m store.APIKey
		if err := rows.Scan(scanAPIKey(&m)...); err != nil {
			return nil, s.mapErr(err)
		}
		out = append(out, m)
	}
	return out, s.mapErr(rows.Err())
}

// RevokeAPIKey implements store.APIKeyStore.
func (s *Store) RevokeAPIKey(ctx context.Context, id, byUserID string, at time.Time) error {
	res, err := s.exec(ctx,
		"UPDATE "+s.n.APIKeys+" SET revoked_at = ?, revoked_by = ? WHERE id = ? AND revoked_at IS NULL",
		s.bindTime(at), byUserID, id)
	if err != nil {
		return s.mapErr(err)
	}
	return requireAffected(res)
}

// TouchAPIKey implements store.APIKeyStore.
func (s *Store) TouchAPIKey(ctx context.Context, id string, at time.Time) error {
	_, err := s.exec(ctx, "UPDATE "+s.n.APIKeys+" SET last_used_at = ? WHERE id = ?", s.bindTime(at), id)
	return s.mapErr(err)
}
