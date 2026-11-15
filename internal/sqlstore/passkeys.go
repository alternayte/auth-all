package sqlstore

import (
	"context"
	"time"

	"github.com/alternayte/auth-all/store"
)

const passkeyColumns = "id, user_id, credential_id, name, credential, created_at, last_used_at"

func scanPasskey(m *store.Passkey) []any {
	return []any{&m.ID, &m.UserID, &m.CredentialID, &m.Name, &m.Credential,
		timeScan{&m.CreatedAt}, nullTimeScan{&m.LastUsedAt}}
}

// CreatePasskey implements store.PasskeyStore.
func (s *Store) CreatePasskey(ctx context.Context, p *store.Passkey) error {
	_, err := s.exec(ctx,
		"INSERT INTO "+s.pk.Passkeys+" ("+passkeyColumns+") VALUES (?, ?, ?, ?, ?, ?, ?)",
		p.ID, p.UserID, p.CredentialID, p.Name, p.Credential,
		s.bindTime(p.CreatedAt), s.bindNullTime(p.LastUsedAt))
	return s.mapErr(err)
}

// PasskeyByCredentialID implements store.PasskeyStore.
func (s *Store) PasskeyByCredentialID(ctx context.Context, credentialID string) (*store.Passkey, error) {
	row := s.queryRow(ctx,
		"SELECT "+passkeyColumns+" FROM "+s.pk.Passkeys+" WHERE credential_id = ?", credentialID)
	var m store.Passkey
	if err := row.Scan(scanPasskey(&m)...); err != nil {
		return nil, s.mapErr(err)
	}
	return &m, nil
}

// ListPasskeys implements store.PasskeyStore.
func (s *Store) ListPasskeys(ctx context.Context, userID string) ([]store.Passkey, error) {
	rows, err := s.query(ctx,
		"SELECT "+passkeyColumns+" FROM "+s.pk.Passkeys+
			" WHERE user_id = ? ORDER BY created_at DESC, id DESC", userID)
	if err != nil {
		return nil, s.mapErr(err)
	}
	defer rows.Close()
	var out []store.Passkey
	for rows.Next() {
		var m store.Passkey
		if err := rows.Scan(scanPasskey(&m)...); err != nil {
			return nil, s.mapErr(err)
		}
		out = append(out, m)
	}
	return out, s.mapErr(rows.Err())
}

// UpdatePasskeyUse implements store.PasskeyStore.
func (s *Store) UpdatePasskeyUse(ctx context.Context, id, credential string, at time.Time) error {
	res, err := s.exec(ctx,
		"UPDATE "+s.pk.Passkeys+" SET credential = ?, last_used_at = ? WHERE id = ?",
		credential, s.bindTime(at), id)
	if err != nil {
		return s.mapErr(err)
	}
	return requireAffected(res)
}

// DeletePasskey implements store.PasskeyStore.
func (s *Store) DeletePasskey(ctx context.Context, id, userID string) error {
	res, err := s.exec(ctx, "DELETE FROM "+s.pk.Passkeys+" WHERE id = ? AND user_id = ?", id, userID)
	if err != nil {
		return s.mapErr(err)
	}
	return requireAffected(res)
}

const passkeyChallengeColumns = "id, kind, user_id, session_data, created_at, expires_at, consumed_at"

// CreatePasskeyChallenge implements store.PasskeyStore.
func (s *Store) CreatePasskeyChallenge(ctx context.Context, c *store.PasskeyChallenge) error {
	_, err := s.exec(ctx,
		"INSERT INTO "+s.pk.Challenges+" ("+passkeyChallengeColumns+") VALUES (?, ?, ?, ?, ?, ?, ?)",
		c.ID, c.Kind, nullString(c.UserID), c.SessionData,
		s.bindTime(c.CreatedAt), s.bindTime(c.ExpiresAt), s.bindNullTime(c.ConsumedAt))
	return s.mapErr(err)
}

// ConsumePasskeyChallenge implements store.PasskeyStore. One statement
// consumes the row, so two concurrent calls produce at most one success.
func (s *Store) ConsumePasskeyChallenge(ctx context.Context, id, kind string, at time.Time) (*store.PasskeyChallenge, error) {
	res, err := s.exec(ctx,
		"UPDATE "+s.pk.Challenges+" SET consumed_at = ? WHERE id = ? AND kind = ? AND consumed_at IS NULL AND expires_at > ?",
		s.bindTime(at), id, kind, s.bindTime(at))
	if err != nil {
		return nil, s.mapErr(err)
	}
	if err := requireAffected(res); err != nil {
		return nil, err
	}
	row := s.queryRow(ctx, "SELECT "+passkeyChallengeColumns+" FROM "+s.pk.Challenges+" WHERE id = ?", id)
	var m store.PasskeyChallenge
	if err := row.Scan(&m.ID, &m.Kind, nullStringScan{&m.UserID}, &m.SessionData,
		timeScan{&m.CreatedAt}, timeScan{&m.ExpiresAt}, nullTimeScan{&m.ConsumedAt}); err != nil {
		return nil, s.mapErr(err)
	}
	return &m, nil
}

// DeleteExpiredPasskeyChallenges implements store.PasskeyStore.
func (s *Store) DeleteExpiredPasskeyChallenges(ctx context.Context, before time.Time) (int, error) {
	res, err := s.exec(ctx, "DELETE FROM "+s.pk.Challenges+" WHERE expires_at < ?", s.bindTime(before))
	if err != nil {
		return 0, s.mapErr(err)
	}
	n, err := res.RowsAffected()
	return int(n), err
}
