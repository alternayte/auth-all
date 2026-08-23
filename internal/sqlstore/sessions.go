package sqlstore

import (
	"context"
	"time"

	"github.com/alternayte/auth-all/schema"
	"github.com/alternayte/auth-all/store"
)

type sessionStore struct{ s *Store }

const sessionColumns = "id, user_id, token_hash, created_at, expires_at, last_seen_at"

func (ss *sessionStore) Create(ctx context.Context, m *store.Session) error {
	_, err := ss.s.exec(ctx,
		"INSERT INTO "+schema.TableSessions+" ("+sessionColumns+") VALUES (?, ?, ?, ?, ?, ?)",
		m.ID, m.UserID, m.TokenHash, ss.s.bindTime(m.CreatedAt), ss.s.bindTime(m.ExpiresAt), ss.s.bindTime(m.LastSeenAt))
	return ss.s.mapErr(err)
}

func (ss *sessionStore) GetByTokenHash(ctx context.Context, tokenHash string) (*store.Session, error) {
	row := ss.s.queryRow(ctx,
		"SELECT "+sessionColumns+" FROM "+schema.TableSessions+" WHERE token_hash = ?", tokenHash)
	var m store.Session
	if err := row.Scan(&m.ID, &m.UserID, &m.TokenHash, timeScan{&m.CreatedAt}, timeScan{&m.ExpiresAt}, timeScan{&m.LastSeenAt}); err != nil {
		return nil, ss.s.mapErr(err)
	}
	return &m, nil
}

func (ss *sessionStore) Touch(ctx context.Context, id string, at time.Time) error {
	res, err := ss.s.exec(ctx,
		"UPDATE "+schema.TableSessions+" SET last_seen_at = ? WHERE id = ?", ss.s.bindTime(at), id)
	if err != nil {
		return ss.s.mapErr(err)
	}
	return requireAffected(res)
}

func (ss *sessionStore) Delete(ctx context.Context, id string) error {
	res, err := ss.s.exec(ctx, "DELETE FROM "+schema.TableSessions+" WHERE id = ?", id)
	if err != nil {
		return ss.s.mapErr(err)
	}
	return requireAffected(res)
}

func (ss *sessionStore) DeleteByUser(ctx context.Context, userID string) (int, error) {
	res, err := ss.s.exec(ctx, "DELETE FROM "+schema.TableSessions+" WHERE user_id = ?", userID)
	if err != nil {
		return 0, ss.s.mapErr(err)
	}
	n, err := res.RowsAffected()
	return int(n), err
}

func (ss *sessionStore) DeleteExpired(ctx context.Context, before time.Time) (int, error) {
	res, err := ss.s.exec(ctx, "DELETE FROM "+schema.TableSessions+" WHERE expires_at <= ?", ss.s.bindTime(before))
	if err != nil {
		return 0, ss.s.mapErr(err)
	}
	n, err := res.RowsAffected()
	return int(n), err
}
