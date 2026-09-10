package sqlstore

import (
	"context"
	"strings"
	"time"

	"github.com/alternayte/auth-all/store"
)

type sessionStore struct{ s *Store }

const sessionColumns = "id, user_id, token_hash, created_at, expires_at, last_seen_at"

func (ss *sessionStore) Create(ctx context.Context, m *store.Session) error {
	_, err := ss.s.exec(ctx,
		"INSERT INTO "+ss.s.n.Sessions+" ("+sessionColumns+") VALUES (?, ?, ?, ?, ?, ?)",
		m.ID, m.UserID, m.TokenHash, ss.s.bindTime(m.CreatedAt), ss.s.bindTime(m.ExpiresAt), ss.s.bindTime(m.LastSeenAt))
	return ss.s.mapErr(err)
}

func (ss *sessionStore) GetByTokenHash(ctx context.Context, tokenHash string) (*store.Session, error) {
	row := ss.s.queryRow(ctx,
		"SELECT "+sessionColumns+" FROM "+ss.s.n.Sessions+" WHERE token_hash = ?", tokenHash)
	var m store.Session
	if err := row.Scan(&m.ID, &m.UserID, &m.TokenHash, timeScan{&m.CreatedAt}, timeScan{&m.ExpiresAt}, timeScan{&m.LastSeenAt}); err != nil {
		return nil, ss.s.mapErr(err)
	}
	return &m, nil
}

func (ss *sessionStore) ListByUser(ctx context.Context, userID string) ([]store.Session, error) {
	// The order is deterministic, so a list is stable across two adapters. The
	// id breaks a tie of two equal timestamps.
	rows, err := ss.s.query(ctx,
		"SELECT "+sessionColumns+" FROM "+ss.s.n.Sessions+
			" WHERE user_id = ? ORDER BY created_at DESC, id DESC", userID)
	if err != nil {
		return nil, ss.s.mapErr(err)
	}
	defer rows.Close()
	out := []store.Session{}
	for rows.Next() {
		var m store.Session
		if err := rows.Scan(&m.ID, &m.UserID, &m.TokenHash,
			timeScan{&m.CreatedAt}, timeScan{&m.ExpiresAt}, timeScan{&m.LastSeenAt}); err != nil {
			return nil, ss.s.mapErr(err)
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, ss.s.mapErr(err)
	}
	return out, nil
}

func (ss *sessionStore) Touch(ctx context.Context, id string, at time.Time) error {
	res, err := ss.s.exec(ctx,
		"UPDATE "+ss.s.n.Sessions+" SET last_seen_at = ? WHERE id = ?", ss.s.bindTime(at), id)
	if err != nil {
		return ss.s.mapErr(err)
	}
	return requireAffected(res)
}

func (ss *sessionStore) Delete(ctx context.Context, id string) error {
	res, err := ss.s.exec(ctx, "DELETE FROM "+ss.s.n.Sessions+" WHERE id = ?", id)
	if err != nil {
		return ss.s.mapErr(err)
	}
	return requireAffected(res)
}

func (ss *sessionStore) DeleteByUser(ctx context.Context, userID string) (int, error) {
	res, err := ss.s.exec(ctx, "DELETE FROM "+ss.s.n.Sessions+" WHERE user_id = ?", userID)
	if err != nil {
		return 0, ss.s.mapErr(err)
	}
	n, err := res.RowsAffected()
	return int(n), err
}

func (ss *sessionStore) DeleteExpired(ctx context.Context, before time.Time) (int, error) {
	res, err := ss.s.exec(ctx, "DELETE FROM "+ss.s.n.Sessions+" WHERE expires_at <= ?", ss.s.bindTime(before))
	if err != nil {
		return 0, ss.s.mapErr(err)
	}
	n, err := res.RowsAffected()
	return int(n), err
}

// SessionWithUser implements store.SessionUserReader. It joins the session row
// and the user row, so credential resolution costs one round trip.
func (s *Store) SessionWithUser(ctx context.Context, tokenHash string) (*store.Session, *store.User, error) {
	sessionCols := prefixColumns("s", sessionColumns)
	userCols := prefixColumns("u", userColumns)
	row := s.queryRow(ctx,
		"SELECT "+sessionCols+", "+userCols+" FROM "+s.n.Sessions+" s "+
			"JOIN "+s.n.Users+" u ON u.id = s.user_id WHERE s.token_hash = ?", tokenHash)
	var sess store.Session
	var user store.User
	targets := []any{&sess.ID, &sess.UserID, &sess.TokenHash,
		timeScan{&sess.CreatedAt}, timeScan{&sess.ExpiresAt}, timeScan{&sess.LastSeenAt}}
	targets = append(targets, scanUser(&user)...)
	if err := row.Scan(targets...); err != nil {
		return nil, nil, s.mapErr(err)
	}
	return &sess, &user, nil
}

// prefixColumns returns the column list with one table alias.
func prefixColumns(alias, columns string) string {
	parts := strings.Split(columns, ", ")
	for i, c := range parts {
		parts[i] = alias + "." + c
	}
	return strings.Join(parts, ", ")
}

// DeleteSessionsExcept implements store.SessionRevoker. One statement finds the
// owner and removes the other sessions, so no read and no lock is needed.
func (s *Store) DeleteSessionsExcept(ctx context.Context, sessionID string) (int, error) {
	res, err := s.exec(ctx,
		"DELETE FROM "+s.n.Sessions+" WHERE id <> ? AND user_id = "+
			"(SELECT user_id FROM "+s.n.Sessions+" WHERE id = ?)", sessionID, sessionID)
	if err != nil {
		return 0, s.mapErr(err)
	}
	n, err := res.RowsAffected()
	return int(n), err
}
