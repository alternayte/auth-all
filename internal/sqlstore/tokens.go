package sqlstore

import (
	"context"
	"database/sql"
	"time"

	"github.com/alternayte/auth-all/schema"
	"github.com/alternayte/auth-all/store"
)

type tokenStore struct{ s *Store }

const tokenColumns = "id, user_id, kind, identifier, token_hash, created_at, expires_at, consumed_at"

func (t *tokenStore) Create(ctx context.Context, m *store.Token) error {
	var userID any
	if m.UserID != nil {
		userID = *m.UserID
	}
	_, err := t.s.exec(ctx,
		"INSERT INTO "+schema.TableTokens+" ("+tokenColumns+") VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		m.ID, userID, m.Kind, m.Identifier, m.TokenHash,
		t.s.bindTime(m.CreatedAt), t.s.bindTime(m.ExpiresAt), t.s.bindNullTime(m.ConsumedAt))
	return t.s.mapErr(err)
}

// Consume marks one token consumed in a single statement. The WHERE clause
// makes the update the atomic guard against replay.
func (t *tokenStore) Consume(ctx context.Context, kind, tokenHash string, now time.Time) (*store.Token, error) {
	row := t.s.queryRow(ctx,
		"UPDATE "+schema.TableTokens+" SET consumed_at = ? "+
			"WHERE kind = ? AND token_hash = ? AND consumed_at IS NULL AND expires_at > ? "+
			"RETURNING "+tokenColumns,
		t.s.bindTime(now), kind, tokenHash, t.s.bindTime(now))
	return scanToken(t.s, row)
}

func (t *tokenStore) Get(ctx context.Context, kind, tokenHash string) (*store.Token, error) {
	row := t.s.queryRow(ctx,
		"SELECT "+tokenColumns+" FROM "+schema.TableTokens+" WHERE kind = ? AND token_hash = ?", kind, tokenHash)
	return scanToken(t.s, row)
}

func (t *tokenStore) DeleteByIdentifier(ctx context.Context, kind, identifier string) error {
	_, err := t.s.exec(ctx,
		"DELETE FROM "+schema.TableTokens+" WHERE kind = ? AND identifier = ?", kind, identifier)
	return t.s.mapErr(err)
}

func (t *tokenStore) DeleteExpired(ctx context.Context, before time.Time) (int, error) {
	res, err := t.s.exec(ctx, "DELETE FROM "+schema.TableTokens+" WHERE expires_at <= ?", t.s.bindTime(before))
	if err != nil {
		return 0, t.s.mapErr(err)
	}
	n, err := res.RowsAffected()
	return int(n), err
}

func scanToken(s *Store, row *sql.Row) (*store.Token, error) {
	var m store.Token
	var userID sql.NullString
	err := row.Scan(&m.ID, &userID, &m.Kind, &m.Identifier, &m.TokenHash,
		timeScan{&m.CreatedAt}, timeScan{&m.ExpiresAt}, nullTimeScan{&m.ConsumedAt})
	if err != nil {
		return nil, s.mapErr(err)
	}
	if userID.Valid {
		v := userID.String
		m.UserID = &v
	}
	return &m, nil
}
