package sqlstore

import (
	"context"
	"database/sql"
	"time"

	"github.com/alternayte/auth-all/schema"
	"github.com/alternayte/auth-all/store"
)

type oauthStateStore struct{ s *Store }

const oauthStateColumns = "id, state_hash, provider, verifier, nonce, redirect_to, link_user_id, created_at, expires_at, consumed_at"

func (o *oauthStateStore) Create(ctx context.Context, m *store.OAuthState) error {
	var linkUserID any
	if m.LinkUserID != nil {
		linkUserID = *m.LinkUserID
	}
	_, err := o.s.exec(ctx,
		"INSERT INTO "+schema.TableOAuthStates+" ("+oauthStateColumns+") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		m.ID, m.StateHash, m.Provider, m.Verifier, m.Nonce, m.RedirectTo, linkUserID,
		o.s.bindTime(m.CreatedAt), o.s.bindTime(m.ExpiresAt), o.s.bindNullTime(m.ConsumedAt))
	return o.s.mapErr(err)
}

func (o *oauthStateStore) Consume(ctx context.Context, stateHash string, now time.Time) (*store.OAuthState, error) {
	row := o.s.queryRow(ctx,
		"UPDATE "+schema.TableOAuthStates+" SET consumed_at = ? "+
			"WHERE state_hash = ? AND consumed_at IS NULL AND expires_at > ? "+
			"RETURNING "+oauthStateColumns,
		o.s.bindTime(now), stateHash, o.s.bindTime(now))
	var m store.OAuthState
	var linkUserID sql.NullString
	err := row.Scan(&m.ID, &m.StateHash, &m.Provider, &m.Verifier, &m.Nonce, &m.RedirectTo, &linkUserID,
		timeScan{&m.CreatedAt}, timeScan{&m.ExpiresAt}, nullTimeScan{&m.ConsumedAt})
	if err != nil {
		return nil, o.s.mapErr(err)
	}
	if linkUserID.Valid {
		v := linkUserID.String
		m.LinkUserID = &v
	}
	return &m, nil
}

func (o *oauthStateStore) DeleteExpired(ctx context.Context, before time.Time) (int, error) {
	res, err := o.s.exec(ctx, "DELETE FROM "+schema.TableOAuthStates+" WHERE expires_at <= ?", o.s.bindTime(before))
	if err != nil {
		return 0, o.s.mapErr(err)
	}
	n, err := res.RowsAffected()
	return int(n), err
}
