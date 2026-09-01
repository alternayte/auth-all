package sqlstore

import (
	"context"
	"time"

	"github.com/alternayte/auth-all/schema"
	"github.com/alternayte/auth-all/store"
)

type totpStore struct{ s *Store }

const totpColumns = "user_id, secret, confirmed_at, last_step, created_at, updated_at"

func (p *totpStore) Get(ctx context.Context, userID string) (*store.TOTP, error) {
	row := p.s.queryRow(ctx,
		"SELECT "+totpColumns+" FROM "+schema.TableTOTP+" WHERE user_id = ?", userID)
	var t store.TOTP
	err := row.Scan(&t.UserID, &t.Secret, nullTimeScan{&t.ConfirmedAt}, &t.LastStep,
		timeScan{&t.CreatedAt}, timeScan{&t.UpdatedAt})
	if err != nil {
		return nil, p.s.mapErr(err)
	}
	return &t, nil
}

// Upsert replaces any existing row of the user.
//
// A replacement clears confirmed_at and last_step. A new secret starts a new
// enrolment, so a row that kept the old confirmation would accept the new
// secret with no proof.
func (p *totpStore) Upsert(ctx context.Context, t *store.TOTP) error {
	res, err := p.s.exec(ctx,
		"UPDATE "+schema.TableTOTP+
			" SET secret = ?, confirmed_at = NULL, last_step = 0, updated_at = ?"+
			" WHERE user_id = ?",
		t.Secret, p.s.bindTime(t.UpdatedAt), t.UserID)
	if err != nil {
		return p.s.mapErr(err)
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return nil
	}
	_, err = p.s.exec(ctx,
		"INSERT INTO "+schema.TableTOTP+" ("+totpColumns+") VALUES (?, ?, NULL, 0, ?, ?)",
		t.UserID, t.Secret, p.s.bindTime(t.CreatedAt), p.s.bindTime(t.UpdatedAt))
	return p.s.mapErr(err)
}

func (p *totpStore) Confirm(ctx context.Context, userID string, at time.Time) error {
	res, err := p.s.exec(ctx,
		"UPDATE "+schema.TableTOTP+" SET confirmed_at = ?, updated_at = ? WHERE user_id = ?",
		p.s.bindTime(at), p.s.bindTime(at), userID)
	if err != nil {
		return p.s.mapErr(err)
	}
	return requireAffected(res)
}

func (p *totpStore) SetLastStep(ctx context.Context, userID string, step int64) error {
	res, err := p.s.exec(ctx,
		"UPDATE "+schema.TableTOTP+" SET last_step = ? WHERE user_id = ?", step, userID)
	if err != nil {
		return p.s.mapErr(err)
	}
	return requireAffected(res)
}

func (p *totpStore) Delete(ctx context.Context, userID string) error {
	res, err := p.s.exec(ctx, "DELETE FROM "+schema.TableTOTP+" WHERE user_id = ?", userID)
	if err != nil {
		return p.s.mapErr(err)
	}
	return requireAffected(res)
}
