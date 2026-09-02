package sqlstore

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

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

// AdvanceStep writes the step under a condition, so the comparison and the
// write are one atomic operation.
//
// A read followed by a later write would let two concurrent requests that
// carry one stolen code both pass the replay guard. The database performs the
// comparison here, so exactly one of those requests changes the row.
func (p *totpStore) AdvanceStep(ctx context.Context, userID string, step int64) (bool, error) {
	res, err := p.s.exec(ctx,
		"UPDATE "+schema.TableTOTP+" SET last_step = ? WHERE user_id = ? AND last_step < ?",
		step, userID, step)
	if err != nil {
		return false, p.s.mapErr(err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	if n > 0 {
		return true, nil
	}
	// No row changed. The user holds no secret, or the step did not advance.
	// The caller must tell those apart, so the absent row is read one time on
	// this path only.
	if _, err := p.Get(ctx, userID); err != nil {
		return false, err
	}
	return false, nil
}

func (p *totpStore) Delete(ctx context.Context, userID string) error {
	res, err := p.s.exec(ctx, "DELETE FROM "+schema.TableTOTP+" WHERE user_id = ?", userID)
	if err != nil {
		return p.s.mapErr(err)
	}
	return requireAffected(res)
}

type recoveryCodeStore struct{ s *Store }

// ReplaceAll writes a new set inside one transaction, so a failed regeneration
// never leaves a user with no codes.
func (p *recoveryCodeStore) ReplaceAll(ctx context.Context, userID string, hashes []string) error {
	return p.s.Transaction(ctx, func(tx store.Store) error {
		inner, ok := tx.(*Store)
		if !ok {
			return fmt.Errorf("authall/sqlstore: unexpected transaction store %T", tx)
		}
		if _, err := inner.exec(ctx,
			"DELETE FROM "+schema.TableTOTPRecovery+" WHERE user_id = ?", userID); err != nil {
			return inner.mapErr(err)
		}
		now := time.Now().UTC()
		for _, h := range hashes {
			if _, err := inner.exec(ctx,
				"INSERT INTO "+schema.TableTOTPRecovery+" (id, user_id, code_hash, created_at) VALUES (?, ?, ?, ?)",
				uuid.NewString(), userID, h, inner.bindTime(now)); err != nil {
				return inner.mapErr(err)
			}
		}
		return nil
	})
}

// Consume removes one code under a condition on the owner and the hash, so the
// match and the removal are one atomic operation.
//
// The user is named in the statement, so a code of one user never authenticates
// another user.
func (p *recoveryCodeStore) Consume(ctx context.Context, userID, codeHash string) (bool, error) {
	res, err := p.s.exec(ctx,
		"DELETE FROM "+schema.TableTOTPRecovery+" WHERE user_id = ? AND code_hash = ?",
		userID, codeHash)
	if err != nil {
		return false, p.s.mapErr(err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

func (p *recoveryCodeStore) CountByUser(ctx context.Context, userID string) (int, error) {
	row := p.s.queryRow(ctx,
		"SELECT COUNT(*) FROM "+schema.TableTOTPRecovery+" WHERE user_id = ?", userID)
	var n int
	if err := row.Scan(&n); err != nil {
		return 0, p.s.mapErr(err)
	}
	return n, nil
}

func (p *recoveryCodeStore) DeleteByUser(ctx context.Context, userID string) (int, error) {
	res, err := p.s.exec(ctx,
		"DELETE FROM "+schema.TableTOTPRecovery+" WHERE user_id = ?", userID)
	if err != nil {
		return 0, p.s.mapErr(err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	return int(n), nil
}
