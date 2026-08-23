package sqlstore

import (
	"context"
	"database/sql"

	"github.com/alternayte/auth-all/schema"
	"github.com/alternayte/auth-all/store"
)

type userStore struct{ s *Store }

const userColumns = "id, email, email_normalized, email_verified_at, display_name, image_url, created_at, updated_at"

func (u *userStore) Create(ctx context.Context, m *store.User) error {
	_, err := u.s.exec(ctx,
		"INSERT INTO "+schema.TableUsers+" ("+userColumns+") VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		m.ID, m.Email, m.EmailNormalized, u.s.bindNullTime(m.EmailVerifiedAt),
		m.DisplayName, m.ImageURL, u.s.bindTime(m.CreatedAt), u.s.bindTime(m.UpdatedAt))
	return u.s.mapErr(err)
}

func (u *userStore) GetByID(ctx context.Context, id string) (*store.User, error) {
	return u.get(ctx, "id = ?", id)
}

func (u *userStore) GetByNormalizedEmail(ctx context.Context, normalized string) (*store.User, error) {
	return u.get(ctx, "email_normalized = ?", normalized)
}

func (u *userStore) get(ctx context.Context, where string, arg any) (*store.User, error) {
	row := u.s.queryRow(ctx, "SELECT "+userColumns+" FROM "+schema.TableUsers+" WHERE "+where, arg)
	var m store.User
	err := row.Scan(&m.ID, &m.Email, &m.EmailNormalized, nullTimeScan{&m.EmailVerifiedAt},
		&m.DisplayName, &m.ImageURL, timeScan{&m.CreatedAt}, timeScan{&m.UpdatedAt})
	if err != nil {
		return nil, u.s.mapErr(err)
	}
	return &m, nil
}

func (u *userStore) Update(ctx context.Context, m *store.User) error {
	res, err := u.s.exec(ctx,
		"UPDATE "+schema.TableUsers+" SET email = ?, email_normalized = ?, email_verified_at = ?, display_name = ?, image_url = ?, updated_at = ? WHERE id = ?",
		m.Email, m.EmailNormalized, u.s.bindNullTime(m.EmailVerifiedAt), m.DisplayName, m.ImageURL,
		u.s.bindTime(m.UpdatedAt), m.ID)
	if err != nil {
		return u.s.mapErr(err)
	}
	return requireAffected(res)
}

func (u *userStore) Delete(ctx context.Context, id string) error {
	res, err := u.s.exec(ctx, "DELETE FROM "+schema.TableUsers+" WHERE id = ?", id)
	if err != nil {
		return u.s.mapErr(err)
	}
	return requireAffected(res)
}

func (u *userStore) GetCredential(ctx context.Context, userID string) (*store.Credential, error) {
	row := u.s.queryRow(ctx,
		"SELECT user_id, password_hash, created_at, updated_at FROM "+schema.TableCredentials+" WHERE user_id = ?", userID)
	var c store.Credential
	if err := row.Scan(&c.UserID, &c.PasswordHash, timeScan{&c.CreatedAt}, timeScan{&c.UpdatedAt}); err != nil {
		return nil, u.s.mapErr(err)
	}
	return &c, nil
}

func (u *userStore) SetCredential(ctx context.Context, c *store.Credential) error {
	res, err := u.s.exec(ctx,
		"UPDATE "+schema.TableCredentials+" SET password_hash = ?, updated_at = ? WHERE user_id = ?",
		c.PasswordHash, u.s.bindTime(c.UpdatedAt), c.UserID)
	if err != nil {
		return u.s.mapErr(err)
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return nil
	}
	_, err = u.s.exec(ctx,
		"INSERT INTO "+schema.TableCredentials+" (user_id, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?)",
		c.UserID, c.PasswordHash, u.s.bindTime(c.CreatedAt), u.s.bindTime(c.UpdatedAt))
	return u.s.mapErr(err)
}

func (u *userStore) DeleteCredential(ctx context.Context, userID string) error {
	res, err := u.s.exec(ctx, "DELETE FROM "+schema.TableCredentials+" WHERE user_id = ?", userID)
	if err != nil {
		return u.s.mapErr(err)
	}
	return requireAffected(res)
}

func requireAffected(res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}
