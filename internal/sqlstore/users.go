package sqlstore

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/alternayte/auth-all/store"
)

type userStore struct{ s *Store }

// scanUser returns the scan targets of userColumns, in that order.
func scanUser(m *store.User) []any {
	return []any{&m.ID, &m.Email, &m.EmailNormalized, nullTimeScan{&m.EmailVerifiedAt},
		&m.DisplayName, &m.ImageURL, timeScan{&m.CreatedAt}, timeScan{&m.UpdatedAt},
		&m.Role, nullTimeScan{&m.DisabledAt}, &m.MustChangePassword}
}

// userColumnList returns the column list of a user row, with the host-owned
// fields at the end.
func (s *Store) userColumnList() string {
	out := userColumns
	for _, f := range s.fields {
		out += ", " + f.Name
	}
	return out
}

// scanUserRow returns the scan targets of userColumnList.
func (s *Store) scanUserRow(m *store.User, extra []any) []any {
	targets := scanUser(m)
	for i := range s.fields {
		targets = append(targets, &extra[i])
	}
	return targets
}

// collectExtra puts the read host-owned values in the user.
func (s *Store) collectExtra(m *store.User, extra []any) {
	if len(s.fields) == 0 {
		return
	}
	values := make(map[string]any, len(s.fields))
	for i, f := range s.fields {
		values[f.Name] = extra[i]
	}
	m.Extra = store.NewExtraFields(values)
}

// extraValues returns the bound values of the host-owned fields.
func (s *Store) extraValues(m *store.User) []any {
	out := make([]any, 0, len(s.fields))
	for _, f := range s.fields {
		value, ok := m.Extra.Get(f.Name)
		if !ok {
			out = append(out, nil)
			continue
		}
		if t, isTime := value.(time.Time); isTime {
			value = s.bindTime(t)
		}
		out = append(out, value)
	}
	return out
}

const userColumns = "id, email, email_normalized, email_verified_at, display_name, image_url, created_at, updated_at, role, disabled_at, must_change_password"

func (u *userStore) Create(ctx context.Context, m *store.User) error {
	values := []any{m.ID, m.Email, m.EmailNormalized, u.s.bindNullTime(m.EmailVerifiedAt),
		m.DisplayName, m.ImageURL, u.s.bindTime(m.CreatedAt), u.s.bindTime(m.UpdatedAt),
		m.Role, u.s.bindNullTime(m.DisabledAt), m.MustChangePassword}
	values = append(values, u.s.extraValues(m)...)
	placeholders := strings.TrimSuffix(strings.Repeat("?, ", len(values)), ", ")
	_, err := u.s.exec(ctx,
		"INSERT INTO "+u.s.n.Users+" ("+u.s.userColumnList()+") VALUES ("+placeholders+")", values...)
	return u.s.mapErr(err)
}

func (u *userStore) GetByID(ctx context.Context, id string) (*store.User, error) {
	return u.get(ctx, "id = ?", id)
}

func (u *userStore) GetByNormalizedEmail(ctx context.Context, normalized string) (*store.User, error) {
	return u.get(ctx, "email_normalized = ?", normalized)
}

func (u *userStore) get(ctx context.Context, where string, arg any) (*store.User, error) {
	row := u.s.queryRow(ctx, "SELECT "+u.s.userColumnList()+" FROM "+u.s.n.Users+" WHERE "+where, arg)
	var m store.User
	extra := make([]any, len(u.s.fields))
	if err := row.Scan(u.s.scanUserRow(&m, extra)...); err != nil {
		return nil, u.s.mapErr(err)
	}
	u.s.collectExtra(&m, extra)
	return &m, nil
}

func (u *userStore) Update(ctx context.Context, m *store.User) error {
	set := "email = ?, email_normalized = ?, email_verified_at = ?, display_name = ?, image_url = ?, " +
		"updated_at = ?, role = ?, disabled_at = ?, must_change_password = ?"
	values := []any{m.Email, m.EmailNormalized, u.s.bindNullTime(m.EmailVerifiedAt), m.DisplayName,
		m.ImageURL, u.s.bindTime(m.UpdatedAt), m.Role, u.s.bindNullTime(m.DisabledAt), m.MustChangePassword}
	for i, f := range u.s.fields {
		set += ", " + f.Name + " = ?"
		values = append(values, u.s.extraValues(m)[i])
	}
	values = append(values, m.ID)
	res, err := u.s.exec(ctx, "UPDATE "+u.s.n.Users+" SET "+set+" WHERE id = ?", values...)
	if err != nil {
		return u.s.mapErr(err)
	}
	return requireAffected(res)
}

func (u *userStore) Delete(ctx context.Context, id string) error {
	res, err := u.s.exec(ctx, "DELETE FROM "+u.s.n.Users+" WHERE id = ?", id)
	if err != nil {
		return u.s.mapErr(err)
	}
	return requireAffected(res)
}

func (u *userStore) GetCredential(ctx context.Context, userID string) (*store.Credential, error) {
	row := u.s.queryRow(ctx,
		"SELECT user_id, password_hash, created_at, updated_at FROM "+u.s.n.Credentials+" WHERE user_id = ?", userID)
	var c store.Credential
	if err := row.Scan(&c.UserID, &c.PasswordHash, timeScan{&c.CreatedAt}, timeScan{&c.UpdatedAt}); err != nil {
		return nil, u.s.mapErr(err)
	}
	return &c, nil
}

func (u *userStore) SetCredential(ctx context.Context, c *store.Credential) error {
	res, err := u.s.exec(ctx,
		"UPDATE "+u.s.n.Credentials+" SET password_hash = ?, updated_at = ? WHERE user_id = ?",
		c.PasswordHash, u.s.bindTime(c.UpdatedAt), c.UserID)
	if err != nil {
		return u.s.mapErr(err)
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return nil
	}
	_, err = u.s.exec(ctx,
		"INSERT INTO "+u.s.n.Credentials+" (user_id, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?)",
		c.UserID, c.PasswordHash, u.s.bindTime(c.CreatedAt), u.s.bindTime(c.UpdatedAt))
	return u.s.mapErr(err)
}

func (u *userStore) DeleteCredential(ctx context.Context, userID string) error {
	res, err := u.s.exec(ctx, "DELETE FROM "+u.s.n.Credentials+" WHERE user_id = ?", userID)
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
