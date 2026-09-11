package sqlstore

import (
	"context"
	"encoding/base64"
	"strings"
	"time"

	"github.com/alternayte/auth-all/schema"

	"github.com/alternayte/auth-all/store"
)

// maxUserPage is the highest accepted page size of the administrative list.
const maxUserPage = 200

// ListUsers implements store.UserAdminStore.
//
// The order is the normalized email and then the identifier, so two users with
// one address order the same way in every page.
func (s *Store) ListUsers(ctx context.Context, f store.UserListFilter) ([]store.User, string, error) {
	limit := f.Limit
	if limit < 1 {
		limit = 50
	}
	if limit > maxUserPage {
		limit = maxUserPage
	}
	var where []string
	var args []any
	if f.EmailPrefix != "" {
		where = append(where, "email_normalized LIKE ?")
		args = append(args, escapeLike(strings.ToLower(f.EmailPrefix))+"%")
	}
	if f.Role != nil {
		where = append(where, "role = ?")
		args = append(args, *f.Role)
	}
	if f.Disabled != nil {
		if *f.Disabled {
			where = append(where, "disabled_at IS NOT NULL")
		} else {
			where = append(where, "disabled_at IS NULL")
		}
	}
	if f.Cursor != "" {
		email, id, err := decodeCursor(f.Cursor)
		if err != nil {
			return nil, "", err
		}
		where = append(where, "(email_normalized > ? OR (email_normalized = ? AND id > ?))")
		args = append(args, email, email, id)
	}
	query := "SELECT " + s.userColumnList() + " FROM " + s.n.Users
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += " ORDER BY email_normalized, id LIMIT ?"
	// One more row reports whether a page follows.
	args = append(args, limit+1)

	rows, err := s.query(ctx, query, args...)
	if err != nil {
		return nil, "", s.mapErr(err)
	}
	defer rows.Close()
	var out []store.User
	for rows.Next() {
		var m store.User
		extra := make([]any, len(s.fields))
		if err := rows.Scan(s.scanUserRow(&m, extra)...); err != nil {
			return nil, "", s.mapErr(err)
		}
		s.collectExtra(&m, extra)
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, "", s.mapErr(err)
	}
	if len(out) > limit {
		last := out[limit-1]
		return out[:limit], encodeCursor(last.EmailNormalized, last.ID), nil
	}
	return out, "", nil
}

// LockEnabledUsersWithRole implements store.UserAdminStore.
func (s *Store) LockEnabledUsersWithRole(ctx context.Context, role string) ([]string, error) {
	query := "SELECT id FROM " + s.n.Users + " WHERE role = ? AND disabled_at IS NULL"
	if s.d.Name == schema.Postgres {
		// The row lock ends with the transaction, so it is safe behind a
		// transaction pooler. SQLite needs no clause, because it serializes
		// the writers of one database.
		query += " FOR UPDATE"
	}
	rows, err := s.query(ctx, query, role)
	if err != nil {
		return nil, s.mapErr(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, s.mapErr(err)
		}
		out = append(out, id)
	}
	return out, s.mapErr(rows.Err())
}

// encodeCursor returns the opaque cursor of one row.
func encodeCursor(email, id string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(email + "\x00" + id))
}

// decodeCursor returns the row that a cursor names.
func decodeCursor(value string) (string, string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return "", "", store.ErrInvalidCursor
	}
	email, id, ok := strings.Cut(string(raw), "\x00")
	if !ok {
		return "", "", store.ErrInvalidCursor
	}
	return email, id, nil
}

// escapeLike makes a value safe inside a LIKE pattern.
func escapeLike(value string) string {
	replacer := strings.NewReplacer("\\", "\\\\", "%", "\\%", "_", "\\_")
	return replacer.Replace(value)
}

// InsertRow implements store.RowWriter.
func (s *Store) InsertRow(ctx context.Context, table string, columns []string, values []any) error {
	if len(columns) == 0 || len(columns) != len(values) {
		return store.ErrInvalidCursor
	}
	for i, v := range values {
		if t, ok := v.(time.Time); ok {
			values[i] = s.bindTime(t)
		}
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?, ", len(columns)), ", ")
	query := "INSERT INTO " + table + " (" + strings.Join(columns, ", ") + ") VALUES (" + placeholders + ")"
	_, err := s.exec(ctx, query, values...)
	return s.mapErr(err)
}

// DeleteRows implements store.RowDeleter.
func (s *Store) DeleteRows(ctx context.Context, table, column string, value any) (int, error) {
	result, err := s.exec(ctx, "DELETE FROM "+table+" WHERE "+column+" = ?", value)
	if err != nil {
		return 0, s.mapErr(err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	return int(affected), nil
}
