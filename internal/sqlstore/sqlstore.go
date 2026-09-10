// Package sqlstore implements the Auth-All storage boundary over database/sql.
// One implementation serves every first-party SQL adapter. A Dialect carries
// the small set of engine-specific behaviors.
package sqlstore

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/alternayte/auth-all/schema"
	"github.com/alternayte/auth-all/store"
)

// SQLiteTimeLayout is the fixed-width UTC layout used by text timestamp
// columns. The fixed width keeps lexicographic order equal to time order.
const SQLiteTimeLayout = "2006-01-02T15:04:05.000000000"

// Dialect carries the engine-specific behavior of one adapter.
type Dialect struct {
	// Name is the schema dialect.
	Name schema.Dialect
	// NumberedPlaceholders selects $1 style placeholders instead of ?.
	NumberedPlaceholders bool
	// TextTime stores timestamps as fixed-width UTC text.
	TextTime bool
	// IsUniqueViolation reports whether err is a uniqueness constraint failure.
	IsUniqueViolation func(err error) bool
}

type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// Store is the database/sql implementation of store.Store.
type Store struct {
	db *sql.DB
	ex execer
	d  Dialect
	// n holds the physical table names. UseSchema replaces them.
	n schema.Names
	// fields hold the host-owned columns of the users table.
	fields []schema.UserField
}

// New returns a store over db.
func New(db *sql.DB, d Dialect) *Store {
	return &Store{db: db, ex: db, d: d, n: schema.DefaultNames()}
}

// UseSchema implements store.SchemaConfigurable. It sets the physical table
// names of the host.
func (s *Store) UseSchema(o schema.Options) error {
	o, err := o.Normalize()
	if err != nil {
		return err
	}
	s.n = schema.TableNames(o)
	s.fields = append([]schema.UserField(nil), o.UserFields...)
	return nil
}

// TableColumns implements store.CatalogInspector.
func (s *Store) TableColumns(ctx context.Context, table string) ([]string, bool, error) {
	query := "SELECT column_name FROM information_schema.columns WHERE table_name = ? AND table_schema = current_schema()"
	if s.d.Name == schema.SQLite {
		// SQLite has no information schema. pragma_table_info reads the same
		// facts and takes the table name as a bound value.
		query = "SELECT name FROM pragma_table_info(?)"
	}
	rows, err := s.query(ctx, query, table)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, false, err
		}
		out = append(out, name)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	return out, len(out) > 0, nil
}

// DB returns the underlying handle. It is owned by the application.
func (s *Store) DB() *sql.DB { return s.db }

// Users implements store.Store.
func (s *Store) Users() store.UserStore { return &userStore{s} }

// Accounts implements store.Store.
func (s *Store) Accounts() store.AccountStore { return &accountStore{s} }

// Sessions implements store.Store.
func (s *Store) Sessions() store.SessionStore { return &sessionStore{s} }

// Tokens implements store.Store.
func (s *Store) Tokens() store.TokenStore { return &tokenStore{s} }

// OAuthStates implements store.Store.
func (s *Store) OAuthStates() store.OAuthStateStore { return &oauthStateStore{s} }

// TOTP implements store.Store.
func (s *Store) TOTP() store.TOTPStore { return &totpStore{s} }

// RecoveryCodes implements store.Store.
func (s *Store) RecoveryCodes() store.RecoveryCodeStore { return &recoveryCodeStore{s} }

// Migrator implements store.Store.
func (s *Store) Migrator() store.Migrator { return &migrator{s} }

// Close implements store.Store. The database handle stays open because the
// application owns it.
func (s *Store) Close() error { return nil }

// Transaction implements store.Store. A nested call joins the running
// transaction instead of opening a second one.
func (s *Store) Transaction(ctx context.Context, fn func(store.Store) error) error {
	if _, ok := s.ex.(*sql.Tx); ok {
		return fn(s)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	txStore := &Store{db: s.db, ex: tx, d: s.d, n: s.n, fields: s.fields}
	if err := fn(txStore); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// rebind converts ? placeholders to the dialect form.
func (s *Store) rebind(query string) string {
	if !s.d.NumberedPlaceholders {
		return query
	}
	var b strings.Builder
	n := 0
	for i := 0; i < len(query); i++ {
		if query[i] == '?' {
			n++
			b.WriteByte('$')
			b.WriteString(strconv.Itoa(n))
			continue
		}
		b.WriteByte(query[i])
	}
	return b.String()
}

func (s *Store) exec(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return s.ex.ExecContext(ctx, s.rebind(query), args...)
}

func (s *Store) query(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return s.ex.QueryContext(ctx, s.rebind(query), args...)
}

func (s *Store) queryRow(ctx context.Context, query string, args ...any) *sql.Row {
	return s.ex.QueryRowContext(ctx, s.rebind(query), args...)
}

// bindTime converts a time value for the dialect.
func (s *Store) bindTime(t time.Time) any {
	if s.d.TextTime {
		return t.UTC().Format(SQLiteTimeLayout)
	}
	return t.UTC()
}

func (s *Store) bindNullTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return s.bindTime(*t)
}

func (s *Store) mapErr(err error) error {
	if err == nil {
		return nil
	}
	if err == sql.ErrNoRows {
		return store.ErrNotFound
	}
	if s.d.IsUniqueViolation != nil && s.d.IsUniqueViolation(err) {
		return store.ErrConflict
	}
	return err
}

// timeScan scans a timestamp column written by either dialect.
type timeScan struct{ dst *time.Time }

func (t timeScan) Scan(src any) error {
	switch v := src.(type) {
	case nil:
		*t.dst = time.Time{}
		return nil
	case time.Time:
		*t.dst = v.UTC()
		return nil
	case string:
		return parseTime(v, t.dst)
	case []byte:
		return parseTime(string(v), t.dst)
	default:
		return fmt.Errorf("authall/sqlstore: cannot scan %T as time", src)
	}
}

// nullTimeScan scans a nullable timestamp column.
type nullTimeScan struct{ dst **time.Time }

func (t nullTimeScan) Scan(src any) error {
	if src == nil {
		*t.dst = nil
		return nil
	}
	var out time.Time
	if err := (timeScan{&out}).Scan(src); err != nil {
		return err
	}
	*t.dst = &out
	return nil
}

var timeLayouts = []string{
	SQLiteTimeLayout,
	time.RFC3339Nano,
	"2006-01-02 15:04:05.999999999-07:00",
	"2006-01-02 15:04:05",
}

func parseTime(s string, dst *time.Time) error {
	for _, layout := range timeLayouts {
		if v, err := time.Parse(layout, s); err == nil {
			*dst = v.UTC()
			return nil
		}
	}
	return fmt.Errorf("authall/sqlstore: cannot parse timestamp %q", s)
}

// nullStringScan reads a nullable text column into a string pointer.
type nullStringScan struct{ dst **string }

func (n nullStringScan) Scan(src any) error {
	if src == nil {
		*n.dst = nil
		return nil
	}
	var value sql.NullString
	if err := value.Scan(src); err != nil {
		return err
	}
	out := value.String
	*n.dst = &out
	return nil
}

// nullString returns the bound value of an optional text column.
func nullString(v *string) any {
	if v == nil {
		return nil
	}
	return *v
}
