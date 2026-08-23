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
}

// New returns a store over db.
func New(db *sql.DB, d Dialect) *Store {
	return &Store{db: db, ex: db, d: d}
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
	txStore := &Store{db: s.db, ex: tx, d: s.d}
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
