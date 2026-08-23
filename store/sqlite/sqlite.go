// Package sqlite provides the SQLite storage adapter for Auth-All.
package sqlite

import (
	"database/sql"
	"errors"
	"strings"

	sqlitedriver "modernc.org/sqlite"

	"github.com/alternayte/auth-all/internal/sqlstore"
	"github.com/alternayte/auth-all/schema"
	"github.com/alternayte/auth-all/store"
)

// Dialect describes SQLite to the shared SQL implementation.
var dialect = sqlstore.Dialect{
	Name:                 schema.SQLite,
	NumberedPlaceholders: false,
	TextTime:             true,
	IsUniqueViolation:    isUniqueViolation,
}

// New returns a SQLite store over an application-owned database handle.
//
// The handle must allow the RETURNING clause, which SQLite supports from
// version 3.35. Open configures a handle with the recommended settings.
func New(db *sql.DB) store.Store {
	return sqlstore.New(db, dialect)
}

// Open returns a database handle configured for Auth-All.
//
// It enables WAL mode, foreign keys, and a busy timeout, and it serializes
// writes through a single connection. The application owns the returned handle.
func Open(dsn string) (*sql.DB, error) {
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	full := dsn + sep + "_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", full)
	if err != nil {
		return nil, err
	}
	// SQLite allows one writer. One connection removes lock contention and
	// keeps concurrent callers deterministic.
	db.SetMaxOpenConns(1)
	return db, nil
}

func isUniqueViolation(err error) bool {
	var e *sqlitedriver.Error
	if errors.As(err, &e) {
		// 2067 is SQLITE_CONSTRAINT_UNIQUE and 1555 is SQLITE_CONSTRAINT_PRIMARYKEY.
		if e.Code() == 2067 || e.Code() == 1555 {
			return true
		}
	}
	msg := err.Error()
	return strings.Contains(msg, "UNIQUE constraint failed")
}
