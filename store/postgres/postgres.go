// Package postgres provides the PostgreSQL storage adapter for Auth-All.
package postgres

import (
	"database/sql"
	"errors"

	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib" // registers the pgx database/sql driver

	"github.com/alternayte/auth-all/internal/sqlstore"
	"github.com/alternayte/auth-all/schema"
	"github.com/alternayte/auth-all/store"
)

var dialect = sqlstore.Dialect{
	Name:                 schema.Postgres,
	NumberedPlaceholders: true,
	TextTime:             false,
	IsUniqueViolation:    isUniqueViolation,
}

// New returns a PostgreSQL store over an application-owned database handle.
func New(db *sql.DB) store.Store {
	return sqlstore.New(db, dialect)
}

// Open returns a database handle for a PostgreSQL DSN. The application owns the
// returned handle.
func Open(dsn string) (*sql.DB, error) {
	return sql.Open("pgx", dsn)
}

func isUniqueViolation(err error) bool {
	var e *pgconn.PgError
	if errors.As(err, &e) {
		return e.Code == "23505"
	}
	return false
}
